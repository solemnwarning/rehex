/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020 Daniel Collins <solemnwarning@solemnwarning.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "platform.hpp"

#include <assert.h>
#include <ctype.h>
#include <numeric>

#include "StringPanel.hpp"

static const off_t MIN_STRING_LENGTH = 4;
static const size_t WINDOW_SIZE = 2 * 1024 * 1024; /* 2MiB */
static const size_t MAX_STRINGS = 1000000;
static const size_t UI_THREAD_THRESH = 256 * 1024; /* 256KiB */

static const size_t MAX_STRINGS_BATCH = 64;

static REHex::ToolPanel *StringPanel_factory(wxWindow *parent, REHex::SharedDocumentPointer &document, REHex::DocumentCtrl *document_ctrl)
{
	return new REHex::StringPanel(parent, document, document_ctrl);
}

static REHex::ToolPanelRegistration tpr("StringPanel", "Strings", REHex::ToolPanel::TPS_TALL, &StringPanel_factory);

REHex::StringPanel::StringPanel(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl):
	ToolPanel(parent),
	document(document),
	document_ctrl(document_ctrl),
	update_needed(false),
	threads_exit(true),
	threads_pause(false),
	spawned_threads(0),
	running_threads(0)
{
	list_ctrl = new StringPanelListCtrl(this);
	
	list_ctrl->AppendColumn("Offset");
	list_ctrl->AppendColumn("Text");
	
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);
	sizer->Add(list_ctrl, 1, wxEXPAND);
	SetSizerAndFit(sizer);
	
	this->document.auto_cleanup_bind(DATA_ERASE,     &REHex::StringPanel::OnDataErase,     this);
	this->document.auto_cleanup_bind(DATA_INSERT,    &REHex::StringPanel::OnDataInsert,    this);
	this->document.auto_cleanup_bind(DATA_OVERWRITE, &REHex::StringPanel::OnDataOverwrite, this);
	
	this->document.auto_cleanup_bind(DATA_ERASING,              &REHex::StringPanel::OnDataModifying,        this);
	this->document.auto_cleanup_bind(DATA_ERASE_ABORTED,        &REHex::StringPanel::OnDataModifyAborted,    this);
	this->document.auto_cleanup_bind(DATA_INSERTING,            &REHex::StringPanel::OnDataModifying,        this);
	this->document.auto_cleanup_bind(DATA_INSERT_ABORTED,       &REHex::StringPanel::OnDataModifyAborted,    this);
	
	mark_dirty(0, document->buffer_length());
	
	timer = new wxTimer(this, wxID_ANY);
	
	this->Bind(wxEVT_TIMER, [this](wxTimerEvent &event)
	{
		update();
	});
	
	timer->Start(200, wxTIMER_CONTINUOUS);
	
	start_threads();
}

REHex::StringPanel::~StringPanel()
{
	timer->Stop();
	stop_threads();
}

std::string REHex::StringPanel::name() const
{
	return "StringPanel";
}

void REHex::StringPanel::save_state(wxConfig *config) const
{
	/* TODO */
}

void REHex::StringPanel::load_state(wxConfig *config)
{
	/* TODO */
}

wxSize REHex::StringPanel::DoGetBestClientSize() const
{
	/* TODO */
	return wxSize(100, -1);
}

void REHex::StringPanel::update()
{
	if (!is_visible)
	{
		/* There is no sense in updating this if we are not visible */
		return;
	}
	
	if(update_needed)
	{
		std::lock_guard<std::mutex> sl(strings_lock);
		
		list_ctrl->SetItemCount(strings.size());
		
		static size_t old_capacity = 0;
		
		fprintf(stderr, "update %zu (capacity %zu => %zu)\n", strings.size(), old_capacity, strings.get_ranges().capacity());
		old_capacity = strings.get_ranges().capacity();
	}
}

void REHex::StringPanel::mark_dirty(off_t offset, off_t length)
{
	ByteRangeSet to_pending;
	to_pending.set_range(offset, length);
	
	ByteRangeSet to_dirty = ByteRangeSet::intersection(to_pending, working);
	
	to_pending.clear_ranges(to_dirty.begin(), to_dirty.end());
	
	dirty  .set_ranges(  to_dirty.begin(),   to_dirty.end());
	pending.set_ranges(to_pending.begin(), to_pending.end());
	
	if(!pending.empty())
	{
		/* Notify any sleeping workers that there is now work to be done. */
		resume_cv.notify_all();
	}
}

void REHex::StringPanel::mark_work_done(off_t offset, off_t length)
{
	ByteRangeSet work_done;
	work_done.set_range(offset, length);
	
	ByteRangeSet to_pending = ByteRangeSet::intersection(work_done, dirty);
	
	working.clear_range(offset, length);
	
	dirty.clear_ranges(to_pending.begin(), to_pending.end());
	pending.set_ranges(to_pending.begin(), to_pending.end());
	
	if(!pending.empty())
	{
		/* Notify any sleeping workers that there is now work to be done. */
		resume_cv.notify_all();
	}
}

void REHex::StringPanel::thread_main()
{
	std::unique_lock<std::mutex> pl(pause_lock);
	
	ByteRangeSet set_ranges;
	ByteRangeSet clear_ranges;
	
	while(!threads_exit)
	{
		/* Take up to WINDOW_SIZE bytes from the next range in the dirty pool to be
		 * processed in this thread.
		*/
		
		auto next_dirty_range = pending.begin();
		if(next_dirty_range == pending.end())
		{
			/* Nothing to do.
			 * Wait until some work is available or we need to pause/stop the thread.
			*/
			
			thread_flush(&set_ranges, &clear_ranges, true);
			
			resume_cv.wait(pl, [&]() { return !pending.empty() || threads_pause || threads_exit; });
			
			if(threads_pause)
			{
				--running_threads;
				
				paused_cv.notify_all();
				resume_cv.wait(pl, [this]() { return !threads_pause; });
				
				++running_threads;
			}
			
			continue;
		}
		
		off_t  window_base   = next_dirty_range->offset;
		size_t window_length = std::min<off_t>(next_dirty_range->length, WINDOW_SIZE);
		
		pending.clear_range(window_base, window_length);
		working.set_range(  window_base, window_length);
		
		pl.unlock();
		
		/* Grow both ends of our window by MIN_STRING_LENGTH bytes to ensure we can match
		 * strings starting before/after it. Any data that is part of the string beyond our
		 * expanded window will be merged later.
		*/
		
		off_t window_pre = std::min<off_t>(window_base, MIN_STRING_LENGTH);
		
		off_t  window_base_adj   = window_base   - window_pre;
		size_t window_length_adj = window_length + window_pre + MIN_STRING_LENGTH;
		
		/* Read the data from our window and search for strings in it. */
		
		std::vector<unsigned char> data = document->read_data(window_base_adj, window_length_adj);
		const char *data_p = (const char*)(data.data());
		
		for(size_t i = 0; i < data.size();)
		{
			off_t string_base = window_base_adj + i;
			off_t string_end  = string_base;
			
			bool is_really_string = isascii(data_p[i]) && isprint(data_p[i]);
			
			do {
				++string_end;
				++i;
			} while(!threads_pause && i < data.size() && (isascii(data_p[i]) && isprint(data_p[i])) == is_really_string);
			
			if(threads_pause)
			{
				/* We are being paused to allow for data being inserted or erased.
				 * This may invalidate the base and/or length of our window, so we
				 * mark the window as dirty again from the last point we started
				 * processing so that it can be adjusted correctly and then resumed
				 * when processing continues.
				*/
				
				off_t  new_dirty_base   = std::max(window_base, string_base);
				size_t new_dirty_length = window_length - (new_dirty_base - window_base);
				
				/* vvvvvvvv */
				pl.lock();
				
				if(string_base > window_base)
				{
					mark_work_done(window_base, (string_base - window_base));
				}
				
				mark_dirty(new_dirty_base, new_dirty_length);
				
				thread_flush(&set_ranges, &clear_ranges, true);
				
				--running_threads;
				
				paused_cv.notify_all();
				resume_cv.wait(pl, [this]() { return !threads_pause; });
				
				++running_threads;
				
				pl.unlock();
				/* ^^^^^^^^ */
				
				/* Window is no longer valid, get a new one. */
				window_length = 0;
				break;
			}
			
			off_t clamped_string_base = std::max(string_base, window_base);
			off_t clamped_string_end  = std::min(string_end,  (off_t)(window_base + window_length));
			
			if(clamped_string_base < clamped_string_end)
			{
				if(is_really_string && (string_end - string_base) >= (off_t)(MIN_STRING_LENGTH))
				{
					set_ranges.set_range(clamped_string_base, (clamped_string_end - clamped_string_base));
				}
				else if(clamped_string_base <= clamped_string_end)
				{
					clear_ranges.set_range(clamped_string_base, (clamped_string_end - clamped_string_base));
				}
			}
			
			thread_flush(&set_ranges, &clear_ranges, false);
		}
		
		pl.lock();
		
		mark_work_done(window_base, window_length);
	}
	
	thread_flush(&set_ranges, &clear_ranges, true);
	
	--running_threads;
	--spawned_threads;
}

void REHex::StringPanel::thread_flush(ByteRangeSet *set_ranges, ByteRangeSet *clear_ranges, bool force)
{
	if(force || clear_ranges->size() >= MAX_STRINGS_BATCH)
	{
		std::lock_guard<std::mutex> sl(strings_lock);
		
		strings.clear_ranges(clear_ranges->begin(), clear_ranges->end());
		clear_ranges->clear_all();
		
		update_needed = true;
	}
	
	if(force || set_ranges->size() >= MAX_STRINGS_BATCH)
	{
		std::lock_guard<std::mutex> sl(strings_lock);
		
		off_t dirty_total
			= std::accumulate(dirty.begin(),   dirty.end(),   (off_t)(0), [](off_t sum, const ByteRangeSet::Range &range) { return sum + range.length; })
			+ std::accumulate(pending.begin(), pending.end(), (off_t)(0), [](off_t sum, const ByteRangeSet::Range &range) { return sum + range.length; });
		
		size_t size_hint = (double)(strings.size()) * ((double)(document->buffer_length()) / (double)(document->buffer_length() - dirty_total));
		
		strings.set_ranges(set_ranges->begin(), set_ranges->end(), size_hint);
		set_ranges->clear_all();
		
		update_needed = true;
		
		if(strings.size() >= MAX_STRINGS)
		{
			/* Reached the string limit, start spinning down. */
			threads_exit = true;
		}
	}
}

void REHex::StringPanel::start_threads()
{
	resume_threads();
	
	std::lock_guard<std::mutex> pl(pause_lock);
	
	/* Sum up the lengths of all ranges in dirty and pending. */
	off_t dirty_total
		= std::accumulate(dirty.begin(),   dirty.end(),   (off_t)(0), [](off_t sum, const ByteRangeSet::Range &range) { return sum + range.length; })
		+ std::accumulate(pending.begin(), pending.end(), (off_t)(0), [](off_t sum, const ByteRangeSet::Range &range) { return sum + range.length; });
	
	if(dirty_total > 0)
	{
		threads_exit = false;
		
		#if 0
		if(dirty_total >= (off_t)(UI_THREAD_THRESH))
		{
		#endif
			/* There is more than one "window" worth of data to process, either we are
			 * still initialising, or a huge amount of data has just changed. We shall
			 * do our processing in background threads.
			*/
			
			unsigned int max_threads  = std::thread::hardware_concurrency();
			unsigned int want_threads = dirty_total / WINDOW_SIZE;
			
			if(want_threads == 0)
			{
				want_threads = 1;
			}
			else if(want_threads > max_threads)
			{
				want_threads = max_threads;
			}
			
			while(spawned_threads < want_threads)
			{
				threads.emplace_back(&REHex::StringPanel::thread_main, this);
				
				++spawned_threads;
				++running_threads;
			}
		#if 0
		}
		else{
			/* There is very little data to analyse, do it in the UI thread to avoid
			 * starting and stopping background threads on every changed nibble since
			 * the context switching gets expensive.
			*/
			
			// TODO
			thread_main();
		}
		#endif
	}
}

void REHex::StringPanel::stop_threads()
{
	threads_exit = true;
	
	resume_threads();
	
	while(!threads.empty())
	{
		threads.front().join();
		threads.pop_front();
	}
}

void REHex::StringPanel::pause_threads()
{
	std::unique_lock<std::mutex> pl(pause_lock);
	
	threads_pause = true;
	
	paused_cv.wait(pl, [this]() { return running_threads == 0; });
}

void REHex::StringPanel::resume_threads()
{
	{
		std::lock_guard<std::mutex> pl(pause_lock);
		threads_pause = false;
	}
	
	resume_cv.notify_all();
}

void REHex::StringPanel::OnDataModifying(OffsetLengthEvent &event)
{
	pause_threads();
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::StringPanel::OnDataModifyAborted(OffsetLengthEvent &event)
{
	start_threads();
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::StringPanel::OnDataErase(OffsetLengthEvent &event)
{
	{
		std::lock_guard<std::mutex> sl(strings_lock);
		strings.data_erased(event.offset, event.length);
	}
	
	{
		off_t dirtify_off = std::max((event.offset - MIN_STRING_LENGTH), (off_t)(0));
		off_t dirtify_len = std::min((event.length + (MIN_STRING_LENGTH * 2)), (document->buffer_length() - dirtify_off));
		
		std::lock_guard<std::mutex> pl(pause_lock);
		mark_dirty(dirtify_off, dirtify_len);
	}
	
	start_threads();
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::StringPanel::OnDataInsert(OffsetLengthEvent &event)
{
	{
		std::lock_guard<std::mutex> sl(strings_lock);
		strings.data_inserted(event.offset, event.length);
	}
	
	{
		off_t dirtify_off = std::max((event.offset - MIN_STRING_LENGTH), (off_t)(0));
		off_t dirtify_len = std::min((event.length + (MIN_STRING_LENGTH * 2)), (document->buffer_length() - dirtify_off));
		
		std::lock_guard<std::mutex> pl(pause_lock);
		dirty.data_inserted(event.offset, event.length);
		mark_dirty(dirtify_off, dirtify_len);
	}
	
	start_threads();
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::StringPanel::OnDataOverwrite(OffsetLengthEvent &event)
{
	{
		off_t dirtify_off = std::max((event.offset - MIN_STRING_LENGTH), (off_t)(0));
		off_t dirtify_len = std::min((event.length + (MIN_STRING_LENGTH * 2)), (document->buffer_length() - dirtify_off));
		
		std::lock_guard<std::mutex> pl(pause_lock);
		mark_dirty(dirtify_off, dirtify_len);
	}
	
	start_threads();
	
	/* Continue propogation. */
	event.Skip();
}

REHex::StringPanel::StringPanelListCtrl::StringPanelListCtrl(StringPanel *parent):
	wxListCtrl(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize, (wxLC_REPORT | wxLC_VIRTUAL)) {}

wxString REHex::StringPanel::StringPanelListCtrl::OnGetItemText(long item, long column) const
{
	StringPanel *parent = dynamic_cast<StringPanel*>(GetParent());
	assert(parent != NULL);
	
	std::lock_guard<std::mutex> sl(parent->strings_lock);
	
	if((size_t)(item) >= parent->strings.size())
	{
		/* wxWidgets has asked for an item beyond the end of the set.
		 *
		 * This probably means an element has been removed by a worker thread but the UI
		 * thread hasn't caught up and called SetItemCount() yet.
		*/
		
		return "???";
	}
	
	const ByteRangeSet::Range &si = parent->strings.get_ranges()[item];
	
	switch(column)
	{
		case 0:
		{
			/* Offset column */
			return format_offset(si.offset, parent->document_ctrl->get_offset_display_base(), parent->document->buffer_length());
		}
		
		case 1:
		{
			/* Text column */
			std::vector<unsigned char> string_data = parent->document->read_data(si.offset, si.length);
			std::string string((const char*)(string_data.data()), string_data.size());
			
			return string;
		}
		
		default:
			/* Unknown column */
			abort();
	}
}
