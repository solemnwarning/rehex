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

#include "StringPanel.hpp"

static const size_t MIN_STRING_LENGTH = 4;
static const size_t WINDOW_SIZE = 2 * 1024 * 1024; /* 2MiB */
static const size_t MAX_STRINGS = 0xFFFFFFFF;

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
	last_item_idx(-1),
	run_threads(false),
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
	this->document.auto_cleanup_bind(DATA_OVERWRITING,          &REHex::StringPanel::OnDataModifying,        this);
	this->document.auto_cleanup_bind(DATA_OVERWRITE_ABORTED,    &REHex::StringPanel::OnDataModifyAborted,    this);
	
	dirty.set_range(0, document->buffer_length());
	
	wxTimer *timer = new wxTimer(this, wxID_ANY);
	
	this->Bind(wxEVT_TIMER, [this](wxTimerEvent &event)
	{
		update();
	});
	
	timer->Start(200, wxTIMER_CONTINUOUS);
	
	start_threads();
}

REHex::StringPanel::~StringPanel()
{
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
	
	std::lock_guard<std::mutex> sl(strings_lock);
	list_ctrl->SetItemCount(strings.size());
	
	fprintf(stderr, "update %zu\n", strings.size());
}

void REHex::StringPanel::thread_main()
{
	std::unique_lock<std::mutex> dl(dirty_lock);
	
	while(run_threads)
	{
		/* Take up to WINDOW_SIZE bytes from the next range in the dirty pool to be
		 * processed in this thread.
		*/
		
		auto next_dirty_range = dirty.begin();
		
		if(next_dirty_range == dirty.end())
		{
			/* Nothing to do. */
			break;
		}
		
		size_t window_base   = next_dirty_range->offset;
		size_t window_length = std::min<off_t>(next_dirty_range->length, WINDOW_SIZE);
		
		dirty.clear_range(window_base, window_length);
		
		dl.unlock();
		
		/* Grow both ends of our window by MIN_STRING_LENGTH bytes to ensure we can match
		 * strings starting before/after it. Any data that is part of the string beyond our
		 * expanded window will be merged later.
		*/
		
		off_t window_pre = std::min<off_t>(window_base, MIN_STRING_LENGTH);
		
		window_base   -= window_pre;
		window_length += window_pre;
		
		window_length += MIN_STRING_LENGTH;
		
		/* Read the data from our window and search for strings in it. */
		
		std::vector<unsigned char> data = document->read_data(window_base, window_length);
		const char *data_p = (const char*)(data.data());
		
		for(size_t i = 0; i < data.size(); ++i)
		{
			off_t  string_base   = window_base + i;
			size_t string_length = 0;
			
			while(isascii(data_p[i]) && isprint(data_p[i]) && i < data.size())
			{
				++string_length;
				++i;
			}
			
			if(string_length >= MIN_STRING_LENGTH)
			{
				std::lock_guard<std::mutex> sl(strings_lock);
				
				strings.set_range(string_base, string_length);
				update_needed = true;
				
				last_item_idx = -1;
			}
		}
		
		dl.lock();
	}
	
	--running_threads;
}

void REHex::StringPanel::start_threads()
{
	std::lock_guard<std::mutex> dl(dirty_lock);
	
	size_t dirty_total = 0;
	for(auto i = dirty.begin(); i != dirty.end(); ++i)
	{
		dirty_total += i->length;
	}
	
	if(dirty_total > 0)
	{
		run_threads = true;
		
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
		
		fprintf(stderr, "spawning threads %u => %u\n", running_threads, want_threads);
		
		while(running_threads < want_threads)
		{
			threads.emplace_back(&REHex::StringPanel::thread_main, this);
			++running_threads;
		}
	}
}

void REHex::StringPanel::stop_threads()
{
	run_threads = false;
	
	while(!threads.empty())
	{
		threads.front().join();
		threads.pop_front();
	}
}

std::set<REHex::ByteRangeSet::Range>::const_iterator REHex::StringPanel::get_nth_string(ssize_t n)
{
	assert(n < strings.size());
	
	if(last_item_idx < 0)
	{
		/* last_item_idx is negative, last_item_iter is invalid. Restart. */
		last_item_iter = strings.begin();
		last_item_idx  = 0;
	}
	
	/* Advance last_item_iter to the requested element.
	 * NOTE: Will compute negative distance and walk backwards if necessary.
	*/
	last_item_iter = std::next(last_item_iter, (n - last_item_idx));
	last_item_idx  = n;
	
	return last_item_iter;
}

void REHex::StringPanel::OnDataModifying(OffsetLengthEvent &event)
{
	stop_threads();
	
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
		
		last_item_idx = -1;
	}
	
	{
		std::lock_guard<std::mutex> dl(dirty_lock);
		dirty.data_erased(event.offset, event.length);
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
		
		last_item_idx = -1;
	}
	
	{
		std::lock_guard<std::mutex> dl(dirty_lock);
		dirty.data_inserted(event.offset, event.length);
		dirty.set_range(event.offset, event.length);
	}
	
	start_threads();
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::StringPanel::OnDataOverwrite(OffsetLengthEvent &event)
{
	{
		std::lock_guard<std::mutex> dl(dirty_lock);
		dirty.set_range(event.offset, event.length);
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
	
	auto si = parent->get_nth_string(item);
	
	switch(column)
	{
		case 0:
		{
			/* Offset column */
			return format_offset(si->offset, parent->document_ctrl->get_offset_display_base(), parent->document->buffer_length());
		}
		
		case 1:
		{
			/* Text column */
			std::vector<unsigned char> string_data = parent->document->read_data(si->offset, si->length);
			std::string string((const char*)(string_data.data()), string_data.size());
			
			return string;
		}
		
		default:
			/* Unknown column */
			abort();
	}
}
