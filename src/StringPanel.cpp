/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2022 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <unictype.h>
#include <unistr.h>
#include <wx/artprov.h>
#include <wx/mstream.h>
#include <wx/numformatter.h>

#include "CharacterEncoder.hpp"
#include "StringPanel.hpp"

#include "../res/spinner24.h"

static const size_t WINDOW_SIZE = 2 * 1024 * 1024; /* 2MiB */
static const size_t MAX_STRINGS = 1000000;
static const size_t UI_THREAD_THRESH = 256 * 1024; /* 256KiB */

static const size_t MAX_STRINGS_BATCH = 64;

static REHex::ToolPanel *StringPanel_factory(wxWindow *parent, REHex::SharedDocumentPointer &document, REHex::DocumentCtrl *document_ctrl)
{
	return new REHex::StringPanel(parent, document, document_ctrl);
}

static REHex::ToolPanelRegistration tpr("StringPanel", "Strings", REHex::ToolPanel::TPS_TALL, &StringPanel_factory);

enum {
	ID_ENCODING_CHOICE = 1,
	ID_RESET_BUTTON,
	ID_CONTINUE_BUTTON,
	ID_MIN_STRING_LENGTH,
	ID_CJK_TOGGLE,
};

BEGIN_EVENT_TABLE(REHex::StringPanel, wxPanel)
	EVT_TIMER(wxID_ANY, REHex::StringPanel::OnTimerTick)
	EVT_LIST_ITEM_ACTIVATED(wxID_ANY, REHex::StringPanel::OnItemActivate)
	EVT_CHOICE(ID_ENCODING_CHOICE, REHex::StringPanel::OnEncodingChanged)
	
	EVT_BUTTON(ID_RESET_BUTTON,     REHex::StringPanel::OnReset)
	EVT_BUTTON(ID_CONTINUE_BUTTON,  REHex::StringPanel::OnContinue)
	
	EVT_SPINCTRL(ID_MIN_STRING_LENGTH, REHex::StringPanel::OnMinStringLength)
	EVT_CHECKBOX(ID_CJK_TOGGLE, REHex::StringPanel::OnCJKToggle)
END_EVENT_TABLE()

REHex::StringPanel::StringPanel(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl):
	ToolPanel(parent),
	document(document),
	document_ctrl(document_ctrl),
	min_string_length(8),
	ignore_cjk(false),
	update_needed(false),
	threads_exit(true),
	timer(this, wxID_ANY),
	threads_pause(false),
	spawned_threads(0),
	running_threads(0),
	search_base(0)
{
	const int MARGIN = 4;
	
	list_ctrl = new StringPanelListCtrl(this);
	
	list_ctrl->AppendColumn("Offset");
	list_ctrl->AppendColumn("Text");
	
	status_text = new wxStaticText(this, wxID_ANY, "");
	
	encoding_choice = new wxChoice(this, ID_ENCODING_CHOICE);
	
	std::vector<const CharacterEncoding*> all_encodings = CharacterEncoding::all_encodings();
	for(auto i = all_encodings.begin(); i != all_encodings.end(); ++i)
	{
		const CharacterEncoding *ce = *i;
		encoding_choice->Append(ce->label, (void*)(ce));
	}
	
	encoding_choice->SetSelection(0);
	selected_encoding = all_encodings.front();
	
	min_string_length_ctrl = new wxSpinCtrl(
		this, ID_MIN_STRING_LENGTH, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxSP_ARROW_KEYS,
		1, 1024, min_string_length);
	
	wxBoxSizer *min_string_length_sizer = new wxBoxSizer(wxHORIZONTAL);
	
	min_string_length_sizer->Add(new wxStaticText(this, wxID_ANY, "Minimum string length: "), 0, wxALIGN_CENTER_VERTICAL);
	min_string_length_sizer->Add(min_string_length_ctrl, 0, wxALIGN_CENTER_VERTICAL);
	min_string_length_sizer->Add(new wxStaticText(this, wxID_ANY, " code points"), 0, wxALIGN_CENTER_VERTICAL);
	
	ignore_cjk_check = new wxCheckBox(this, ID_CJK_TOGGLE, "Ignore CJK code points");
	ignore_cjk_check->SetValue(ignore_cjk);
	
	wxMemoryInputStream spinner_stream(spinner24_gif, sizeof(spinner24_gif));
	
	wxAnimation spinner_anim;
	spinner_anim.Load(spinner_stream, wxANIMATION_TYPE_GIF);
	
	spinner = new wxAnimationCtrl(this, wxID_ANY, spinner_anim, wxDefaultPosition, wxSize(24, 24));
	spinner->Hide();
	
	reset_button = new wxBitmapButton(this, ID_RESET_BUTTON, wxArtProvider::GetBitmap(wxART_GOTO_FIRST, wxART_BUTTON));
	reset_button->SetToolTip("Search from start of file");
	reset_button->Disable();
	
	continue_button = new wxBitmapButton(this, ID_CONTINUE_BUTTON, wxArtProvider::GetBitmap(wxART_GO_FORWARD, wxART_BUTTON));
	continue_button->SetToolTip("Continue search");
	continue_button->Disable();
	
	wxBoxSizer *status_sizer = new wxBoxSizer(wxHORIZONTAL);
	
	status_sizer->Add(status_text, 1);
	status_sizer->Add(spinner, 0, (wxRESERVE_SPACE_EVEN_IF_HIDDEN | wxALIGN_CENTER_VERTICAL));
	status_sizer->Add(reset_button, 0, wxALIGN_CENTER_VERTICAL);
	status_sizer->Add(continue_button, 0, wxALIGN_CENTER_VERTICAL);
	
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);
	sizer->Add(encoding_choice, 0, (wxLEFT | wxRIGHT | wxTOP), MARGIN);
	sizer->Add(min_string_length_sizer, 0, (wxLEFT | wxRIGHT | wxTOP), MARGIN);
	sizer->Add(ignore_cjk_check, 0, (wxLEFT | wxRIGHT | wxTOP), MARGIN);
	sizer->Add(status_sizer, 0, (wxEXPAND | wxLEFT | wxRIGHT | wxTOP), MARGIN);
	sizer->Add(list_ctrl, 1, (wxEXPAND | wxALL), MARGIN);
	SetSizerAndFit(sizer);
	
	this->document.auto_cleanup_bind(DATA_ERASE,     &REHex::StringPanel::OnDataErase,     this);
	this->document.auto_cleanup_bind(DATA_INSERT,    &REHex::StringPanel::OnDataInsert,    this);
	this->document.auto_cleanup_bind(DATA_OVERWRITE, &REHex::StringPanel::OnDataOverwrite, this);
	
	this->document.auto_cleanup_bind(DATA_ERASING,              &REHex::StringPanel::OnDataModifying,        this);
	this->document.auto_cleanup_bind(DATA_ERASE_ABORTED,        &REHex::StringPanel::OnDataModifyAborted,    this);
	this->document.auto_cleanup_bind(DATA_INSERTING,            &REHex::StringPanel::OnDataModifying,        this);
	this->document.auto_cleanup_bind(DATA_INSERT_ABORTED,       &REHex::StringPanel::OnDataModifyAborted,    this);
	
	mark_dirty(0, document->buffer_length());
	
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
	
	if(update_needed && document_ctrl)
	{
		size_t strings_count;
		
		{
			std::lock_guard<std::mutex> sl(strings_lock);
			
			strings_count = strings.size();
			update_needed = false;
		}
		
		list_ctrl->SetItemCount(strings_count);
		
		bool searching = spawned_threads > 0;
		std::string status_text = "";
		
		if(searching)
		{
			status_text += "Searching from " + format_offset(search_base, document_ctrl->get_offset_display_base(), document->buffer_length());
			continue_button->Disable();
		}
		else{
			status_text += "Searched from " + format_offset(search_base, document_ctrl->get_offset_display_base(), document->buffer_length());
			
			auto next_pending = pending.find_first_in(search_base, std::numeric_limits<off_t>::max());
			continue_button->Enable(next_pending != pending.end());
		}
		
		status_text += "\n";
		
		if(strings_count > 0)
		{
			status_text += "Found "
				+ wxNumberFormatter::ToString((long)(strings_count))
				+ " strings";
		}
		else if(!searching)
		{
			status_text += "No strings found";
		}
		
		this->status_text->SetLabelText(status_text);
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

void REHex::StringPanel::mark_dirty_pad(off_t offset, off_t length)
{
	const off_t ideal_pad = min_string_length * MAX_CHAR_SIZE;
	
	off_t pre_pad = std::min(ideal_pad, offset);
	offset -= pre_pad;
	length += pre_pad;
	
	off_t post_pad = std::min(ideal_pad, (document->buffer_length() - offset));
	length += post_pad;
	
	mark_dirty(offset, length);
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

off_t REHex::StringPanel::sum_dirty_bytes()
{
	/* Merge the all the ranges in dirty, pending and working. */
	
	ByteRangeSet merged;
	merged.set_ranges(dirty.begin(), dirty.end());
	merged.set_ranges(pending.begin(), pending.end());
	merged.set_ranges(working.begin(), working.end());
	
	/* Sum the length of the merged ranges. */
	
	off_t dirty_total = std::accumulate(merged.begin(), merged.end(),
		(off_t)(0), [](off_t sum, const ByteRangeSet::Range &range) { return sum + range.length; });
	
	return dirty_total;
}

off_t REHex::StringPanel::sum_clean_bytes()
{
	return document->buffer_length() - sum_dirty_bytes();
}

REHex::ByteRangeSet REHex::StringPanel::get_strings()
{
	std::lock_guard<std::mutex> sl(strings_lock);
	return strings;
}

off_t REHex::StringPanel::get_clean_bytes()
{
	std::lock_guard<std::mutex> pl(pause_lock);
	return sum_clean_bytes();
}

size_t REHex::StringPanel::get_num_threads()
{
	return threads.size();
}

void REHex::StringPanel::set_encoding(const std::string &encoding_key)
{
	pause_threads();
	
	int num_encodings = encoding_choice->GetCount();
	
	int encoding_idx = -1;
	const CharacterEncoding *encoding = NULL;
	
	for(int i = 0; i < num_encodings; ++i)
	{
		const CharacterEncoding *ce = (const CharacterEncoding*)(encoding_choice->GetClientData(i));
		
		if(ce->key == encoding_key)
		{
			encoding_idx = i;
			encoding = ce;
			
			break;
		}
	}
	
	if(encoding_idx < 0)
	{
		return;
	}
	
	encoding_choice->SetSelection(encoding_idx);
	this->selected_encoding = encoding;
	
	{
		std::lock_guard<std::mutex> pl(pause_lock);
		mark_dirty(0, document->buffer_length());
	}
	
	{
		std::lock_guard<std::mutex> sl(strings_lock);
		strings.clear_all();
	}
	
	start_threads();
	
	update_needed = true;
}

void REHex::StringPanel::set_min_string_length(int min_string_length)
{
	pause_threads();
	
	min_string_length_ctrl->SetValue(min_string_length);
	this->min_string_length = min_string_length;
	
	{
		std::lock_guard<std::mutex> pl(pause_lock);
		mark_dirty(0, document->buffer_length());
	}
	
	{
		std::lock_guard<std::mutex> sl(strings_lock);
		strings.clear_all();
	}
	
	start_threads();
	
	update_needed = true;
}

void REHex::StringPanel::thread_main()
{
	std::unique_lock<std::mutex> pl(pause_lock);
	
	ByteRangeSet set_ranges;
	ByteRangeSet clear_ranges;
	
	auto get_dirty_range = [&]()
	{
		return pending.find_first_in(search_base, std::numeric_limits<off_t>::max());
	};
	
	while(!threads_exit)
	{
		/* Take up to WINDOW_SIZE bytes from the next range in the dirty pool to be
		 * processed in this thread.
		*/
		
		auto next_dirty_range = get_dirty_range();
		if(next_dirty_range == pending.end())
		{
			/* Nothing to do.
			 * Wait until some work is available or we need to pause/stop the thread.
			*/
			
			thread_flush(&set_ranges, &clear_ranges, true);
			
			resume_cv.wait(pl, [&]() { return get_dirty_range() != pending.end() || threads_pause || threads_exit; });
			
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
		size_t window_length = next_dirty_range->length;
		
		if(window_base < search_base)
		{
			off_t adj = search_base - window_base;
			assert(adj < next_dirty_range->length);
			
			window_base += adj;
			window_length -= adj;
			
		}
		
		window_length = std::min<off_t>(window_length, WINDOW_SIZE);
		
		pending.clear_range(window_base, window_length);
		working.set_range(  window_base, window_length);
		
		pl.unlock();
		
		/* Grow both ends of our window by MIN_STRING_LENGTH bytes to ensure we can match
		 * strings starting before/after it. Any data that is part of the string beyond our
		 * expanded window will be merged later.
		*/
		
		off_t window_pre = std::min<off_t>(window_base, (min_string_length * MAX_CHAR_SIZE));
		
		off_t  window_base_adj   = window_base   - window_pre;
		size_t window_length_adj = window_length + window_pre + (min_string_length * MAX_CHAR_SIZE);
		
		/* Read the data from our window and search for strings in it. */
		
		std::vector<unsigned char> data;
		try {
			data = document->read_data(window_base_adj, window_length_adj);
		}
		catch(const std::exception &e)
		{
			/* Failed to read the file. Stick this back in the dirty queue and fetch
			 * another block to process.
			 *
			 * TODO: Somehow de-prioritise this block or delay it becoming available
			 * again. Permanent I/O errors will result in worker threads trying to read
			 * the same bad blocks over and over as things stand now.
			*/
			
			pl.lock();
			
			working.clear_range(window_base, window_length);
			mark_dirty(window_base, window_length);
			
			continue;
		}
		
		for(size_t i = 0; i < data.size();)
		{
			off_t string_base = window_base_adj + i;
			off_t string_end  = string_base;
			
			/* TODO: Align with encoding word size. */
			
			bool is_really_string;
			size_t num_codepoints = 1;
			
			auto is_i_string = [&](bool force_advance)
			{
				EncodedCharacter ec = selected_encoding->encoder->decode(data.data() + i, data.size() - i);
				
				if(ec.valid)
				{
					ucs4_t c;
					u8_mbtouc_unsafe(&c, (const uint8_t*)(ec.utf8_char().data()), ec.utf8_char().size());
					
					bool is_valid = c >= 0x20
						&& c != 0x7F
						&& c != 0xFFFD
						&& !uc_is_property_unassigned_code_value(c)
						&& !uc_is_property_not_a_character(c)
						&& (!ignore_cjk || !(uc_is_property_ideographic(c) || uc_is_property_unified_ideograph(c) || uc_is_property_radical(c)));
					
					if(force_advance || is_valid == is_really_string)
					{
						string_end += ec.encoded_char().size();
						i          += ec.encoded_char().size();
					}
					
					return is_valid;
				}
				else{
					if(force_advance || !is_really_string)
					{
						++string_end;
						++i;
					}
					
					return false;
				}
			};
			
			is_really_string = is_i_string(true);
			
			while(!threads_pause && i < data.size() && is_i_string(false) == is_really_string)
			{
				++num_codepoints;
			}
			
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
				
				working.clear_range(new_dirty_base, new_dirty_length);
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
				if(is_really_string && num_codepoints >= (size_t)(min_string_length))
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
		
		off_t processed_total = sum_clean_bytes();
		size_t size_hint = (double)(strings.size()) * ((double)(document->buffer_length()) / (double)(processed_total));
		
		if(size_hint > MAX_STRINGS)
		{
			size_hint = MAX_STRINGS;
		}
		
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
	{
		std::lock_guard<std::mutex> sl(strings_lock);
		
		if(strings.size() >= MAX_STRINGS)
		{
			/* Already at the strings limit, don't restart threads. */
			return;
		}
	}
	
	resume_threads();
	
	std::lock_guard<std::mutex> pl(pause_lock);
	
	off_t dirty_total = sum_dirty_bytes();
	
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
			
			if(!timer.IsRunning())
			{
				timer.Start(100, wxTIMER_CONTINUOUS);
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
	
	spinner->Show();
	spinner->Play();
}

void REHex::StringPanel::stop_threads()
{
	spinner->Stop();
	spinner->Hide();
	
	timer.Stop();
	
	{
		std::lock_guard<std::mutex> pl(pause_lock);
		threads_exit = true;
	}
	
	/* Wake any threads that are paused so they can exit. */
	resume_threads();
	
	while(!threads.empty())
	{
		threads.front().join();
		threads.pop_front();
	}
	
	/* Process any lingering update. */
	update();
}

void REHex::StringPanel::pause_threads()
{
	std::unique_lock<std::mutex> pl(pause_lock);
	
	threads_pause = true;
	
	/* Wake any threads that are waiting for work so they can be paused. */
	resume_cv.notify_all();
	
	/* Wait for all threads to pause. */
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
		std::lock_guard<std::mutex> pl(pause_lock);
		
		dirty.data_erased(event.offset, event.length);
		pending.data_erased(event.offset, event.length);
		assert(working.empty());
		
		mark_dirty_pad(event.offset, 0);
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
		std::lock_guard<std::mutex> pl(pause_lock);
		
		dirty.data_inserted(event.offset, event.length);
		pending.data_inserted(event.offset, event.length);
		assert(working.empty());
		
		mark_dirty_pad(event.offset, event.length);
	}
	
	start_threads();
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::StringPanel::OnDataOverwrite(OffsetLengthEvent &event)
{
	{
		std::lock_guard<std::mutex> pl(pause_lock);
		mark_dirty_pad(event.offset, event.length);
	}
	
	start_threads();
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::StringPanel::OnItemActivate(wxListEvent &event)
{
	long item_idx = event.GetIndex();
	assert(item_idx >= 0);
	
	std::lock_guard<std::mutex> sl(strings_lock);
	
	if((size_t)(item_idx) >= strings.size())
	{
		/* UI thread probably hasn't caught up to worker threads yet. */
		return;
	}
	
	const ByteRangeSet::Range &string_range = strings[item_idx];
	
	document->set_cursor_position(string_range.offset);
	document_ctrl->set_selection_raw(string_range.offset, (string_range.offset + string_range.length - 1));
}

void REHex::StringPanel::OnTimerTick(wxTimerEvent &event)
{
	off_t dirty_total;
	
	{
		std::lock_guard<std::mutex> pl(pause_lock);
		dirty_total = sum_dirty_bytes();
	}
	
	if(dirty_total == 0 || threads_exit)
	{
		/* Processing is finished. Shut down threads. */
		stop_threads();
	}
	
	update();
}

void REHex::StringPanel::OnEncodingChanged(wxCommandEvent &event)
{
	pause_threads();
	
	int encoding_idx = event.GetSelection();
	selected_encoding = (const CharacterEncoding*)(encoding_choice->GetClientData(encoding_idx));
	
	{
		std::lock_guard<std::mutex> pl(pause_lock);
		mark_dirty(0, document->buffer_length());
	}
	
	{
		std::lock_guard<std::mutex> sl(strings_lock);
		strings.clear_all();
	}
	
	start_threads();
	
	update_needed = true;
}

void REHex::StringPanel::OnMinStringLength(wxSpinEvent &event)
{
	pause_threads();
	
	min_string_length = event.GetPosition();
	
	{
		std::lock_guard<std::mutex> pl(pause_lock);
		mark_dirty(0, document->buffer_length());
	}
	
	{
		std::lock_guard<std::mutex> sl(strings_lock);
		strings.clear_all();
	}
	
	start_threads();
	
	update_needed = true;
}

void REHex::StringPanel::OnCJKToggle(wxCommandEvent &event)
{
	pause_threads();
	
	ignore_cjk = event.IsChecked();
	
	{
		std::lock_guard<std::mutex> pl(pause_lock);
		mark_dirty(0, document->buffer_length());
	}
	
	{
		std::lock_guard<std::mutex> sl(strings_lock);
		strings.clear_all();
	}
	
	start_threads();
	
	update_needed = true;
}

void REHex::StringPanel::OnReset(wxCommandEvent &event)
{
	pause_threads();
	
	if(!strings.empty())
	{
		off_t strings_begin = strings.first().offset;
		off_t strings_end = strings.last().offset + strings.last().length;
		
		pending.set_range(strings_begin, (strings_end - strings_begin));
	}
	
	search_base = 0;
	strings.clear_all();
	
	start_threads();
	
	reset_button->Disable();
	
	update_needed = true;
}

void REHex::StringPanel::OnContinue(wxCommandEvent &event)
{
	assert(spawned_threads == 0);
	
	auto next_pending = pending.find_first_in(search_base, std::numeric_limits<off_t>::max());
	assert(next_pending != pending.end());
	
	search_base = next_pending->offset;
	
	if(!strings.empty())
	{
		off_t strings_begin = strings.first().offset;
		off_t strings_end = strings.last().offset + strings.last().length;
		
		pending.set_range(strings_begin, (strings_end - strings_begin));
		
		strings.clear_all();
	}
	
	start_threads();
	
	reset_button->Enable();
	
	update_needed = true;
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
			
			try {
				std::vector<unsigned char> string_data = parent->document->read_data(si.offset, si.length);
				std::string string;
				
				for(size_t i = 0; i < string_data.size();)
				{
					EncodedCharacter ec = parent->selected_encoding->encoder->decode(string_data.data() + i, string_data.size() - i);
					
					string += ec.utf8_char();
					i += ec.encoded_char().size();
				}
				
				return wxString::FromUTF8(string.data(), string.size());
			}
			catch(const std::exception &e)
			{
				/* Probably a file I/O error. */
				return "???";
			}
		}
		
		default:
			/* Unknown column */
			abort();
	}
}
