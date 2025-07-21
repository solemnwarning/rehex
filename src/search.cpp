/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <cmath>
#include <functional>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unicase.h>
#include <utility>
#include <wx/msgdlg.h>
#include <wx/sizer.h>
#include <wx/statbox.h>
#include <wx/statline.h>

#include "CharacterEncoder.hpp"
#include "NumericTextCtrl.hpp"
#include "profile.hpp"
#include "search.hpp"
#include "util.hpp"

/* This MUST come after the wxWidgets headers have been included, else we pull in windows.h BEFORE the wxWidgets
 * headers when building on Windows and this causes unicode-flavoured pointer conversion errors.
*/
#include "endian_conv.hpp"

enum {
	ID_FIND_NEXT = 1,
	ID_FIND_PREV,
	ID_TIMER,
	
	ID_RANGE_CB,
	ID_ALIGN_CB,
	ID_RALIGN_CB,
};

static void set_width_chars(wxWindow *window, unsigned int chars)
{
	wxSize text_size = window->GetTextExtent(std::string(chars, 'W'));
	wxSize cur_size  = window->GetSize();
	
	wxSize new_size(text_size.GetWidth(), cur_size.GetHeight());
	
	window->SetMinSize(new_size);
	window->SetMaxSize(new_size);
	window->SetSize(new_size);
}

BEGIN_EVENT_TABLE(REHex::Search, wxDialog)
	EVT_CLOSE(REHex::Search::OnClose)
	
	EVT_CHECKBOX(ID_RANGE_CB,  REHex::Search::OnCheckBox)
	EVT_CHECKBOX(ID_ALIGN_CB,  REHex::Search::OnCheckBox)
	EVT_CHECKBOX(ID_RALIGN_CB, REHex::Search::OnCheckBox)
	
	EVT_BUTTON(ID_FIND_NEXT, REHex::Search::OnFindNext)
	EVT_BUTTON(ID_FIND_PREV, REHex::Search::OnFindPrev)
	EVT_TEXT_ENTER(wxID_ANY, REHex::Search::OnTextEnter)
	EVT_BUTTON(wxID_CANCEL, REHex::Search::OnCancel)
	EVT_TIMER(ID_TIMER, REHex::Search::OnTimer)
END_EVENT_TABLE()

REHex::Search::Search(wxWindow *parent, SharedDocumentPointer &doc, const char *title):
	wxDialog(parent, wxID_ANY, title),
	doc(doc), range_begin(0), range_end(-1), align_to(1), align_from(0), match_found_at(-1), running(false),
	search_end_focus(NULL),
	timer(this, ID_TIMER),
	auto_close(false),
	auto_wrap(false),
	modal_parent(this)
{}

void REHex::Search::setup_window()
{
	wxBoxSizer *main_sizer = new wxBoxSizer(wxVERTICAL);
	
	setup_window_controls(this, main_sizer);
	
	{
		wxStaticBoxSizer *sz = new wxStaticBoxSizer(wxVERTICAL, this, "Search range");
		main_sizer->Add(sz, 0, wxTOP | wxLEFT | wxRIGHT | wxEXPAND, 10);
		
		{
			wxBoxSizer *range_sz = new wxBoxSizer(wxHORIZONTAL);
			sz->Add(range_sz, 0, wxTOP | wxLEFT | wxRIGHT, 5);
			
			range_cb = new wxCheckBox(sz->GetStaticBox(), ID_RANGE_CB, "Only search from offset ");
			range_sz->Add(range_cb, 0);
			
			range_begin_tc = new wxTextCtrl(sz->GetStaticBox(), wxID_ANY);
			set_width_chars(range_begin_tc, 12);
			range_sz->Add(range_begin_tc);
			
			range_sz->Add(new wxStaticText(sz->GetStaticBox(), wxID_ANY, " to "));
			
			range_end_tc = new wxTextCtrl(sz->GetStaticBox(), wxID_ANY);
			set_width_chars(range_end_tc, 12);
			range_sz->Add(range_end_tc);
		}
		
		{
			wxBoxSizer *align_sizer = new wxBoxSizer(wxHORIZONTAL);
			sz->Add(align_sizer, 0, wxTOP | wxLEFT | wxRIGHT, 5);
			
			align_cb = new wxCheckBox(sz->GetStaticBox(), ID_ALIGN_CB, "Results must be aligned to ");
			align_sizer->Add(align_cb);
			
			align_tc = new wxTextCtrl(sz->GetStaticBox(), wxID_ANY);
			set_width_chars(align_tc, 4);
			align_sizer->Add(align_tc);
			
			align_sizer->Add(new wxStaticText(sz->GetStaticBox(), wxID_ANY, " bytes"));
		}
		
		{
			wxBoxSizer *ralign_sz = new wxBoxSizer(wxHORIZONTAL);
			sz->Add(ralign_sz, 0, wxALL, 5);
			
			ralign_cb = new wxCheckBox(sz->GetStaticBox(), ID_RALIGN_CB, "...relative to offset ");
			ralign_sz->Add(ralign_cb);
			
			ralign_tc = new wxTextCtrl(sz->GetStaticBox(), wxID_ANY);
			set_width_chars(ralign_tc, 12);
			ralign_sz->Add(ralign_tc);
		}
	}
	
	{
		wxBoxSizer *button_sz = new wxBoxSizer(wxHORIZONTAL);
		main_sizer->Add(button_sz, 0, wxALIGN_RIGHT | wxALL, 10);
		
		button_sz->Add(new wxButton(this, ID_FIND_PREV, "Find previous"));
		button_sz->Add(new wxButton(this, ID_FIND_NEXT, "Find next"), 0, wxLEFT, 10);
		button_sz->Add(new wxButton(this, wxID_CANCEL,  "Cancel"), 0, wxLEFT, 10);
	}
	
	enable_controls();
	
	SetSizerAndFit(main_sizer);
}

bool REHex::Search::wrap_query(const char *message)
{
	return wxMessageBox(message, wxMessageBoxCaptionStr, (wxYES_NO | wxCENTRE), this) == wxYES;
}

void REHex::Search::not_found_notification()
{
	wxMessageBox("Not found", wxMessageBoxCaptionStr, (wxOK | wxICON_INFORMATION | wxCENTRE), this);
}

void REHex::Search::limit_range(off_t range_begin, off_t range_end, OffsetBase fmt_base)
{
	assert(range_begin >= 0);
	assert(range_end > range_begin);
	
	this->range_begin = range_begin;
	this->range_end   = range_end;
	
	char offset_str[24];

	switch(fmt_base)
	{
		case OFFSET_BASE_HEX:
		{
			snprintf(offset_str, sizeof(offset_str), "0x%llX", (long long unsigned)(range_begin));
			range_begin_tc->SetValue(offset_str);

			snprintf(offset_str, sizeof(offset_str), "0x%llX", (long long unsigned)(range_end - 1));
			range_end_tc->SetValue(offset_str);

			break;
		}
		
		case OFFSET_BASE_DEC:
		{
			snprintf(offset_str, sizeof(offset_str), "0x%lld", (long long)(range_begin));
			range_begin_tc->SetValue(offset_str);

			snprintf(offset_str, sizeof(offset_str), "0x%lld", (long long)(range_end - 1));
			range_end_tc->SetValue(offset_str);
			
			break;
		}

		default:
			assert(false); /* Unreachable. */
			break;
	}

	range_cb->SetValue(true);
	enable_controls();
}

void REHex::Search::require_alignment(off_t alignment, off_t relative_to_offset)
{
	assert(alignment > 0);
	assert(relative_to_offset >= 0);
	
	align_to   = alignment;
	align_from = relative_to_offset;
}

void REHex::Search::set_auto_close(bool auto_close)
{
	this->auto_close = auto_close;
}

void REHex::Search::set_auto_wrap(bool auto_wrap)
{
	this->auto_wrap = auto_wrap;
}

void REHex::Search::set_modal_parent(wxWindow *modal_parent)
{
	this->modal_parent = modal_parent;
}

/* This method is only used by the unit tests. */
off_t REHex::Search::find_next(off_t from_offset, size_t window_size)
{
	if(range_end < 0)
	{
		range_end = doc->buffer_length();
	}
	
	begin_search(from_offset, range_end, SearchDirection::FORWARDS, window_size);
	
	/* Wait for the workers to finish searching. */
	while(!threads.empty())
	{
		threads.back().join();
		threads.pop_back();
	}
	
	end_search();
	
	return match_found_at;
}

void REHex::Search::begin_search(off_t sub_range_begin, off_t sub_range_end, SearchDirection direction, size_t window_size)
{
	assert(!running);
	
	size_t compare_size = test_max_window();
	
	/* Clamp local search range to configured range. */
	if(sub_range_begin < range_begin) { sub_range_begin = range_begin; }
	if(sub_range_end   > range_end)   { sub_range_end   = range_end;   }
	
	search_base = sub_range_begin;
	search_end  = sub_range_end;
	
	if(direction == SearchDirection::FORWARDS)
	{
		next_window_start = sub_range_begin;
	}
	else /* if(direction == SearchDirection::BACKWARDS) */
	{
		next_window_start = std::max((sub_range_end - (off_t)(window_size)), sub_range_begin);
	}
	
	match_found_at = -1;
	running        = true;
	
	search_direction = direction;
	
	/* Number of threads to spawn */
	unsigned int thread_count = std::thread::hardware_concurrency();
	
	while(threads.size() < thread_count)
	{
		threads.emplace_back(&REHex::Search::thread_main, this, window_size, compare_size);
	}
	
	progress = new wxProgressDialog("Searching", "Search in progress...", 100, modal_parent, wxPD_CAN_ABORT | wxPD_REMAINING_TIME);
	timer.Start(200, wxTIMER_CONTINUOUS);
}

void REHex::Search::end_search()
{
	assert(running);
	
	running = false;
	
	while(!threads.empty())
	{
		threads.back().join();
		threads.pop_back();
	}
	
	timer.Stop();
	delete progress;
}

void REHex::Search::OnCheckBox(wxCommandEvent &event)
{
	enable_controls();
}

void REHex::Search::OnFindNext(wxCommandEvent &event)
{
	if(read_base_window_controls() && read_window_controls())
	{
		begin_search((doc->get_cursor_position().byte() + 1), range_end, SearchDirection::FORWARDS);
	}
}

void REHex::Search::OnFindPrev(wxCommandEvent &event)
{
	if(read_base_window_controls() && read_window_controls())
	{
		begin_search(range_begin, doc->get_cursor_position().byte(), SearchDirection::BACKWARDS);
	}
}

void REHex::Search::OnTextEnter(wxCommandEvent &event)
{
	/* The search progress dialog steals focus from whatever text control the user just pressed
	 * enter in, we stash the control and current selection (includes cursor position) so we can
	 * restore it when the search is finished.
	*/
	
	wxComboBox *control = dynamic_cast<wxComboBox*>(event.GetEventObject());
	assert(control != NULL);
	
	search_end_focus = control;
	control->GetSelection(&search_end_focus_from, &search_end_focus_to);
	
	if(wxGetKeyState(WXK_SHIFT))
	{
		OnFindPrev(event);
	}
	else{
		OnFindNext(event);
	}
}

void REHex::Search::OnCancel(wxCommandEvent &event)
{
	Close();
}

void REHex::Search::OnTimer(wxTimerEvent &event)
{
	if(progress->WasCancelled())
	{
		end_search();
		
		if(search_end_focus != NULL)
		{
			search_end_focus->SetFocus();
			search_end_focus->SetSelection(search_end_focus_from, search_end_focus_to);
			search_end_focus = NULL;
		}
		
		if(auto_close)
		{
			Destroy();
		}
		
		return;
	}
	
	if(match_found_at >= 0 || next_window_start < search_base || next_window_start > search_end)
	{
		end_search();
		
		if(match_found_at >= 0)
		{
			doc->set_cursor_position(BitOffset(match_found_at));
		}
		else{
			size_t compare_size = test_max_window();
			
			if(search_direction == SearchDirection::FORWARDS && search_base > range_begin)
			{
				/* Search was not from beginning of file/range, ask if we should go back to the start. */
				
				const char *message = range_begin > 0
					? "Not found. Continue search from start of range?"
					: "Not found. Continue search from start of file?";
				
				if(auto_wrap || wrap_query(message))
				{
					begin_search(range_begin, search_base + compare_size, SearchDirection::FORWARDS);
					return;
				}
			}
			else if(search_direction == SearchDirection::BACKWARDS && search_end < range_end)
			{
				/* Search was not from end of file/range, ask if we should go to the end. */
				
				const char *message = range_begin > 0
					? "Not found. Continue search from end of range?"
					: "Not found. Continue search from end of file?";
				
				if(auto_wrap || wrap_query(message))
				{
					begin_search(search_end - compare_size, range_end, SearchDirection::BACKWARDS);
					return;
				}
			}
			else{
				not_found_notification();
			}
		}
		
		if(search_end_focus != NULL)
		{
			search_end_focus->SetFocus();
			search_end_focus->SetSelection(search_end_focus_from, search_end_focus_to);
			search_end_focus = NULL;
		}
		
		if(auto_close)
		{
			Destroy();
		}
	}
	else{
		int percent_done;
		
		if(search_direction == SearchDirection::FORWARDS)
		{
			percent_done = ((double)(100) / ((search_end - search_base) + 1)) * (next_window_start - search_base);
		}
		else /* if(search_direction == SearchDirection::BACKWARDS) */
		{
			percent_done = ((double)(100) / ((search_end - search_base) + 1)) * (search_end - next_window_start);
		}
		
		percent_done = std::max(percent_done, 0);
		percent_done = std::min(percent_done, 100);
		
		progress->Update(percent_done);
	}
}

void REHex::Search::OnClose(wxCloseEvent &event)
{
	Destroy();
}

void REHex::Search::enable_controls()
{
	range_begin_tc->Enable(range_cb->GetValue());
	range_end_tc  ->Enable(range_cb->GetValue());
	
	align_tc->Enable(align_cb->GetValue());
	
	ralign_cb->Enable(align_cb->GetValue());
	ralign_tc->Enable(align_cb->GetValue() && ralign_cb->GetValue());
}

bool REHex::Search::read_base_window_controls()
{
	bool ok = true;
	
	auto read_off_value = [this, &ok](off_t *dest, wxTextCtrl *tc, bool cannot_be_zero, const char *desc)
	{
		if(!ok)
		{
			/* Already raised an error, don't spam them. */
			return;
		}
		
		std::string tc_val = tc->GetValue().ToStdString();
		
		char *endptr;
		long long ll_val = strtoll(tc_val.c_str(), &endptr, 0);
		
		if(tc_val.empty() || *endptr != '\0' || ll_val < 0)
		{
			wxMessageBox((std::string("Invalid ") + desc), "Error", (wxOK | wxICON_EXCLAMATION | wxCENTRE), this);
			
			ok = false;
			return;
		}
		
		if(cannot_be_zero && ll_val == 0)
		{
			wxMessageBox((std::string(desc) + " cannot be zero"), "Error", (wxOK | wxICON_EXCLAMATION | wxCENTRE), this);
			
			ok = false;
			return;
		}
		
		*dest = ll_val;
	};
	
	if(range_cb->GetValue())
	{
		read_off_value(&range_begin, range_begin_tc, false, "start of range");
		read_off_value(&range_end, range_end_tc, false, "end of range");
		
		++range_end;
	}
	else{
		range_begin = 0;
		range_end   = doc->buffer_length();
	}
	
	if(align_cb->GetValue())
	{
		read_off_value(&align_to, align_tc, true, "alignment");
		
		if(ralign_cb->GetValue())
		{
			read_off_value(&align_from, ralign_tc, false, "alignment offset");
		}
		else{
			align_from = 0;
		}
	}
	else{
		align_to   = 1;
		align_from = 0;
	}
	
	return ok;
}

void REHex::Search::thread_main(size_t window_size, size_t compare_size)
{
	PROFILE_SET_THREAD_GROUP(NONE);
	
	while(running && match_found_at < 0)
	{
		off_t window_begin, window_end;
		off_t at, step;
		
		if(search_direction == SearchDirection::FORWARDS)
		{
			window_begin = next_window_start.fetch_add(window_size);
			window_end = std::min((off_t)(window_begin + window_size), search_end);
			
			at = window_begin;
			if(((at - align_from) % align_to) != 0)
			{
				at += (align_to - ((at - align_from) % align_to));
			}
			
			step = align_to;
		}
		else /* if(direction == SearchDirection::BACKWARDS) */
		{
			window_begin = next_window_start.fetch_sub(window_size);
			window_end = std::min((off_t)(window_begin + window_size), search_end);
			
			at = window_end - 1;
			if(((at - align_from) % align_to) != 0)
			{
				at += (align_to - ((at - align_from) % align_to));
				at -= align_to;
			}
			
			step = -align_to;
		}
		
		if(window_end <= search_base || window_begin > search_end)
		{
			break;
		}
		
		if(window_begin < search_base)
		{
			window_begin = search_base;
		}
		
		try {
			off_t read_size = std::min(((window_end - window_begin) + (off_t)(compare_size)), (search_end - window_begin));
			std::vector<unsigned char> window = doc->read_data(window_begin, read_size);
			
			size_t window_off = at - window_begin;
			
			for(; at >= window_begin && at < window_end && window_off < window.size(); at += step, window_off += step)
			{
				size_t window_avail = window.size() - window_off;
				assert(window_avail > 0);
				
				if(test((window.data() + window_off), window_avail))
				{
					std::unique_lock<std::mutex> l(lock);
					
					if(match_found_at < 0
						|| (search_direction == SearchDirection::FORWARDS && match_found_at > at)
						|| (search_direction == SearchDirection::BACKWARDS && match_found_at < at))
					{
						match_found_at = at;
						return;
					}
				}
			}
		}
		catch(const std::exception &e)
		{
			fprintf(stderr, "Exception in REHex::Search::thread_main: %s\n", e.what());
		}
	}
}

wxArrayString REHex::Search::Text::search_history;
std::set<REHex::Search::Text*> REHex::Search::Text::instances;

REHex::Search::Text::Text(wxWindow *parent, SharedDocumentPointer &doc, const wxString &search_for, bool case_sensitive, const std::string &encoding):
	Search(parent, doc, "Search for text"),
	case_sensitive(case_sensitive),
	cmp_fast_path(encoding == "ASCII"),
	initial_encoding(encoding)
{
	setup_window();
	
	set_search_string(search_for);

	instances.insert(this);
}

/* NOTE: end_search() is called from subclass destructor rather than base to ensure search is
 * stopped before the subclass becomes invalid, else there is a race where the base class will try
 * calling the subclass's test() method and trigger undefined behaviour.
*/
REHex::Search::Text::~Text()
{
	instances.erase(this);

	if(running)
	{
		end_search();
	}
}

bool REHex::Search::Text::test(const void *data, size_t data_size)
{
	if(cmp_fast_path)
	{
		/* Fast path for ASCII text searches.
		 *
		 * All the Unicode normalisation below slows the search down to a crawl, so avoid
		 * it if we can.
		 *
		 * This path takes ~25s to process a 4GB sample on my machine, ~10m via the slow
		 * path - a 24x slow down.
		*/
		if(case_sensitive)
		{
			return data_size >= search_for.size()
				&& strncmp((const char*)(data), search_for.data(), search_for.size()) == 0;
		}
		else{
			return data_size >= search_for.size()
				&& strncasecmp((const char*)(data), search_for.data(), search_for.size()) == 0;
		}
	}
	
	/* We read data in character by character, trying to decode it using the search character
	 * set and then normalising (decomposing any combining characters) and optionally case
	 * folding characters as we go.
	 *
	 * Since the search query is normalised in the same way, we can memcmp() each character
	 * (or group of characters, in the case of a decomposed character) against search_for as we
	 * go until we reach the end (strings match) or a mismatch is found.
	*/
	
	uint8_t *norm_buf = NULL;
	size_t norm_size = 0;
	
	const char *next_cmp = search_for.data();
	size_t remain_cmp = search_for.size();
	
	for(size_t i = 0; i < data_size && remain_cmp > 0;)
	{
		EncodedCharacter c = encoding->encoder->decode(((const char*)(data) + i), (data_size - i));
		if(!c.valid)
		{
			break;
		}
		
		size_t ns = norm_size;
		uint8_t *nc = case_sensitive
			? u8_normalize(UNINORM_NFD, (const uint8_t*)(c.utf8_char().data()), c.utf8_char().size(), norm_buf, &ns)
			: u8_casefold((const uint8_t*)(c.utf8_char().data()), c.utf8_char().size(), NULL, UNINORM_NFD, norm_buf, &ns);
		
		if(nc != NULL)
		{
			if(nc != norm_buf)
			{
				free(norm_buf);
				norm_buf = nc;
				norm_size = ns;
			}
		}
		else{
			/* Normalisation failed (I don't know if there's any way this can happen),
			 * so fall back to comparing the original decoded character. This will
			 * match so long as the file data is normalised the same way, and cased the
			 * same.
			*/
			
			nc = (uint8_t*)(c.utf8_char().data());
			ns = c.utf8_char().size();
		}
		
		if(ns > remain_cmp || memcmp(nc, next_cmp, ns) != 0)
		{
			break;
		}
		
		next_cmp += ns;
		remain_cmp -= ns;
		
		i += c.encoded_char().size();
	}
	
	free(norm_buf);
	
	return remain_cmp == 0;
}

size_t REHex::Search::Text::test_max_window()
{
	return search_for.size();
}

void REHex::Search::Text::setup_window_controls(wxWindow *parent, wxSizer *sizer)
{
	{
		wxBoxSizer *text_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		text_sizer->Add(new wxStaticText(parent, wxID_ANY, "Text: "), 0, wxALIGN_CENTER_VERTICAL);
		
		search_for_tc = new wxComboBox(parent, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, search_history, wxTE_PROCESS_ENTER);
		text_sizer->Add(search_for_tc, 1);
		
		sizer->Add(text_sizer, 0, wxTOP | wxLEFT | wxRIGHT | wxEXPAND, 10);
	}
	
	{
		case_sensitive_cb = new wxCheckBox(parent, wxID_ANY, "Case sensitive");
		sizer->Add(case_sensitive_cb, 0, wxTOP | wxLEFT | wxRIGHT, 10);
	}
	
	{
		wxBoxSizer *enc_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		enc_sizer->Add(new wxStaticText(parent, wxID_ANY, "Charcter set: "), 0, wxALIGN_CENTER_VERTICAL);
		
		encoding_choice = new wxChoice(parent, wxID_ANY);
		enc_sizer->Add(encoding_choice, 0, wxLEFT, 10);
		
		auto all_encodings = CharacterEncoding::all_encodings();
		int idx = 0;
		
		for(auto i = all_encodings.begin(); i != all_encodings.end(); ++i, ++idx)
		{
			const CharacterEncoding *ce = *i;
			encoding_choice->Append(ce->label, (void*)(ce));
			
			if(ce->key == initial_encoding)
			{
				encoding_choice->SetSelection(idx);
				encoding = ce;
			}
		}
		
		sizer->Add(enc_sizer, 0, wxTOP | wxLEFT | wxRIGHT, 10);
	}
}

bool REHex::Search::Text::set_search_string(const wxString &search_for)
{
	std::string search_for_utf8(search_for.utf8_str());
	
	size_t ns = 0;
	uint8_t *nd = case_sensitive
		? u8_normalize(UNINORM_NFD, (const uint8_t*)(search_for_utf8.data()), search_for_utf8.size(), NULL, &ns)
		: u8_casefold((const uint8_t*)(search_for_utf8.data()), search_for_utf8.size(), NULL, UNINORM_NFD, NULL, &ns);
	
	if(nd != NULL)
	{
		this->search_for = std::string((const char*)(nd), ns);
		search_for_tc->SetValue(search_for_utf8);
	}
	else{
		/* Not sure if this can/should ever fail... fall back to un-normalised input. */
		
		this->search_for = search_for_utf8;
		search_for_tc->SetValue(search_for_utf8);
	}
	
	free(nd);
	
	return true;
}

bool REHex::Search::Text::read_window_controls()
{
	case_sensitive = case_sensitive_cb->GetValue();
	
	const CharacterEncoding *ce = (const CharacterEncoding*)(encoding_choice->GetClientData(encoding_choice->GetSelection()));
	encoding = ce;
	
	cmp_fast_path = encoding->key == "ASCII";
	
	wxString search_for = search_for_tc->GetValue();
	
	if(search_for.empty())
	{
		wxMessageBox("Please enter a string to search for", "Error", (wxOK | wxICON_EXCLAMATION | wxCENTRE), this);
		return false;
	}
	
	if(!set_search_string(search_for))
	{
		wxMessageBox("The string cannot be encoded in the chosen character set", "Error", (wxOK | wxICON_EXCLAMATION | wxCENTRE), this);
		return false;
	}

	/* Add new search term to history. */
	search_history.Insert(search_for, 0);

	/* Remove previous instances of the search term from history. */
	for(size_t i = 1; i < search_history.GetCount();)
	{
		if(search_history[i] == search_for)
		{
			search_history.RemoveAt(i);
		}
		else{
			++i;
		}
	}

	/* Clamp search history size. */
	while(search_history.GetCount() > 8)
	{
		search_history.RemoveAt(search_history.GetCount() - 1);
	}

	/* Update the suggestions in each open text search dialog. */
	for(auto it = instances.begin(); it != instances.end(); ++it)
	{
		wxComboBox *combo = (*it)->search_for_tc;

		wxString old_string = combo->GetValue();
		combo->Set(search_history);
		combo->SetValue(old_string);
	}
	
	return true;
}

REHex::Search::ByteSequence::ByteSequence(wxWindow *parent, SharedDocumentPointer &doc, const std::vector<unsigned char> &search_for):
	Search(parent, doc, "Search for byte sequence"),
	search_for(search_for)
{
	setup_window();
}

/* NOTE: end_search() is called from subclass destructor rather than base to ensure search is
 * stopped before the subclass becomes invalid, else there is a race where the base class will try
 * calling the subclass's test() method and trigger undefined behaviour.
*/
REHex::Search::ByteSequence::~ByteSequence()
{
	if(running)
	{
		end_search();
	}
}

bool REHex::Search::ByteSequence::test(const void *data, size_t data_size)
{
	return (data_size >= search_for.size()
		&& memcmp(data, search_for.data(), search_for.size()) == 0);
}

size_t REHex::Search::ByteSequence::test_max_window()
{
	return search_for.size();
}

void REHex::Search::ByteSequence::setup_window_controls(wxWindow *parent, wxSizer *sizer)
{
	{
		wxBoxSizer *text_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		text_sizer->Add(new wxStaticText(parent, wxID_ANY, "Data: "), 0, wxALIGN_CENTER_VERTICAL);
		
		search_for_tc = new wxTextCtrl(parent, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER);
		text_sizer->Add(search_for_tc, 1);
		
		sizer->Add(text_sizer, 0, wxTOP | wxLEFT | wxRIGHT | wxEXPAND, 10);
	}
}

bool REHex::Search::ByteSequence::read_window_controls()
{
	std::string search_for_text = search_for_tc->GetValue().ToStdString();
	
	if(search_for_text.empty())
	{
		wxMessageBox("Please enter a hex string to search for", "Error", (wxOK | wxICON_EXCLAMATION | wxCENTRE), this);
		return false;
	}
	
	try {
		search_for = REHex::parse_hex_string(search_for_text);
	}
	catch(const REHex::ParseError &e) {
		wxMessageBox(e.what(), "Error", (wxOK | wxICON_EXCLAMATION | wxCENTRE), this);
		return false;
	}
	
	return true;
}

REHex::Search::Value::Value(wxWindow *parent, SharedDocumentPointer &doc):
	Search(parent, doc, "Search for value")
{
	setup_window();
}

/* NOTE: end_search() is called from subclass destructor rather than base to ensure search is
 * stopped before the subclass becomes invalid, else there is a race where the base class will try
 * calling the subclass's test() method and trigger undefined behaviour.
*/
REHex::Search::Value::~Value()
{
	if(running)
	{
		end_search();
	}
}

void REHex::Search::Value::configure(const std::string &value, unsigned formats, const std::string &epsilon)
{
	search_for_tc->SetValue(value);
	
	if((formats & FMT_LE) && (formats & FMT_BE))
	{
		e_either->SetValue(true);
	}
	else if((formats & FMT_LE))
	{
		e_little->SetValue(true);
	}
	else if((formats & FMT_BE))
	{
		e_big->SetValue(true);
	}
	
	i8_cb->SetValue(!!(formats & FMT_I8));
	i16_cb->SetValue(!!(formats & FMT_I16));
	i32_cb->SetValue(!!(formats & FMT_I32));
	i64_cb->SetValue(!!(formats & FMT_I64));
	f32_cb->SetValue(!!(formats & FMT_F32));
	f64_cb->SetValue(!!(formats & FMT_F64));
	
	epsilon_tc->SetValue(epsilon);
	
	read_window_controls();
}

bool REHex::Search::Value::test(const void *data, size_t data_size)
{
	for(auto i = search_for.begin(); i != search_for.end(); ++i)
	{
		if(data_size >= i->size() && memcmp(data, i->data(), i->size()) == 0)
		{
			return true;
		}
	}
	
	if(f32_enabled && data_size >= sizeof(float))
	{
		if(be_enabled)
		{
			float f = beXXXtoh_p<float>(data);
			
			if(isnan(f) && isnan(f32_value))
			{
				return true;
			}
			else if(isinf(f) && isinf(f32_value) && f == f32_value)
			{
				return true;
			}
			else if(std::isfinite(f) && std::isfinite(f32_value) && fabsf(f - f32_value) <= f32_epsilon)
			{
				return true;
			}
		}
		
		if(le_enabled)
		{
			float f = leXXXtoh_p<float>(data);
			
			if(isnan(f) && isnan(f32_value))
			{
				return true;
			}
			else if(isinf(f) && isinf(f32_value) && f == f32_value)
			{
				return true;
			}
			else if(std::isfinite(f) && std::isfinite(f32_value) && fabsf(f - f32_value) <= f32_epsilon)
			{
				return true;
			}
		}
	}
	
	if(f64_enabled && data_size >= sizeof(double))
	{
		if(be_enabled)
		{
			double f = beXXXtoh_p<double>(data);
			
			if(isnan(f) && isnan(f64_value))
			{
				return true;
			}
			else if(isinf(f) && isinf(f64_value) && f == f64_value)
			{
				return true;
			}
			else if(std::isfinite(f) && std::isfinite(f64_value) && fabs(f - f64_value) <= f64_epsilon)
			{
				return true;
			}
		}
		
		if(le_enabled)
		{
			double f = leXXXtoh_p<double>(data);
			
			if(isnan(f) && isnan(f64_value))
			{
				return true;
			}
			else if(isinf(f) && isinf(f64_value) && f == f64_value)
			{
				return true;
			}
			else if(std::isfinite(f) && std::isfinite(f64_value) && fabs(f - f64_value) <= f64_epsilon)
			{
				return true;
			}
		}
	}
	
	return false;
}

size_t REHex::Search::Value::test_max_window()
{
	size_t search_for_max = 0;
	
	for(auto i = search_for.begin(); i != search_for.end(); ++i)
	{
		search_for_max = std::max(search_for_max, i->size());
	}
	
	if(f32_enabled)
	{
		search_for_max = std::max(search_for_max, sizeof(float));
	}
	
	if(f64_enabled)
	{
		search_for_max = std::max(search_for_max, sizeof(double));
	}
	
	return search_for_max;
}

void REHex::Search::Value::setup_window_controls(wxWindow *parent, wxSizer *sizer)
{
	{
		wxBoxSizer *text_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		text_sizer->Add(new wxStaticText(parent, wxID_ANY, "Value: "), 0, wxALIGN_CENTER_VERTICAL);
		
		search_for_tc = new NumericTextCtrl(parent, wxID_ANY, "", wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER);
		text_sizer->Add(search_for_tc, 1);
		
		search_for_tc->Bind(wxEVT_TEXT, &REHex::Search::Value::OnText, this);
		
		sizer->Add(text_sizer, 0, wxTOP | wxLEFT | wxRIGHT | wxEXPAND, 10);
	}
	
	{
		wxStaticBoxSizer *sz = new wxStaticBoxSizer(wxVERTICAL, parent, "Value formats");
		
		wxGridSizer *sz1 = new wxGridSizer(4);
		sz->Add(sz1, 0, wxTOP | wxBOTTOM, 5);
		
		i8_cb = new wxCheckBox(sz->GetStaticBox(), wxID_ANY, "8-bit integer");
		i8_cb->SetValue(true);
		sz1->Add(i8_cb, 0, wxLEFT, 5);
		
		i16_cb = new wxCheckBox(sz->GetStaticBox(), wxID_ANY, "16-bit integer");
		i16_cb->SetValue(true);
		sz1->Add(i16_cb, 0, wxLEFT, 5);
		
		i32_cb = new wxCheckBox(sz->GetStaticBox(), wxID_ANY, "32-bit integer");
		i32_cb->SetValue(true);
		sz1->Add(i32_cb, 0, wxLEFT, 5);
		
		i64_cb = new wxCheckBox(sz->GetStaticBox(), wxID_ANY, "64-bit integer");
		i64_cb->SetValue(true);
		sz1->Add(i64_cb, 0, wxLEFT | wxRIGHT, 5);
		
		sz1->AddSpacer(1);
		sz1->AddSpacer(1);
		
		f32_cb = new wxCheckBox(sz->GetStaticBox(), wxID_ANY, "32-bit float");
		f32_cb->SetValue(true);
		sz1->Add(f32_cb, 0, wxLEFT, 5);
		
		f64_cb = new wxCheckBox(sz->GetStaticBox(), wxID_ANY, "64-bit float");
		f64_cb->SetValue(true);
		sz1->Add(f64_cb, 0, wxLEFT | wxRIGHT, 5);
		
		wxStaticLine *sl1 = new wxStaticLine(sz->GetStaticBox(), wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLI_HORIZONTAL);
		sz->Add(sl1, 0, wxEXPAND | wxLEFT | wxRIGHT, 5);
		
		wxBoxSizer *sz2 = new wxBoxSizer(wxHORIZONTAL);
		sz->Add(sz2, 0, wxTOP | wxBOTTOM, 5);
		
		e_little = new wxRadioButton(sz->GetStaticBox(), wxID_ANY, "Little endian", wxDefaultPosition, wxDefaultSize, wxRB_GROUP);
		sz2->Add(e_little, 0, wxLEFT, 5);
		
		e_big = new wxRadioButton(sz->GetStaticBox(), wxID_ANY, "Big endian");
		sz2->Add(e_big, 0, wxLEFT, 5);
		
		e_either = new wxRadioButton(sz->GetStaticBox(), wxID_ANY, "Either");
		e_either->SetValue(true);
		sz2->Add(e_either, 0, wxLEFT | wxRIGHT, 5);
		
		wxStaticLine *sl2 = new wxStaticLine(sz->GetStaticBox(), wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLI_HORIZONTAL);
		sz->Add(sl2, 0, wxEXPAND | wxLEFT | wxRIGHT, 5);
		
		wxBoxSizer *sz3 = new wxBoxSizer(wxHORIZONTAL);
		sz->Add(sz3, 0, wxTOP | wxBOTTOM, 5);
		
		sz3->Add(new wxStaticText(sz->GetStaticBox(), wxID_ANY, "Floating point epsilon:"), 0, wxLEFT | wxALIGN_CENTER_VERTICAL, 5);
		
		epsilon_tc = new NumericTextCtrl(sz->GetStaticBox(), wxID_ANY, "0", wxDefaultPosition, wxDefaultSize, 0);
		epsilon_tc->SetToolTip("Tolerance when comparing floating point numbers");
		sz3->Add(epsilon_tc, 0, wxALL | wxALIGN_CENTER_VERTICAL, 5);
		
		sizer->Add(sz, 0, wxTOP | wxLEFT | wxRIGHT | wxEXPAND, 10);
	}
}

#define INTEGER_TYPE_SIZE(x) \
{ \
	if(i ## x ## _cb->GetValue()) \
	{ \
		try { \
			uint ## x ## _t v = search_for_tc->GetValue<uint ## x ## _t>(); \
			\
			if(e_little->GetValue() || e_either->GetValue()) \
			{ \
				uint ## x ## _t lv = htole ## x(v); \
				search_for.push_back(std::vector<unsigned char>((unsigned char*)(&(lv)), (unsigned char*)(&(lv) + 1))); \
			} \
			\
			if(e_big->GetValue() || e_either->GetValue()) \
			{ \
				uint ## x ## _t bv = htobe ## x(v); \
				search_for.push_back(std::vector<unsigned char>((unsigned char*)(&(bv)), (unsigned char*)(&(bv) + 1))); \
			} \
		} \
		catch(const REHex::NumericTextCtrl::RangeError &) \
		{ \
			try { \
				int ## x ## _t v = search_for_tc->GetValue<int ## x ## _t>(); \
				\
				if(e_little->GetValue() || e_either->GetValue()) \
				{ \
					int ## x ## _t lv = htole ## x(v); \
					search_for.push_back(std::vector<unsigned char>((unsigned char*)(&(lv)), (unsigned char*)(&(lv) + 1))); \
				} \
				\
				if(e_big->GetValue() || e_either->GetValue()) \
				{ \
					int ## x ## _t bv = htobe ## x(v); \
					search_for.push_back(std::vector<unsigned char>((unsigned char*)(&(bv)), (unsigned char*)(&(bv) + 1))); \
				} \
			} \
			catch(REHex::NumericTextCtrl::InputError &) {} \
		} \
		catch(REHex::NumericTextCtrl::InputError &) {} \
	} \
}

bool REHex::Search::Value::read_window_controls()
{
	search_for.clear();
	
	le_enabled = e_little->GetValue() || e_either->GetValue();
	be_enabled = e_big->GetValue() || e_either->GetValue();
	
	if(i8_cb->GetValue())
	{
		try {
			uint8_t v = search_for_tc->GetValue<uint8_t>();
			search_for.push_back(std::vector<unsigned char>((unsigned char*)(&(v)), (unsigned char*)(&(v) + 1)));
		}
		catch(const REHex::NumericTextCtrl::RangeError &)
		{
			try {
				int8_t v = search_for_tc->GetValue<int8_t>();
				search_for.push_back(std::vector<unsigned char>((unsigned char*)(&(v)), (unsigned char*)(&(v) + 1)));
			}
			catch(REHex::NumericTextCtrl::InputError &) {}
		}
		catch(REHex::NumericTextCtrl::InputError &) {}
	}
	
	INTEGER_TYPE_SIZE(16);
	INTEGER_TYPE_SIZE(32);
	INTEGER_TYPE_SIZE(64);
	
	f32_enabled = false;
	if(f32_cb->GetValue())
	{
		try {
			f32_value = parse_float(search_for_tc->GetStringValue().ToStdString());
			f32_epsilon = parse_float(epsilon_tc->GetStringValue().ToStdString());
			f32_enabled = true;
		}
		catch(const ParseError&) {}
	}
	
	f64_enabled = false;
	if(f64_cb->GetValue())
	{
		try {
			f64_value = parse_double(search_for_tc->GetStringValue().ToStdString());
			f64_epsilon = parse_double(epsilon_tc->GetStringValue().ToStdString());
			f64_enabled = true;
		}
		catch(const ParseError&) {}
	}
	
	if(search_for.empty() && !f32_enabled && !f64_enabled)
	{
		wxMessageBox("Please enter a valid value to search for", "Error", (wxOK | wxICON_EXCLAMATION | wxCENTRE), this);
		return false;
	}
	
	return true;
}

void REHex::Search::Value::OnText(wxCommandEvent &event)
{
	i8_cb->Disable();
	
	try { search_for_tc->GetValue<int8_t>(); i8_cb->Enable(); }
	catch(const REHex::NumericTextCtrl::InputError &) {}
	
	try { search_for_tc->GetValue<uint8_t>(); i8_cb->Enable(); }
	catch(const REHex::NumericTextCtrl::InputError &) {}
	
	i16_cb->Disable();
	
	try { search_for_tc->GetValue<int16_t>(); i16_cb->Enable(); }
	catch(const REHex::NumericTextCtrl::InputError &) {}
	
	try { search_for_tc->GetValue<uint16_t>(); i16_cb->Enable(); }
	catch(const REHex::NumericTextCtrl::InputError &) {}
	
	i32_cb->Disable();
	
	try { search_for_tc->GetValue<int32_t>(); i32_cb->Enable(); }
	catch(const REHex::NumericTextCtrl::InputError &) {}
	
	try { search_for_tc->GetValue<uint32_t>(); i32_cb->Enable(); }
	catch(const REHex::NumericTextCtrl::InputError &) {}
	
	i64_cb->Disable();
	
	try { search_for_tc->GetValue<int64_t>(); i64_cb->Enable(); }
	catch(const REHex::NumericTextCtrl::InputError &) {}
	
	try { search_for_tc->GetValue<uint64_t>(); i64_cb->Enable(); }
	catch(const REHex::NumericTextCtrl::InputError &) {}
	
	f32_cb->Disable();
	
	try { parse_float(search_for_tc->GetStringValue().ToStdString()); f32_cb->Enable(); }
	catch(const ParseError&) {}
	
	f64_cb->Disable();
	
	try { parse_double(search_for_tc->GetStringValue().ToStdString()); f64_cb->Enable(); }
	catch(const ParseError&) {}
}
