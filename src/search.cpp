/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018-2020 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <assert.h>
#include <functional>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <utility>
#include <wx/msgdlg.h>
#include <wx/sizer.h>
#include <wx/statbox.h>
#include <wx/statline.h>

#include "NumericTextCtrl.hpp"
#include "search.hpp"
#include "util.hpp"

/* This MUST come after the wxWidgets headers have been included, else we pull in windows.h BEFORE the wxWidgets
 * headers when building on Windows and this causes unicode-flavoured pointer conversion errors.
*/
#include <portable_endian.h>

enum {
	ID_FIND_NEXT = 1,
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
	EVT_BUTTON(wxID_CANCEL, REHex::Search::OnCancel)
	EVT_TIMER(ID_TIMER, REHex::Search::OnTimer)
END_EVENT_TABLE()

REHex::Search::Search(wxWindow *parent, SharedDocumentPointer &doc, const char *title):
	wxDialog(parent, wxID_ANY, title),
	doc(doc), range_begin(0), range_end(-1), align_to(1), align_from(0), match_found_at(-1), running(false),
	timer(this, ID_TIMER)
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
		
		button_sz->Add(new wxButton(this, ID_FIND_NEXT, "Find next"));
		button_sz->Add(new wxButton(this, wxID_CANCEL,  "Cancel"), 0, wxLEFT, 10);
	}
	
	enable_controls();
	
	SetSizerAndFit(main_sizer);
}

void REHex::Search::limit_range(off_t range_begin, off_t range_end)
{
	assert(range_begin >= 0);
	
	this->range_begin = range_begin;
	this->range_end   = range_end;
}

void REHex::Search::require_alignment(off_t alignment, off_t relative_to_offset)
{
	assert(alignment > 0);
	assert(relative_to_offset >= 0);
	
	align_to   = alignment;
	align_from = relative_to_offset;
}

/* This method is only used by the unit tests. */
off_t REHex::Search::find_next(off_t from_offset, size_t window_size)
{
	begin_search(from_offset, range_end, window_size);
	
	/* Wait for the workers to finish searching. */
	while(!threads.empty())
	{
		threads.back().join();
		threads.pop_back();
	}
	
	end_search();
	
	return match_found_at;
}

void REHex::Search::begin_search(off_t from_offset, off_t range_end, size_t window_size)
{
	assert(!running);
	
	size_t compare_size = test_max_window();
	
	next_window_start = std::max(from_offset, range_begin);
	match_found_at    = -1;
	running           = true;
	
	search_base = next_window_start;
	search_end  = (range_end >= 0 ? range_end : doc->buffer_length());
	
	/* Number of threads to spawn */
	unsigned int thread_count = std::thread::hardware_concurrency();
	
	while(threads.size() < thread_count)
	{
		threads.emplace_back(&REHex::Search::thread_main, this, window_size, compare_size);
	}
	
	progress = new wxProgressDialog("Searching", "Search in progress...", 100, this, wxPD_CAN_ABORT | wxPD_REMAINING_TIME);
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
		begin_search((doc->get_cursor_position() + 1), range_end);
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
		return;
	}
	
	if(match_found_at >= 0 || next_window_start > search_end)
	{
		end_search();
		
		if(match_found_at >= 0)
		{
			doc->set_cursor_position(match_found_at);
		}
		else{
			if(search_base > range_begin)
			{
				/* Search was not from beginning of file/range, ask if we should go back to the start. */
				
				const char *message = range_begin > 0
					? "Not found. Continue search from start of range?"
					: "Not found. Continue search from start of file?";
				
				if(wxMessageBox(message, wxMessageBoxCaptionStr, (wxYES_NO | wxCENTRE), this) == wxYES)
				{
					begin_search(range_begin, search_base);
				}
			}
			else{
				wxMessageBox("Not found", wxMessageBoxCaptionStr, (wxOK | wxICON_INFORMATION | wxCENTRE), this);
			}
		}
	}
	else{
		progress->Update(((double)(100) / ((search_end - search_base) + 1)) * (next_window_start - search_base));
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
		read_off_value(&range_begin, range_begin_tc, false, "end of range");
	}
	else{
		range_begin = 0;
		range_end   = -1;
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
	while(running && match_found_at < 0)
	{
		off_t window_base = next_window_start.fetch_add(window_size);
		off_t next_window = std::min((off_t)(window_base + window_size), (search_end + 1));
		
		if(window_base > search_end)
		{
			break;
		}
		
		try {
			std::vector<unsigned char> window = doc->read_data(window_base, window_size + compare_size);
			
			off_t search_base = window_base;
			if(((search_base - align_from) % align_to) != 0)
			{
				search_base += (align_to - ((search_base - align_from) % align_to));
			}
			
			for(off_t at = search_base; at < next_window; at += align_to)
			{
				off_t  window_off   = at - window_base;
				size_t window_avail = std::min((size_t)(window.size() - window_off), (size_t)(search_end - at));
				
				if(test((window.data() + window_off), window_avail))
				{
					std::unique_lock<std::mutex> l(lock);
					
					if(match_found_at < 0 || match_found_at > at)
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

REHex::Search::Text::Text(wxWindow *parent, SharedDocumentPointer &doc, const std::string &search_for, bool case_sensitive):
	Search(parent, doc, "Search for text"),
	search_for(search_for),
	case_sensitive(case_sensitive)
{
	setup_window();
}

REHex::Search::Text::~Text()
{
	if(running)
	{
		end_search();
	}
}

bool REHex::Search::Text::test(const void *data, size_t data_size)
{
	if(case_sensitive)
	{
		return (data_size >= search_for.size()
			&& strncmp((const char*)(data), search_for.c_str(), search_for.size()) == 0);
	}
	else{
		return (data_size >= search_for.size()
			&& strncasecmp((const char*)(data), search_for.c_str(), search_for.size()) == 0);
	}
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
		
		search_for_tc = new wxTextCtrl(parent, wxID_ANY, "");
		text_sizer->Add(search_for_tc, 1);
		
		sizer->Add(text_sizer, 0, wxTOP | wxLEFT | wxRIGHT | wxEXPAND, 10);
	}
	
	{
		case_sensitive_cb = new wxCheckBox(parent, wxID_ANY, "Case sensitive");
		sizer->Add(case_sensitive_cb, 0, wxTOP | wxLEFT | wxRIGHT, 10);
	}
}

bool REHex::Search::Text::read_window_controls()
{
	search_for     = search_for_tc->GetValue();
	case_sensitive = case_sensitive_cb->GetValue();
	
	if(search_for.empty())
	{
		wxMessageBox("Please enter a string to search for", "Error", (wxOK | wxICON_EXCLAMATION | wxCENTRE), this);
		return false;
	}
	
	return true;
}

REHex::Search::ByteSequence::ByteSequence(wxWindow *parent, SharedDocumentPointer &doc, const std::vector<unsigned char> &search_for):
	Search(parent, doc, "Search for byte sequence"),
	search_for(search_for)
{
	setup_window();
}

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
		
		search_for_tc = new wxTextCtrl(parent, wxID_ANY, "");
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

REHex::Search::Value::~Value()
{
	if(running)
	{
		end_search();
	}
}

void REHex::Search::Value::configure(const std::string &value, unsigned formats)
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
	
	return false;
}

size_t REHex::Search::Value::test_max_window()
{
	size_t search_for_max = 0;
	
	for(auto i = search_for.begin(); i != search_for.end(); ++i)
	{
		search_for_max = std::max(search_for_max, i->size());
	}
	
	return search_for_max;
}

void REHex::Search::Value::setup_window_controls(wxWindow *parent, wxSizer *sizer)
{
	{
		wxBoxSizer *text_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		text_sizer->Add(new wxStaticText(parent, wxID_ANY, "Value: "), 0, wxALIGN_CENTER_VERTICAL);
		
		search_for_tc = new NumericTextCtrl(parent, wxID_ANY, "", wxDefaultPosition, wxDefaultSize, 0);
		text_sizer->Add(search_for_tc, 1);
		
		search_for_tc->Bind(wxEVT_TEXT, &REHex::Search::Value::OnText, this);
		
		sizer->Add(text_sizer, 0, wxTOP | wxLEFT | wxRIGHT | wxEXPAND, 10);
	}
	
	{
		wxStaticBoxSizer *sz = new wxStaticBoxSizer(wxVERTICAL, parent, "Value formats");
		
		wxBoxSizer *sz1 = new wxBoxSizer(wxHORIZONTAL);
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
	
	if(search_for.empty())
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
}
