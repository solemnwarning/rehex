/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <utility>
#include <wx/msgdlg.h>

#include "search.hpp"
#include "util.hpp"

enum {
	ID_FIND_NEXT = 1,
	
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
	EVT_CHECKBOX(ID_RANGE_CB,  REHex::Search::OnCheckBox)
	EVT_CHECKBOX(ID_ALIGN_CB,  REHex::Search::OnCheckBox)
	EVT_CHECKBOX(ID_RALIGN_CB, REHex::Search::OnCheckBox)
	
	EVT_BUTTON(ID_FIND_NEXT, REHex::Search::OnFindNext)
END_EVENT_TABLE()

REHex::Search::Search(wxWindow *parent, REHex::Document &doc, const char *title):
	wxDialog(parent, wxID_ANY, title),
	doc(doc), range_begin(0), range_end(-1), align_to(1), align_from(0)
{}

void REHex::Search::setup_window()
{
	wxBoxSizer *main_sizer = new wxBoxSizer(wxVERTICAL);
	
	setup_window_controls(this, main_sizer);
	
	{
		wxBoxSizer *range_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		range_cb = new wxCheckBox(this, ID_RANGE_CB, "Only search from offset ");
		range_sizer->Add(range_cb);
		
		range_begin_tc = new wxTextCtrl(this, wxID_ANY);
		set_width_chars(range_begin_tc, 12);
		range_sizer->Add(range_begin_tc);
		
		range_sizer->Add(new wxStaticText(this, wxID_ANY, " to "));
		
		range_end_tc = new wxTextCtrl(this, wxID_ANY);
		set_width_chars(range_end_tc, 12);
		range_sizer->Add(range_end_tc);
		
		main_sizer->Add(range_sizer);
	}
	
	{
		wxBoxSizer *align_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		align_cb = new wxCheckBox(this, ID_ALIGN_CB, "Results must be aligned to ");
		align_sizer->Add(align_cb);
		
		align_tc = new wxTextCtrl(this, wxID_ANY);
		set_width_chars(align_tc, 4);
		align_sizer->Add(align_tc);
		
		align_sizer->Add(new wxStaticText(this, wxID_ANY, " bytes"));
		
		main_sizer->Add(align_sizer);
	}
	
	{
		wxBoxSizer *ralign_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		ralign_cb = new wxCheckBox(this, ID_RALIGN_CB, "...relative to offset ");
		ralign_sizer->Add(ralign_cb);
		
		ralign_tc = new wxTextCtrl(this, wxID_ANY);
		set_width_chars(ralign_tc, 12);
		ralign_sizer->Add(ralign_tc);
		
		main_sizer->Add(ralign_sizer);
	}
	
	{
		wxBoxSizer *button_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		button_sizer->Add(new wxButton(this, ID_FIND_NEXT, "Find next"), 0, wxALL, 10);
		button_sizer->Add(new wxButton(this, wxID_CANCEL,  "Cancel"),    0, wxALL, 10);
		
		main_sizer->Add(button_sizer, 0, wxALIGN_RIGHT);
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

off_t REHex::Search::find_next(off_t from_offset, size_t window_size)
{
	from_offset = std::max(from_offset, range_begin);
	
	if(((from_offset - align_from) % align_to) != 0)
	{
		from_offset += (align_to - ((from_offset - align_from) % align_to));
	}
	
	off_t end = (range_end >= 0 ? range_end : doc.buffer_length());
	
	size_t want_window = test_max_window();
	
	assert(window_size >= want_window);
	
	std::vector<unsigned char> window = doc.read_data(from_offset, window_size);
	off_t window_base = from_offset;
	
	for(off_t at = from_offset; at < end; at += align_to)
	{
		assert(window_base <= at);
		
		off_t  window_off   = at - window_base;
		size_t window_avail = std::min((size_t)(window.size() - window_off), (size_t)(end - at));
		
		if(want_window > window_avail
			&& (window_base + (off_t)(window.size())) < doc.buffer_length())
		{
			/* The test() method wants more data than is available in the current
			 * window and there is more data in the buffer past the end of it.
			 *
			 * Remake the window starting at the current position.
			*/
			
			window      = doc.read_data(at, window_size);
			window_base = at;
			
			window_off   = 0;
			window_avail = window.size();
		}
		
		if(test((window.data() + window_off), window_avail))
		{
			return at;
		}
	}
	
	return -1;
}

void REHex::Search::OnCheckBox(wxCommandEvent &event)
{
	enable_controls();
}

void REHex::Search::OnFindNext(wxCommandEvent &event)
{
	if(read_base_window_controls() && read_window_controls())
	{
		off_t found_at = find_next(doc.get_offset() + 1);
		if(found_at < 0)
		{
			wxMessageBox("Not found", wxMessageBoxCaptionStr, (wxOK | wxICON_INFORMATION | wxCENTRE), this);
		}
		else{
			doc.set_cursor_position(found_at);
		}
	}
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

REHex::Search::Text::Text(wxWindow *parent, REHex::Document &doc, const std::string &search_for, bool case_sensitive):
	Search(parent, doc, "Search for text"),
	search_for(search_for),
	case_sensitive(case_sensitive)
{
	setup_window();
}

bool REHex::Search::Text::test(const unsigned char *data, size_t data_size)
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
		
		sizer->Add(text_sizer, 0, wxEXPAND | wxALL, 2);
	}
	
	{
		case_sensitive_cb = new wxCheckBox(parent, wxID_ANY, "Case sensitive");
		sizer->Add(case_sensitive_cb);
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

REHex::Search::ByteSequence::ByteSequence(wxWindow *parent, REHex::Document &doc, const std::vector<unsigned char> &search_for):
	Search(parent, doc, "Search for byte sequence"),
	search_for(search_for)
{
	setup_window();
}

bool REHex::Search::ByteSequence::test(const unsigned char *data, size_t data_size)
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
		
		sizer->Add(text_sizer, 0, wxEXPAND | wxALL, 2);
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
