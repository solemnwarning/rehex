/* Reverse Engineer's Hex Editor
 * Copyright (C) 2019-2021 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <string>
#include <tuple>
#include <wx/stattext.h>

#include "SelectRangeDialog.hpp"

BEGIN_EVENT_TABLE(REHex::SelectRangeDialog, wxDialog)
	EVT_BUTTON(wxID_OK, REHex::SelectRangeDialog::OnOK)
	EVT_RADIOBUTTON(wxID_ANY, REHex::SelectRangeDialog::OnRadio)
END_EVENT_TABLE()

REHex::SelectRangeDialog::SelectRangeDialog(wxWindow *parent, Document &document, DocumentCtrl &document_ctrl):
	wxDialog(parent, wxID_ANY, "Select range"),
	document(document),
	document_ctrl(document_ctrl)
{
	wxBoxSizer *topsizer = new wxBoxSizer(wxVERTICAL);
	
	char initial_from[64] = "";
	char initial_to[64]   = "";
	char initial_len[64]  = "";
	
	if(document_ctrl.has_selection())
	{
		off_t selection_first, selection_last;
		std::tie(selection_first, selection_last) = document_ctrl.get_selection_raw();
		
		off_t selection_diff = document_ctrl.region_offset_sub(selection_last, selection_first);
		assert(selection_diff >= 0);
		
		snprintf(initial_from, sizeof(initial_from), "0x%08llX", (long long unsigned)(selection_first));
		snprintf(initial_to,   sizeof(initial_to),   "0x%08llX", (long long unsigned)(selection_last));
		snprintf(initial_len,  sizeof(initial_len),  "0x%08llX", (long long unsigned)(selection_diff + 1));
	}
	else{
		off_t cursor_pos = document_ctrl.get_cursor_position();
		snprintf(initial_from, sizeof(initial_from), "0x%08llX", (long long unsigned)(cursor_pos));
	}
	
	{
		wxBoxSizer *from_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		wxStaticText *from_label = new wxStaticText(this, wxID_ANY, "From offset");
		from_sizer->Add(from_label, 1, wxEXPAND | wxALIGN_CENTER_VERTICAL);
		
		range_from = new NumericTextCtrl(this, wxID_ANY, initial_from);
		from_sizer->Add(range_from, 0, wxALIGN_CENTER_VERTICAL | wxLEFT, 10);
		
		topsizer->Add(from_sizer, 0, wxEXPAND | wxALL, 10);
	}
	
	{
		wxBoxSizer *to_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		range_to_enable = new wxRadioButton(this, wxID_ANY, "To offset");
		to_sizer->Add(range_to_enable, 1, wxEXPAND | wxALIGN_CENTER_VERTICAL);
		
		range_to = new NumericTextCtrl(this, wxID_ANY, initial_to);
		to_sizer->Add(range_to, 0, wxALIGN_CENTER_VERTICAL | wxLEFT, 10);
		
		topsizer->Add(to_sizer, 0, wxEXPAND | wxLEFT | wxRIGHT, 10);
		
		/* Default to "To offset" */
		range_to_enable->SetValue(true);
	}
	
	{
		wxBoxSizer *len_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		range_len_enable = new wxRadioButton(this, wxID_ANY, "Selection length");
		len_sizer->Add(range_len_enable, 1, wxEXPAND | wxALIGN_CENTER_VERTICAL);
		
		range_len = new NumericTextCtrl(this, wxID_ANY, initial_len);
		len_sizer->Add(range_len, 0, wxALIGN_CENTER_VERTICAL | wxLEFT, 10);
		
		topsizer->Add(len_sizer, 0, wxEXPAND | wxLEFT | wxRIGHT, 10);
	}
	
	enable_inputs();
	
	wxBoxSizer *button_sizer = new wxBoxSizer(wxHORIZONTAL);
	
	wxButton *ok     = new wxButton(this, wxID_OK,     "OK");
	wxButton *cancel = new wxButton(this, wxID_CANCEL, "Cancel");
	
	button_sizer->Add(ok,     0, wxALL, 10);
	button_sizer->Add(cancel, 0, wxALL, 10);
	
	topsizer->Add(button_sizer, 0, wxALIGN_CENTER_HORIZONTAL);
	
	SetSizerAndFit(topsizer);
	
	/* Trigger the "OK" button if enter is pressed. */
	ok->SetDefault();
}

REHex::SelectRangeDialog::~SelectRangeDialog() {}

void REHex::SelectRangeDialog::enable_inputs()
{
	range_to->Enable(range_to_enable->GetValue());
	range_len->Enable(range_len_enable->GetValue());
}

void REHex::SelectRangeDialog::OnOK(wxCommandEvent &event)
{
	off_t doc_length = document.buffer_length();
	off_t selection_first, selection_last;
	
	try {
		selection_first = range_from->GetValue<off_t>(0, (doc_length - 1));
	}
	catch(const NumericTextCtrl::InputError &e)
	{
		wxMessageBox(e.what(), "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
		return;
	}
	
	assert(range_to_enable->GetValue() || range_len_enable->GetValue());
	
	if(range_to_enable->GetValue())
	{
		try {
			selection_last = range_to->GetValue<off_t>(0, (doc_length - 1));
		}
		catch(const NumericTextCtrl::InputError &e)
		{
			wxMessageBox(e.what(), "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
			return;
		}
	}
	else if(range_len_enable->GetValue())
	{
		off_t selection_length;
		
		try {
			selection_length = range_len->GetValue<off_t>(1);
		}
		catch(const NumericTextCtrl::InputError &e)
		{
			wxMessageBox(e.what(), "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
			return;
		}
		
		selection_last = document_ctrl.region_offset_add(selection_first, selection_length - 1);
	}
	else{
		/* Shouldn't be reachable. */
		return;
	}
	
	if(document_ctrl.region_offset_sub(selection_last, selection_first) != (selection_last - selection_first))
	{
		/* TODO: Display warning about discontiguous selection? */
	}
	
	document_ctrl.set_selection_raw(selection_first, selection_last); /* TODO: Warn about invalid selections. */
	Close();
}

void REHex::SelectRangeDialog::OnRadio(wxCommandEvent &event)
{
	enable_inputs();
}
