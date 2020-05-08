/* Reverse Engineer's Hex Editor
 * Copyright (C) 2019-2020 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <string>
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
	
	std::pair<off_t, off_t> selection = document_ctrl.get_selection();
	off_t selection_off    = selection.first;
	off_t selection_length = selection.second;
	
	if(selection_length > 0)
	{
		snprintf(initial_from, sizeof(initial_from), "0x%08llX", (long long unsigned)(selection_off));
		snprintf(initial_to,   sizeof(initial_to),   "0x%08llX", (long long unsigned)(selection_off + selection_length - 1));
		snprintf(initial_len,  sizeof(initial_len),  "0x%08llX", (long long unsigned)(selection_length));
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
	off_t selection_off, selection_length;
	
	try {
		selection_off = range_from->GetValue<off_t>(0, (doc_length - 1));
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
			off_t selection_to = range_to->GetValue<off_t>(selection_off, (doc_length - 1));
			selection_length = (selection_to - selection_off) + 1;
		}
		catch(const NumericTextCtrl::InputError &e)
		{
			wxMessageBox(e.what(), "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
			return;
		}
	}
	else if(range_len_enable->GetValue())
	{
		try {
			selection_length = range_len->GetValue<off_t>(0, (doc_length - selection_off));
		}
		catch(const NumericTextCtrl::InputError &e)
		{
			wxMessageBox(e.what(), "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
			return;
		}
	}
	else{
		/* Shouldn't be reachable. */
		return;
	}
	
	document_ctrl.set_selection(selection_off, selection_length);
	Close();
}

void REHex::SelectRangeDialog::OnRadio(wxCommandEvent &event)
{
	enable_inputs();
}
