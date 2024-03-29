/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <stdio.h>
#include <string>
#include <vector>
#include <wx/sizer.h>
#include <wx/stattext.h>

#include "FillRangeDialog.hpp"
#include "util.hpp"

BEGIN_EVENT_TABLE(REHex::FillRangeDialog, wxDialog)
	EVT_BUTTON(wxID_OK, REHex::FillRangeDialog::OnOK)
	EVT_RADIOBUTTON(wxID_ANY, REHex::FillRangeDialog::OnRadio)
END_EVENT_TABLE()

REHex::FillRangeDialog::FillRangeDialog(wxWindow *parent, Document &document, DocumentCtrl &document_ctrl):
	wxDialog(parent, wxID_ANY, "Fill range"),
	document(document)
{
	wxBoxSizer *topsizer = new wxBoxSizer(wxVERTICAL);
	
	char initial_from[64] = "";
	char initial_to[64]   = "";
	char initial_len[64]  = "";
	
	BitOffset selection_off, selection_length;
	std::tie(selection_off, selection_length) = document_ctrl.get_selection_linear();
	
	if(selection_length > BitOffset::ZERO && selection_off.byte_aligned() && selection_length.byte_aligned())
	{
		snprintf(initial_from, sizeof(initial_from), "0x%08llX", (long long unsigned)(selection_off.byte()));
		snprintf(initial_to,   sizeof(initial_to),   "0x%08llX", (long long unsigned)((selection_off + selection_length - 1).byte()));
		snprintf(initial_len,  sizeof(initial_len),  "0x%08llX", (long long unsigned)(selection_length.byte()));
	}
	else{
		off_t cursor_pos = document_ctrl.get_cursor_position().byte();
		snprintf(initial_from, sizeof(initial_from), "0x%08llX", (long long unsigned)(cursor_pos));
	}
	
	{
		wxBoxSizer *data_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		wxStaticText *data_label = new wxStaticText(this, wxID_ANY, "Data (hex)");
		data_sizer->Add(data_label, 0, wxALIGN_CENTER_VERTICAL);
		
		data_input = new wxTextCtrl(this, wxID_ANY, "");
		data_sizer->Add(data_input, 1, wxALIGN_CENTER_VERTICAL | wxLEFT, 10);
		
		topsizer->Add(data_sizer, 0, wxEXPAND | wxALL, 10);
	}
	
	{
		wxBoxSizer *mode_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		overwrite_mode = new wxRadioButton(this, wxID_ANY, "Overwrite data", wxDefaultPosition, wxDefaultSize, wxRB_GROUP);
		mode_sizer->Add(overwrite_mode, 0, wxALIGN_CENTER_VERTICAL);
		
		insert_mode = new wxRadioButton(this, wxID_ANY, "Insert data");
		mode_sizer->Add(insert_mode, 1, wxALIGN_CENTER_VERTICAL | wxLEFT, 10);
		
		topsizer->Add(mode_sizer, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 10);
		
		/* Default to overwrite mode. */
		overwrite_mode->SetValue(true);
	}
	
	topsizer->Add(
		new wxStaticText(this, wxID_ANY, "Data will be truncated or repeated as\n"
		                                 "necessary to fill the entire range."),
		0, wxLEFT | wxRIGHT, 10);
	
	wxBoxSizer *range_sizer = new wxBoxSizer(wxVERTICAL);
	
	{
		wxBoxSizer *from_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		wxStaticText *from_label = new wxStaticText(this, wxID_ANY, "From offset");
		from_sizer->Add(from_label, 1, wxALIGN_CENTER_VERTICAL);
		
		range_from = new NumericTextCtrl(this, wxID_ANY, initial_from);
		from_sizer->Add(range_from, 0, wxALIGN_CENTER_VERTICAL | wxLEFT, 10);
		
		wxSize initial_size = range_from->GetSize();
		wxSize text_size = range_from->GetTextExtent("0x0000000000000000+0b");
		range_from->SetMinSize(wxSize(((float)(text_size.GetWidth()) * 1.2f), initial_size.GetHeight()));
		
		range_sizer->Add(from_sizer, 0, wxEXPAND | wxALL, 10);
	}
	
	{
		wxBoxSizer *to_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		range_to_enable = new wxRadioButton(this, wxID_ANY, "To offset", wxDefaultPosition, wxDefaultSize, wxRB_GROUP);
		to_sizer->Add(range_to_enable, 1, wxALIGN_CENTER_VERTICAL);
		
		range_to = new NumericTextCtrl(this, wxID_ANY, initial_to);
		to_sizer->Add(range_to, 0, wxALIGN_CENTER_VERTICAL | wxLEFT, 10);
		
		wxSize initial_size = range_to->GetSize();
		wxSize text_size = range_to->GetTextExtent("0x0000000000000000+0b");
		range_to->SetMinSize(wxSize(((float)(text_size.GetWidth()) * 1.2f), initial_size.GetHeight()));
		
		range_sizer->Add(to_sizer, 0, wxEXPAND | wxLEFT | wxRIGHT, 10);
		
		/* Default to "To offset" */
		range_to_enable->SetValue(true);
	}
	
	{
		wxBoxSizer *len_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		range_len_enable = new wxRadioButton(this, wxID_ANY, "Range length");
		len_sizer->Add(range_len_enable, 1, wxALIGN_CENTER_VERTICAL);
		
		range_len = new NumericTextCtrl(this, wxID_ANY, initial_len);
		len_sizer->Add(range_len, 0, wxALIGN_CENTER_VERTICAL | wxLEFT, 10);
		
		wxSize initial_size = range_len->GetSize();
		wxSize text_size = range_len->GetTextExtent("0x0000000000000000+0b");
		range_len->SetMinSize(wxSize(((float)(text_size.GetWidth()) * 1.2f), initial_size.GetHeight()));
		
		range_sizer->Add(len_sizer, 0, wxEXPAND | wxLEFT | wxRIGHT, 10);
	}
	
	topsizer->Add(range_sizer);
	
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

REHex::FillRangeDialog::~FillRangeDialog() {}

void REHex::FillRangeDialog::enable_inputs()
{
	range_to->Enable(range_to_enable->GetValue());
	range_len->Enable(range_len_enable->GetValue());
}

void REHex::FillRangeDialog::OnOK(wxCommandEvent &event)
{
	std::string data_text = data_input->GetValue().ToStdString();
	
	if(data_text.empty())
	{
		wxMessageBox("Please enter a hex string to fill the range with", "Error", (wxOK | wxICON_EXCLAMATION | wxCENTRE), this);
		return;
	}
	
	std::vector<unsigned char> data_pattern;
	try {
		data_pattern = REHex::parse_hex_string(data_text);
	}
	catch(const REHex::ParseError &e) {
		wxMessageBox(e.what(), "Error", (wxOK | wxICON_EXCLAMATION | wxCENTRE), this);
		return;
	}
	
	bool insert_mode_selected = insert_mode->GetValue();
	
	off_t doc_length = document.buffer_length();
	off_t selection_off, selection_length;
	
	try {
		if(insert_mode_selected)
		{
			selection_off = range_from->GetValue<off_t>(0, doc_length);
		}
		else{
			selection_off = range_from->GetValue<off_t>(0, (doc_length - 1));
		}
	}
	catch(const NumericTextCtrl::InputError &e)
	{
		std::string message = std::string(e.what()) + "\n\nPlease enter a valid start offset";
		wxMessageBox(message, "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
		return;
	}
	
	assert(range_to_enable->GetValue() || range_len_enable->GetValue());
	
	if(range_to_enable->GetValue())
	{
		try {
			if(insert_mode_selected)
			{
				off_t selection_to = range_to->GetValue<off_t>(selection_off);
				selection_length = (selection_to - selection_off) + 1;
			}
			else{
				off_t selection_to = range_to->GetValue<off_t>(selection_off, (doc_length - 1));
				selection_length = (selection_to - selection_off) + 1;
			}
		}
		catch(const NumericTextCtrl::InputError &e)
		{
			std::string message = std::string(e.what()) + "\n\nPlease enter a valid end offset";
			
			wxMessageBox(message, "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
			return;
		}
	}
	else if(range_len_enable->GetValue())
	{
		try {
			if(insert_mode_selected)
			{
				selection_length = range_len->GetValue<off_t>(0);
			}
			else{
				selection_length = range_len->GetValue<off_t>(0, (doc_length - selection_off));
			}
		}
		catch(const NumericTextCtrl::InputError &e)
		{
			std::string message = std::string(e.what()) + "\n\nPlease enter a valid range length";
			
			wxMessageBox(message, "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
			return;
		}
	}
	else{
		/* Shouldn't be reachable. */
		return;
	}
	
	/* TODO: Rework to avoid allocating whole range temporarily. Will need repeated-overwrite
	 * method on Document or transactions for the undo operations.
	*/
	
	std::vector<unsigned char> data;
	try {
		data.reserve(selection_length);
		
		while((off_t)(data.size()) < selection_length)
		{
			off_t insert_len = std::min<off_t>(data_pattern.size(), (selection_length - data.size()));
			data.insert(data.end(), data_pattern.begin(), std::next(data_pattern.begin(), insert_len));
		}
		
		assert((off_t)(data.size()) == selection_length);
	}
	catch(const std::exception &e)
	{
		wxMessageBox(e.what(), "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
		return;
	}
	
	if(insert_mode_selected)
	{
		document.insert_data(selection_off, data.data(), data.size(),
			-1, Document::CSTATE_CURRENT, "fill range");
	}
	else{
		document.overwrite_data(selection_off, data.data(), data.size(),
			-1, Document::CSTATE_CURRENT, "fill range");
	}
	
	Close();
}

void REHex::FillRangeDialog::OnRadio(wxCommandEvent &event)
{
	enable_inputs();
}
