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

#include <wx/stattext.h>

#include "BytesPerLineDialog.hpp"
#include "DocumentCtrl.hpp"

enum {
	ID_FIT_RB = 1,
	ID_FIXED_RB,
};

BEGIN_EVENT_TABLE(REHex::BytesPerLineDialog, wxDialog)
	EVT_RADIOBUTTON(ID_FIT_RB,   REHex::BytesPerLineDialog::OnFit)
	EVT_RADIOBUTTON(ID_FIXED_RB, REHex::BytesPerLineDialog::OnFixed)
END_EVENT_TABLE()

REHex::BytesPerLineDialog::BytesPerLineDialog(wxWindow *parent, int initial_value):
	wxDialog(parent, wxID_ANY, "Set bytes per line")
{
	fit_rb = new wxRadioButton(this, ID_FIT_RB, "Fit to window width");
	fixed_rb = new wxRadioButton(this, ID_FIXED_RB, "Fixed number");
	
	fit_groups_cb = new wxCheckBox(this, wxID_ANY, "Display whole groups only");
	
	fixed_sc = new wxSpinCtrl(this, wxID_ANY, "", wxDefaultPosition, wxDefaultSize, wxSP_ARROW_KEYS,
		DocumentCtrl::BYTES_PER_LINE_MIN, DocumentCtrl::BYTES_PER_LINE_MAX);
	
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);
	
	sizer->Add(new wxStaticText(this, wxID_ANY, "Number of bytes to show on each line"), 0, wxALL, 10);
	
	wxBoxSizer *fit_sizer = new wxBoxSizer(wxVERTICAL);
	fit_sizer->Add(fit_groups_cb, 0, (wxLEFT | wxRIGHT | wxBOTTOM), 10);
	
	sizer->Add(fit_rb, 0, (wxLEFT | wxRIGHT | wxBOTTOM), 10);
	sizer->Add(fit_sizer, 0, wxLEFT, 40);
	
	wxBoxSizer *fixed_sizer = new wxBoxSizer(wxHORIZONTAL);
	fixed_sizer->Add(fixed_sc, 0, (wxLEFT | wxRIGHT | wxBOTTOM), 10);
	fixed_sizer->Add(new wxStaticText(this, wxID_ANY, "bytes"), (wxRIGHT | wxBOTTOM), 10);
	
	sizer->Add(fixed_rb, 0, (wxLEFT | wxRIGHT | wxBOTTOM), 10);
	sizer->Add(fixed_sizer, 0, wxLEFT, 40);
	
	wxButton *ok     = new wxButton(this, wxID_OK,     "OK");
	wxButton *cancel = new wxButton(this, wxID_CANCEL, "Cancel");
	
	wxBoxSizer *button_sizer = new wxBoxSizer(wxHORIZONTAL);
	button_sizer->Add(ok,     0, wxALL, 10);
	button_sizer->Add(cancel, 0, wxALL, 10);
	
	sizer->Add(button_sizer, 0, wxALIGN_RIGHT);
	
	SetSizerAndFit(sizer);
	
	/* Trigger the "OK" button if enter is pressed. */
	ok->SetDefault();
	
	if(initial_value > 0)
	{
		fit_groups_cb->Disable();
		
		fixed_rb->SetValue(true);
		fixed_sc->SetValue(std::to_string(initial_value));
	}
	else{
		fixed_sc->Disable();
		
		fit_rb->SetValue(true);
		fit_groups_cb->SetValue(initial_value == DocumentCtrl::BYTES_PER_LINE_FIT_GROUPS);
	}
}

int REHex::BytesPerLineDialog::get_bytes_per_line()
{
	if(fit_rb->GetValue())
	{
		return fit_groups_cb->GetValue()
			? DocumentCtrl::BYTES_PER_LINE_FIT_GROUPS
			: DocumentCtrl::BYTES_PER_LINE_FIT_BYTES;
	}
	else{
		assert(fixed_rb->GetValue());
		
		return fixed_sc->GetValue();
	}
}

void REHex::BytesPerLineDialog::OnFit(wxCommandEvent &event)
{
	fit_groups_cb->Enable();
	fixed_sc->Disable();
}

void REHex::BytesPerLineDialog::OnFixed(wxCommandEvent &event)
{
	fit_groups_cb->Disable();
	fixed_sc->Enable();
}
