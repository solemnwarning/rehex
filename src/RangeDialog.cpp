/* Reverse Engineer's Hex Editor
 * Copyright (C) 2019-2022 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "RangeDialog.hpp"

BEGIN_EVENT_TABLE(REHex::RangeDialog, wxDialog)
	EVT_BUTTON(wxID_OK, REHex::RangeDialog::OnOK)
	EVT_RADIOBUTTON(wxID_ANY, REHex::RangeDialog::OnRadio)
END_EVENT_TABLE()

REHex::RangeDialog::RangeDialog(wxWindow *parent, DocumentCtrl *document_ctrl, const wxString &title, bool allow_nonlinear):
	wxDialog(parent, wxID_ANY, title),
	document_ctrl(document_ctrl),
	allow_nonlinear(allow_nonlinear),
	range_first(-1),
	range_last(-1)
{
	wxBoxSizer *topsizer = new wxBoxSizer(wxVERTICAL);
	
	{
		wxBoxSizer *from_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		wxStaticText *from_label = new wxStaticText(this, wxID_ANY, "From offset");
		from_sizer->Add(from_label, 1, wxEXPAND | wxALIGN_CENTER_VERTICAL);
		
		range_from = new NumericTextCtrl(this, wxID_ANY);
		from_sizer->Add(range_from, 0, wxALIGN_CENTER_VERTICAL | wxLEFT, 10);
		
		topsizer->Add(from_sizer, 0, wxEXPAND | wxALL, 10);
	}
	
	{
		wxBoxSizer *to_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		range_to_enable = new wxRadioButton(this, wxID_ANY, "To offset");
		to_sizer->Add(range_to_enable, 1, wxEXPAND | wxALIGN_CENTER_VERTICAL);
		
		range_to = new NumericTextCtrl(this, wxID_ANY);
		to_sizer->Add(range_to, 0, wxALIGN_CENTER_VERTICAL | wxLEFT, 10);
		
		topsizer->Add(to_sizer, 0, wxEXPAND | wxLEFT | wxRIGHT, 10);
		
		/* Default to "To offset" */
		range_to_enable->SetValue(true);
	}
	
	{
		wxBoxSizer *len_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		range_len_enable = new wxRadioButton(this, wxID_ANY, "Selection length");
		len_sizer->Add(range_len_enable, 1, wxEXPAND | wxALIGN_CENTER_VERTICAL);
		
		range_len = new NumericTextCtrl(this, wxID_ANY);
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

REHex::RangeDialog::~RangeDialog() {}

bool REHex::RangeDialog::range_valid() const
{
	return range_first >= 0 && range_last >= 0;
}

void REHex::RangeDialog::set_range_raw(off_t first, off_t last)
{
	if(document_ctrl->region_offset_cmp(first, last) > 0)
	{
		/* first offset comes after last */
		abort();
	}
	
	off_t virt_length = document_ctrl->region_offset_cmp(last, first) + 1;
	assert(virt_length > 0);
	
	range_first = first;
	range_last  = last;
	
	off_t virt_first = document_ctrl->region_offset_to_virt(first);
	off_t virt_last  = document_ctrl->region_offset_to_virt(last);
	
	char range_from_val[64];
	snprintf(range_from_val, sizeof(range_from_val), "0x%08llX", (long long unsigned)(virt_first));
	range_from->SetValue(range_from_val);
	
	char range_to_val[64];
	snprintf(range_to_val, sizeof(range_to_val), "0x%08llX", (long long unsigned)(virt_last));
	range_to->SetValue(range_to_val);
	
	char range_len_val[64];
	snprintf(range_len_val, sizeof(range_len_val), "0x%08llX", (long long unsigned)(virt_length));
	range_len->SetValue(range_len_val);
}

std::pair<off_t, off_t> REHex::RangeDialog::get_range_raw() const
{
	return std::make_pair(range_first, range_last);
}

void REHex::RangeDialog::set_range_linear(off_t offset, off_t length)
{
	off_t end_incl = document_ctrl->region_offset_add(offset, length) - 1;
	
	if(!document_ctrl->region_range_linear(offset, end_incl))
	{
		/* nonlinear input range. */
		abort();
	}
	
	set_range_raw(offset, end_incl);
}

std::pair<off_t, off_t> REHex::RangeDialog::get_range_linear() const
{
	if(!document_ctrl->region_range_linear(range_first, range_last))
	{
		return std::make_pair<off_t, off_t>(0, 0);
	}
	
	return std::make_pair(range_first, (range_last - range_first) + 1);
}

void REHex::RangeDialog::set_offset_hint(off_t offset)
{
	off_t virt_offset = document_ctrl->region_offset_to_virt(offset);
	
	char range_from_val[64];
	snprintf(range_from_val, sizeof(range_from_val), "0x%08llX", (long long unsigned)(virt_offset));
	range_from->SetValue(range_from_val);
}

void REHex::RangeDialog::enable_inputs()
{
	range_to->Enable(range_to_enable->GetValue());
	range_len->Enable(range_len_enable->GetValue());
}

void REHex::RangeDialog::OnOK(wxCommandEvent &event)
{
	off_t virt_offset;
	try {
		virt_offset = range_from->GetValue<off_t>();
	}
	catch(const NumericTextCtrl::InputError &e)
	{
		wxMessageBox(e.what(), "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
		return;
	}
	
	off_t real_offset = document_ctrl->region_virt_to_offset(virt_offset);
	if(real_offset < 0)
	{
		wxMessageBox("Start offset out of range", "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
		return;
	}
	
	assert(range_to_enable->GetValue() || range_len_enable->GetValue());
	
	off_t real_end_incl;
	
	if(range_to_enable->GetValue())
	{
		off_t virt_end_incl;
		try {
			virt_end_incl = range_to->GetValue<off_t>();
		}
		catch(const NumericTextCtrl::InputError &e)
		{
			wxMessageBox(e.what(), "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
			return;
		}
		
		real_end_incl = document_ctrl->region_virt_to_offset(virt_end_incl);
	}
	else if(range_len_enable->GetValue())
	{
		off_t length;
		try {
			length = range_len->GetValue<off_t>(1);
		}
		catch(const NumericTextCtrl::InputError &e)
		{
			wxMessageBox(e.what(), "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
			return;
		}
		
		real_end_incl = document_ctrl->region_offset_add(real_offset, length - 1);
	}
	else{
		/* Shouldn't be reachable. */
		return;
	}
	
	if(real_end_incl < 0)
	{
		wxMessageBox("End offset is out of range", "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
		return;
	}
	
	if(!allow_nonlinear && !document_ctrl->region_range_linear(real_offset, real_end_incl))
	{
		wxMessageBox("Range is not linear in virtual address space", "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
		return;
	}
	
	range_first = real_offset;
	range_last  = real_end_incl;
	
	event.Skip(); /* Continue propagation. */
}

void REHex::RangeDialog::OnRadio(wxCommandEvent &event)
{
	enable_inputs();
}
