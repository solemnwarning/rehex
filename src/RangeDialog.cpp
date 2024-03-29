/* Reverse Engineer's Hex Editor
 * Copyright (C) 2019-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

REHex::RangeDialog::RangeDialog(wxWindow *parent, DocumentCtrl *document_ctrl, const wxString &title, bool allow_nonlinear, bool allow_bit_offset, bool allow_bit_length):
	wxDialog(parent, wxID_ANY, title),
	document_ctrl(document_ctrl),
	allow_nonlinear(allow_nonlinear),
	allow_bit_offset(allow_bit_offset),
	allow_bit_length(allow_bit_length),
	range_first(-1),
	range_last(-1)
{
	wxBoxSizer *topsizer = new wxBoxSizer(wxVERTICAL);
	
	{
		wxBoxSizer *from_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		wxStaticText *from_label = new wxStaticText(this, wxID_ANY, "From offset");
		from_sizer->Add(from_label, 1, wxALIGN_CENTER_VERTICAL);
		
		range_from = new NumericTextCtrl(this, wxID_ANY);
		from_sizer->Add(range_from, 0, wxALIGN_CENTER_VERTICAL | wxLEFT, 10);
		
		wxSize initial_size = range_from->GetSize();
		wxSize text_size = range_from->GetTextExtent("0x0000000000000000+0b");
		range_from->SetMinSize(wxSize(((float)(text_size.GetWidth()) * 1.2f), initial_size.GetHeight()));
		
		topsizer->Add(from_sizer, 0, wxEXPAND | wxALL, 10);
	}
	
	{
		wxBoxSizer *to_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		range_to_enable = new wxRadioButton(this, wxID_ANY, "To offset");
		to_sizer->Add(range_to_enable, 1, wxALIGN_CENTER_VERTICAL);
		
		range_to = new NumericTextCtrl(this, wxID_ANY);
		to_sizer->Add(range_to, 0, wxALIGN_CENTER_VERTICAL | wxLEFT, 10);
		
		wxSize initial_size = range_to->GetSize();
		wxSize text_size = range_to->GetTextExtent("0x0000000000000000+0b");
		range_to->SetMinSize(wxSize(((float)(text_size.GetWidth()) * 1.2f), initial_size.GetHeight()));
		
		topsizer->Add(to_sizer, 0, wxEXPAND | wxLEFT | wxRIGHT, 10);
		
		/* Default to "To offset" */
		range_to_enable->SetValue(true);
	}
	
	{
		wxBoxSizer *len_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		range_len_enable = new wxRadioButton(this, wxID_ANY, "Selection length");
		len_sizer->Add(range_len_enable, 1, wxALIGN_CENTER_VERTICAL);
		
		range_len = new NumericTextCtrl(this, wxID_ANY);
		len_sizer->Add(range_len, 0, wxALIGN_CENTER_VERTICAL | wxLEFT, 10);
		
		wxSize initial_size = range_len->GetSize();
		wxSize text_size = range_len->GetTextExtent("0x0000000000000000+0b");
		range_len->SetMinSize(wxSize(((float)(text_size.GetWidth()) * 1.2f), initial_size.GetHeight()));
		
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

void REHex::RangeDialog::set_range_raw(BitOffset first, BitOffset last)
{
	if(document_ctrl->region_offset_cmp(first, last) > 0)
	{
		/* first offset comes after last */
		abort();
	}
	
	BitOffset virt_length = document_ctrl->region_offset_cmp(last, first) + BitOffset(0, 1);
	assert(virt_length > BitOffset::ZERO);
	
	range_first = first;
	range_last  = last;
	
	BitOffset virt_first = document_ctrl->region_offset_to_virt(first);
	BitOffset virt_last  = document_ctrl->region_offset_to_virt(last);
	
	char range_from_val[64];
	int rf_len = snprintf(range_from_val, sizeof(range_from_val), "0x%08llX", (long long unsigned)(virt_first.byte()));
	
	if(!virt_first.byte_aligned() || virt_last.bit() != 7)
	{
		rf_len += snprintf((range_from_val + rf_len), (sizeof(range_from_val) - rf_len), "+%db", virt_first.bit());
	}
	
	char range_to_val[64];
	int rt_len = snprintf(range_to_val, sizeof(range_to_val), "0x%08llX", (long long unsigned)(virt_last.byte()));
	
	if(virt_first.byte_aligned() && virt_last.bit() == 7)
	{
		/* If a range of aligned bytes has been selected, we assume the user is working on
		 * whole byte quantities and omit the "+7b" from the end of the end offset.
		*/
	}
	else{
		rt_len += snprintf((range_to_val + rt_len), (sizeof(range_to_val) - rt_len), "+%db", virt_last.bit());
	}
	
	char range_len_val[64];
	int rl_len = snprintf(range_len_val, sizeof(range_len_val), "0x%08llX", (long long unsigned)(virt_length.byte()));
	
	if(!virt_length.byte_aligned())
	{
		rl_len += snprintf((range_len_val + rl_len), (sizeof(range_len_val) - rl_len), "+%db", virt_length.bit());
	}
	
	range_from->SetValue(range_from_val);
	range_to->SetValue(range_to_val);
	range_len->SetValue(range_len_val);
}

std::pair<REHex::BitOffset, REHex::BitOffset> REHex::RangeDialog::get_range_raw() const
{
	return std::make_pair(range_first, range_last);
}

void REHex::RangeDialog::set_range_linear(BitOffset offset, BitOffset length)
{
	BitOffset end_incl = document_ctrl->region_offset_add(offset, length) - BitOffset(0, 1);
	
	if(!document_ctrl->region_range_linear(offset, end_incl))
	{
		/* nonlinear input range. */
		abort();
	}
	
	set_range_raw(offset, end_incl);
}

std::pair<REHex::BitOffset, REHex::BitOffset> REHex::RangeDialog::get_range_linear() const
{
	if(!document_ctrl->region_range_linear(range_first, range_last))
	{
		return std::make_pair(BitOffset::ZERO, BitOffset::ZERO);
	}
	
	return std::make_pair(range_first, (range_last - range_first) + BitOffset(0, 1));
}

void REHex::RangeDialog::set_offset_hint(BitOffset offset)
{
	BitOffset virt_offset = document_ctrl->region_offset_to_virt(offset);
	
	char range_from_val[64];
	int rf_len = snprintf(range_from_val, sizeof(range_from_val), "0x%08llX", (long long unsigned)(virt_offset.byte()));
	
	if(!virt_offset.byte_aligned())
	{
		rf_len += snprintf((range_from_val + rf_len), (sizeof(range_from_val) - rf_len), "+%db", virt_offset.bit());
	}
	
	range_from->SetValue(range_from_val);
}

void REHex::RangeDialog::enable_inputs()
{
	range_to->Enable(range_to_enable->GetValue());
	range_len->Enable(range_len_enable->GetValue());
}

void REHex::RangeDialog::OnOK(wxCommandEvent &event)
{
	BitOffset virt_offset;
	bool virt_offset_bit;
	try {
		virt_offset = range_from->GetValue<BitOffset>(BitOffset::MIN, BitOffset::MAX, BitOffset::ZERO, 0, &virt_offset_bit);
	}
	catch(const NumericTextCtrl::InputError &e)
	{
		wxMessageBox(e.what(), "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
		return;
	}
	
	BitOffset real_offset = document_ctrl->region_virt_to_offset(virt_offset);
	if(real_offset < BitOffset::ZERO)
	{
		wxMessageBox("Start offset out of range", "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
		return;
	}
	
	assert(range_to_enable->GetValue() || range_len_enable->GetValue());
	
	BitOffset real_end_incl;
	
	if(range_to_enable->GetValue())
	{
		BitOffset virt_end_incl;
		bool virt_end_bit;
		try {
			virt_end_incl = range_to->GetValue<BitOffset>(BitOffset::MIN, BitOffset::MAX, BitOffset::ZERO, 0, &virt_end_bit);
		}
		catch(const NumericTextCtrl::InputError &e)
		{
			wxMessageBox(e.what(), "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
			return;
		}
		
		if(!virt_offset_bit && !virt_end_bit)
		{
			/* If both the start and end offset were specified as bytes, assume they
			 * want the whole end byte, not just the first bit of it.
			*/
			
			virt_end_incl = BitOffset(virt_end_incl.byte(), 7);
		}
		
		real_end_incl = document_ctrl->region_virt_to_offset(virt_end_incl);
	}
	else if(range_len_enable->GetValue())
	{
		BitOffset length;
		try {
			length = range_len->GetValue<BitOffset>(BitOffset(0, 1));
		}
		catch(const NumericTextCtrl::InputError &e)
		{
			wxMessageBox(e.what(), "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
			return;
		}
		
		real_end_incl = document_ctrl->region_offset_add(real_offset, length - BitOffset(0, 1));
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
	
	if(!allow_bit_offset && !real_offset.byte_aligned())
	{
		wxMessageBox("Start offset must be a whole number of bytes", "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
		return;
	}
	
	if(!allow_bit_length && (real_end_incl - real_offset).bit() != 7)
	{
		wxMessageBox("Selection length must be a whole number of bytes", "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
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
