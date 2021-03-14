/* Reverse Engineer's Hex Editor
 * Copyright (C) 2021 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <wx/artprov.h>
#include <wx/sizer.h>
#include <wx/stattext.h>

#include "VirtualMappingDialog.hpp"
#include "util.hpp"

BEGIN_EVENT_TABLE(REHex::VirtualMappingDialog, wxDialog)
	EVT_BUTTON(wxID_OK, REHex::VirtualMappingDialog::OnOK)
	EVT_TEXT(wxID_ANY, REHex::VirtualMappingDialog::OnText)
END_EVENT_TABLE()

REHex::VirtualMappingDialog::VirtualMappingDialog(wxWindow *parent, SharedDocumentPointer &document, off_t real_base, off_t segment_length):
	wxDialog(parent, wxID_ANY, "Set virtual mapping"),
	initialised(false),
	initial_real_base(-1),
	initial_virt_base(-1),
	initial_segment_length(-1),
	document(document)
{
	wxBoxSizer *topsizer = new wxBoxSizer(wxVERTICAL);
	
	topsizer->Add(
		new wxStaticText(this, wxID_ANY,
			"This dialog maps file offsets to a virtual address space.\n\n"
			"The virtual addresses can be shown in place of or in addition to the file offsets.\n"
			"Multiple mappings cannot use the same file or virtual address ranges."),
		0, wxALL, 10);
	
	char initial_real_base_text[64] = "";
	char initial_virt_base_text[64] = "";
	char initial_segment_length_text[64] = "";
	
	if(real_base >= 0)
	{
		snprintf(initial_real_base_text, sizeof(initial_real_base_text), "0x%08llX", (long long unsigned)(real_base));
		
		if(segment_length > 0)
		{
			snprintf(initial_segment_length_text,  sizeof(initial_segment_length_text),  "0x%08llX", (long long unsigned)(segment_length));
			
			const ByteRangeMap<off_t> &real_to_virt_segs = document->get_real_to_virt_segs();
			
			auto r2v = real_to_virt_segs.get_range_in(real_base, segment_length);
			if(r2v != real_to_virt_segs.end() && r2v->first.offset == real_base && r2v->first.length == segment_length)
			{
				initial_real_base      = r2v->first.offset;
				initial_virt_base      = r2v->second;
				initial_segment_length = r2v->first.length;
				
				snprintf(initial_virt_base_text, sizeof(initial_virt_base_text), "0x%08llX", (long long unsigned)(r2v->second));
			}
		}
	}
	
	wxBoxSizer *input_field_sizer = new wxBoxSizer(wxVERTICAL);
	
	wxSize input_size;
	wxBitmap bad_input_bitmap;
	
	{
		wxBoxSizer *real_base_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		real_base_sizer->Add(
			new wxStaticText(this, wxID_ANY, "Base file offset"),
			1, wxALIGN_CENTER_VERTICAL);
		
		real_base_input = new NumericTextCtrl(this, wxID_ANY, initial_real_base_text);
		
		input_size = real_base_input->GetSizeFromTextSize(real_base_input->GetTextExtent("0x000000000000"));
		bad_input_bitmap = wxArtProvider::GetBitmap(wxART_WARNING, wxART_OTHER, wxSize(input_size.GetHeight(), input_size.GetHeight()));
		
		real_base_input->SetInitialSize(input_size);
		real_base_sizer->Add(real_base_input, 0, wxALIGN_CENTER_VERTICAL | wxLEFT, 10);
		
		real_base_bad = new wxStaticBitmap(this, wxID_ANY, bad_input_bitmap);
		real_base_sizer->Add(real_base_bad, 0, wxALIGN_CENTER_VERTICAL | wxLEFT | wxRESERVE_SPACE_EVEN_IF_HIDDEN, 10);
		
		input_field_sizer->Add(real_base_sizer, 0, wxEXPAND | wxLEFT | wxRIGHT, 10);
	}
	
	{
		wxBoxSizer *arrow_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		wxSize arrow_size(input_size.GetHeight(), input_size.GetHeight());
		wxBitmap arrow_bitmap = wxArtProvider::GetBitmap(wxART_GO_DOWN, wxART_OTHER, arrow_size);
		
		arrow_sizer->Add(0, 0, wxEXPAND);
		
		arrow_sizer->Add(
			new wxStaticBitmap(this, wxID_ANY, arrow_bitmap),
			0, wxRIGHT, ((input_size.GetWidth() - arrow_size.GetWidth()) / 2));
		
		arrow_sizer->Add(input_size.GetHeight(), 0,
			0, wxLEFT, 10);
		
		input_field_sizer->Add(arrow_sizer, 0, wxEXPAND | wxLEFT | wxRIGHT, 10);
	}
	
	{
		wxBoxSizer *virt_base_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		virt_base_sizer->Add(
			new wxStaticText(this, wxID_ANY, "Base virtual address"),
			1, wxALIGN_CENTER_VERTICAL);
		
		virt_base_input = new NumericTextCtrl(this, wxID_ANY, initial_virt_base_text);
		virt_base_input->SetInitialSize(input_size);
		virt_base_sizer->Add(virt_base_input, 0, wxALIGN_CENTER_VERTICAL | wxLEFT, 10);
		
		virt_base_bad = new wxStaticBitmap(this, wxID_ANY, bad_input_bitmap);
		virt_base_sizer->Add(virt_base_bad, 0, wxALIGN_CENTER_VERTICAL | wxLEFT | wxRESERVE_SPACE_EVEN_IF_HIDDEN, 10);
		
		input_field_sizer->Add(virt_base_sizer, 0, wxEXPAND | wxLEFT | wxRIGHT, 10);
	}
	
	{
		wxBoxSizer *segment_length_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		segment_length_sizer->Add(
			new wxStaticText(this, wxID_ANY, "Mapping length"),
			1, wxALIGN_CENTER_VERTICAL);
		
		segment_length_input = new NumericTextCtrl(this, wxID_ANY, initial_segment_length_text);
		segment_length_input->SetInitialSize(input_size);
		segment_length_sizer->Add(segment_length_input, 0, wxALIGN_CENTER_VERTICAL | wxLEFT, 10);
		
		segment_length_bad = new wxStaticBitmap(this, wxID_ANY, bad_input_bitmap);
		segment_length_sizer->Add(segment_length_bad, 0, wxALIGN_CENTER_VERTICAL | wxLEFT | wxRESERVE_SPACE_EVEN_IF_HIDDEN, 10);
		
		input_field_sizer->Add(segment_length_sizer, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 10);
	}
	
	topsizer->Add(input_field_sizer, 0, wxALIGN_CENTER_HORIZONTAL);
	
	conflict_warning = new wxStaticText(this, wxID_ANY, "Warning: This mapping conflicts with and will replace another!");
	topsizer->Add(conflict_warning, 0, wxEXPAND | wxALL | wxRESERVE_SPACE_EVEN_IF_HIDDEN, 10);
	
	wxBoxSizer *button_sizer = new wxBoxSizer(wxHORIZONTAL);
	
	wxButton *ok     = new wxButton(this, wxID_OK,     "OK");
	wxButton *cancel = new wxButton(this, wxID_CANCEL, "Cancel");
	
	button_sizer->Add(ok,     0, wxALL, 10);
	button_sizer->Add(cancel, 0, wxALL, 10);
	
	topsizer->Add(button_sizer, 0, wxALIGN_CENTER_HORIZONTAL);
	
	SetSizerAndFit(topsizer);
	
	/* Trigger the "OK" button if enter is pressed. */
	ok->SetDefault();
	
	update_warning();
	
	initialised = true;
}

REHex::VirtualMappingDialog::~VirtualMappingDialog() {}

off_t REHex::VirtualMappingDialog::get_real_base()
{
	off_t min = 0;
	off_t max = std::max<off_t>(0, (document->buffer_length() - 1));;
	
	return real_base_input->GetValue<off_t>(min, max);
}

off_t REHex::VirtualMappingDialog::get_virt_base()
{
	return virt_base_input->GetValue<off_t>(0);
}

off_t REHex::VirtualMappingDialog::get_segment_length(off_t real_base)
{
	off_t min = 1;
	off_t max = document->buffer_length() - real_base;
	
	return segment_length_input->GetValue<off_t>(min, max);
}

void REHex::VirtualMappingDialog::update_warning()
{
	try {
		off_t real_base = get_real_base();
		real_base_bad->Hide();
		
		try {
			get_segment_length(real_base);
			segment_length_bad->Hide();
		}
		catch(const NumericTextCtrl::InputError &e)
		{
			segment_length_bad->SetToolTip(e.what());
			segment_length_bad->Show();
		}
	}
	catch(const NumericTextCtrl::InputError &e)
	{
		real_base_bad->SetToolTip(e.what());
		real_base_bad->Show();
		
		segment_length_bad->Hide();
	}
	
	try {
		get_virt_base();
		virt_base_bad->Hide();
	}
	catch(const NumericTextCtrl::InputError &e)
	{
		virt_base_bad->SetToolTip(e.what());
		virt_base_bad->Show();
	}
	
	try {
		off_t real_base = get_real_base();
		off_t virt_base = get_virt_base();
		off_t segment_length = get_segment_length(real_base);
		
		bool found_conflict = false;
		
		const ByteRangeMap<off_t> &real_to_virt_segs = document->get_real_to_virt_segs();
		const ByteRangeMap<off_t> &virt_to_real_segs = document->get_virt_to_real_segs();
		
		for(
			auto r2v = real_to_virt_segs.get_range_in(real_base, segment_length);
			r2v != real_to_virt_segs.end() && r2v->first.offset < (real_base + segment_length) && !found_conflict;
			++r2v)
		{
			if(r2v->first.offset != initial_real_base || r2v->first.length != initial_segment_length)
			{
				found_conflict = true;
			}
		}
		
		for(
			auto v2r = virt_to_real_segs.get_range_in(virt_base, segment_length);
			v2r != virt_to_real_segs.end() && v2r->first.offset < (virt_base + segment_length) && !found_conflict;
			++v2r)
		{
			if(v2r->first.offset != initial_virt_base || v2r->first.length != initial_segment_length)
			{
				found_conflict = true;
			}
		}
		
		if(found_conflict)
		{
			conflict_warning->Show();
		}
		else{
			conflict_warning->Hide();
		}
	}
	catch(const NumericTextCtrl::InputError &e)
	{
		conflict_warning->Hide();
	}
}

void REHex::VirtualMappingDialog::OnOK(wxCommandEvent &event)
{
	off_t real_base, virt_base, segment_length;
	
	try {
		real_base = get_real_base();
	}
	catch(const NumericTextCtrl::InputError &e)
	{
		std::string message = std::string(e.what()) + "\n\nPlease enter a valid base file offset";
		wxMessageBox(message, "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
		return;
	}
	
	try {
		virt_base = get_virt_base();
	}
	catch(const NumericTextCtrl::InputError &e)
	{
		std::string message = std::string(e.what()) + "\n\nPlease enter a valid base virtual address";
		wxMessageBox(message, "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
		return;
	}
	
	try {
		segment_length = get_segment_length(real_base);
	}
	catch(const NumericTextCtrl::InputError &e)
	{
		std::string message = std::string(e.what()) + "\n\nPlease enter a valid mapping length";
		
		wxMessageBox(message, "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
		return;
	}
	
	/* TODO: Roll all these into same undo transaction. */
	
	if(initial_real_base >= 0)
	{
		assert(initial_segment_length > 0);
		document->clear_virt_mapping_r(initial_real_base, initial_segment_length);
	}
	
	document->clear_virt_mapping_r(real_base, segment_length);
	document->clear_virt_mapping_v(virt_base, segment_length);
	
	document->set_virt_mapping(real_base, virt_base, segment_length);
	
	Close();
}

void REHex::VirtualMappingDialog::OnText(wxCommandEvent &event)
{
	if(initialised)
	{
		update_warning();
	}
}
