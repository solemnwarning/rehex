/* Reverse Engineer's Hex Editor
 * Copyright (C) 2024-2026 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <wx/sizer.h>
#include <wx/stattext.h>

#include "App.hpp"
#include "SettingsDialogGeneral.hpp"

bool REHex::SettingsDialogGeneral::Create(wxWindow *parent)
{
	wxPanel::Create(parent);
	
	wxBoxSizer *top_sizer = new wxBoxSizer(wxVERTICAL);
	
	wxBoxSizer *cnm_sizer = new wxBoxSizer(wxHORIZONTAL);
	top_sizer->Add(cnm_sizer, 0, wxBOTTOM, SettingsDialog::MARGIN);
	
	cnm_sizer->Add(new wxStaticText(this, wxID_ANY, "Hex cursor navigation:"), 0, wxALIGN_CENTER_VERTICAL);
	
	cnm_byte = new wxRadioButton(this, wxID_ANY, "By byte");
	cnm_sizer->Add(cnm_byte, 0, (wxALIGN_CENTER_VERTICAL | wxLEFT), SettingsDialog::MARGIN);
	
	cnm_byte->SetToolTip("The arrow keys will move the cursor in whole byte increments");
	
	cnm_nibble = new wxRadioButton(this, wxID_ANY, "By nibble");
	cnm_sizer->Add(cnm_nibble, 0, (wxALIGN_CENTER_VERTICAL | wxLEFT), SettingsDialog::MARGIN);
	
	cnm_nibble->SetToolTip("The arrow keys will move the cursor in nibble (half byte) increments");
	
	switch(wxGetApp().settings->get_cursor_nav_mode())
	{
		case CursorNavMode::BYTE:
			cnm_byte->SetValue(true);
			break;
			
		case CursorNavMode::NIBBLE:
			cnm_nibble->SetValue(true);
			break;
	}
	
	wxBoxSizer *su_sizer = new wxBoxSizer(wxHORIZONTAL);
	top_sizer->Add(su_sizer, 0, wxBOTTOM, SettingsDialog::MARGIN);
	
	su_sizer->Add(new wxStaticText(this, wxID_ANY, "Size units:"), 0, wxALIGN_CENTER_VERTICAL);
	
	su_byte = new wxRadioButton(this, wxID_ANY, "Bytes", wxDefaultPosition, wxDefaultSize, wxRB_GROUP);
	su_sizer->Add(su_byte, 0, (wxALIGN_CENTER_VERTICAL | wxLEFT), SettingsDialog::MARGIN);
	
	su_byte->SetToolTip("Sizes will always be displayed in bytes");
	
	su_xib = new wxRadioButton(this, wxID_ANY, "KiB, MiB, etc");
	su_sizer->Add(su_xib, 0, (wxALIGN_CENTER_VERTICAL | wxLEFT), SettingsDialog::MARGIN);
	
	su_xib->SetToolTip("Sizes will be displayed in units of 1,024 (1,024 bytes = 1 KiB, 1,024 KiB = 1MB etc)");
	
	su_xb = new wxRadioButton(this, wxID_ANY, "kB, MB, etc");
	su_sizer->Add(su_xb, 0, (wxALIGN_CENTER_VERTICAL | wxLEFT), SettingsDialog::MARGIN);
	
	su_xb->SetToolTip("Sizes will be displayed in units of 1,000 (1,000 bytes = 1 kB, 1,000 kB = 1 MB etc)");
	
	switch(wxGetApp().settings->get_size_unit())
	{
		case SizeUnit::B:
			su_byte->SetValue(true);
			break;
			
		case SizeUnit::AUTO_XiB:
			su_xib->SetValue(true);
			break;
			
		case SizeUnit::AUTO_XB:
			su_xb->SetValue(true);
			break;
			
		default:
			break;
	}
	
	goto_offset_modeless = new wxCheckBox(this, wxID_ANY, "Non-modal 'Jump to offset' dialog");
	top_sizer->Add(goto_offset_modeless, 0, wxBOTTOM, SettingsDialog::MARGIN);
	
	goto_offset_modeless->SetValue(!(wxGetApp().settings->get_goto_offset_modal()));
	goto_offset_modeless->SetToolTip("The 'Jump to offset' dialog will remain open after use and allow interacting with the editor window.");
	
	#ifdef REHEX_ENABLE_PRIMARY_SELECTION
	{
		primary_copy_enable = new wxCheckBox(this, wxID_ANY, "Copy selections to \"PRIMARY\" selection");
		top_sizer->Add(primary_copy_enable, 0, wxBOTTOM, SettingsDialog::MARGIN);
		
		primary_copy_enable->SetToolTip("Update the X11/Wayland \"PRIMARY\" buffer when data is selected.");
		
		wxBoxSizer *primary_copy_kb_sizer = new wxBoxSizer(wxHORIZONTAL);
		top_sizer->Add(primary_copy_kb_sizer, 0, wxBOTTOM, SettingsDialog::MARGIN);
		
		primary_copy_kb_sizer->Add(new wxStaticText(this, wxID_ANY, "Maximum selection size:"), 0, (wxALIGN_CENTER_VERTICAL | wxLEFT), (4 * SettingsDialog::MARGIN));
		
		primary_copy_kb = new wxSpinCtrl(this, wxID_ANY, "", wxDefaultPosition, wxDefaultSize, wxSP_ARROW_KEYS, 1);
		primary_copy_kb_sizer->Add(primary_copy_kb, 0, (wxALIGN_CENTER_VERTICAL | wxLEFT), SettingsDialog::MARGIN);
		
		primary_copy_kb->SetToolTip("Maximum length of string to place in \"PRIMARY\" buffer.");
		
		primary_copy_kb_sizer->Add(new wxStaticText(this, wxID_ANY, "KiB"), 0, (wxALIGN_CENTER_VERTICAL | wxLEFT), SettingsDialog::MARGIN);
		
		primary_copy_enable->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent &event)
		{
			primary_copy_kb->Enable(event.IsChecked());
		});
		
		size_t primary_copy_limit = wxGetApp().settings->get_primary_copy_limit();
		
		if(primary_copy_limit >= 1024)
		{
			primary_copy_enable->SetValue(true);
			primary_copy_kb->Enable();
			
			primary_copy_kb->SetValue(primary_copy_limit / 1024);
		}
		else{
			primary_copy_enable->SetValue(false);
			primary_copy_kb->Disable();
			
			primary_copy_kb->SetValue(AppSettings::DEFAULT_PRIMARY_COPY_LIMIT / 1024);
		}
	}
	#endif
	
	SetSizerAndFit(top_sizer);
	
	return true;
}

std::string REHex::SettingsDialogGeneral::label() const
{
	return "General";
}

bool REHex::SettingsDialogGeneral::validate() { return true; }

void REHex::SettingsDialogGeneral::save()
{
	if(cnm_byte->GetValue())
	{
		wxGetApp().settings->set_cursor_nav_mode(CursorNavMode::BYTE);
	}
	else if(cnm_nibble->GetValue())
	{
		wxGetApp().settings->set_cursor_nav_mode(CursorNavMode::NIBBLE);
	}
	
	if(su_byte->GetValue())
	{
		wxGetApp().settings->set_size_unit(SizeUnit::B);
	}
	else if(su_xib->GetValue())
	{
		wxGetApp().settings->set_size_unit(SizeUnit::AUTO_XiB);
	}
	else if(su_xb->GetValue())
	{
		wxGetApp().settings->set_size_unit(SizeUnit::AUTO_XB);
	}
	
	wxGetApp().settings->set_goto_offset_modal(!(goto_offset_modeless->GetValue()));
	
	#ifdef REHEX_ENABLE_PRIMARY_SELECTION
	if(primary_copy_enable->GetValue())
	{
		wxGetApp().settings->set_primary_copy_limit(primary_copy_kb->GetValue() * 1024);
	}
	else{
		wxGetApp().settings->set_primary_copy_limit(0);
	}
	#endif
}

void REHex::SettingsDialogGeneral::reset() {}
