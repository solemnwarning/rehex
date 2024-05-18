/* Reverse Engineer's Hex Editor
 * Copyright (C) 2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <wx/stattext.h>

#include "App.hpp"
#include "SettingsDialogGeneral.hpp"

bool REHex::SettingsDialogGeneral::Create(wxWindow *parent)
{
	wxPanel::Create(parent);
	
	wxBoxSizer *top_sizer = new wxBoxSizer(wxVERTICAL);
	
	wxBoxSizer *hcm_sizer = new wxBoxSizer(wxHORIZONTAL);
	top_sizer->Add(hcm_sizer);
	
	hcm_sizer->Add(new wxStaticText(this, wxID_ANY, "Hex cursor behaviour:"));
	
	wxBoxSizer *hcm_rb_sizer = new wxBoxSizer(wxVERTICAL);
	hcm_sizer->Add(hcm_rb_sizer);
	
	hcm_byte_rb = new wxRadioButton(this, wxID_ANY, "Navigate by byte");
	hcm_rb_sizer->Add(hcm_byte_rb);
	
	hcm_nibble_rb = new wxRadioButton(this, wxID_ANY, "Navigate by nibble");
	hcm_rb_sizer->Add(hcm_nibble_rb);
	
	SetSizerAndFit(top_sizer);
	
	HexCursorMode hex_cursor_mode = wxGetApp().settings->get_hex_cursor_mode();
	switch(hex_cursor_mode)
	{
		case HexCursorMode::BYTE:
			hcm_byte_rb->SetValue(true);
			break;
			
		case HexCursorMode::NIBBLE:
			hcm_nibble_rb->SetValue(true);
			break;
	}
	
	return true;
}

std::string REHex::SettingsDialogGeneral::label() const
{
	return "General settings";
}

bool REHex::SettingsDialogGeneral::validate()
{
	return true;
}

void REHex::SettingsDialogGeneral::save()
{
	if(hcm_byte_rb->GetValue())
	{
		wxGetApp().settings->set_hex_cursor_mode(HexCursorMode::BYTE);
	}
	else if(hcm_nibble_rb->GetValue())
	{
		wxGetApp().settings->set_hex_cursor_mode(HexCursorMode::NIBBLE);
	}
}

void REHex::SettingsDialogGeneral::reset()
{
	
}
