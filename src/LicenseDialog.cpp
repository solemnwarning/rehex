/* Reverse Engineer's Hex Editor
 * Copyright (C) 2019 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <wx/button.h>
#include <wx/dc.h>
#include <wx/dcclient.h>
#include <wx/sizer.h>
#include <wx/textctrl.h>

#include "LicenseDialog.hpp"
#include "../res/license.h"

REHex::LicenseDialog::LicenseDialog(wxWindow *parent, wxWindowID id):
	wxDialog(parent, id, "License")
{
	wxBoxSizer *main_sizer = new wxBoxSizer(wxVERTICAL);
	
	{
		wxTextCtrl *text = new wxTextCtrl(this, wxID_ANY, LICENSE_TXT, wxDefaultPosition, wxDefaultSize,
			(wxTE_MULTILINE | wxTE_READONLY));
		
		wxFont font = text->GetFont();
		font.SetFamily(wxFONTFAMILY_MODERN);
		text->SetFont(font);
		
		wxClientDC text_dc(text);
		
		wxSize extent = text_dc.GetTextExtent(wxString('X', 80));
		text->SetMinClientSize(wxSize(extent.GetWidth(), extent.GetHeight() * 20));
		
		text->ShowPosition(0);
		
		main_sizer->Add(text, 1, wxEXPAND | wxALL, 10);
	}
	
	{
		main_sizer->Add(new wxButton(this, wxID_CLOSE, "Close"),
			0, wxLEFT | wxRIGHT | wxBOTTOM | wxALIGN_RIGHT, 10);
		
		SetEscapeId(wxID_CLOSE);
	}
	
	SetSizerAndFit(main_sizer);
}
