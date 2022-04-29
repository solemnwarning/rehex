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
#include <wx/button.h>
#include <wx/sizer.h>
#include <wx/statbmp.h>
#include <wx/stattext.h>

#include "AboutDialog.hpp"
#include "LicenseDialog.hpp"
#include "ClickText.hpp"
#include "../res/icon128.h"
#include "../res/version.h"

enum {
	ID_LICENSE = 1,
};

BEGIN_EVENT_TABLE(REHex::AboutDialog, wxDialog)
	EVT_BUTTON(ID_LICENSE, REHex::AboutDialog::OnLicense)
END_EVENT_TABLE()

REHex::AboutDialog::AboutDialog(wxWindow *parent, wxWindowID id):
	wxDialog(parent, id, "About Reverse Engineers' Hex Editor")
{
	wxBoxSizer *main_sizer = new wxBoxSizer(wxVERTICAL);
	
	{
		wxBoxSizer *top_sizer = new wxBoxSizer(wxHORIZONTAL);
		
		wxBitmap icon_bitmap = wxBITMAP_PNG_FROM_DATA(icon128);
		wxStaticBitmap *icon_sb = new wxStaticBitmap(this, wxID_ANY, icon_bitmap);
		top_sizer->Add(icon_sb, 0, wxALL, 10);
		
		wxBoxSizer *right_sizer = new wxBoxSizer(wxVERTICAL);
		
		right_sizer->Add(new wxStaticText(this, wxID_ANY, "Reverse Engineers' Hex Editor"));
		right_sizer->Add(new wxStaticText(this, wxID_ANY, REHEX_VERSION));
		right_sizer->Add(new wxStaticText(this, wxID_ANY, std::string("Built on ") + REHEX_BUILD_DATE));
		
		right_sizer->Add(new wxStaticText(this, wxID_ANY, L"Copyright \u00A9 2017-2022 Daniel Collins"),
			0, wxTOP, 10);
		
		wxBoxSizer *license_sizer = new wxBoxSizer(wxHORIZONTAL);
		license_sizer->Add(new wxStaticText(this, wxID_ANY, "Released under the "));
		license_sizer->Add(new REHex::ClickText(this, ID_LICENSE, "GNU General Public License"));
		
		right_sizer->Add(license_sizer);
		
		top_sizer->Add(right_sizer, 0, wxALL, 10);
		
		main_sizer->Add(top_sizer);
	}
	
	{
		main_sizer->Add(new wxButton(this, wxID_CLOSE, "Close"),
			0, wxLEFT | wxRIGHT | wxBOTTOM | wxALIGN_RIGHT, 10);
		
		SetEscapeId(wxID_CLOSE);
	}
	
	SetSizerAndFit(main_sizer);
}

void REHex::AboutDialog::OnLicense(wxCommandEvent &event)
{
	LicenseDialog ld(this);
	ld.ShowModal();
}
