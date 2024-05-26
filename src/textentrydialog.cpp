/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <wx/dialog.h>
#include <wx/wx.h>

#include "textentrydialog.hpp"

REHex::TextEntryDialog::TextEntryDialog(wxWindow *parent, const std::string &title, const wxString &initial_text):
	wxDialog(parent, wxID_ANY, title)
{
	wxBoxSizer *topsizer = new wxBoxSizer(wxVERTICAL);
	
	textbox = new wxTextCtrl(this, wxID_ANY, initial_text, wxDefaultPosition, wxSize(480,120), wxTE_MULTILINE);
	topsizer->Add(textbox, 1, wxEXPAND | wxALL, 10);

	textbox->Bind(wxEVT_CHAR, [&](wxKeyEvent &event)
	{
		if(event.GetKeyCode() == WXK_RETURN && event.GetModifiers() == wxMOD_SHIFT)
		{
			EndModal(wxID_OK);
		}
		else {
			event.Skip();
		}
	});
	
	wxBoxSizer *button_sizer = new wxBoxSizer(wxHORIZONTAL);
	
	button_sizer->Add(new wxButton(this, wxID_OK,     "OK"),     0, wxALL, 10);
	button_sizer->Add(new wxButton(this, wxID_CANCEL, "Cancel"), 0, wxALL, 10);
	
	topsizer->Add(button_sizer, 0, wxALIGN_RIGHT);
	
	SetSizerAndFit(topsizer);
}

wxString REHex::TextEntryDialog::get_text()
{
	return textbox->GetValue();
}
