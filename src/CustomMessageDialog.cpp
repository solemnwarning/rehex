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

#include <assert.h>
#include <wx/artprov.h>
#include <wx/button.h>
#include <wx/statbmp.h>
#include <wx/stattext.h>

#include "CustomMessageDialog.hpp"

#define MARGIN 10

BEGIN_EVENT_TABLE(REHex::CustomMessageDialog, wxDialog)
	EVT_BUTTON(wxID_ANY, REHex::CustomMessageDialog::OnButtonPress)
END_EVENT_TABLE()

REHex::CustomMessageDialog::CustomMessageDialog(wxWindow *parent, const wxString &message, const wxString &caption, long style):
	wxDialog(parent, wxID_ANY, caption, wxDefaultPosition, wxDefaultSize, style)
{
	wxBitmap bitmap = wxNullBitmap;
	
	if((style & wxICON_EXCLAMATION) != 0)
	{
		bitmap = wxArtProvider::GetBitmap(wxART_WARNING, wxART_MESSAGE_BOX);
	}
	else if((style & wxICON_ERROR) != 0)
	{
		bitmap = wxArtProvider::GetBitmap(wxART_ERROR, wxART_MESSAGE_BOX);
	}
	else if((style & wxICON_QUESTION) != 0)
	{
		bitmap = wxArtProvider::GetBitmap(wxART_QUESTION, wxART_MESSAGE_BOX);
	}
	else if((style & wxICON_INFORMATION) != 0)
	{
		bitmap = wxArtProvider::GetBitmap(wxART_INFORMATION, wxART_MESSAGE_BOX);
	}
	
	wxBoxSizer *top_sizer = new wxBoxSizer(wxVERTICAL);
	
	wxBoxSizer *message_sizer = new wxBoxSizer(wxHORIZONTAL);
	top_sizer->Add(message_sizer, 0, (wxALIGN_LEFT | wxALL), MARGIN);
	
	if(bitmap.IsOk())
	{
		message_sizer->Add(new wxStaticBitmap(this, wxID_ANY, bitmap), 0, (wxRIGHT | wxALIGN_TOP | wxFIXED_MINSIZE), MARGIN);
	}
	
	message_sizer->Add(new wxStaticText(this, wxID_ANY, message), 1, wxALIGN_LEFT);
	
	button_sizer = new wxBoxSizer(wxHORIZONTAL);
	top_sizer->Add(button_sizer, 0, (wxALIGN_CENTER | wxLEFT | wxRIGHT | wxBOTTOM), MARGIN);
	
	SetSizerAndFit(top_sizer);
}

REHex::CustomMessageDialog::~CustomMessageDialog() {}

void REHex::CustomMessageDialog::AddButton(wxWindowID id, const wxString &label, const wxBitmap &bitmap)
{
	wxButton *button = new wxButton(this, id, label);
	button->SetBitmap(bitmap);
	
	int left_margin = button_sizer->GetItemCount() > 0
		? MARGIN
		: 0;
	
	button_sizer->Add(button, 0, wxLEFT, left_margin);
	
	// GetSizer()->Layout();
	// Fit();
}

void REHex::CustomMessageDialog::AddButton(wxWindowID id, const wxString &label, const wxArtID &bitmap_id)
{
	AddButton(id, label, wxArtProvider::GetBitmap(bitmap_id, wxART_BUTTON));
}

void REHex::CustomMessageDialog::SetAffirmativeId(int id)
{
	wxWindow *default_btn = wxWindow::FindWindowById(id, this);
	assert(default_btn != NULL);
	
	default_btn->SetFocus();
	
	wxDialog::SetAffirmativeId(id);
}

void REHex::CustomMessageDialog::OnButtonPress(wxCommandEvent &event)
{
	EndModal(event.GetId());
}
