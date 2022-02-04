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
#include <wx/settings.h>

#include "ClickText.hpp"

REHex::ClickText::ClickText(wxWindow *parent, wxWindowID id, const wxString &label, const wxPoint &pos, const wxSize &size, long style):
	wxPanel(parent, id, pos, size)
{
	text = new wxStaticText(this, id, label, wxPoint(0,0), size, style);
	
	wxFont font = text->GetFont();
	font.SetUnderlined(true);
	text->SetFont(font);
	
	text->SetForegroundColour(*wxBLUE);
	
	text->SetCursor(wxCursor(wxCURSOR_HAND));
	
	text->Bind(wxEVT_LEFT_DOWN, [this](wxMouseEvent &event)
	{
		wxCommandEvent button_event(wxEVT_BUTTON, this->GetId());
		button_event.SetEventObject(this);
		wxPostEvent(this, button_event);
	});
}
