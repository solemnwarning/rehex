/* Reverse Engineer's Hex Editor
 * Copyright (C) 2024-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <wx/dcclient.h>
#include <wx/settings.h>

#include "App.hpp"
#include "PopupTipWindow.hpp"

static const wxCoord TEXT_MARGIN_X = 3;
static const wxCoord TEXT_MARGIN_Y = 3;

wxBEGIN_EVENT_TABLE(REHex::PopupTipWindow, wxPopupWindow)
    EVT_PAINT(REHex::PopupTipWindow::OnPaint)
wxEND_EVENT_TABLE()

REHex::PopupTipWindow::PopupTipWindow(wxWindow *parent, const wxString &text, const wxPoint &cursor_screen_pos):
	wxPopupWindow(parent)
{
	SetFont(wxSystemSettings::GetFont(wxSYS_DEFAULT_GUI_FONT));
	
	SetForegroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_INFOTEXT));
	SetBackgroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_INFOBK));
	
	set_text(text);
	move_to_cursor_screen_position(cursor_screen_pos);
	
	Show();
}

REHex::PopupTipWindow::PopupTipWindow(wxWindow *parent, const wxString &text, wxWindow *cursor_window, const wxPoint &cursor_window_pos):
	wxPopupWindow(parent)
{
	SetFont(wxSystemSettings::GetFont(wxSYS_DEFAULT_GUI_FONT));
	
	SetForegroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_INFOTEXT));
	SetBackgroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_INFOBK));
	
	set_text(text);
	move_to_cursor_window_position(cursor_window, cursor_window_pos);
	
	Show();
}

void REHex::PopupTipWindow::set_text(const wxString &text)
{
	wxClientDC dc(this);
	dc.SetFont(GetFont());
	
	int text_width = 0;
	int text_height = 0;
	
	for(size_t i = 0; i < text.length();)
	{
		size_t next_newline = text.find_first_of('\n', i);
		if(next_newline == wxString::npos)
		{
			next_newline = text.length();
		}
		
		wxString line = text.substr(i, (next_newline - i));
		wxSize line_size = dc.GetTextExtent(line);
		
		text_width = std::max(text_width, line_size.GetWidth());
		text_height += line_size.GetHeight();
		
		i = next_newline + 1;
	}
	
	this->text = text;
	
	SetSize(wxSize((text_width + (2 * TEXT_MARGIN_X)), (text_height + (2 * TEXT_MARGIN_Y))));
	
	Refresh();
}

void REHex::PopupTipWindow::move_to_cursor_screen_position(const wxPoint &cursor_screen_pos)
{
	wxPoint pos = cursor_screen_pos;
	
	int cursor_height = wxSystemSettings::GetMetric(wxSYS_CURSOR_Y);
	
	#if wxCHECK_VERSION(3, 1, 0)
	wxPoint cursor_hotspot = wxSTANDARD_CURSOR->GetHotSpot();
	wxPoint tip_pos = wxPoint(pos.x, (pos.y + (cursor_height - cursor_hotspot.y)));
	#else
	wxPoint tip_pos = wxPoint(pos.x, (pos.y + cursor_height));
	#endif
	
	SetPosition(tip_pos);
	
	/* Wayland doesn't allow setting the position of a window, however if we hide the window and
	 * then re-show it, it gets re-created with a hint on where it should be placed within the
	 * co-ordinate space of its parent top-level window.
	*/
	
	#ifdef REHEX_ENABLE_WAYLAND_HACKS
	if(IsShown() && REHex::App::is_wayland_session())
	{
		Hide();
		Show();
	}
	#endif
}

void REHex::PopupTipWindow::move_to_cursor_window_position(wxWindow *cursor_window, const wxPoint &cursor_window_pos)
{
	wxPoint pos = cursor_window->ClientToScreen(cursor_window_pos);
	
	int cursor_height = wxSystemSettings::GetMetric(wxSYS_CURSOR_Y, cursor_window);
	
	#if wxCHECK_VERSION(3, 1, 0)
	wxPoint cursor_hotspot = cursor_window->GetCursor().GetHotSpot();
	wxPoint tip_pos = wxPoint(pos.x, (pos.y + (cursor_height - cursor_hotspot.y)));
	#else
	wxPoint tip_pos = wxPoint(pos.x, (pos.y + cursor_height));
	#endif
	
	SetPosition(tip_pos);
	
	/* Wayland doesn't allow setting the position of a window, however if we hide the window and
	 * then re-show it, it gets re-created with a hint on where it should be placed within the
	 * co-ordinate space of its parent top-level window.
	*/
	
	#ifdef REHEX_ENABLE_WAYLAND_HACKS
	if(IsShown() && REHex::App::is_wayland_session())
	{
		Hide();
		Show();
	}
	#endif
}

void REHex::PopupTipWindow::OnPaint(wxPaintEvent &event)
{
	wxPaintDC dc(this);
	
	wxRect rect;
	wxSize size = GetClientSize();
	rect.width = size.x;
	rect.height = size.y;
	
	// first filll the background
	dc.SetBrush(wxBrush(GetBackgroundColour(), wxBRUSHSTYLE_SOLID));
	dc.SetPen(wxPen(GetForegroundColour(), 1, wxPENSTYLE_SOLID));
	dc.DrawRectangle(rect);
	
	// and then draw the text line by line
	dc.SetTextBackground(GetBackgroundColour());
	dc.SetTextForeground(GetForegroundColour());
	dc.SetFont(GetFont());
	
	dc.DrawText(text, TEXT_MARGIN_X, TEXT_MARGIN_Y);
}
