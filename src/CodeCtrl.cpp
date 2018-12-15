/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <wx/dcbuffer.h>

#include "CodeCtrl.hpp"

BEGIN_EVENT_TABLE(REHex::CodeCtrl, wxControl)
	EVT_PAINT(REHex::CodeCtrl::OnPaint)
	EVT_SCROLLWIN(REHex::CodeCtrl::OnScroll)
	EVT_MOUSEWHEEL(REHex::CodeCtrl::OnWheel)
END_EVENT_TABLE()

REHex::CodeCtrl::CodeCtrl(wxWindow *parent, wxWindowID id):
	wxControl(parent, id, wxDefaultPosition, wxDefaultSize, (wxVSCROLL | wxHSCROLL)),
	scroll_xoff(0), scroll_xoff_max(0),
	scroll_yoff(0), scroll_yoff_max(0)
{
	wxFontInfo finfo;
	finfo.Family(wxFONTFAMILY_MODERN);
	
	font = new wxFont(finfo);
	assert(font->IsFixedWidth());
	
	wxClientDC dc(this);
	dc.SetFont(*font);
	
	wxSize char_extent = dc.GetTextExtent("X");
	font_width  = char_extent.GetWidth();
	font_height = char_extent.GetHeight();
}

void REHex::CodeCtrl::append_line(off_t offset, const std::string &text, bool active)
{
	wxClientDC dc(this);
	dc.SetFont(*font);
	
	wxSize extent = dc.GetTextExtent(std::string("00000000  ") + text);
	if(max_line_width < extent.GetWidth())
	{
		max_line_width = extent.GetWidth();
	}
	
	lines.emplace_back(offset, text, active);
	
	update_scrollbars();
	Refresh();
}

void REHex::CodeCtrl::clear()
{
	max_line_width = 0;
	lines.clear();
	
	update_scrollbars();
	Refresh();
}

void REHex::CodeCtrl::center_line(int line)
{
	wxSize client_size = GetClientSize();
	
	scroll_yoff = (line * font_height) - (client_size.GetHeight() / 2);
	
	if(scroll_yoff < 0)
	{
		scroll_yoff = 0;
	}
	else if(scroll_yoff > scroll_yoff_max)
	{
		scroll_yoff = scroll_yoff_max;
	}
	
	scroll_xoff = 0;
	
	update_scrollbars();
	Refresh();
}

void REHex::CodeCtrl::update_scrollbars()
{
	SetScrollbar(wxVERTICAL, 0, 0, 0);
	SetScrollbar(wxHORIZONTAL, 0, 0, 0);
	
	auto update_vert = [this]()
	{
		wxSize client_size = GetClientSize();
		int virt_height = lines.size() * font_height;
		
		if(virt_height > client_size.GetHeight())
		{
			scroll_yoff_max = virt_height - client_size.GetHeight();
			if(scroll_yoff > scroll_yoff_max)
			{
				scroll_yoff = scroll_xoff_max;
			}
			
			SetScrollbar(wxVERTICAL, scroll_yoff, client_size.GetHeight(), virt_height);
		}
		else{
			scroll_yoff_max = 0;
			scroll_yoff     = 0;
			
			SetScrollbar(wxVERTICAL, 0, 0, 0);
		}
	};
	
	auto update_horiz = [this]()
	{
		wxSize client_size = GetClientSize();
		
		if(max_line_width > client_size.GetWidth())
		{
			scroll_xoff_max = max_line_width - client_size.GetWidth();
			if(scroll_xoff > scroll_xoff_max)
			{
				scroll_xoff = scroll_xoff_max;
			}
			
			SetScrollbar(wxHORIZONTAL, scroll_xoff, client_size.GetWidth(), max_line_width);
		}
		else{
			scroll_xoff_max = 0;
			scroll_xoff     = 0;
			
			SetScrollbar(wxHORIZONTAL, 0, 0, 0);
		}
	};
	
	update_vert();
	update_horiz();
	update_vert();
}

void REHex::CodeCtrl::OnPaint(wxPaintEvent &event)
{
	wxSize client_size = GetClientSize();
	
	wxBufferedPaintDC dc(this);
	
	dc.SetFont(*font);
	dc.SetBackground(*wxWHITE_BRUSH);
	dc.SetBackgroundMode(wxTRANSPARENT);
	
	dc.Clear();
	
	wxSize off_extent = dc.GetTextExtent("00000000  ");
	
	int x = -scroll_xoff;
	int y = -scroll_yoff;
	
	for(auto line = lines.begin(); line != lines.end(); ++line, y += font_height)
	{
		if((y + font_height) <= 0 || y >= client_size.GetHeight())
		{
			/* Line not visible, no point rendering it. */
			continue;
		}
		
		dc.SetTextForeground(line->active ? *wxRED : *wxBLACK);
		
		char offset_str[16];
		snprintf(offset_str, sizeof(offset_str), "%08X", (unsigned)(line->offset & 0xFFFFFFFF));
		dc.DrawText(offset_str, x, y);
		
		dc.DrawText(line->text, x + off_extent.GetWidth(), y);
	}
}

void REHex::CodeCtrl::OnScroll(wxScrollWinEvent &event)
{
	wxEventType type = event.GetEventType();
	int orientation  = event.GetOrientation();
	
	wxSize client_size = GetClientSize();
	
	if(orientation == wxVERTICAL)
	{
		if(type == wxEVT_SCROLLWIN_THUMBTRACK || type == wxEVT_SCROLLWIN_THUMBRELEASE)
		{
			scroll_yoff = event.GetPosition();
		}
		else if(event.GetEventType() == wxEVT_SCROLLWIN_TOP)
		{
			scroll_yoff = 0;
		}
		else if(event.GetEventType() == wxEVT_SCROLLWIN_BOTTOM)
		{
			scroll_yoff = scroll_yoff_max;
		}
		else if(event.GetEventType() == wxEVT_SCROLLWIN_LINEUP)
		{
			--scroll_yoff;
		}
		else if(event.GetEventType() == wxEVT_SCROLLWIN_LINEDOWN)
		{
			++scroll_yoff;
		}
		else if(event.GetEventType() == wxEVT_SCROLLWIN_PAGEUP)
		{
			scroll_yoff -= client_size.GetHeight();
		}
		else if(event.GetEventType() == wxEVT_SCROLLWIN_PAGEDOWN)
		{
			scroll_yoff += client_size.GetHeight();
		}
		
		if(scroll_yoff < 0)
		{
			scroll_yoff = 0;
		}
		else if(scroll_yoff > scroll_yoff_max)
		{
			scroll_yoff = scroll_yoff_max;
		}
		
		SetScrollPos(wxVERTICAL, scroll_yoff);
		Refresh();
	}
	else if(orientation == wxHORIZONTAL)
	{
		if(type == wxEVT_SCROLLWIN_THUMBTRACK || type == wxEVT_SCROLLWIN_THUMBRELEASE)
		{
			scroll_xoff = event.GetPosition();
		}
		else if(event.GetEventType() == wxEVT_SCROLLWIN_TOP)
		{
			scroll_xoff = 0;
		}
		else if(event.GetEventType() == wxEVT_SCROLLWIN_BOTTOM)
		{
			scroll_xoff = scroll_xoff_max;
		}
		else if(event.GetEventType() == wxEVT_SCROLLWIN_LINEUP)
		{
			scroll_xoff -= font_width;
		}
		else if(event.GetEventType() == wxEVT_SCROLLWIN_LINEDOWN)
		{
			scroll_xoff += font_width;
		}
		else if(event.GetEventType() == wxEVT_SCROLLWIN_PAGEUP)
		{
			scroll_xoff -= client_size.GetWidth();
		}
		else if(event.GetEventType() == wxEVT_SCROLLWIN_PAGEDOWN)
		{
			scroll_xoff += client_size.GetWidth();
		}
		
		if(scroll_xoff < 0)
		{
			scroll_xoff = 0;
		}
		else if(scroll_xoff > scroll_xoff_max)
		{
			scroll_xoff = scroll_xoff_max;
		}
		
		SetScrollPos(wxHORIZONTAL, scroll_xoff);
		Refresh();
	}
}

void REHex::CodeCtrl::OnWheel(wxMouseEvent &event)
{
	wxMouseWheelAxis axis = event.GetWheelAxis();
	int delta             = event.GetWheelDelta();
	int ticks_per_delta   = event.GetLinesPerAction();
	
	if(axis == wxMOUSE_WHEEL_VERTICAL)
	{
		ticks_per_delta *= font_height;
		
		wheel_vert_accum += event.GetWheelRotation();
		
		scroll_yoff -= (wheel_vert_accum / delta) * ticks_per_delta;
		
		wheel_vert_accum = (wheel_vert_accum % delta);
		
		if(scroll_yoff < 0)
		{
			scroll_yoff = 0;
		}
		else if(scroll_yoff > scroll_yoff_max)
		{
			scroll_yoff = scroll_yoff_max;
		}
		
		SetScrollPos(wxVERTICAL, scroll_yoff);
		Refresh();
	}
	else if(axis == wxMOUSE_WHEEL_HORIZONTAL)
	{
		ticks_per_delta *= font_width;
		
		wheel_horiz_accum += event.GetWheelRotation();
		
		scroll_xoff += (wheel_horiz_accum / delta) * ticks_per_delta;
		
		wheel_horiz_accum = (wheel_horiz_accum % delta);
		
		if(scroll_xoff < 0)
		{
			scroll_xoff = 0;
		}
		else if(scroll_xoff > scroll_xoff_max)
		{
			scroll_xoff = scroll_xoff_max;
		}
		
		SetScrollPos(wxHORIZONTAL, scroll_xoff);
		Refresh();
	}
}
