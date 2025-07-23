/* Reverse Engineer's Hex Editor
 * Copyright (C) 2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <algorithm>
#include <wx/dcclient.h>

#include "ProceduralBitmap.hpp"

BEGIN_EVENT_TABLE(REHex::ProceduralBitmap, wxControl)
	EVT_PAINT(REHex::ProceduralBitmap::OnPaint)
	EVT_SIZE(REHex::ProceduralBitmap::OnSize)
	
	EVT_SCROLLWIN(REHex::ProceduralBitmap::OnScroll)
	EVT_MOUSEWHEEL(REHex::ProceduralBitmap::OnWheel)
END_EVENT_TABLE()

REHex::ProceduralBitmap::ProceduralBitmap(wxWindow *parent, wxWindowID id, const wxSize &size, const wxPoint &pos, long style):
	wxControl(parent, id, pos, size, (wxVSCROLL | wxHSCROLL | style)),
	m_bitmap_size(size),
	m_scroll_x(0),
	m_scroll_x_max(0),
	m_scroll_y(0),
	m_scroll_y_max(0),
	m_wheel_x_accum(0),
	m_wheel_y_accum(0)
{
	SetMaxClientSize(size);
	
	m_client_size = GetClientSize();
	update_scroll_ranges();
}

void REHex::ProceduralBitmap::set_bitmap_size(const wxSize &size)
{
	m_bitmap_size = size;
	SetMaxClientSize(m_bitmap_size);
	
	update_scroll_ranges();
	Refresh();
}

wxSize REHex::ProceduralBitmap::get_bitmap_size() const
{
	return m_bitmap_size;
}

void REHex::ProceduralBitmap::update_scroll_ranges()
{
	m_scroll_x_max = std::max(0, (m_bitmap_size.GetWidth() - m_client_size.GetWidth()));
	m_scroll_x = std::min(m_scroll_x, m_scroll_x_max);
	
	m_scroll_y_max = std::max(0, (m_bitmap_size.GetHeight() - m_client_size.GetHeight()));
	m_scroll_y = std::min(m_scroll_y, m_scroll_y_max);
	
	SetScrollbar(wxHORIZONTAL, m_scroll_x, m_client_size.GetWidth(), m_bitmap_size.GetWidth());
	SetScrollbar(wxVERTICAL, m_scroll_y, m_client_size.GetHeight(), m_bitmap_size.GetHeight());
}

void REHex::ProceduralBitmap::OnPaint(wxPaintEvent &event)
{
	wxPaintDC dc(this);
	
	wxRegionIterator ri(GetUpdateRegion());
	while (ri)
	{
		wxRect rect = ri.GetRect();
		
		wxRect virt_rect = rect;
		virt_rect.x += m_scroll_x;
		virt_rect.y += m_scroll_y;
		
		wxBitmap bitmap = render_rect(virt_rect);
		dc.DrawBitmap(bitmap, rect.GetPosition());
		
		++ri;
	}
}

void REHex::ProceduralBitmap::OnSize(wxSizeEvent &event)
{
	m_client_size = GetClientSize();
	update_scroll_ranges();
	
	Refresh();
}

void REHex::ProceduralBitmap::OnScroll(wxScrollWinEvent &event)
{
	wxEventType type = event.GetEventType();
	int orientation  = event.GetOrientation();
	
	auto handle_scroll_axis = [&](int *pos, int thumb, int range)
	{
		int newpos = *pos;
		
		if(type == wxEVT_SCROLLWIN_THUMBTRACK || type == wxEVT_SCROLLWIN_THUMBRELEASE)
		{
			newpos = event.GetPosition();
		}
		else if(event.GetEventType() == wxEVT_SCROLLWIN_TOP)
		{
			newpos = 0;
		}
		else if(event.GetEventType() == wxEVT_SCROLLWIN_BOTTOM)
		{
			newpos = range;
		}
		else if(event.GetEventType() == wxEVT_SCROLLWIN_LINEUP)
		{
			--newpos;
		}
		else if(event.GetEventType() == wxEVT_SCROLLWIN_LINEDOWN)
		{
			++newpos;
		}
		else if(event.GetEventType() == wxEVT_SCROLLWIN_PAGEUP)
		{
			newpos -= thumb;
		}
		else if(event.GetEventType() == wxEVT_SCROLLWIN_PAGEDOWN)
		{
			newpos += thumb;
		}
		
		newpos = std::max(0, std::min(newpos, (range - thumb)));
		
		if(newpos != *pos)
		{
			*pos = newpos;
			
			SetScrollPos(orientation, *pos);
			Refresh();
		}
	};
	
	if(orientation == wxVERTICAL)
	{
		handle_scroll_axis(&m_scroll_y, m_client_size.GetHeight(), m_bitmap_size.GetHeight());
	}
	else if(orientation == wxHORIZONTAL)
	{
		handle_scroll_axis(&m_scroll_x, m_client_size.GetWidth(), m_bitmap_size.GetWidth());
	}
}

void REHex::ProceduralBitmap::OnWheel(wxMouseEvent &event)
{
	wxMouseWheelAxis axis = event.GetWheelAxis();
	int delta             = event.GetWheelDelta();
	int ticks_per_delta   = event.GetLinesPerAction();
	
	/* Pixel step per tick on the scroll wheel. */
	constexpr int PIXELS_PER_TICK = 10;
	
	if(axis == wxMOUSE_WHEEL_VERTICAL)
	{
		m_wheel_y_accum += event.GetWheelRotation();
		
		m_scroll_y -= (m_wheel_y_accum / delta) * ticks_per_delta * PIXELS_PER_TICK;
		
		m_wheel_y_accum = (m_wheel_y_accum % delta);
		
		if(m_scroll_y < 0)
		{
			m_scroll_y = 0;
		}
		else if(m_scroll_y > m_scroll_y_max)
		{
			m_scroll_y = m_scroll_y_max;
		}
		
		SetScrollPos(wxVERTICAL, m_scroll_y);
		Refresh();
	}
	else if(axis == wxMOUSE_WHEEL_HORIZONTAL)
	{
		m_wheel_x_accum += event.GetWheelRotation();
		
		m_scroll_x -= (m_wheel_x_accum / delta) * ticks_per_delta * PIXELS_PER_TICK;
		
		m_wheel_x_accum = (m_wheel_x_accum % delta);
		
		if(m_scroll_x < 0)
		{
			m_scroll_x = 0;
		}
		else if(m_scroll_x > m_scroll_x_max)
		{
			m_scroll_x = m_scroll_x_max;
		}
		
		SetScrollPos(wxHORIZONTAL, m_scroll_x);
		Refresh();
	}
}
