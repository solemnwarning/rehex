/* Reverse Engineer's Hex Editor
 * Copyright (C) 2023 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <wx/graphics.h>
#include <wx/settings.h>
#include <wx/time.h>

#include "LoadingSpinner.hpp"

BEGIN_EVENT_TABLE(REHex::LoadingSpinner, wxControl)
	EVT_PAINT(REHex::LoadingSpinner::OnPaint)
	EVT_TIMER(wxID_ANY, REHex::LoadingSpinner::OnRepaintTimer)
END_EVENT_TABLE()

REHex::LoadingSpinner::LoadingSpinner(wxWindow *parent, wxWindowID id, const wxPoint &pos, const wxSize &size, long style):
	wxControl(parent, id, pos, size, style),
	repaint_timer(this, wxID_ANY)
{
	SetBackgroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_LISTBOX));
	SetForegroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_WINDOWTEXT));
}

void REHex::LoadingSpinner::OnPaint(wxPaintEvent &event)
{
	/* Select how many dots to display based on the client area size.
	 *
	 * total_dots  - Total number of spots to divide circumference into.
	 * solid_dots  - Number of solid (100% opacity) spots spinning around.
	 * fade_dots   - Number of fading spots trailing after the solid spots.
	*/
	
	wxSize client_size = GetClientSize();
	int client_min = std::min(client_size.GetWidth(), client_size.GetHeight());
	
	int total_dots, solid_dots, fade_dots, ms_per_tick;
	if(client_min >= 72)
	{
		total_dots  = 16;
		solid_dots  = 4;
		fade_dots   = 8;
		
		ms_per_tick = 80;
	}
	else if(client_min >= 48)
	{
		total_dots  = 12;
		solid_dots  = 3;
		fade_dots   = 6;
		
		ms_per_tick = 120;
	}
	else{
		total_dots  = 8;
		solid_dots  = 2;
		fade_dots   = 4;
		
		ms_per_tick = 160;
	}
	
	unsigned long now = wxGetUTCTimeMillis().GetLo();
	
	int current_dot = (now / ms_per_tick) % total_dots;
	
	int next_step_in = ms_per_tick - (now % ms_per_tick);
	repaint_timer.Start(next_step_in, wxTIMER_ONE_SHOT);
	
	wxPoint origin((client_size.GetWidth() / 2), (client_size.GetHeight() / 2));
	
	int circle_diameter = 0.9f * std::min(client_size.GetWidth(), client_size.GetHeight());
	
	int dot_diameter = 0.15f * circle_diameter;
	int dot_radius = dot_diameter / 2;
	
	int dot_origin_radius = (circle_diameter / 2) - dot_radius;
	
	wxPaintDC dc(this);
	wxGraphicsContext *gc = wxGraphicsContext::Create(dc);
	
	if(gc)
	{
		gc->SetBrush(wxBrush(GetForegroundColour()));
		
		for(int i = current_dot; i < (current_dot + solid_dots + fade_dots); ++i)
		{
			double angle_deg = (360.0f / total_dots) * i;
			double angle_rad = 0.0174533f * angle_deg;
			
			/* https://stackoverflow.com/a/22491252 */
			
			double cos_ang = cos(angle_rad);
			double sin_ang = sin(angle_rad);
			
			wxPoint dot_origin = origin;
			dot_origin.y -= dot_origin_radius;
			
			double x1 = dot_origin.x - origin.x;
			double y1 = dot_origin.y - origin.y;
			
			double x2 = x1 * cos_ang - y1 * sin_ang;
			double y2 = x1 * sin_ang + y1 * cos_ang;
			
			dot_origin.x = x2 + origin.x;
			dot_origin.y = y2 + origin.y;
			
			/* Progressively fade in over the first fade_dots dots. */
			
			if(i < (current_dot + fade_dots))
			{
				gc->BeginLayer(1.0f - ((1.0 / fade_dots) * ((current_dot + fade_dots) - i)));
			}
			
			/* Adjust dot_origin from the center of the dot to the top-left of the
			 * dot's bounding box for wxGraphicsContext::DrawEllipse().
			*/
			gc->DrawEllipse((dot_origin.x - dot_radius), (dot_origin.y - dot_radius), dot_diameter, dot_diameter);
			
			if(i < (current_dot + fade_dots))
			{
				gc->EndLayer();
			}
		}
		
		delete gc;
	}
}

void REHex::LoadingSpinner::OnRepaintTimer(wxTimerEvent &event)
{
	Refresh();
}
