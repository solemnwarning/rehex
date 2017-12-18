/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "document.hpp"

BEGIN_EVENT_TABLE(REHex::Document, wxControl)
	EVT_PAINT(REHex::Document::OnPaint)
	EVT_SIZE(REHex::Document::OnSize)
	EVT_SCROLLWIN(REHex::Document::OnScroll)
END_EVENT_TABLE()

REHex::Document::Document(wxWindow *parent, wxWindowID id, const wxPoint &pos, const wxSize &size):
	wxControl(parent, id, pos, size, wxVSCROLL | wxHSCROLL)
{
	wxFontInfo finfo;
	finfo.Family(wxFONTFAMILY_MODERN);
	
	hex_font = new wxFont(finfo);
}

void REHex::Document::OnPaint(wxPaintEvent &event)
{
	wxPaintDC dc(this);
	
	wxSize client_size = dc.GetSize();
	
	dc.SetFont(*hex_font);
	
	wxSize char_size        = dc.GetTextExtent("X");
	unsigned int char_width = char_size.GetWidth();
	
	unsigned int draw_rows = (client_size.GetHeight() / char_size.GetHeight()) + 1;
	
	for(unsigned int r = 0, y = 0; r < draw_rows; ++r)
	{
		int x = (0 - this->scroll_xoff);
		
		for(unsigned int c = 0; c < this->line_bytes_calc; ++c)
		{
			if(c > 0 && (c % this->group_bytes) == 0)
			{
				x += char_width;
			}
			
			dc.DrawText(wxT("AA"), x, y);
			x += (2 * char_width);
		}
		
		y += char_size.GetHeight();
	}
}

void REHex::Document::OnSize(wxSizeEvent &event)
{
	wxClientDC dc(this);
	
	/* Force a vertical scrollbar so the bytes per line doesn't jump around and screw us over.
	 * TODO: Do this less hackily (is this possible on non-win32 wxWidgets?)
	 * TODO: Compute real vertical scrollbar size after deciding if we need a horizontal one.
	*/
	this->SetScrollbar(wxVERTICAL, 0, 1, 2);
	
	/* Get the size of the area we can draw into */
	
	wxSize client_size        = this->GetClientSize();
	unsigned int client_width = client_size.GetWidth();
	
	/* Get the size of a character in the (fixed-width) font we use for the hex bytes. */
	
	dc.SetFont(*hex_font);
	wxSize char_size        = dc.GetTextExtent("X");
	unsigned int char_width = char_size.GetWidth();
	unsigned int byte_width = 2 * char_width;
	
	auto calc_row_width = [this, char_width, byte_width](unsigned int line_bytes)
	{
		unsigned int px = (line_bytes * byte_width);
		if(line_bytes > this->group_bytes)
		{
			px += (((line_bytes - this->group_bytes) / this->group_bytes) * char_width);
		}
		
		return px;
	};
	
	/* Decide how many bytes to display per line */
	
	if(this->line_bytes_cfg == 0) /* 0 is "as many as will fit in the window" */
	{
		/* TODO: Can I do this algorithmically? */
		
		this->line_bytes_calc = 1;
		
		while(calc_row_width(this->line_bytes_calc + 1) <= client_width)
		{
			++(this->line_bytes_calc);
		}
	}
	else{
		this->line_bytes_calc = this->line_bytes_cfg;
	}
	
	/* Calculate the number of pixels necessary to render a full line and decide if we need a
	 * horizontal scroll bar.
	*/
	
	unsigned int row_width_px = calc_row_width(this->line_bytes_calc);
	
	if(row_width_px > client_width)
	{
		this->SetScrollbar(wxHORIZONTAL, 0, client_width, row_width_px);
	}
	else{
		this->SetScrollbar(wxHORIZONTAL, 0, 0, 0);
	}
}

void REHex::Document::OnScroll(wxScrollWinEvent &event)
{
	if(event.GetOrientation() == wxHORIZONTAL)
	{
		this->scroll_xoff = event.GetPosition();
		this->Refresh();
	}
}
