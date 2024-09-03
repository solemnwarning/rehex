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
#include <wx/dcbuffer.h>

#include "DataMapScrollbar.hpp"
#include "profile.hpp"

BEGIN_EVENT_TABLE(REHex::DataMapScrollbar, wxControl)
	EVT_PAINT(REHex::DataMapScrollbar::OnPaint)
	EVT_ERASE_BACKGROUND(REHex::DataMapScrollbar::OnErase)
	EVT_SIZE(REHex::DataMapScrollbar::OnSize)
END_EVENT_TABLE()

REHex::DataMapScrollbar::DataMapScrollbar(wxWindow *parent, wxWindowID id, const SharedDocumentPointer &document):
	wxControl(parent, id),
	document(document)
{
	wxSize client_size = GetClientSize();
	client_height = std::max(client_size.GetHeight(), 1);
	
	source.reset(new EntropyDataMapSource(document, BitOffset(0, 0), document->buffer_length(), client_height));
	
	redraw_timer.Bind(wxEVT_TIMER, [this](wxTimerEvent &event)
	{
		Refresh();
	});
	
	redraw_timer.Start(1000, wxTIMER_CONTINUOUS);
	
	SetMinSize(wxSize(40, 100));
}

REHex::DataMapScrollbar::~DataMapScrollbar()
{
	
}

void REHex::DataMapScrollbar::OnPaint(wxPaintEvent &event)
{
	wxSize client_size = GetClientSize();
	
	wxBufferedPaintDC dc(this);
	
	BitRangeMap<wxColour> data_map = source->get_data_map();
	
	dc.SetBackground(*wxWHITE_BRUSH);
	dc.SetBackgroundMode(wxTRANSPARENT);
	
	dc.Clear();
	
	off_t bytes_per_y = document->buffer_length() / client_size.GetHeight();
	off_t next_off = 0;
	
	for(int y = 0; y < client_size.GetHeight(); ++y)
	{
		auto dm_it = data_map.get_range(BitOffset(next_off, 0));
		if(dm_it != data_map.end())
		{
			dc.SetPen(wxPen(dm_it->second, 1));
			dc.DrawLine(0, y, client_size.GetWidth(), y);
		}
		
		next_off += bytes_per_y;
	}
}

void REHex::DataMapScrollbar::OnErase(wxEraseEvent& event)
{
	// Left blank to disable erase
}

void REHex::DataMapScrollbar::OnSize(wxSizeEvent &event)
{
	PROFILE_BLOCK("REHex::DataMapScrollbar::OnSize");
	
	wxSize client_size = GetClientSize();
	int new_height = std::max(client_size.GetHeight(), 1);
	
	if(client_height != new_height)
	{
		client_height = new_height;
		source.reset(new EntropyDataMapSource(document, BitOffset(0, 0), document->buffer_length(), client_height));
	}
	
	Refresh();
}
