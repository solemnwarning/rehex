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

#include <assert.h>
#include <wx/dcbuffer.h>

#include "App.hpp"
#include "DataMapScrollbar.hpp"
#include "Palette.hpp"
#include "profile.hpp"

/* Interval between screen updates while data is processing. */
static constexpr int REDRAW_INTERVAL = 250;

BEGIN_EVENT_TABLE(REHex::DataMapScrollbar, wxControl)
	EVT_PAINT(REHex::DataMapScrollbar::OnPaint)
	EVT_ERASE_BACKGROUND(REHex::DataMapScrollbar::OnErase)
	EVT_SIZE(REHex::DataMapScrollbar::OnSize)
	EVT_MOTION(REHex::DataMapScrollbar::OnMotion)
	EVT_ENTER_WINDOW(REHex::DataMapScrollbar::OnMouseEnter)
	EVT_LEAVE_WINDOW(REHex::DataMapScrollbar::OnMouseLeave)
	EVT_LEFT_DOWN(REHex::DataMapScrollbar::OnLeftDown)
	EVT_LEFT_UP(REHex::DataMapScrollbar::OnLeftUp)
	EVT_MOUSE_CAPTURE_LOST(REHex::DataMapScrollbar::OnMouseCaptureLost)
END_EVENT_TABLE()

REHex::DataMapScrollbar::DataMapScrollbar(wxWindow *parent, wxWindowID id, const SharedEvtHandler<DataView> &view, std::unique_ptr<EntropyDataMapSource> &&source, DocumentCtrl *document_ctrl):
	wxControl(parent, id),
	view(view),
	document_ctrl(document_ctrl),
	m_source(std::move(source)),
	mouse_dragging(false),
	mouse_in_window(false),
	tip_window(NULL)
{
	wxSize client_size = GetClientSize();
	client_height = std::max(client_size.GetHeight(), 1);
	
	m_source->reset_max_points(client_height);
	m_source->Bind(PROCESSING_START, &REHex::DataMapScrollbar::OnSourceProcessing, this);
	
	m_data_update_timer.Bind(wxEVT_TIMER, [this](wxTimerEvent &event)
	{
		if(!(m_source->processing()))
		{
			m_data_update_timer.Stop();
		}
		
		m_data = m_source->get_data_map();
		Refresh();
	});
	
	m_data_update_timer.Start(REDRAW_INTERVAL, wxTIMER_CONTINUOUS);
	
	this->document_ctrl.auto_cleanup_bind(SCROLL_UPDATE, &REHex::DataMapScrollbar::OnDocumentCtrlScroll, this);
	
	SetMinSize(wxSize(40, 100));
}

REHex::DataMapScrollbar::~DataMapScrollbar()
{
	
}

void REHex::DataMapScrollbar::OnPaint(wxPaintEvent &event)
{
	PROFILE_BLOCK("REHex::DataMapScrollbar::OnPaint");
	
	wxSize client_size = GetClientSize();
	
	wxBufferedPaintDC dc(this);
	
	dc.SetBackground(wxBrush((*active_palette)[Palette::PAL_NORMAL_TEXT_BG]));
	dc.SetBackgroundMode(wxTRANSPARENT);
	
	dc.Clear();
	
	off_t bytes_per_y = view->view_length() / client_size.GetHeight();
	off_t next_off = 0;
	
	uint64_t num_visible_lines = document_ctrl->get_visible_lines();
	
	int64_t first_visible_line = document_ctrl->get_scroll_yoff();
	int64_t last_visible_line  = std::min<int64_t>((first_visible_line + num_visible_lines), document_ctrl->get_total_lines()) - 1;
	
	BitOffset first_visible_offset, last_visible_offset;
	
	std::tie(first_visible_offset, std::ignore) = document_ctrl->get_indent_offset_at_line(first_visible_line);
	std::tie(std::ignore, last_visible_offset) = document_ctrl->get_indent_offset_at_line(last_visible_line);
	
	int box_top_y = -1;
	int box_bottom_y = -1;
	
	for(int y = 0; y < client_size.GetHeight(); ++y)
	{
		auto dm_it = m_data.get_range(BitOffset(next_off, 0));
		if(dm_it != m_data.end())
		{
			dc.SetPen(wxPen(dm_it->second.colour, 1));
			dc.DrawLine(4, y, (client_size.GetWidth() - 4), y);
			
			BitOffset dm_virt_offset = view->view_offset_to_virt_offset(next_off);
			assert(dm_virt_offset >= BitOffset::ZERO);
			
			if(dm_virt_offset >= first_visible_offset)
			{
				if(box_top_y < 0)
				{
					box_top_y = y;
					box_bottom_y = y;
				}
				else if(dm_virt_offset <= last_visible_offset)
				{
					box_bottom_y = y;
				}
			}
		}
		
		next_off += bytes_per_y;
	}
	
	dc.SetBrush(*wxTRANSPARENT_BRUSH);
	dc.SetPen(wxPen(*wxBLUE, 1));
	
	dc.DrawRectangle(0, box_top_y, client_size.GetWidth(), ((box_bottom_y - box_top_y) + 1));
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
		m_source->reset_max_points(client_height);
		
		if(!(m_data_update_timer.IsRunning()))
		{
			m_data_update_timer.Start(REDRAW_INTERVAL, wxTIMER_CONTINUOUS);
		}
	}
	
	Refresh();
}

void REHex::DataMapScrollbar::OnMotion(wxMouseEvent &event)
{
	if(!mouse_in_window && !mouse_dragging)
	{
		if(tip_window != NULL)
		{
			tip_window->Destroy();
		}
		
		return;
	}
	
	if(document_ctrl)
	{
		off_t bytes_per_y = std::max<off_t>((view->view_length() / client_height), 1);
		BitOffset y_offset = BitOffset((bytes_per_y * (off_t)(event.GetY())), 0);
		
		if(mouse_dragging && y_offset >= BitOffset::ZERO && y_offset < BitOffset(view->view_length(), 0))
		{
			BitOffset y_offset_real = view->view_offset_to_real_offset(y_offset);
			
			DocumentCtrl::GenericDataRegion *region = document_ctrl->data_region_by_offset(y_offset_real);
			assert(region != NULL);
			
			DocumentCtrl::Rect offset_rect = region->calc_offset_bounds(y_offset_real, document_ctrl);
			
			document_ctrl->set_scroll_yoff(offset_rect.y - (document_ctrl->get_visible_lines() / 2));
			
			Refresh();
		}
		
		auto dm_it = m_data.get_range(y_offset);
		if(dm_it != m_data.end())
		{
			off_t y_offset_view_last = std::min((y_offset.byte() + bytes_per_y), view->view_length()) - 1;
			
			off_t y_offset_virt_first = view->view_offset_to_virt_offset(y_offset).byte();
			off_t y_offset_virt_last  = view->view_offset_to_virt_offset(y_offset_view_last).byte();
			
			wxString tip_text = format_offset(y_offset_virt_first, document_ctrl->get_offset_display_base()) + " - "
				+ format_offset(y_offset_virt_last, document_ctrl->get_offset_display_base()) + "\n"
				+ dm_it->second.description;
			
			if(tip_window != NULL)
			{
				tip_window->set_text(tip_text);
				tip_window->move_to_cursor_window_position(this, event.GetPosition());
			}
			else{
				tip_window.reset(new PopupTipWindow(this, tip_text, this, event.GetPosition()));
			}
		}
		else if(tip_window != NULL)
		{
			tip_window->move_to_cursor_window_position(this, event.GetPosition());
		}
	}
}

void REHex::DataMapScrollbar::OnMouseEnter(wxMouseEvent &event)
{
	mouse_in_window = true;
	OnMotion(event);
}

void REHex::DataMapScrollbar::OnMouseLeave(wxMouseEvent &event)
{
	mouse_in_window = false;
	
	if(tip_window != NULL)
	{
		tip_window->Destroy();
	}
}

void REHex::DataMapScrollbar::OnLeftDown(wxMouseEvent &event)
{
	if(!mouse_dragging)
	{
		mouse_dragging = true;
		CaptureMouse();
	}
	
	if(document_ctrl)
	{
		off_t bytes_per_y = view->view_length() / client_height;
		BitOffset y_offset = BitOffset((bytes_per_y * (off_t)(event.GetY())), 0);
		
		BitOffset y_offset_real = view->view_offset_to_real_offset(y_offset);
		
		DocumentCtrl::GenericDataRegion *region = document_ctrl->data_region_by_offset(y_offset_real);
		assert(region != NULL);
		
		DocumentCtrl::Rect offset_rect = region->calc_offset_bounds(y_offset_real, document_ctrl);
		
		document_ctrl->set_scroll_yoff(offset_rect.y - (document_ctrl->get_visible_lines() / 2));
		
		Refresh();
	}
}

void REHex::DataMapScrollbar::OnLeftUp(wxMouseEvent &event)
{
	if(mouse_dragging)
	{
		ReleaseMouse();
		mouse_dragging = false;
	}
	
	if(!mouse_in_window && tip_window != NULL)
	{
		tip_window->Destroy();
	}
}

void REHex::DataMapScrollbar::OnMouseCaptureLost(wxMouseCaptureLostEvent &event)
{
	mouse_dragging = false;
}

void REHex::DataMapScrollbar::OnDocumentCtrlScroll(ScrollUpdateEvent &event)
{
	Refresh();
	event.Skip(); /* Continue propagation. */
}

void REHex::DataMapScrollbar::OnSourceProcessing(wxCommandEvent &event)
{
	if(!(m_data_update_timer.IsRunning()))
	{
		m_data_update_timer.Start(REDRAW_INTERVAL, wxTIMER_CONTINUOUS);
	}
	
	event.Skip(); /* Continue propagation. */
}
