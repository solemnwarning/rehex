/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <functional>
#include <wx/checkbox.h>
#include <wx/choice.h>
#include <wx/clipbrd.h>
#include <wx/dataobj.h>
#include <wx/filename.h>
#include <wx/rawbmp.h>
#include <wx/scrolwin.h>
#include <wx/sizer.h>
#include <wx/statbmp.h>
#include <wx/stattext.h>

#include "App.hpp"
#include "DataMapTool.hpp"
#include "NumericTextCtrl.hpp"
#include "profile.hpp"
#include "util.hpp"

static const int PIXELS_PER_POINT = 8;
static const int CURSOR_LINE_WIDTH = 2;
static const int MARGIN = 4;

static REHex::ToolPanel *DataMapTool_factory(wxWindow *parent, REHex::SharedDocumentPointer &document, REHex::DocumentCtrl *document_ctrl)
{
	return new REHex::DataMapTool(parent, document, document_ctrl);
}

static REHex::ToolPanelRegistration tpr("DataMapTool", "Data visualisation", REHex::ToolPanel::TPS_TALL, &DataMapTool_factory);

enum {
	ID_MODE_CHOICE = 1,
	ID_RANGE_CHOICE,
	ID_UPDATE_TIMER,
};

/* The minimum interval between updates when rendering the preview bitmap.
 * This only comes into play if the system is heavily loaded - normally we will
 * render chunks at a time in idle events and reset the timer.
*/
static const int UPDATE_TIMER_MS = 250;

BEGIN_EVENT_TABLE(REHex::DataMapTool, wxPanel)
	EVT_CHOICE(ID_MODE_CHOICE,  REHex::DataMapTool::OnModeChanged)
	EVT_COMMAND(ID_RANGE_CHOICE, EV_SELECTION_CHANGED, REHex::DataMapTool::OnRangeChanged)
	
	EVT_TIMER(ID_UPDATE_TIMER, REHex::DataMapTool::OnUpdateTimer)
	
	EVT_MOTION(REHex::DataMapTool::OnMotion)
	EVT_LEFT_UP(REHex::DataMapTool::OnLeftUp)
	EVT_MOUSE_CAPTURE_LOST(REHex::DataMapTool::OnMouseCaptureLost)
END_EVENT_TABLE()

REHex::DataMapTool::DataMapTool(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl):
	ToolPanel(parent),
	document(document),
	document_ctrl(document_ctrl),
	m_source_reset_pending(false),
	m_update_pending(false),
	update_timer(this, ID_UPDATE_TIMER),
	m_data_width(-1),
	m_data_height(-1),
	m_bytes_per_row(-1),
	m_bytes_per_point(-1),
	m_dragging(false),
	m_tip_window(NULL)
{
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);
	
	wxFlexGridSizer *grid_sizer = new wxFlexGridSizer(2);
	sizer->Add(grid_sizer);
	
	auto sizer_add_pair = [&](const char *label, wxWindow *window)
	{
		grid_sizer->Add(new wxStaticText(this, wxID_ANY, label), 0, (wxALIGN_CENTER_VERTICAL | wxLEFT | wxTOP), 8);
		grid_sizer->Add(window, 0, (wxALIGN_CENTER_VERTICAL | wxLEFT | wxTOP), 4);
	};
	
	mode_choice = new wxChoice(this, ID_MODE_CHOICE);
	mode_choice->Append("Entropy");
	mode_choice->SetSelection(0);
	
	sizer_add_pair("Mode:", mode_choice);
	
	range_choice = new RangeChoiceLinear(this, ID_RANGE_CHOICE, document, document_ctrl);
	sizer_add_pair("Range:", range_choice);
	
	m_base_bitmap = wxBitmap(16, 16, 24);
	
	s_bitmap = new wxGenericStaticBitmap(this, wxID_ANY, m_base_bitmap);
	sizer->Add(s_bitmap, 1, (wxEXPAND | wxALL), MARGIN);
	
	s_bitmap->Bind(wxEVT_SIZE, &REHex::DataMapTool::OnBitmapSize, this);
	s_bitmap->Bind(wxEVT_LEFT_DOWN, &REHex::DataMapTool::OnBitmapLeftDown, this);
	s_bitmap->Bind(wxEVT_MOTION, &REHex::DataMapTool::OnBitmapMotion, this);
	s_bitmap->Bind(wxEVT_LEAVE_WINDOW, &REHex::DataMapTool::OnBitmapLeaveWindow, this);
	
	SetSizerAndFit(sizer);
	
	m_view.reset(new FlatDocumentView(document));
	
	source.reset(new EntropyDataMapSource(m_view, 1));
	source->Bind(PROCESSING_START, &REHex::DataMapTool::OnSourceProcessing, this);
	
	update_stage = UpdateStage::GETTING_DATA;
	update_get_data_task = wxGetApp().thread_pool->queue_task([this]()
	{
		/* If the source isn't processing any data, then we will stop updating after this
		 * (until a PROCESSING_START event is raised).
		*/
		
		m_update_pending = source->processing();
		
		m_new_map = source->get_data_map();
		update_stage = UpdateStage::REDRAW;
	});
	
	update();
}

REHex::DataMapTool::~DataMapTool()
{
	update_get_data_task.join();
}

std::string REHex::DataMapTool::name() const
{
	return "DataMapTool";
}

std::string REHex::DataMapTool::label() const
{
	return "Data visualisation";
}

REHex::ToolPanel::Shape REHex::DataMapTool::shape() const
{
	return ToolPanel::TPS_TALL;
}

void REHex::DataMapTool::save_state(wxConfig *config) const
{
	// TODO
}

void REHex::DataMapTool::load_state(wxConfig *config)
{
	// TODO
}

wxSize REHex::DataMapTool::DoGetBestClientSize() const
{
	/* TODO: Calculate a reasonable initial size. */
	return wxPanel::DoGetBestClientSize();
}

void REHex::DataMapTool::reset_view()
{
	if(range_choice->is_whole_file())
	{
		/* TODO: Support virtual view. */
		m_view.reset(new FlatDocumentView(document));
	}
	else{
		BitOffset range_offset, range_length;
		std::tie(range_offset, range_length) = range_choice->get_range();
		
		m_view.reset(new FlatRangeView(document, range_offset, range_length.byte()));
	}
	
	int max_points = m_data_width * m_data_height;
	
	m_bytes_per_point = m_view->view_length() / (off_t)(max_points);
	if((m_view->view_length() % (off_t)(max_points)) != 0)
	{
		++m_bytes_per_point;
	}
	
	/* Avoid division by zero crashes when range is empty. */
	if(m_bytes_per_point == 0)
	{
		m_bytes_per_point = -1;
	}
	
	m_bytes_per_row = m_bytes_per_point * m_data_width;
	
	m_source_reset_pending = true;
	m_update_pending = true;
	
	update();
}

void REHex::DataMapTool::update()
{
	PROFILE_BLOCK("REHex::DataMapTool::update");
	
	if(is_visible)
	{
		switch(update_stage.load())
		{
			case UpdateStage::IDLE:
				if(m_source_reset_pending)
				{
					source.reset(new EntropyDataMapSource(m_view, ((size_t)(m_data_width) * (size_t)(m_data_height))));
					source->Bind(PROCESSING_START, &REHex::DataMapTool::OnSourceProcessing, this);
					
					m_source_reset_pending = false;
				}
				
				update_stage = UpdateStage::GETTING_DATA;
				
				source->reset_max_points((size_t)(m_data_width) * (size_t)(m_data_height));
				update_get_data_task.restart();
				
				/* Fall through. */
				
			case UpdateStage::GETTING_DATA:
				update_timer.Start(UPDATE_TIMER_MS, wxTIMER_ONE_SHOT);
				break;
				
			case UpdateStage::REDRAW:
			{
				m_map = std::move(m_new_map);
				m_new_map.clear();
				
				wxColour bg = wxSystemSettings::GetColour(wxSYS_COLOUR_BACKGROUND);
				
				wxNativePixelData bmp_data(m_base_bitmap);
				assert(bmp_data);
				
				wxNativePixelData::Iterator output_ptr(bmp_data);
				
				for(int output_y = 0; output_y < m_base_bitmap.GetHeight(); ++output_y)
				{
					int scaled_y = output_y / PIXELS_PER_POINT;
					
					wxNativePixelData::Iterator output_col_ptr = output_ptr;
					
					for(int output_x = 0; output_x < m_base_bitmap.GetWidth(); ++output_x, ++output_col_ptr)
					{
						int scaled_x = output_x / PIXELS_PER_POINT;
						
						BitOffset data_offset((((off_t)(scaled_y * m_data_width) + (off_t)(scaled_x)) * m_bytes_per_point), 0);
						
						auto dm_it = m_map.get_range(data_offset);
						if(dm_it != m_map.end())
						{
							output_col_ptr.Red() = dm_it->second.colour.Red();
							output_col_ptr.Green() = dm_it->second.colour.Green();
							output_col_ptr.Blue() = dm_it->second.colour.Blue();
						}
						else{
							output_col_ptr.Red() = bg.Red();
							output_col_ptr.Green() = bg.Green();
							output_col_ptr.Blue() = bg.Blue();
						}
					}
					
					output_ptr.OffsetY(bmp_data, 1);
				}
				
				update_stage = UpdateStage::IDLE;
				
				update_output_bitmap();
				
				if(m_update_pending)
				{
					update_timer.Start(UPDATE_TIMER_MS, wxTIMER_ONE_SHOT);
				}
				
				break;
			}
		}
	}
	else{
		update_timer.Stop();
		return;
	}
}

void REHex::DataMapTool::update_output_bitmap()
{
	off_t rel_cursor_position = m_view->real_offset_to_view_offset(document->get_cursor_position()).byte();
	
	int cursor_y = rel_cursor_position / m_bytes_per_row;
	int cursor_x = (rel_cursor_position % m_bytes_per_row) / m_bytes_per_point;
	
	int cursor_y_min = (cursor_y * PIXELS_PER_POINT) + ((PIXELS_PER_POINT - CURSOR_LINE_WIDTH) / 2);
	int cursor_y_max = cursor_y_min + CURSOR_LINE_WIDTH - 1;
	
	int cursor_x_min = (cursor_x * PIXELS_PER_POINT) + ((PIXELS_PER_POINT - CURSOR_LINE_WIDTH) / 2);
	int cursor_x_max = cursor_x_min + CURSOR_LINE_WIDTH - 1;
	
	wxNativePixelData base_data(m_base_bitmap);
	assert(base_data);
	
	wxBitmap output_bitmap(m_base_bitmap.GetSize(), 24);
	
	wxNativePixelData output_data(output_bitmap);
	assert(output_data);
	
	wxNativePixelData::Iterator output_ptr(output_data);
	wxNativePixelData::Iterator base_ptr(base_data);
	
	for(int y = 0; y < output_bitmap.GetHeight(); ++y)
	{
		wxNativePixelData::Iterator output_col_ptr = output_ptr;
		wxNativePixelData::Iterator base_col_ptr = base_ptr;
		
		for(int x = 0; x < output_bitmap.GetWidth(); ++x, ++output_col_ptr, ++base_col_ptr)
		{
			if(m_view->view_length() > 0 && rel_cursor_position >= 0
				&& ((x >= cursor_x_min && x <= cursor_x_max) || (y >= cursor_y_min && y <= cursor_y_max)))
			{
				output_col_ptr.Red() = 255;
				output_col_ptr.Green() = 0;
				output_col_ptr.Blue() = 0;
			}
			else{
				output_col_ptr.Red() = base_col_ptr.Red();
				output_col_ptr.Green() = base_col_ptr.Green();
				output_col_ptr.Blue() = base_col_ptr.Blue();
			}
		}
		
		output_ptr.OffsetY(output_data, 1);
		base_ptr.OffsetY(base_data, 1);
	}
	
	s_bitmap->SetBitmap(output_bitmap);
	s_bitmap->Refresh();
}

void REHex::DataMapTool::update_tip(const wxPoint &bitmap_mouse_point)
{
	int point_x = bitmap_mouse_point.x / PIXELS_PER_POINT;
	int point_y = bitmap_mouse_point.y / PIXELS_PER_POINT;
	
	off_t rel_offset_bytes = ((off_t)(point_y) * m_bytes_per_row) + ((off_t)(point_x) * m_bytes_per_point);
	
	auto dm_it = m_map.get_range(BitOffset(rel_offset_bytes, 0));
	if(dm_it != m_map.end())
	{
		BitOffset cursor_off = m_view->view_offset_to_virt_offset(BitOffset(rel_offset_bytes, 0));
		
		BitOffset elem_first_off = m_view->view_offset_to_virt_offset(dm_it->first.offset);
		BitOffset elem_last_off = m_view->view_offset_to_virt_offset(dm_it->first.offset + dm_it->first.length - BitOffset(0, 1));
		
		wxString tip_text = format_offset(cursor_off, document_ctrl->get_offset_display_base()) + "\n"
			+ format_offset(elem_first_off, document_ctrl->get_offset_display_base()) + " - "
			+ format_offset(elem_last_off, document_ctrl->get_offset_display_base())
			+ " (" + format_size(dm_it->first.length.byte()) + ")\n"
			+ dm_it->second.description;
		
		if(m_tip_window != NULL)
		{
			m_tip_window->set_text(tip_text);
			m_tip_window->move_to_cursor_window_position(s_bitmap, bitmap_mouse_point);
		}
		else{
			m_tip_window.reset(new PopupTipWindow(this, tip_text, s_bitmap, bitmap_mouse_point));
		}
	}
	else if(m_tip_window != NULL)
	{
		m_tip_window->Destroy();
		m_tip_window.reset(NULL);
	}
}

void REHex::DataMapTool::OnSize(wxSizeEvent &event)
{
	update();
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::DataMapTool::OnModeChanged(wxCommandEvent &event)
{

}

void REHex::DataMapTool::OnRangeChanged(wxCommandEvent &event)
{
	reset_view();
}

void REHex::DataMapTool::OnUpdateTimer(wxTimerEvent &event)
{
	update();
}

void REHex::DataMapTool::OnBitmapSize(wxSizeEvent &event)
{
	wxSize old_size = m_base_bitmap.GetSize();
	wxSize new_size = event.GetSize();
	
	if((old_size.GetWidth() / PIXELS_PER_POINT) != (new_size.GetWidth() / PIXELS_PER_POINT)
		|| (old_size.GetHeight() / PIXELS_PER_POINT) != (new_size.GetHeight() / PIXELS_PER_POINT))
	{
		m_data_width = std::max(1, (new_size.GetWidth() / PIXELS_PER_POINT));
		m_data_height = std::max(1, (new_size.GetHeight() / PIXELS_PER_POINT));
		
		int bitmap_width = m_data_width * PIXELS_PER_POINT;
		int bitmap_height = m_data_height * PIXELS_PER_POINT;
		
		m_base_bitmap = wxBitmap(bitmap_width, bitmap_height, 24);
		
		BitOffset range_offset, range_length;
		std::tie(range_offset, range_length) = range_choice->get_range();
		
		reset_view();
	}
	
	event.Skip(); /* Continue propogation. */
}

void REHex::DataMapTool::OnBitmapLeftDown(wxMouseEvent &event)
{
	wxPoint bitmap_mouse_point = event.GetPosition();
	
	int point_x = bitmap_mouse_point.x / PIXELS_PER_POINT;
	int point_y = bitmap_mouse_point.y / PIXELS_PER_POINT;
	
	off_t rel_offset_bytes = ((off_t)(point_y) * m_bytes_per_row) + ((off_t)(point_x) * m_bytes_per_point);
	
	document->set_cursor_position(m_view->view_offset_to_virt_offset(BitOffset(rel_offset_bytes, 0)));
	
	update_output_bitmap();
	
	m_dragging = true;
	CaptureMouse();
}

void REHex::DataMapTool::OnBitmapMotion(wxMouseEvent &event)
{
	update_tip(event.GetPosition());
}

void REHex::DataMapTool::OnBitmapLeaveWindow(wxMouseEvent &event)
{
	if(m_tip_window != NULL)
	{
		m_tip_window->Destroy();
		m_tip_window.reset(NULL);
	}
}

void REHex::DataMapTool::OnMotion(wxMouseEvent &event)
{
	wxPoint screen_mouse_point = ClientToScreen(event.GetPosition());
	wxPoint bitmap_mouse_point = s_bitmap->ScreenToClient(screen_mouse_point);
	
	if(m_dragging)
	{
		int max_w = (m_data_width * PIXELS_PER_POINT) - 1;
		int max_h = (m_data_height * PIXELS_PER_POINT) - 1;
		
		int point_x = std::max(0, std::min(bitmap_mouse_point.x, max_w)) / PIXELS_PER_POINT;
		int point_y = std::max(0, std::min(bitmap_mouse_point.y, max_h)) / PIXELS_PER_POINT;
		
		off_t rel_offset_bytes = ((off_t)(point_y) * m_bytes_per_row) + ((off_t)(point_x) * m_bytes_per_point);
		
		document->set_cursor_position(m_view->view_offset_to_virt_offset(BitOffset(rel_offset_bytes, 0)));
		
		update_output_bitmap();
	}
	
	if(s_bitmap->GetScreenRect().Contains(screen_mouse_point))
	{
		update_tip(bitmap_mouse_point);
	}
	else if(m_tip_window != NULL)
	{
		m_tip_window->Destroy();
		m_tip_window.reset(NULL);
	}
}

void REHex::DataMapTool::OnLeftUp(wxMouseEvent &event)
{
	if(m_dragging)
	{
		m_dragging = false;
		ReleaseMouse();
	}
}

void REHex::DataMapTool::OnMouseCaptureLost(wxMouseCaptureLostEvent &event)
{
	m_dragging = false;
}

void REHex::DataMapTool::OnSourceProcessing(wxCommandEvent &event)
{
	m_update_pending = true;
	
	/* We can't call update() within this handler as it may destroy the DataMapSource while it
	 * is still dispatching this event, causing a crash.
	*/
	CallAfter([this]()
	{
		update();
	});
	
	event.Skip(); /* Continue propogation */
}
