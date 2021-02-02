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

#include "platform.hpp"
#include <assert.h>
#include <wx/clipbrd.h>
#include <wx/dcbuffer.h>

#include "App.hpp"
#include "CodeCtrl.hpp"

enum {
	ID_SELECT_TIMER = 1,
};

BEGIN_EVENT_TABLE(REHex::CodeCtrl, wxControl)
	EVT_PAINT(REHex::CodeCtrl::OnPaint)
	EVT_ERASE_BACKGROUND(REHex::CodeCtrl::OnErase)
	EVT_SIZE(REHex::CodeCtrl::OnSize)
	EVT_SCROLLWIN(REHex::CodeCtrl::OnScroll)
	EVT_MOUSEWHEEL(REHex::CodeCtrl::OnWheel)
	EVT_CHAR(REHex::CodeCtrl::OnChar)
	EVT_LEFT_DOWN(REHex::CodeCtrl::OnLeftDown)
	EVT_LEFT_UP(REHex::CodeCtrl::OnLeftUp)
	EVT_RIGHT_DOWN(REHex::CodeCtrl::OnRightDown)
	EVT_MENU(wxID_COPY, REHex::CodeCtrl::OnCopy)
	EVT_MENU(wxID_SELECTALL, REHex::CodeCtrl::OnSelectAll)
	EVT_MOTION(REHex::CodeCtrl::OnMotion)
	EVT_TIMER(ID_SELECT_TIMER, REHex::CodeCtrl::OnSelectTick)
END_EVENT_TABLE()

REHex::CodeCtrl::CodeCtrl(wxWindow *parent, wxWindowID id):
	wxControl(parent, id, wxDefaultPosition, wxDefaultSize, (wxVSCROLL | wxHSCROLL | wxWANTS_CHARS)),
	font(wxFontInfo().Family(wxFONTFAMILY_MODERN)),
	max_line_width(0),
	offset_display_base(OFFSET_BASE_HEX),
	offset_display_upper_bound(0xFFFFFFFF),
	scroll_xoff(0), scroll_xoff_max(0),
	scroll_yoff(0), scroll_yoff_max(0),
	wheel_vert_accum(0),
	wheel_horiz_accum(0),
	mouse_selecting(false),
	mouse_selecting_timer(this, ID_SELECT_TIMER),
	selection_begin(-1, -1),
	selection_end(-1, -1)
{
	App &app = wxGetApp();
	
	app.Bind(FONT_SIZE_ADJUSTMENT_CHANGED, &REHex::CodeCtrl::OnFontSizeAdjustmentChanged, this);
	
	int font_size_adjustment = app.get_font_size_adjustment();
	
	while(font_size_adjustment > 0) { font.MakeLarger(); --font_size_adjustment; }
	while(font_size_adjustment < 0) { font.MakeSmaller(); ++font_size_adjustment; }
	
	assert(font.IsFixedWidth());
	
	wxClientDC dc(this);
	dc.SetFont(font);
	
	wxSize char_extent = dc.GetTextExtent("X");
	font_width  = char_extent.GetWidth();
	font_height = char_extent.GetHeight();
	
	std::string offset_str = format_offset(0, offset_display_base, offset_display_upper_bound);
	code_xoff = dc.GetTextExtent(offset_str + "  ").GetWidth();
}

REHex::CodeCtrl::~CodeCtrl()
{
	wxGetApp().Unbind(FONT_SIZE_ADJUSTMENT_CHANGED, &REHex::CodeCtrl::OnFontSizeAdjustmentChanged, this);
}

void REHex::CodeCtrl::append_line(off_t offset, const std::string &text, bool active)
{
	wxClientDC dc(this);
	dc.SetFont(font);
	
	/* GetTextExtent() doesn't seem to handle tabs correctly, so we expand
	 * them into spaces.
	*/
	
	std::string text_no_tabs = text;
	static const int TAB_WIDTH = 8;
	
	for(size_t p = 0; (p = text_no_tabs.find('\t', p)) != std::string::npos;)
	{
		size_t n_spaces = TAB_WIDTH - (p % TAB_WIDTH);
		text_no_tabs.replace(p, 1, n_spaces, ' ');
	}
	
	int line_width = code_xoff + dc.GetTextExtent(text_no_tabs).GetWidth();
	if(max_line_width < line_width)
	{
		max_line_width = line_width;
	}
	
	lines.emplace_back(offset, text_no_tabs, active);
	
	update_scrollbars();
	Refresh();
}

void REHex::CodeCtrl::clear()
{
	selection_begin = CodeCharRef(-1, -1);
	selection_end   = CodeCharRef(-1, -1);
	
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
	wxSize client_size = GetClientSize();
	
	int virt_height = lines.size() * font_height;
	if(virt_height > client_size.GetHeight())
	{
		scroll_yoff_max = virt_height - client_size.GetHeight();
		if(scroll_yoff > scroll_yoff_max)
		{
			scroll_yoff = scroll_yoff_max;
		}
		
		SetScrollbar(wxVERTICAL, scroll_yoff, client_size.GetHeight(), virt_height);
	}
	else{
		scroll_yoff_max = 0;
		scroll_yoff     = 0;
		
		SetScrollbar(wxVERTICAL, 0, 0, 0);
	}
	
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
}

void REHex::CodeCtrl::update_widths()
{
	wxClientDC dc(this);
	dc.SetFont(font);
	
	std::string offset_str = format_offset(0, offset_display_base, offset_display_upper_bound);
	code_xoff = dc.GetTextExtent(offset_str + "  ").GetWidth();
	
	max_line_width = 0;
	
	for(auto l = lines.begin(); l != lines.end(); ++l)
	{
		int line_width = code_xoff + dc.GetTextExtent(l->text).GetWidth();
		if(max_line_width < line_width)
		{
			max_line_width = line_width;
		}
	}
}

REHex::CodeCtrl::CodeCharRef REHex::CodeCtrl::char_near_abs_xy(int abs_x, int abs_y)
{
	if(lines.empty())
	{
		return CodeCharRef(-1, -1);
	}
	
	int line_idx = std::min((abs_y / font_height), (int)(lines.size() - 1));
	const Line &line = *(std::next(lines.begin(), line_idx));
	
	int col = 0;
	
	wxClientDC dc(this);
	dc.SetFont(font);
	
	while((code_xoff + dc.GetTextExtent(std::string((col + 1), 'X')).GetWidth()) < abs_x && col < (int)(line.text.length()))
	{
		++col;
	}
	
	return CodeCharRef(line_idx, col);
}

REHex::CodeCtrl::CodeCharRef REHex::CodeCtrl::char_near_rel_xy(int rel_x, int rel_y)
{
	return char_near_abs_xy((rel_x + scroll_xoff), (rel_y + scroll_yoff));
}

void REHex::CodeCtrl::copy_selection()
{
	if(selection_end > selection_begin && wxTheClipboard->Open())
	{
		std::string copy_text;
		
		for(int i = selection_begin.first; i <= selection_end.first; ++i)
		{
			assert(i >= 0);
			assert((unsigned)(i) < lines.size());
			
			const std::string &line_text = lines[i].text;
			
			if(i > selection_begin.first)
			{
				copy_text += '\n';
			}
			
			int substr_off = (i == selection_begin.first ? selection_begin.second : 0);
			assert(substr_off >= 0);
			assert((unsigned)(substr_off) <= line_text.length());
			
			int substr_len = (i == selection_end.first ? selection_end.second : line_text.length()) - substr_off;
			assert(substr_len >= 0);
			assert((unsigned)(substr_off + substr_len) <= line_text.length());
			
			copy_text += line_text.substr(substr_off, substr_len);
		}
		
		wxTheClipboard->SetData(new wxTextDataObject(copy_text));
		wxTheClipboard->Close();
	}
}

void REHex::CodeCtrl::select_all()
{
	if(!lines.empty())
	{
		selection_begin = CodeCharRef(0, 0);
		selection_end = CodeCharRef((lines.size() - 1), lines.back().text.length());
		
		Refresh();
	}
}

void REHex::CodeCtrl::set_offset_display(REHex::OffsetBase offset_display_base, off_t offset_display_upper_bound)
{
	this->offset_display_base        = offset_display_base;
	this->offset_display_upper_bound = offset_display_upper_bound;
	
	update_widths();
	update_scrollbars();
	Refresh();
}

void REHex::CodeCtrl::OnPaint(wxPaintEvent &event)
{
	wxSize client_size = GetClientSize();
	
	wxBufferedPaintDC dc(this);
	
	dc.SetFont(font);
	dc.SetBackground(*wxWHITE_BRUSH);
	dc.SetBackgroundMode(wxTRANSPARENT);
	
	dc.Clear();
	
	int x = -scroll_xoff;
	int y = -scroll_yoff;
	
	int line_idx = 0;
	for(auto line = lines.begin(); line != lines.end(); ++line, y += font_height, ++line_idx)
	{
		if((y + font_height) <= 0 || y >= client_size.GetHeight())
		{
			/* Line not visible, no point rendering it. */
			continue;
		}
		
		wxColour fg_colour;
		wxColour bg_colour;
		
		int line_x = x + code_xoff;
		std::string pending;
		
		auto flush = [&dc, &line_x, &pending, &y]()
		{
			if(!pending.empty())
			{
				dc.DrawText(pending, line_x, y);
				line_x += dc.GetTextExtent(pending).GetWidth();
				
				pending.clear();
			}
		};
		
		auto set = [&dc, &fg_colour, &bg_colour, &flush](const wxColour &fg, const wxColour &bg, bool force = false)
		{
			if(fg != fg_colour || bg != bg_colour || force)
			{
				flush();
				
				dc.SetTextForeground(fg_colour = fg);
				dc.SetTextBackground(bg_colour = bg);
				dc.SetBackgroundMode(bg_colour == *wxWHITE ? wxTRANSPARENT : wxSOLID);
			}
		};
		
		if(line->active)
		{
			set(*wxRED, *wxWHITE, true);
		}
		else{
			set(*wxBLACK, *wxWHITE, true);
		}
		
		std::string offset_str = format_offset(line->offset, offset_display_base, offset_display_upper_bound);
		dc.DrawText(offset_str.c_str(), x, y);
		
		for(size_t c = 0; c < line->text.length(); ++c)
		{
			if(selection_begin <= CodeCharRef(line_idx, c) && selection_end > CodeCharRef(line_idx, c))
			{
				set(*wxWHITE, *wxBLUE);
			}
			else if(line->active)
			{
				set(*wxRED, *wxWHITE);
			}
			else{
				set(*wxBLACK, *wxWHITE);
			}
			
			pending.push_back(line->text[c]);
		}
		
		flush();
	}
}

void REHex::CodeCtrl::OnErase(wxEraseEvent& event)
{
	// Left blank to disable erase
}

void REHex::CodeCtrl::OnSize(wxSizeEvent &event)
{
	update_scrollbars();
}

void REHex::CodeCtrl::OnFontSizeAdjustmentChanged(FontSizeAdjustmentEvent &event)
{
	font = wxFont(wxFontInfo().Family(wxFONTFAMILY_MODERN));
	
	for(int i = 0; i < event.font_size_adjustment; ++i) { font.MakeLarger(); }
	for(int i = 0; i > event.font_size_adjustment; --i) { font.MakeSmaller(); }
	
	assert(font.IsFixedWidth());
	
	wxClientDC dc(this);
	dc.SetFont(font);
	
	wxSize char_extent = dc.GetTextExtent("X");
	font_width  = char_extent.GetWidth();
	font_height = char_extent.GetHeight();
	
	update_widths();
	update_scrollbars();
	Refresh();
	
	event.Skip();
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

void REHex::CodeCtrl::OnChar(wxKeyEvent &event)
{
	int key       = event.GetKeyCode();
	int modifiers = event.GetModifiers();
	
	if((modifiers & wxMOD_CONTROL) && key == WXK_CONTROL_A)
	{
		select_all();
	}
	else if((modifiers & wxMOD_CONTROL) && key == WXK_CONTROL_C)
	{
		copy_selection();
	}
	else{
		/* Not for us. Continue propagation. */
		event.Skip();
	}
}

void REHex::CodeCtrl::OnLeftDown(wxMouseEvent &event)
{
	int mouse_x = event.GetX();
	int mouse_y = event.GetY();
	
	mouse_selecting_from = char_near_rel_xy(mouse_x, mouse_y);
	if(mouse_selecting_from.first >= 0)
	{
		mouse_selecting = true;
		
		CaptureMouse();
		mouse_selecting_timer.Start(MOUSE_SELECT_INTERVAL, wxTIMER_CONTINUOUS);
		
		OnMotionTick(mouse_x, mouse_y);
	}
	
	Refresh();
	
	/* We take focus when clicked. */
	SetFocus();
}

void REHex::CodeCtrl::OnLeftUp(wxMouseEvent &event)
{
	if(mouse_selecting)
	{
		mouse_selecting_timer.Stop();
		ReleaseMouse();
		
		mouse_selecting = false;
	}
}

void REHex::CodeCtrl::OnRightDown(wxMouseEvent &event)
{
	/* If the user right clicks while selecting, and then releases the left button over the
	 * menu, we never receive the EVT_LEFT_UP event. Release the mouse and cancel the selection
	 * now, else we wind up keeping the mouse grabbed and stop it interacting with any other
	 * windows...
	*/
	
	if(mouse_selecting)
	{
		mouse_selecting_timer.Stop();
		ReleaseMouse();
		
		mouse_selecting = false;
	}
	
	wxMenu menu;
	
	menu.Append(wxID_COPY,  "&Copy");
	menu.Enable(wxID_COPY, (selection_begin < selection_end));
	
	menu.AppendSeparator();
	
	menu.Append(wxID_SELECTALL, "Select &All");
	
	PopupMenu(&menu);
	
	/* We take focus when clicked. */
	SetFocus();
}

void REHex::CodeCtrl::OnCopy(wxCommandEvent &event)
{
	copy_selection();
}

void REHex::CodeCtrl::OnSelectAll(wxCommandEvent &event)
{
	select_all();
}

void REHex::CodeCtrl::OnMotion(wxMouseEvent &event)
{
	OnMotionTick(event.GetX(), event.GetY());
}

void REHex::CodeCtrl::OnSelectTick(wxTimerEvent &event)
{
	wxPoint window_pos = GetScreenPosition();
	wxPoint mouse_pos  = wxGetMousePosition();
	
	OnMotionTick((mouse_pos.x - window_pos.x), (mouse_pos.y - window_pos.y));
}

void REHex::CodeCtrl::OnMotionTick(int mouse_x, int mouse_y)
{
	if(mouse_selecting)
	{
		mouse_selecting_to = char_near_rel_xy(mouse_x, mouse_y);
		
		if(mouse_selecting_to > mouse_selecting_from)
		{
			selection_begin = mouse_selecting_from;
			selection_end   = mouse_selecting_to;
		}
		else if(mouse_selecting_to < mouse_selecting_from)
		{
			selection_begin = mouse_selecting_to;
			selection_end   = mouse_selecting_from;
		}
		else{
			selection_begin = CodeCharRef(-1, -1);
			selection_end   = CodeCharRef(-1, -1);
		}
		
		Refresh();
	}
}
