/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2018 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <iterator>
#include <jansson.h>
#include <limits>
#include <map>
#include <string>
#include <wx/dcbuffer.h>

#include "app.hpp"
#include "document.hpp"
#include "Palette.hpp"
#include "textentrydialog.hpp"
#include "util.hpp"

static_assert(std::numeric_limits<json_int_t>::max() >= std::numeric_limits<off_t>::max(),
	"json_int_t must be large enough to store any offset in an off_t");

/* Is the given byte a printable 7-bit ASCII character? */
static bool isasciiprint(int c)
{
	return (c >= ' ' && c <= '~');
}

/* Is the given value a 7-bit ASCII character representing a hex digit? */
static bool isasciihex(int c)
{
	return (c >= '0' && c <= '9')
		|| (c >= 'A' && c <= 'F')
		|| (c >= 'a' && c <= 'f');
}

enum {
	ID_REDRAW_CURSOR = 1,
	ID_SET_COMMENT,
	ID_SELECT_TIMER,
	ID_CLEAR_HIGHLIGHT,
};

BEGIN_EVENT_TABLE(REHex::Document, wxControl)
	EVT_PAINT(REHex::Document::OnPaint)
	EVT_SIZE(REHex::Document::OnSize)
	EVT_SCROLLWIN(REHex::Document::OnScroll)
	EVT_MOUSEWHEEL(REHex::Document::OnWheel)
	EVT_CHAR(REHex::Document::OnChar)
	EVT_LEFT_DOWN(REHex::Document::OnLeftDown)
	EVT_LEFT_UP(REHex::Document::OnLeftUp)
	EVT_RIGHT_DOWN(REHex::Document::OnRightDown)
	EVT_MOTION(REHex::Document::OnMotion)
	EVT_TIMER(ID_SELECT_TIMER, REHex::Document::OnSelectTick)
	EVT_TIMER(ID_REDRAW_CURSOR, REHex::Document::OnRedrawCursor)
	EVT_MENU(ID_SET_COMMENT, REHex::Document::OnSetComment)
	EVT_MENU(ID_CLEAR_HIGHLIGHT, REHex::Document::OnClearHighlight)
END_EVENT_TABLE()

wxDEFINE_EVENT(REHex::EV_CURSOR_MOVED,      wxCommandEvent);
wxDEFINE_EVENT(REHex::EV_INSERT_TOGGLED,    wxCommandEvent);
wxDEFINE_EVENT(REHex::EV_SELECTION_CHANGED, wxCommandEvent);

REHex::Document::Document(wxWindow *parent):
	wxControl(),
	redraw_cursor_timer(this, ID_REDRAW_CURSOR),
	mouse_select_timer(this, ID_SELECT_TIMER)
{
	_ctor_pre(parent);
	
	buffer = new REHex::Buffer();
	title  = "Untitled";
	
	_init_regions(NULL);
	
	_ctor_post();
}

REHex::Document::Document(wxWindow *parent, const std::string &filename):
	wxControl(),
	filename(filename),
	redraw_cursor_timer(this, ID_REDRAW_CURSOR),
	mouse_select_timer(this, ID_SELECT_TIMER)
{
	_ctor_pre(parent);
	
	buffer = new REHex::Buffer(filename);
	
	size_t last_slash = filename.find_last_of("/\\");
	title = (last_slash != std::string::npos ? filename.substr(last_slash + 1) : filename);
	
	/* TODO: Report errors (except ENOENT) */
	
	json_error_t json_err;
	json_t *meta = json_load_file((filename + ".rehex-meta").c_str(), 0, &json_err);
	
	_init_regions(meta);
	
	json_decref(meta);
	
	_ctor_post();
}

REHex::Document::~Document()
{
	for(auto region = regions.begin(); region != regions.end(); ++region)
	{
		delete *region;
	}
	
	delete buffer;
}

void REHex::Document::save()
{
	buffer->write_inplace();
	_save_metadata(filename + ".rehex-meta");
	
	dirty = false;
}

void REHex::Document::save(const std::string &filename)
{
	buffer->write_inplace(filename);
	this->filename = filename;
	
	size_t last_slash = filename.find_last_of("/\\");
	title = (last_slash != std::string::npos ? filename.substr(last_slash + 1) : filename);
	
	_save_metadata(filename + ".rehex-meta");
	
	dirty = false;
}

std::string REHex::Document::get_title()
{
	return title;
}

std::string REHex::Document::get_filename()
{
	return filename;
}

bool REHex::Document::is_dirty()
{
	return dirty;
}

unsigned int REHex::Document::get_bytes_per_line()
{
	return bytes_per_line;
}

void REHex::Document::set_bytes_per_line(unsigned int bytes_per_line)
{
	this->bytes_per_line = bytes_per_line;
	_handle_width_change();
}

unsigned int REHex::Document::get_bytes_per_group()
{
	return bytes_per_group;
}

void REHex::Document::set_bytes_per_group(unsigned int bytes_per_group)
{
	this->bytes_per_group = bytes_per_group;
	_handle_width_change();
}

bool REHex::Document::get_show_offsets()
{
	return offset_column;
}

void REHex::Document::set_show_offsets(bool show_offsets)
{
	offset_column = show_offsets;
	_handle_width_change();
}

bool REHex::Document::get_show_ascii()
{
	return show_ascii;
}

void REHex::Document::set_show_ascii(bool show_ascii)
{
	this->show_ascii = show_ascii;
	_handle_width_change();
}

off_t REHex::Document::get_cursor_position() const
{
	return this->cpos_off;
}

void REHex::Document::set_cursor_position(off_t off)
{
	_set_cursor_position(off, CSTATE_GOTO);
}

void REHex::Document::_set_cursor_position(off_t position, enum CursorState cursor_state)
{
	assert(position >= 0 && position <= buffer->length());
	
	if(!insert_mode && position > 0 && position == buffer->length())
	{
		--position;
	}
	
	if(cursor_state == CSTATE_GOTO)
	{
		if(this->cursor_state == CSTATE_HEX_MID)
		{
			cursor_state = CSTATE_HEX;
		}
		else{
			cursor_state = this->cursor_state;
		}
	}
	
	/* Blink cursor to visibility and reset timer */
	cursor_visible = true;
	redraw_cursor_timer.Start();
	
	bool cursor_moved = (cpos_off != position);
	
	cpos_off = position;
	this->cursor_state = cursor_state;
	
	_make_byte_visible(cpos_off);
	
	if(cursor_moved)
	{
		_raise_moved();
	}
}

bool REHex::Document::get_insert_mode()
{
	return this->insert_mode;
}

void REHex::Document::set_insert_mode(bool enabled)
{
	if(insert_mode == enabled)
	{
		return;
	}
	
	insert_mode = enabled;
	
	off_t cursor_pos = get_cursor_position();
	if(!insert_mode && cursor_pos > 0 && cursor_pos == buffer_length())
	{
		/* Move cursor back if going from insert to overwrite mode and it
		 * was at the end of the file.
		*/
		set_cursor_position(cursor_pos - 1);
	}
	
	wxCommandEvent event(REHex::EV_INSERT_TOGGLED);
	event.SetEventObject(this);
	wxPostEvent(this, event);
	
	/* TODO: Limit paint to affected area */
	this->Refresh();
}

void REHex::Document::set_selection(off_t off, off_t length)
{
	selection_off    = off;
	selection_length = length;
	
	{
		wxCommandEvent event(REHex::EV_SELECTION_CHANGED);
		event.SetEventObject(this);
		
		wxPostEvent(this, event);
	}
	
	/* TODO: Limit paint to affected area */
	Refresh();
}

void REHex::Document::clear_selection()
{
	set_selection(0, 0);
}

std::pair<off_t, off_t> REHex::Document::get_selection()
{
	return std::make_pair(selection_off, selection_length);
}

std::vector<unsigned char> REHex::Document::read_data(off_t offset, off_t max_length) const
{
	return buffer->read_data(offset, max_length);
}

void REHex::Document::overwrite_data(off_t offset, const unsigned char *data, off_t length)
{
	_tracked_overwrite_data("change data", offset, data, length, get_cursor_position(), cursor_state);
}

void REHex::Document::insert_data(off_t offset, const unsigned char *data, off_t length)
{
	_tracked_insert_data("change data", offset, data, length, get_cursor_position(), cursor_state);
}

void REHex::Document::erase_data(off_t offset, off_t length)
{
	_tracked_erase_data("change data", offset, length);
}

off_t REHex::Document::buffer_length()
{
	return buffer->length();
}

void REHex::Document::handle_paste(const std::string &clipboard_text)
{
	auto paste_data = [this](const unsigned char* data, size_t size)
	{
		off_t cursor_pos = get_cursor_position();
		
		if(selection_length > 0)
		{
			/* Some data is selected, replace it. */
			
			_tracked_replace_data("paste", selection_off, selection_length, data, size, selection_off + size, CSTATE_GOTO);
			clear_selection();
		}
		else if(insert_mode)
		{
			/* We are in insert mode, insert at the cursor. */
			_tracked_insert_data("paste", cursor_pos, data, size, cursor_pos + size, CSTATE_GOTO);
		}
		else{
			/* We are in overwrite mode, overwrite up to the end of the file. */
			
			off_t to_end = buffer->length() - cursor_pos;
			off_t to_write = std::min(to_end, (off_t)(size));
			
			_tracked_overwrite_data("paste", cursor_pos, data, to_write, cursor_pos + to_write, CSTATE_GOTO);
		}
		
		Refresh();
	};
	
	if(cursor_state == CSTATE_ASCII)
	{
		/* Paste into ASCII view, handle as string of characters. */
		
		paste_data((const unsigned char*)(clipboard_text.data()), clipboard_text.size());
	}
	else{
		/* Paste into hex view, handle as hex string of bytes. */
		
		try {
			std::vector<unsigned char> clipboard_data = REHex::parse_hex_string(clipboard_text);
			paste_data(clipboard_data.data(), clipboard_data.size());
		}
		catch(const REHex::ParseError &e)
		{
			/* Ignore paste if clipboard didn't contain a valid hex string. */
		}
	}
}

std::string REHex::Document::handle_copy(bool cut)
{
	if(selection_length > 0)
	{
		std::vector<unsigned char> selection_data = read_data(selection_off, selection_length);
		assert((off_t)(selection_data.size()) == selection_length);
		
		if(cut)
		{
			_tracked_erase_data("cut selection", selection_off, selection_data.size());
		}
		
		if(cursor_state == CSTATE_ASCII)
		{
			std::string ascii_string;
			ascii_string.reserve(selection_data.size());
			
			for(auto c = selection_data.begin(); c != selection_data.end(); ++c)
			{
				if((*c >= ' ' && *c <= '~') || *c == '\t' || *c == '\n' || *c == '\r')
				{
					ascii_string.push_back(*c);
				}
			}
			
			return ascii_string;
		}
		else{
			std::string hex_string;
			hex_string.reserve(selection_data.size() * 2);
			
			for(auto c = selection_data.begin(); c != selection_data.end(); ++c)
			{
				const char *nibble_to_hex = "0123456789ABCDEF";
				
				unsigned char high_nibble = (*c & 0xF0) >> 4;
				unsigned char low_nibble  = (*c & 0x0F);
				
				hex_string.push_back(nibble_to_hex[high_nibble]);
				hex_string.push_back(nibble_to_hex[low_nibble]);
			}
			
			return hex_string;
		}
	}
	else{
		/* Nothing selected */
		return "";
	}
}

void REHex::Document::undo()
{
	if(!undo_stack.empty())
	{
		auto &act = undo_stack.back();
		act.undo();
		
		cpos_off     = act.old_cpos_off;
		cursor_state = act.old_cursor_state;
		highlights   = act.old_highlights;
		
		redo_stack.push_back(act);
		undo_stack.pop_back();
		
		Refresh();
	}
}

void REHex::Document::redo()
{
	if(!redo_stack.empty())
	{
		auto &act = redo_stack.back();
		act.redo();
		
		undo_stack.push_back(act);
		redo_stack.pop_back();
		
		Refresh();
	}
}

void REHex::Document::OnPaint(wxPaintEvent &event)
{
	wxBufferedPaintDC dc(this);
	
	dc.SetFont(*hex_font);
	
	dc.SetBackground(*wxWHITE_BRUSH);
	dc.Clear();
	
	if(offset_column)
	{
		int offset_vl_x = (offset_column_width - scroll_xoff) - (hf_char_width() / 2);
		
		dc.DrawLine(offset_vl_x, 0, offset_vl_x, client_height);
	}
	
	if(show_ascii)
	{
		int ascii_vl_x = ((int)(ascii_text_x) - (hf_char_width() / 2)) - scroll_xoff;
		dc.DrawLine(ascii_vl_x, 0, ascii_vl_x, client_height);
	}
	
	/* Iterate over the regions to find the last one which does NOT start beyond the current
	 * scroll_y.
	*/
	
	auto region = regions.begin();
	for(auto next = std::next(region); next != regions.end() && (*next)->y_offset <= scroll_yoff; ++next)
	{
		region = next;
	}
	
	int64_t yo_end = scroll_yoff + visible_lines + 1;
	for(; region != regions.end() && (*region)->y_offset < yo_end; ++region)
	{
		int x_px = 0 - scroll_xoff;
		
		int64_t y_px = (*region)->y_offset;
		assert(y_px >= 0);
		
		y_px -= scroll_yoff;
		y_px *= hf_height;
		
		(*region)->draw(*this, dc, x_px, y_px);
	}
}

void REHex::Document::OnSize(wxSizeEvent &event)
{
	if(regions.empty())
	{
		/* Great big dirty hack: If regions is empty, we're being invoked within the
		 * Create() method call and we aren't set up properly yet, do nothing.
		*/
		return;
	}
	
	/* Get the size of the area we can draw into */
	
	wxSize client_size    = GetClientSize();
	int new_client_width  = client_size.GetWidth();
	int new_client_height = client_size.GetHeight();
	
	bool width_changed  = (new_client_width  != client_width);
	bool height_changed = (new_client_height != client_height);
	
	client_width  = new_client_width;
	client_height = new_client_height;
	visible_lines = client_height / hf_height;
	
	if(width_changed)
	{
		_handle_width_change();
	}
	else if(height_changed)
	{
		/* _handle_height_change() is a subset of _handle_width_change() */
		_handle_height_change();
	}
}

void REHex::Document::_handle_width_change()
{
	/* Calculate how much space (if any) to reserve for the offsets to the left. */
	
	if(offset_column)
	{
		offset_column_width = hf_string_width(18);
	}
	else{
		offset_column_width = 0;
	}
	
	auto calc_row_width = [this](unsigned int line_bytes)
	{
		return offset_column_width
			/* hex data */
			+ hf_string_width(line_bytes * 2)
			+ hf_string_width((line_bytes - 1) / bytes_per_group)
			
			/* ASCII data */
			+ (show_ascii * hf_char_width())
			+ (show_ascii * hf_string_width(line_bytes));
	};
	
	/* Decide how many bytes to display per line */
	
	if(bytes_per_line == 0) /* 0 is "as many as will fit in the window" */
	{
		/* TODO: Can I do this algorithmically? */
		
		bytes_per_line_calc = 1;
		
		while(calc_row_width(bytes_per_line_calc + 1) <= client_width)
		{
			++bytes_per_line_calc;
		}
	}
	else{
		bytes_per_line_calc = bytes_per_line;
	}
	
	/* Calculate the number of pixels necessary to render a full line and decide if we need a
	 * horizontal scroll bar.
	*/
	virtual_width = calc_row_width(bytes_per_line_calc);
	if(virtual_width < client_width)
	{
		/* Raise virtual_width to client_width, so that things drawn relative to the right
		 * edge of the virtual client area don't end up in the middle.
		*/
		virtual_width = client_width;
	}
	
	/* TODO: Preserve/scale the position as the window size changes. */
	SetScrollbar(wxHORIZONTAL, 0, client_width, virtual_width);
	
	if(show_ascii)
	{
		ascii_text_x = virtual_width - hf_string_width(bytes_per_line_calc);
	}
	
	/* Recalculate the height and y offset of each region. */
	
	{
		wxClientDC dc(this);
		_recalc_regions(dc);
	}
	
	/* Update vertical scrollbar, since we just recalculated the height of the document. */
	_update_vscroll();
	
	/* Force a redraw of the whole control since resizing can change pretty much the entire
	 * thing depending on rendering settings.
	*/
	Refresh();
}

void REHex::Document::_handle_height_change()
{
	/* Update vertical scrollbar, since the client area height has changed. */
	_update_vscroll();
	
	/* Force a redraw of the whole control since resizing can change pretty much the entire
	 * thing depending on rendering settings.
	*/
	Refresh();
}

void REHex::Document::_update_vscroll()
{
	static const int MAX_STEPS = 10000;
	
	uint64_t total_lines = regions.back()->y_offset + regions.back()->y_lines;
	
	if(total_lines > visible_lines)
	{
		int64_t new_scroll_yoff_max = total_lines - visible_lines;
		
		/* Try to keep the vertical scroll position at roughly the same point in the file. */
		scroll_yoff = (scroll_yoff > 0)
			? ((double)(scroll_yoff) * ((double)(new_scroll_yoff_max) / (double)(scroll_yoff_max)))
			: 0;
		
		/* In case of rounding errors. */
		if(scroll_yoff > scroll_yoff_max)
		{
			scroll_yoff = scroll_yoff_max;
		}
		else if(scroll_yoff < 0)
		{
			scroll_yoff = 0;
		}
		
		int range, thumb, position;
		
		if(total_lines <= (uint64_t)(MAX_STEPS))
		{
			scroll_ydiv = 1;
			
			range    = total_lines;
			thumb    = visible_lines;
			position = scroll_yoff;
		}
		else{
			scroll_ydiv = total_lines / MAX_STEPS;
			
			range    = MAX_STEPS;
			thumb    = 1;
			position = std::min((int)(scroll_yoff / scroll_ydiv), (range - thumb));
			
			if(position == 0 && scroll_yoff > 0)
			{
				/* Past the first line, but not the first scrollbar division.
				 * Skip to the next so the scrollbar doesn't appear fully scrolled
				 * up when there's a bit to go.
				*/
				position = 1;
			}
			else if(position == (range - thumb) && scroll_yoff < scroll_yoff_max)
			{
				/* Ditto, but for the bottom of the document. */
				--position;
			}
		}
		
		assert(range > 0);
		assert(range <= MAX_STEPS);
		assert(thumb > 0);
		assert(thumb <= range);
		assert(position >= 0);
		assert(position <= (range - thumb));
		
		SetScrollbar(wxVERTICAL, position, thumb, range);
		scroll_yoff_max = new_scroll_yoff_max;
	}
	else{
		/* We don't need a vertical scroll bar, but force one to appear anyway so
		 * the bytes per line can't change within OnSize and get us stuck in a loop.
		*/
		#ifdef _WIN32
		SetScrollbar(wxVERTICAL, 0, 0, -1);
		#else
		/* TODO: Do this in a non-crappy way on non-win32 */
		SetScrollbar(wxVERTICAL, 0, 1, 2);
		#endif
		
		scroll_yoff_max = 0;
	}
}

void REHex::Document::_update_vscroll_pos()
{
	int range = GetScrollRange(wxVERTICAL);
	int thumb = GetScrollThumb(wxVERTICAL);
	
	if(scroll_yoff == scroll_yoff_max)
	{
		/* Last line, overcome any rounding and set scroll bar to max. */
		SetScrollPos(wxVERTICAL, (range - thumb));
	}
	else{
		int position = std::min((int)(scroll_yoff / scroll_ydiv), (range - thumb));
		if(position == 0 && scroll_yoff > 0)
		{
			/* Past the first line, but not the first scrollbar division.
			 * Skip to the next so the scrollbar doesn't appear fully scrolled
			 * up when there's a bit to go.
			*/
			position = 1;
		}
		else if(position == (range - thumb) && scroll_yoff < scroll_yoff_max)
		{
			/* Ditto, but for the bottom of the document. */
			--position;
		}
		
		assert(position >= 0);
		assert(position <= (range - thumb));
		
		SetScrollPos(wxVERTICAL, position);
	}
}

void REHex::Document::OnScroll(wxScrollWinEvent &event)
{
	wxEventType type = event.GetEventType();
	int orientation  = event.GetOrientation();
	
	if(orientation == wxVERTICAL)
	{
		if(type == wxEVT_SCROLLWIN_THUMBTRACK || type == wxEVT_SCROLLWIN_THUMBRELEASE)
		{
			int position = event.GetPosition();
			int range = GetScrollRange(wxVERTICAL);
			int thumb = GetScrollThumb(wxVERTICAL);
			
			if(position == (range - thumb))
			{
				/* Dragged to the end of the scroll bar, jump to last line. */
				scroll_yoff = scroll_yoff_max;
			}
			else{
				scroll_yoff = position * scroll_ydiv;
			}
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
			scroll_yoff -= visible_lines;
		}
		else if(event.GetEventType() == wxEVT_SCROLLWIN_PAGEDOWN)
		{
			scroll_yoff += visible_lines;
		}
		
		if(scroll_yoff < 0)
		{
			scroll_yoff = 0;
		}
		else if(scroll_yoff > scroll_yoff_max)
		{
			scroll_yoff = scroll_yoff_max;
		}
		
		_update_vscroll_pos();
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
			scroll_xoff = virtual_width - client_width;
		}
		else if(event.GetEventType() == wxEVT_SCROLLWIN_LINEUP)
		{
			scroll_xoff -= hf_char_width();
		}
		else if(event.GetEventType() == wxEVT_SCROLLWIN_LINEDOWN)
		{
			scroll_xoff += hf_char_width();
		}
		else if(event.GetEventType() == wxEVT_SCROLLWIN_PAGEUP)   {}
		else if(event.GetEventType() == wxEVT_SCROLLWIN_PAGEDOWN) {}
		
		if(scroll_xoff < 0)
		{
			scroll_xoff = 0;
		}
		else if(scroll_xoff > (virtual_width - client_width))
		{
			scroll_xoff = virtual_width - client_width;
		}
		
		SetScrollPos(wxHORIZONTAL, scroll_xoff);
		Refresh();
	}
}

void REHex::Document::OnWheel(wxMouseEvent &event)
{
	wxMouseWheelAxis axis = event.GetWheelAxis();
	int delta             = event.GetWheelDelta();
	int ticks_per_delta   = event.GetLinesPerAction();
	
	if(axis == wxMOUSE_WHEEL_VERTICAL)
	{
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
		
		_update_vscroll_pos();
		Refresh();
	}
	else if(axis == wxMOUSE_WHEEL_HORIZONTAL)
	{
		ticks_per_delta *= hf_char_width();
		
		wheel_horiz_accum += event.GetWheelRotation();
		
		scroll_xoff += (wheel_horiz_accum / delta) * ticks_per_delta;
		
		wheel_horiz_accum = (wheel_horiz_accum % delta);
		
		if(scroll_xoff < 0)
		{
			scroll_xoff = 0;
		}
		else if(scroll_xoff > (virtual_width - client_width))
		{
			scroll_xoff = virtual_width - client_width;
		}
		
		SetScrollPos(wxHORIZONTAL, scroll_xoff);
		Refresh();
	}
}

void REHex::Document::OnChar(wxKeyEvent &event)
{
	int key       = event.GetKeyCode();
	int modifiers = event.GetModifiers();
	
	off_t cursor_pos = get_cursor_position();
	
	if(modifiers & wxMOD_CONTROL)
	{
		/* Some control sequence, pass it on. */
		event.Skip();
	}
	else if(key == WXK_TAB && modifiers == wxMOD_NONE)
	{
		if(cursor_state != CSTATE_ASCII)
		{
			/* Hex view is focused, focus the ASCII view. */
			
			cursor_state = CSTATE_ASCII;
			Refresh();
		}
		else{
			/* ASCII view is focused, get wxWidgets to process this and focus the next
			 * control in the window.
			*/
			
			HandleAsNavigationKey(event);
		}
		
		return;
	}
	else if(key == WXK_TAB && modifiers == wxMOD_SHIFT)
	{
		if(cursor_state == CSTATE_ASCII)
		{
			/* ASCII view is focused, focus the hex view. */
			
			cursor_state = CSTATE_HEX;
			Refresh();
		}
		else{
			/* Hex view is focused, get wxWidgets to process this and focus the previous
			 * control in the window.
			*/
			
			HandleAsNavigationKey(event);
		}
	}
	else if(cursor_state != CSTATE_ASCII && (modifiers == wxMOD_NONE || modifiers == wxMOD_SHIFT) && isasciihex(key))
	{
		unsigned char nibble = REHex::parse_ascii_nibble(key);
		
		if(cursor_state == CSTATE_HEX_MID)
		{
			/* Overwrite least significant nibble of current byte, then move onto
			 * inserting or overwriting at the next byte.
			*/
			
			std::vector<unsigned char> cur_data = buffer->read_data(cursor_pos, 1);
			assert(cur_data.size() == 1);
			
			unsigned char old_byte = cur_data[0];
			unsigned char new_byte = (old_byte & 0xF0) | nibble;
			
			_tracked_overwrite_data("Change data", cursor_pos, &new_byte, 1, cursor_pos + 1, CSTATE_HEX);
		}
		else if(this->insert_mode)
		{
			/* Inserting a new byte. Initialise the most significant nibble then move
			 * onto overwriting the least significant.
			*/
			
			unsigned char byte = (nibble << 4);
			_tracked_insert_data("change data", cursor_pos, &byte, 1, cursor_pos, CSTATE_HEX_MID);
		}
		else{
			/* Overwrite most significant nibble of current byte, then move onto
			 * overwriting the least significant.
			*/
			
			std::vector<unsigned char> cur_data = buffer->read_data(cursor_pos, 1);
			
			if(!cur_data.empty())
			{
				unsigned char old_byte = cur_data[0];
				unsigned char new_byte = (old_byte & 0x0F) | (nibble << 4);
				
				_tracked_overwrite_data("Change data", cursor_pos, &new_byte, 1, cursor_pos, CSTATE_HEX_MID);
			}
		}
		
		clear_selection();
		
		/* TODO: Limit paint to affected area */
		this->Refresh();
	}
	else if(cursor_state == CSTATE_ASCII && (modifiers == wxMOD_NONE || modifiers == wxMOD_SHIFT) && isasciiprint(key))
	{
		unsigned char byte = key;
		
		if(this->insert_mode)
		{
			_tracked_insert_data("Change data", cursor_pos, &byte, 1, cursor_pos + 1, CSTATE_ASCII);
		}
		else if(cursor_pos < buffer->length())
		{
			std::vector<unsigned char> cur_data = buffer->read_data(cursor_pos, 1);
			assert(cur_data.size() == 1);
			
			_tracked_overwrite_data("Change data", cursor_pos, &byte, 1, cursor_pos + 1, CSTATE_ASCII);
		}
		
		clear_selection();
		
		/* TODO: Limit paint to affected area */
		this->Refresh();
	}
	else if(modifiers == wxMOD_NONE)
	{
		if(key == WXK_LEFT)
		{
			set_cursor_position(cursor_pos - (cursor_pos > 0));
			clear_selection();
			
			/* TODO: Limit paint to affected area */
			this->Refresh();
		}
		else if(key == WXK_RIGHT)
		{
			off_t max_pos = std::max((buffer_length() - !get_insert_mode()), (off_t)(0));
			set_cursor_position(std::min((cursor_pos + 1), max_pos));
			clear_selection();
			
			/* TODO: Limit paint to affected area */
			this->Refresh();
		}
		else if(key == WXK_UP)
		{
			auto cur_region = _data_region_by_offset(cursor_pos);
			assert(cur_region != NULL);
			
			off_t offset_within_cur = cursor_pos - cur_region->d_offset;
			
			if(offset_within_cur >= bytes_per_line_calc)
			{
				/* We are at least on the second line of the current
				 * region, can jump to the previous one.
				*/
				set_cursor_position(cursor_pos - bytes_per_line_calc);
			}
			else if(cur_region->d_offset > 0)
			{
				/* We are on the first line of the current region, but there is at
				 * last one region before us.
				*/
				auto prev_region = _data_region_by_offset(cur_region->d_offset - 1);
				assert(prev_region != NULL);
				
				/* How many bytes on the last line of prev_region? */
				off_t pr_last_line_len = (prev_region->d_length % bytes_per_line_calc);
				if(pr_last_line_len == 0)
				{
					pr_last_line_len = bytes_per_line_calc;
				}
				
				if(pr_last_line_len > offset_within_cur)
				{
					/* The last line of the previous block is at least long
					 * enough to have a byte above the current cursor position
					 * on the screen.
					*/
					
					set_cursor_position((cursor_pos - offset_within_cur) - (pr_last_line_len - offset_within_cur));
				}
				else{
					/* The last line of the previous block falls short of the
					 * horizontal position of the cursor, just jump to the end
					 * of it.
					*/
					
					set_cursor_position(cur_region->d_offset - 1);
				}
			}
			
			if(cursor_state == CSTATE_HEX_MID)
			{
				cursor_state = CSTATE_HEX;
			}
			
			clear_selection();
			
			/* TODO: Limit paint to affected area */
			this->Refresh();
		}
		else if(key == WXK_DOWN)
		{
			auto cur_region = _data_region_by_offset(cursor_pos);
			assert(cur_region != NULL);
			
			off_t offset_within_cur = cursor_pos - cur_region->d_offset;
			off_t remain_within_cur = cur_region->d_length - offset_within_cur;
			
			off_t last_line_within_cur = cur_region->d_length
				- (((cur_region->d_length % bytes_per_line_calc) == 0)
					? bytes_per_line_calc
					: (cur_region->d_length % bytes_per_line_calc));
			
			if(remain_within_cur > bytes_per_line_calc)
			{
				/* There is at least one more line's worth of bytes in the
				 * current region, can just skip ahead.
				*/
				set_cursor_position(cursor_pos + bytes_per_line_calc);
			}
			else if(offset_within_cur < last_line_within_cur)
			{
				/* There is another line in the current region which falls short of
				 * the cursor's horizontal position, jump to its end.
				*/
				set_cursor_position(cur_region->d_offset + cur_region->d_length - 1);
			}
			else{
				auto next_region = _data_region_by_offset(cur_region->d_offset + cur_region->d_length);
				
				if(next_region != NULL && cur_region != next_region)
				{
					/* There is another region after this one, jump to the same
					 * it, offset by our offset in the current line.
					*/
					off_t new_cursor_pos = next_region->d_offset + (offset_within_cur % bytes_per_line_calc);
					
					/* Clamp to the end of the next region. */
					off_t max_pos = (next_region->d_offset + next_region->d_length - 1);
					new_cursor_pos = std::min(max_pos, new_cursor_pos);
					
					set_cursor_position(new_cursor_pos);
				}
			}
			
			if(cursor_state == CSTATE_HEX_MID)
			{
				cursor_state = CSTATE_HEX;
			}
			
			clear_selection();
			
			/* TODO: Limit paint to affected area */
			this->Refresh();
		}
		else if(key == WXK_INSERT)
		{
			set_insert_mode(!get_insert_mode());
		}
		else if(key == WXK_DELETE)
		{
			if(selection_length > 0)
			{
				_tracked_erase_data("delete selection", selection_off, selection_length);
			}
			else if(cursor_pos < this->buffer->length())
			{
				_tracked_erase_data("delete", cursor_pos, 1);
			}
		}
		else if(key == WXK_BACK)
		{
			if(selection_length > 0)
			{
				_tracked_erase_data("delete selection", selection_off, selection_length);
			}
			else if(cursor_state == CSTATE_HEX_MID)
			{
				/* Backspace while waiting for the second nibble in a byte should erase the current byte
				 * rather than the previous one.
				*/
				_tracked_erase_data("delete", cursor_pos, 1);
			}
			else if(cursor_pos > 0)
			{
				_tracked_erase_data("delete", cursor_pos - 1, 1);
			}
		}
		else if(key == '/')
		{
			_edit_comment_popup(cursor_pos);
		}
	}
}

void REHex::Document::OnLeftDown(wxMouseEvent &event)
{
	wxClientDC dc(this);
	
	int mouse_x = event.GetX();
	int rel_x   = mouse_x + this->scroll_xoff;
	int mouse_y = event.GetY();
	
	/* Iterate over the regions to find the last one which does NOT start beyond the current
	 * scroll_y.
	*/
	
	auto region = regions.begin();
	for(auto next = std::next(region); next != regions.end() && (*next)->y_offset <= scroll_yoff; ++next)
	{
		region = next;
	}
	
	/* If we are scrolled past the start of the regiomn, will need to skip some of the first one. */
	int64_t skip_lines_in_region = (this->scroll_yoff - (*region)->y_offset);
	
	int64_t line_off = (mouse_y / hf_height) + skip_lines_in_region;
	
	while(region != regions.end() && line_off >= (*region)->y_lines)
	{
		line_off -= (*region)->y_lines;
		++region;
	}
	
	if(region != regions.end())
	{
		REHex::Document::Region::Data    *dr = dynamic_cast<REHex::Document::Region::Data*>   (*region);
		REHex::Document::Region::Comment *cr = dynamic_cast<REHex::Document::Region::Comment*>(*region);
		
		if(dr != NULL)
		{
			if(rel_x < offset_column_width)
			{
				/* Click was within the offset area */
			}
			else if(show_ascii && rel_x >= ascii_text_x)
			{
				/* Click was within the ASCII area */
				
				off_t clicked_offset = dr->offset_at_xy_ascii(*this, rel_x, line_off);
				if(clicked_offset >= 0)
				{
					/* Clicked on a character */
					
					_set_cursor_position(clicked_offset, CSTATE_ASCII);
					
					clear_selection();
					
					mouse_down_at_offset = clicked_offset;
					mouse_down_in_ascii  = true;
					
					CaptureMouse();
					mouse_select_timer.Start(MOUSE_SELECT_INTERVAL, wxTIMER_CONTINUOUS);
					
					/* TODO: Limit paint to affected area */
					Refresh();
				}
			}
			else{
				/* Click was within the hex area */
				
				off_t clicked_offset = dr->offset_at_xy_hex(*this, rel_x, line_off);
				if(clicked_offset >= 0)
				{
					/* Clicked on a byte */
					
					_set_cursor_position(clicked_offset, CSTATE_HEX);
					
					clear_selection();
					
					mouse_down_at_offset = clicked_offset;
					mouse_down_in_hex    = true;
					
					CaptureMouse();
					mouse_select_timer.Start(MOUSE_SELECT_INTERVAL, wxTIMER_CONTINUOUS);
					
					/* TODO: Limit paint to affected area */
					Refresh();
				}
			}
		}
		else if(cr != NULL)
		{
			/* Mouse was clicked within a Comment region, ensure we are within the border drawn around the
			 * comment text.
			*/
			
			int hf_width = hf_char_width();
			
			if(
				(line_off > 0 || (mouse_y % hf_height) >= (hf_height / 4)) /* Not above top edge. */
				&& (line_off < (cr->y_lines - 1) || (mouse_y % hf_height) <= ((hf_height / 4) * 3)) /* Not below bottom edge. */
				&& rel_x >= (hf_width / 4) /* Not left of left edge. */
				&& rel_x < (virtual_width - (hf_width / 4))) /* Not right of right edge. */
			{
				_edit_comment_popup(cr->c_offset);
			}
		}
	}
	
	/* Document takes focus when clicked. */
	SetFocus();
}

void REHex::Document::OnLeftUp(wxMouseEvent &event)
{
	if(mouse_down_in_hex || mouse_down_in_ascii)
	{
		mouse_select_timer.Stop();
		ReleaseMouse();
	}
	
	mouse_down_in_hex   = false;
	mouse_down_in_ascii = false;
}

void REHex::Document::OnRightDown(wxMouseEvent &event)
{
	/* If the user right clicks while selecting, and then releases the left button over the
	 * menu, we never receive the EVT_LEFT_UP event. Release the mouse and cancel the selection
	 * now, else we wind up keeping the mouse grabbed and stop it interacting with any other
	 * windows...
	*/
	
	if(mouse_down_in_hex || mouse_down_in_ascii)
	{
		mouse_select_timer.Stop();
		ReleaseMouse();
		
		mouse_down_in_hex   = false;
		mouse_down_in_ascii = false;
	}
	
	wxClientDC dc(this);
	
	int mouse_x = event.GetX();
	int rel_x   = mouse_x + this->scroll_xoff;
	int mouse_y = event.GetY();
	
	/* Iterate over the regions to find the last one which does NOT start beyond the current
	 * scroll_y.
	*/
	
	auto region = regions.begin();
	for(auto next = std::next(region); next != regions.end() && (*next)->y_offset <= scroll_yoff; ++next)
	{
		region = next;
	}
	
	/* If we are scrolled past the start of the regiomn, will need to skip some of the first one. */
	int64_t skip_lines_in_region = (this->scroll_yoff - (*region)->y_offset);
	
	int64_t line_off = (mouse_y / hf_height) + skip_lines_in_region;
	
	while(region != regions.end() && line_off >= (*region)->y_lines)
	{
		line_off -= (*region)->y_lines;
		++region;
	}
	
	if(region != regions.end())
	{
		REHex::Document::Region::Data *dr = dynamic_cast<REHex::Document::Region::Data*>(*region);
		if(dr != NULL)
		{
			if(rel_x < offset_column_width)
			{
				/* Click was within the offset area */
			}
			else if(show_ascii && rel_x >= ascii_text_x)
			{
				/* Click was within the ASCII area */
				
				off_t clicked_offset = dr->offset_at_xy_ascii(*this, rel_x, line_off);
				if(clicked_offset >= 0)
				{
					/* Clicked on a character */
					
					_set_cursor_position(clicked_offset, CSTATE_ASCII);
					
					if(clicked_offset < selection_off || clicked_offset >= selection_off + selection_length)
					{
						clear_selection();
					}
					
					/* TODO: Limit paint to affected area */
					Refresh();
				}
			}
			else{
				/* Click was within the hex area */
				
				off_t clicked_offset = dr->offset_at_xy_hex(*this, rel_x, line_off);
				if(clicked_offset >= 0)
				{
					/* Clicked on a byte */
					
					_set_cursor_position(clicked_offset, CSTATE_HEX);
					
					if(clicked_offset < selection_off || clicked_offset >= selection_off + selection_length)
					{
						clear_selection();
					}
					
					/* TODO: Limit paint to affected area */
					Refresh();
				}
			}
			
			wxMenu menu;
			
			menu.Append(wxID_CUT, "&Cut");
			menu.Enable(wxID_CUT,  (selection_length > 0));
			
			menu.Append(wxID_COPY,  "&Copy");
			menu.Enable(wxID_COPY, (selection_length > 0));
			
			menu.Append(wxID_PASTE, "&Paste");
			
			menu.AppendSeparator();
			
			if(_get_comment_text(get_cursor_position()).empty())
			{
				menu.Append(ID_SET_COMMENT, "Insert comment...");
			}
			else{
				menu.Append(ID_SET_COMMENT, "Edit comment...");
			}
			
			/* We need to maintain bitmap instances for lifespan of menu. */
			std::list<wxBitmap> bitmaps;
			
			off_t highlight_off;
			off_t highlight_length = 0;
			
			off_t cursor_pos = get_cursor_position();
			auto highlight_at_cur = NestedOffsetLengthMap_get(highlights, cursor_pos);
			
			if(selection_length > 0)
			{
				highlight_off    = selection_off;
				highlight_length = selection_length;
			}
			else if(highlight_at_cur != highlights.end())
			{
				highlight_off    = highlight_at_cur->first.offset;
				highlight_length = highlight_at_cur->first.length;
			}
			else if(cursor_pos < buffer_length())
			{
				highlight_off    = cursor_pos;
				highlight_length = 1;
			}
			
			if(highlight_length > 0 && NestedOffsetLengthMap_can_set(highlights, highlight_off, highlight_length))
			{
				wxMenu *hlmenu = new wxMenu();
				
				const REHex::Palette &pal = wxGetApp().palette;
				
				for(int i = 0; i < Palette::NUM_HIGHLIGHT_COLOURS; ++i)
				{
					wxMenuItem *itm = new wxMenuItem(hlmenu, wxID_ANY, " ");
					
					wxColour bg_colour = pal.get_highlight_bg(i);
					
					/* TODO: Get appropriate size for menu bitmap.
					 * TODO: Draw a character in image using foreground colour.
					*/
					wxImage img(16, 16);
					img.SetRGB(wxRect(0, 0, img.GetWidth(), img.GetHeight()),
						bg_colour.Red(), bg_colour.Green(), bg_colour.Blue());
					
					bitmaps.emplace_back(img);
					itm->SetBitmap(bitmaps.back());
					
					hlmenu->Append(itm);
					
					/* On Windows, event bindings on a submenu don't work.
					 * On OS X, event bindings on a parent menu don't work.
					 * On GTK, both work.
					*/
					#ifdef _WIN32
					menu.Bind(wxEVT_MENU, [this, highlight_off, highlight_length, i](wxCommandEvent &event)
					#else
					hlmenu->Bind(wxEVT_MENU, [this, highlight_off, highlight_length, i](wxCommandEvent &event)
					#endif
					{
						int colour = i;
						_tracked_change("set highlight",
							[this, highlight_off, highlight_length, colour]()
							{
								NestedOffsetLengthMap_set(highlights, highlight_off, highlight_length, colour);
								
								/* TODO: Limit paint to affected area. */
								Refresh();
							},
							
							[]()
							{
								/* Highlight changes are undone implicitly. */
							});
					}, itm->GetId(), itm->GetId());
				}
				
				menu.AppendSubMenu(hlmenu, "Set Highlight");
			}
			
			if(highlight_at_cur != highlights.end())
			{
				menu.Append(ID_CLEAR_HIGHLIGHT, "Remove Highlight");
			}
			
			PopupMenu(&menu);
		}
	}
	
	/* Document takes focus when clicked. */
	SetFocus();
}

void REHex::Document::OnMotion(wxMouseEvent &event)
{
	OnMotionTick(event.GetX(), event.GetY());
}

void REHex::Document::OnSelectTick(wxTimerEvent &event)
{
	wxPoint window_pos = GetScreenPosition();
	wxPoint mouse_pos  = wxGetMousePosition();
	
	OnMotionTick((mouse_pos.x - window_pos.x), (mouse_pos.y - window_pos.y));
}

void REHex::Document::OnMotionTick(int mouse_x, int mouse_y)
{
	if(!mouse_down_in_ascii && !mouse_down_in_hex)
	{
		return;
	}
	
	wxClientDC dc(this);
	
	int scroll_xoff_max = GetScrollRange(wxHORIZONTAL) - GetScrollThumb(wxHORIZONTAL);
	
	if(mouse_x < 0)
	{
		scroll_xoff -= std::min(abs(mouse_x), scroll_xoff);
		SetScrollPos(wxHORIZONTAL, scroll_xoff);
		
		mouse_x = 0;
	}
	else if(mouse_x >= client_width)
	{
		scroll_xoff += std::min((int)(mouse_x - client_width), (scroll_xoff_max - scroll_xoff));
		SetScrollPos(wxHORIZONTAL, scroll_xoff);
		
		mouse_x = client_width - 1;
	}
	
	if(mouse_y < 0)
	{
		scroll_yoff -= std::min((int64_t)(abs(mouse_y) / hf_height + 1), scroll_yoff);
		_update_vscroll_pos();
		
		mouse_y = 0;
	}
	else if(mouse_y >= client_height)
	{
		scroll_yoff += std::min((int64_t)((mouse_y - client_height) / hf_height + 1), (scroll_yoff_max - scroll_yoff));
		_update_vscroll_pos();
		
		mouse_y = client_height - 1;
	}
	
	int rel_x = mouse_x + scroll_xoff;
	
	/* Iterate over the regions to find the last one which does NOT start beyond the current
	 * scroll_y.
	*/
	
	auto region = regions.begin();
	for(auto next = std::next(region); next != regions.end() && (*next)->y_offset <= scroll_yoff; ++next)
	{
		region = next;
	}
	
	/* If we are scrolled past the start of the regiomn, will need to skip some of the first one. */
	int64_t skip_lines_in_region = (this->scroll_yoff - (*region)->y_offset);
	
	int64_t line_off = (mouse_y / hf_height) + skip_lines_in_region;
	
	while(region != regions.end() && line_off >= (*region)->y_lines)
	{
		line_off -= (*region)->y_lines;
		++region;
	}
	
	if(region != regions.end())
	{
		REHex::Document::Region::Data *dr = dynamic_cast<REHex::Document::Region::Data*>(*region);
		if(dr != NULL)
		{
			if(mouse_down_in_hex)
			{
				/* Started dragging in hex area */
				
				off_t select_to_offset = dr->offset_near_xy_hex(*this, rel_x, line_off);
				if(select_to_offset >= 0)
				{
					if(select_to_offset >= mouse_down_at_offset)
					{
						set_selection(mouse_down_at_offset,
							((select_to_offset - mouse_down_at_offset) + 1));
					}
					else{
						set_selection(select_to_offset,
							((mouse_down_at_offset - select_to_offset) + 1));
					}
					
					/* TODO: Limit paint to affected area */
					Refresh();
				}
			}
			else if(mouse_down_in_ascii)
			{
				/* Started dragging in ASCII area */
				
				off_t select_to_offset = dr->offset_near_xy_ascii(*this, rel_x, line_off);
				if(select_to_offset >= 0)
				{
					if(select_to_offset >= mouse_down_at_offset)
					{
						set_selection(mouse_down_at_offset,
							((select_to_offset - mouse_down_at_offset) + 1));
					}
					else{
						set_selection(select_to_offset,
							((mouse_down_at_offset - select_to_offset) + 1));
					}
					
					/* TODO: Limit paint to affected area */
					Refresh();
				}
			}
		}
	}
}

void REHex::Document::OnRedrawCursor(wxTimerEvent &event)
{
	cursor_visible = !cursor_visible;
	
	/* TODO: Limit paint to cursor area */
	Refresh();
}

/* Handles the "Insert comment" context menu option */
void REHex::Document::OnSetComment(wxCommandEvent &event)
{
	_edit_comment_popup(get_cursor_position());
}

void REHex::Document::OnClearHighlight(wxCommandEvent &event)
{
	off_t cursor_pos = get_cursor_position();
	
	_tracked_change("remove highlight",
		[this, cursor_pos]()
		{
			auto highlight = NestedOffsetLengthMap_get(highlights, cursor_pos);
			highlights.erase(highlight);
			
			/* TODO: Limit paint to affected area. */
			Refresh();
		},
		
		[]()
		{
			/* Highlighting is implicitly restored by undo() */
		});
}

void REHex::Document::_ctor_pre(wxWindow *parent)
{
	/* The background style MUST be set before the control is created. */
	SetBackgroundStyle(wxBG_STYLE_PAINT);
	Create(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize,
		(wxVSCROLL | wxHSCROLL | wxWANTS_CHARS));
	
	dirty             = false;
	client_width      = 0;
	client_height     = 0;
	bytes_per_line    = 0;
	bytes_per_group   = 4;
	show_ascii        = true;
	scroll_xoff       = 0;
	scroll_yoff       = 0;
	scroll_yoff_max   = 0;
	scroll_ydiv       = 1;
	wheel_vert_accum  = 0;
	wheel_horiz_accum = 0;
	selection_length  = 0;
	cursor_visible    = true;
	cursor_state      = CSTATE_HEX;
}

void REHex::Document::_ctor_post()
{
	wxFontInfo finfo;
	finfo.Family(wxFONTFAMILY_MODERN);
	
	hex_font = new wxFont(finfo);
	assert(hex_font->IsFixedWidth());
	
	{
		wxClientDC dc(this);
		dc.SetFont(*hex_font);
		
		wxSize hf_char_size = dc.GetTextExtent("X");
		hf_height           = hf_char_size.GetHeight();
		
		/* Precompute widths for hf_string_width() */
		
		for(unsigned int i = 0; i < PRECOMP_HF_STRING_WIDTH_TO; ++i)
		{
			hf_string_width_precomp[i]
				= dc.GetTextExtent(std::string((i + 1), 'X')).GetWidth();
		}
	}
	
	redraw_cursor_timer.Start(750, wxTIMER_CONTINUOUS);
	
	/* SetDoubleBuffered() isn't implemented on all platforms. */
	#if defined(__WXMSW__) || defined(__WXGTK__)
	SetDoubleBuffered(true);
	#endif
	
	SetMinClientSize(wxSize(300, 200));
}

void REHex::Document::_init_regions(const json_t *meta)
{
	assert(regions.empty());
	
	/* Load any comments from the document metadata into a std::map, which ensures they are
	 * sorted by their offset.
	*/
	
	std::map<off_t,wxString> comments;
	
	{
		/* TODO: Validate JSON structure */
		
		json_t *j_comments   = json_object_get(meta, "comments");
		json_t *j_highlights = json_object_get(meta, "highlights");
		
		size_t index;
		json_t *value;
		
		json_array_foreach(j_comments, index, value)
		{
			comments[json_integer_value(json_object_get(value, "offset"))]
				= wxString::FromUTF8(json_string_value(json_object_get(value, "text")));
		}
		
		json_array_foreach(j_highlights, index, value)
		{
			off_t h_offset = json_integer_value(json_object_get(value, "offset"));
			off_t h_length = json_integer_value(json_object_get(value, "length"));
			int   h_colour = json_integer_value(json_object_get(value, "colour-idx"));
			
			NestedOffsetLengthMap_set(highlights, h_offset, h_length, h_colour);
		}
	}
	
	/* Construct a list of interlaced comment/data regions. */
	
	data_regions_count = 0;
	
	auto next_comment = comments.begin();
	off_t next_data = 0, remain_data = buffer->length();
	
	while(remain_data > 0)
	{
		off_t dr_length = remain_data;
		
		if(next_comment != comments.end() && next_comment->first == next_data)
		{
			regions.push_back(new REHex::Document::Region::Comment(next_comment->first, next_comment->second));
			++next_comment;
		}
		
		if(next_comment != comments.end() && next_comment->first > next_data)
		{
			dr_length = std::min(dr_length, (next_comment->first - next_data));
		}
		
		regions.push_back(new REHex::Document::Region::Data(next_data, dr_length));
		++data_regions_count;
		
		next_data   += dr_length;
		remain_data -= dr_length;
	}
	
	if(regions.empty())
	{
		/* Empty buffers need a data region too! */
		
		assert(buffer->length() == 0);
		
		regions.push_back(new REHex::Document::Region::Data(0, 0));
		++data_regions_count;
	}
}

void REHex::Document::_recalc_regions(wxDC &dc)
{
	uint64_t next_yo = 0;
	auto i = regions.begin();
	
	for(; i != regions.end(); ++i)
	{
		(*i)->y_offset = next_yo;
		(*i)->update_lines(*this, dc);
		
		next_yo += (*i)->y_lines;
	}
}

void REHex::Document::_UNTRACKED_overwrite_data(wxDC &dc, off_t offset, const unsigned char *data, off_t length)
{
	bool ok = buffer->overwrite_data(offset, data, length);
	assert(ok);
	
	if(ok)
	{
		dirty = true;
	}
}

/* Insert some data into the Buffer and update our own data structures. */
void REHex::Document::_UNTRACKED_insert_data(wxDC &dc, off_t offset, const unsigned char *data, off_t length)
{
	bool ok = buffer->insert_data(offset, data, length);
	assert(ok);
	
	if(ok)
	{
		dirty = true;
		
		auto region = regions.begin();
		
		/* Increment region until it is pointing at the Data region which encompasses the
		 * point we have inserted at.
		*/
		for(;; ++region)
		{
			assert(region != regions.end());
			auto dr = dynamic_cast<REHex::Document::Region::Data*>(*region);
			
			if(dr == NULL)
			{
				/* Not a data region, carry on searching... */
				continue;
			}
			
			if((dr->d_offset + dr->d_length) > offset)
			{
				/* Regions are ordered, so the first one whose offset plus length
				 * encompasses our starting point is the one.
				*/
				break;
			}
			
			if((dr->d_offset + dr->d_length) == offset && std::next(region) == regions.end())
			{
				/* Special case: Inserting at the end of the last region. */
				break;
			}
		}
		
		/* Grow the length of the region. */
		
		{
			auto dr = dynamic_cast<REHex::Document::Region::Data*>(*region);
			assert(dr != NULL);
			
			dr->d_length += length;
			
			dr->update_lines(*this, dc);
		}
		
		/* Shuffle the rest of the regions along. */
		
		uint64_t next_yo = (*region)->y_offset + (*region)->y_lines;
		++region;
		
		while(region != regions.end())
		{
			auto dr = dynamic_cast<REHex::Document::Region::Data*>(*region);
			if(dr != NULL)
			{
				dr->d_offset += length;
			}
			
			auto cr = dynamic_cast<REHex::Document::Region::Comment*>(*region);
			if(cr != NULL)
			{
				cr->c_offset += length;
			}
			
			(*region)->y_offset = next_yo;
			next_yo += (*region)->y_lines;
			
			++region;
		}
		
		NestedOffsetLengthMap_data_inserted(highlights, offset, length);
	}
	
}

/* Erase a range of data from the Buffer and update our own data structures. */
void REHex::Document::_UNTRACKED_erase_data(wxDC &dc, off_t offset, off_t length)
{
	bool ok = buffer->erase_data(offset, length);
	assert(ok);
	
	if(ok)
	{
		dirty = true;
		
		auto region = regions.begin();
		
		/* Increment region until it is pointing at the Data region which encompasses the
		 * start of the data being erased.
		*/
		for(REHex::Document::Region::Data *d; (d = dynamic_cast<REHex::Document::Region::Data*>(*region)) == NULL || (d->d_offset + d->d_length) <= offset; ++region) {}
		assert(region != regions.end());
		
		uint64_t next_yo = (*region)->y_offset;
		
		off_t to_shift  = 0;
		off_t to_shrink = length;
		off_t dr_offset = offset - dynamic_cast<REHex::Document::Region::Data*>(*region)->d_offset;
		
		while(region != regions.end())
		{
			auto dr = dynamic_cast<REHex::Document::Region::Data*>(*region);
			if(dr != NULL)
			{
				/* This is a data region, so we need to munge the d_offset and
				 * d_length values according to our state within the erase.
				*/
				
				off_t to_shrink_here = std::min(to_shrink, dr->d_length - dr_offset);
				
				dr->d_offset -= to_shift;
				dr->d_length -= to_shrink_here;
				
				to_shift  += to_shrink_here;
				to_shrink -= to_shrink_here;
				dr_offset = 0;
				
				if(region != regions.begin() && dr->d_length == 0)
				{
					/* If this isn't the first region, it is now zero bytes long
					 * and was preceeded by a comment, delete that comment.
					*/
					
					auto prev = std::prev(region);
					auto cr = dynamic_cast<REHex::Document::Region::Comment*>(*prev);
					if(cr != NULL)
					{
						next_yo = (*prev)->y_offset;
						
						delete *prev;
						region = regions.erase(prev);
					}
				}
				
				if(dr->d_length == 0 && data_regions_count > 1)
				{
					/* If we've shrunk this region to zero bytes and it isn't
					 * the last one, get rid of it.
					*/
					
					delete *region;
					region = regions.erase(region);
					
					--data_regions_count;
					
					/* ...and carry on to the next one. */
					continue;
				}
				else if(to_shrink_here > 0)
				{
					(*region)->update_lines(*this, dc);
				}
			}
			
			auto cr = dynamic_cast<REHex::Document::Region::Comment*>(*region);
			if(cr != NULL)
			{
				cr->c_offset -= to_shift;
			}
			
			/* All blocks from the point where we started erasing must have their
			 * y_offset values updated, since region heights may have changed.
			*/
			
			(*region)->y_offset = next_yo;
			next_yo += (*region)->y_lines;
			
			++region;
		}
		
		assert(to_shift == length);
		assert(to_shrink == 0);
		
		NestedOffsetLengthMap_data_erased(highlights, offset, length);
	}
}

void REHex::Document::_tracked_overwrite_data(const char *change_desc, off_t offset, const unsigned char *data, off_t length, off_t new_cursor_pos, CursorState new_cursor_state)
{
	std::vector<unsigned char> old_data = read_data(offset, length);
	assert(old_data.size() == length);
	
	std::vector<unsigned char> new_data(data, data + length);
	
	_tracked_change(change_desc,
		[this, offset, new_data, new_cursor_pos, new_cursor_state]()
		{
			wxClientDC dc(this);
			_UNTRACKED_overwrite_data(dc, offset, new_data.data(), new_data.size());
			_set_cursor_position(new_cursor_pos, new_cursor_state);
		},
		 
		[this, offset, old_data]()
		{
			wxClientDC dc(this);
			_UNTRACKED_overwrite_data(dc, offset, old_data.data(), old_data.size());
		});
}

void REHex::Document::_tracked_insert_data(const char *change_desc, off_t offset, const unsigned char *data, off_t length, off_t new_cursor_pos, CursorState new_cursor_state)
{
	std::vector<unsigned char> data_copy(data, data + length);
	
	_tracked_change(change_desc,
		[this, offset, data_copy, new_cursor_pos, new_cursor_state]()
		{
			wxClientDC dc(this);
			_UNTRACKED_insert_data(dc, offset, data_copy.data(), data_copy.size());
			_set_cursor_position(new_cursor_pos, new_cursor_state);
		},
		 
		[this, offset, length]()
		{
			wxClientDC dc(this);
			_UNTRACKED_erase_data(dc, offset, length);
		});
}

void REHex::Document::_tracked_erase_data(const char *change_desc, off_t offset, off_t length)
{
	std::vector<unsigned char> erase_data = read_data(offset, length);
	assert(erase_data.size() == length);
	
	_tracked_change(change_desc,
		[this, offset, erase_data]()
		{
			wxClientDC dc(this);
			_UNTRACKED_erase_data(dc, offset, erase_data.size());
			
			set_cursor_position(offset);
			clear_selection();
			
			/* TODO: Limit paint to affected area */
			Refresh();
		},
		
		[this, offset, erase_data]()
		{
			wxClientDC dc(this);
			_UNTRACKED_insert_data(dc, offset, erase_data.data(), erase_data.size());
		});
}

void REHex::Document::_tracked_replace_data(const char *change_desc, off_t offset, off_t old_data_length, const unsigned char *new_data, off_t new_data_length, off_t new_cursor_pos, CursorState new_cursor_state)
{
	if(old_data_length == new_data_length)
	{
		/* Save unnecessary shuffling of the Buffer pages. */
		/* TODO */
	}
	
	std::vector<unsigned char> old_data_copy = buffer->read_data(offset, old_data_length);
	std::vector<unsigned char> new_data_copy(new_data, new_data + new_data_length);
	
	_tracked_change(change_desc,
		[this, offset, old_data_length, new_data_copy, new_cursor_pos, new_cursor_state]()
		{
			wxClientDC dc(this);
			_UNTRACKED_erase_data(dc, offset, old_data_length);
			_UNTRACKED_insert_data(dc, offset, new_data_copy.data(), new_data_copy.size());
			_set_cursor_position(new_cursor_pos, new_cursor_state);
		},
		
		[this, offset, old_data_copy, new_data_length]()
		{
			wxClientDC dc(this);
			_UNTRACKED_erase_data(dc, offset, new_data_length);
			_UNTRACKED_insert_data(dc, offset, old_data_copy.data(), old_data_copy.size());
		});
}

void REHex::Document::_tracked_change(const char *desc, std::function< void() > do_func, std::function< void() > undo_func)
{
	struct TrackedChange change;
	
	change.desc = desc;
	change.undo = undo_func;
	change.redo = do_func;
	
	change.old_cpos_off     = cpos_off;
	change.old_cursor_state = cursor_state;
	change.old_highlights   = highlights;
	
	do_func();
	
	undo_stack.push_back(change);
	redo_stack.clear();
}

wxString REHex::Document::_get_comment_text(off_t offset)
{
	for(auto region = regions.begin(); region != regions.end(); ++region)
	{
		auto cr = dynamic_cast<REHex::Document::Region::Comment*>(*region);
		if(cr != NULL && cr->c_offset == offset)
		{
			return cr->c_text;
		}
	}
	
	return "";
}

void REHex::Document::_set_comment_text(wxDC &dc, off_t offset, const wxString &text)
{
	for(auto region = regions.begin(); region != regions.end(); ++region)
	{
		auto cr = dynamic_cast<REHex::Document::Region::Comment*>(*region);
		if(cr != NULL && cr->c_offset == offset)
		{
			/* Updating an existing comment. */
			cr->c_text = text;
			break;
		}
		
		auto dr = dynamic_cast<REHex::Document::Region::Data*>(*region);
		if(dr != NULL)
		{
			if(dr->d_offset == offset)
			{
				/* Placing a comment at the start of a Data region. */
				regions.insert(region, new REHex::Document::Region::Comment(offset, text));
				break;
			}
			else if((dr->d_offset + dr->d_length) > offset)
			{
				/* Splitting a Data region in two and placing a comment in between
				 * them.
				*/
				
				off_t rel_off = offset - dr->d_offset;
				
				auto ci = regions.insert(region, new REHex::Document::Region::Comment(offset, text));
				regions.insert(ci, new REHex::Document::Region::Data(dr->d_offset, rel_off));
				++data_regions_count;
				
				dr->d_offset += rel_off;
				dr->d_length -= rel_off;
				
				break;
			}
		}
	}
	
	dirty = true;
	
	_recalc_regions(dc);
}

void REHex::Document::_delete_comment(wxDC &dc, off_t offset)
{
	auto region = regions.begin();
	uint64_t next_yo = 0;
	
	for(; region != regions.end(); ++region)
	{
		auto cr = dynamic_cast<REHex::Document::Region::Comment*>(*region);
		if(cr != NULL && cr->c_offset == offset)
		{
			/* Found the requested comment Region, destroy it. */
			delete *region;
			region = regions.erase(region);
			
			/* ...and merge the Data regions from either side
			 * (unless we deleted a comment from the beginning).
			*/
			if(region != regions.begin())
			{
				/* ...get the Data region from before the comment... */
				auto dr1 = dynamic_cast<REHex::Document::Region::Data*>(*(std::prev(region)));
				assert(dr1 != NULL);
				
				/* ...get the Data region from after the comment... */
				auto dr2 = dynamic_cast<REHex::Document::Region::Data*>(*region);
				assert(dr2 != NULL);
				
				/* ...extend the first to encompass the second... */
				dr1->d_length += dr2->d_length;
				dr1->update_lines(*this, dc);
				
				/* ...and make the second go away. */
				delete *region;
				region = regions.erase(region);
				--data_regions_count;
				
				/* Set the y_offset for regions after this to begin at. */
				next_yo = dr1->y_offset + dr1->y_lines;
			}
			
			break;
		}
	}
	
	/* Fixup the y_offset of all following regions */
	for(; region != regions.end(); ++region)
	{
		(*region)->y_offset = next_yo;
		next_yo += (*region)->y_lines;
	}
}

void REHex::Document::_edit_comment_popup(off_t offset)
{
	wxString old_comment = _get_comment_text(offset);
	REHex::TextEntryDialog te(this, "Enter comment", old_comment);
	
	int rc = te.ShowModal();
	if(rc == wxID_OK)
	{
		wxString new_comment = te.get_text();
		
		if(new_comment.empty() && old_comment.empty())
		{
			return;
		}
		
		if(new_comment.empty())
		{
			_tracked_change("delete comment",
				[this, offset]()
				{
					wxClientDC dc(this);
					_delete_comment(dc, offset);
				},
				[this, offset, old_comment]()
				{
					wxClientDC dc(this);
					_set_comment_text(dc, offset, old_comment);
				});
		}
		else if(old_comment.empty())
		{
			_tracked_change("insert comment",
				[this, offset, new_comment]()
				{
					wxClientDC dc(this);
					_set_comment_text(dc, offset, new_comment);
				},
				[this, offset]()
				{
					wxClientDC dc(this);
					_delete_comment(dc, offset);
				});
		}
		else{
			_tracked_change("modify comment",
				[this, offset, new_comment]()
				{
					wxClientDC dc(this);
					_set_comment_text(dc, offset, new_comment);
				},
				[this, offset, old_comment]()
				{
					wxClientDC dc(this);
					_set_comment_text(dc, offset, old_comment);
				});
		}
		
		/* TODO: Limit paint to affected area */
		Refresh();
	}
}

json_t *REHex::Document::_dump_metadata()
{
	json_t *root = json_object();
	if(root == NULL)
	{
		return NULL;
	}
	
	json_t *comments = json_array();
	if(json_object_set_new(root, "comments", comments) == -1)
	{
		json_decref(root);
		return NULL;
	}
	
	for(auto region = regions.begin(); region != regions.end(); ++region)
	{
		auto cr = dynamic_cast<REHex::Document::Region::Comment*>(*region);
		if(cr == NULL)
		{
			continue;
		}
		
		const wxScopedCharBuffer utf8_text = cr->c_text.utf8_str();
		
		json_t *comment = json_object();
		if(json_array_append(comments, comment) == -1
			|| json_object_set_new(comment, "offset", json_integer(cr->c_offset)) == -1
			|| json_object_set_new(comment, "text",   json_stringn(utf8_text.data(), utf8_text.length())) == -1)
		{
			json_decref(root);
			return NULL;
		}
	}
	
	json_t *highlights = json_array();
	if(json_object_set_new(root, "highlights", highlights) == -1)
	{
		json_decref(root);
		return NULL;
	}
	
	for(auto h = this->highlights.begin(); h != this->highlights.end(); ++h)
	{
		json_t *highlight = json_object();
		if(json_array_append(highlights, highlight) == -1
			|| json_object_set_new(highlight, "offset",     json_integer(h->first.offset)) == -1
			|| json_object_set_new(highlight, "length",     json_integer(h->first.length)) == -1
			|| json_object_set_new(highlight, "colour-idx", json_integer(h->second)) == -1)
		{
			json_decref(root);
			return NULL;
		}
	}
	
	return root;
}

void REHex::Document::_save_metadata(const std::string &filename)
{
	/* TODO: Report errors, atomically replace file? */
	json_t *meta = _dump_metadata();
	json_dump_file(meta, filename.c_str(), JSON_INDENT(2));
	json_decref(meta);
}

REHex::Document::Region::Data *REHex::Document::_data_region_by_offset(off_t offset)
{
	for(auto region = regions.begin(); region != regions.end(); ++region)
	{
		auto dr = dynamic_cast<REHex::Document::Region::Data*>(*region);
		if(dr != NULL
			&& dr->d_offset <= offset
			&& ((dr->d_offset + dr->d_length) > offset
				|| ((dr->d_offset + dr->d_length) == offset && buffer->length() == offset)))
		{
			return dr;
		}
	}
	
	return NULL;
}

/* Scroll the Document vertically to make the given line visible.
 * Does nothing if the line is already on-screen.
*/
void REHex::Document::_make_line_visible(int64_t line)
{
	if(scroll_yoff > line)
	{
		/* Need to scroll up, line will be at the top. */
		scroll_yoff = line;
	}
	else if((scroll_yoff + visible_lines) <= line)
	{
		/* Need to scroll down, line will be the last fully-visible one. */
		scroll_yoff = (line - visible_lines) + !!visible_lines;
	}
	else{
		/* Don't need to scroll. */
		return;
	}
	
	assert(scroll_yoff <= line);
	assert((scroll_yoff + visible_lines + !visible_lines) > line);
	
	_update_vscroll_pos();
	Refresh();
}

/* Scroll the Document horizontally to (try to) make the given range of X co-ordinates visible.
 * Does nothing if the range is fully visible.
*/
void REHex::Document::_make_x_visible(int x_px, int width_px)
{
	if(scroll_xoff > x_px)
	{
		/* Scroll to the left */
		scroll_xoff = x_px;
	}
	else if((scroll_xoff + client_width) < (x_px + width_px) && width_px <= client_width)
	{
		/* Scroll to the right. */
		scroll_xoff = x_px - (client_width - width_px);
	}
	else{
		/* Don't need to scroll. */
		return;
	}
	
	assert(scroll_xoff <= x_px);
	assert((scroll_xoff + client_width) >= (x_px + width_px) || width_px > client_width);
	
	SetScrollPos(wxHORIZONTAL, scroll_xoff);
	Refresh();
}

/* Scroll the Document to make the byte at the given offset visible.
 * Does nothing if the byte is already on-screen.
*/
void REHex::Document::_make_byte_visible(off_t offset)
{
	auto dr = _data_region_by_offset(offset);
	assert(dr != NULL);
	
	/* TODO: Move these maths into Region::Data */
	
	off_t region_offset = offset - dr->d_offset;
	
	uint64_t region_line = dr->y_offset + (region_offset / bytes_per_line_calc);
	_make_line_visible(region_line);
	
	off_t line_off = region_offset % bytes_per_line_calc;
	
	if(cursor_state == CSTATE_HEX || cursor_state == CSTATE_HEX_MID)
	{
		unsigned int line_x = offset_column_width
			+ hf_string_width(line_off * 2)
			+ hf_string_width(line_off / bytes_per_group);
		_make_x_visible(line_x, hf_string_width(2));
	}
	else if(cursor_state == CSTATE_ASCII)
	{
		off_t byte_x = ascii_text_x + hf_string_width(line_off);
		_make_x_visible(byte_x, hf_char_width());
	}
}

std::list<wxString> REHex::Document::_format_text(const wxString &text, unsigned int cols, unsigned int from_line, unsigned int max_lines)
{
	assert(cols > 0);
	
	/* TODO: Throw myself into the abyss and support Unicode properly...
	 * (This function assumes one byte is one full-width character on the screen.
	*/
	
	std::list<wxString> lines;
	
	for(size_t at = 0; at < text.size();)
	{
		size_t newline_at = text.find_first_of('\n', at);
		
		if(newline_at != std::string::npos && newline_at <= (at + cols))
		{
			/* There is a newline within one row's worth of text of our current position.
			 * Add all the text up to it and continue from after it.
			*/
			lines.push_back(text.substr(at, newline_at - at));
			at = newline_at + 1;
		}
		else{
			/* The line is too long, just wrap it at whatever character is on the boundary.
			 *
			 * std::string::substr() will clamp the length if it goes beyond the end of
			 * the string.
			*/
			lines.push_back(text.substr(at, cols));
			at += cols;
		}
	}
	
	lines.erase(lines.begin(), std::next(lines.begin(), std::min((size_t)(from_line), lines.size())));
	lines.erase(std::next(lines.begin(), std::min((size_t)(max_lines), lines.size())), lines.end());
	
	return lines;
}

void REHex::Document::_raise_moved()
{
	wxCommandEvent event(REHex::EV_CURSOR_MOVED);
	event.SetEventObject(this);
	
	wxPostEvent(this, event);
}

/* Calculate the width of a character in hex_font. */
int REHex::Document::hf_char_width()
{
	return hf_string_width(1);
}

/* Calculate the bounding box for a string which is length characters long when
 * rendered using hex_font. The string should fit within the box.
 *
 * We can't just multiply the width of a single character because certain
 * platforms *cough* *OSX* use subpixel co-ordinates for character spacing.
*/
int REHex::Document::hf_string_width(int length)
{
	if(length <= PRECOMP_HF_STRING_WIDTH_TO)
	{
		return hf_string_width_precomp[length - 1];
	}
	
	wxClientDC dc(this);
	dc.SetFont(*hex_font);
	
	wxSize te = dc.GetTextExtent(std::string(length, 'X'));
	return te.GetWidth();
}

/* Calculate the character at the pixel offset relative to the start of the string. */
int REHex::Document::hf_char_at_x(int x_px)
{
	for(int i = 0;; ++i)
	{
		int w = hf_string_width(i + 1);
		if(w > x_px)
		{
			return i;
		}
	}
}

REHex::Document::Region::~Region() {}

REHex::Document::Region::Data::Data(off_t d_offset, off_t d_length):
	d_offset(d_offset), d_length(d_length) {}

void REHex::Document::Region::Data::update_lines(REHex::Document &doc, wxDC &dc)
{
	/* Height of the region is simply the number of complete lines of data plus an incomplete
	 * one if the data isn't a round number of lines.
	*/
	y_lines = (d_length / doc.bytes_per_line_calc) + !!(d_length % doc.bytes_per_line_calc);
}

void REHex::Document::Region::Data::draw(REHex::Document &doc, wxDC &dc, int x, int64_t y)
{
	const REHex::Palette &pal = wxGetApp().palette;
	
	dc.SetFont(*(doc.hex_font));
	
	wxPen norm_fg_1px(pal[Palette::PAL_NORMAL_TEXT_FG], 1);
	wxPen selected_bg_1px(pal[Palette::PAL_SELECTED_TEXT_BG], 1);
	dc.SetBrush(*wxTRANSPARENT_BRUSH);
	
	bool alternate_row = true;
	
	auto normal_text_colour = [&dc,&pal,&alternate_row]()
	{
		dc.SetTextForeground(pal[alternate_row ? Palette::PAL_ALTERNATE_TEXT_FG : Palette::PAL_NORMAL_TEXT_FG ]);
		dc.SetBackgroundMode(wxTRANSPARENT);
	};
	
	auto inverted_text_colour = [&dc,&pal]()
	{
		dc.SetTextForeground(pal[Palette::PAL_INVERT_TEXT_FG]);
		dc.SetTextBackground(pal[Palette::PAL_INVERT_TEXT_BG]);
		dc.SetBackgroundMode(wxSOLID);
	};
	
	auto selected_text_colour = [&dc,&pal]()
	{
		dc.SetTextForeground(pal[Palette::PAL_SELECTED_TEXT_FG]);
		dc.SetTextBackground(pal[Palette::PAL_SELECTED_TEXT_BG]);
		dc.SetBackgroundMode(wxSOLID);
	};
	
	auto highlighted_text_colour = [&dc,&pal](int highlight_idx)
	{
		dc.SetTextForeground(pal.get_highlight_fg(highlight_idx));
		dc.SetTextBackground(pal.get_highlight_bg(highlight_idx));
		dc.SetBackgroundMode(wxSOLID);
	};
	
	/* If we are scrolled part-way into a data region, don't render data above the client area
	 * as it would get expensive very quickly with large files.
	*/
	int64_t skip_lines = (y < 0 ? (-y / doc.hf_height) : 0);
	off_t skip_bytes  = skip_lines * doc.bytes_per_line_calc;
	
	/* Increment y up to our real drawing start point. We can now trust it to be within a
	 * hf_height of zero, not the stratospheric integer-overflow-causing values it could
	 * previously have on huge files.
	*/
	y += skip_lines * doc.hf_height;
	
	/* The maximum amount of data that can be drawn on the screen before we're past the bottom
	 * of the client area. Drawing more than this would be pointless and very expensive in the
	 * case of large files.
	*/
	int max_lines = ((doc.client_height - y) / doc.hf_height) + 1;
	int max_bytes = max_lines * doc.bytes_per_line_calc;
	
	/* Fetch the data to be drawn. */
	std::vector<unsigned char> data = doc.buffer->read_data(d_offset + skip_bytes, std::min((off_t)(max_bytes), (d_length - skip_bytes)));
	
	/* The offset of the character in the Buffer currently being drawn. */
	off_t cur_off = d_offset + skip_bytes;
	
	bool hex_active   = doc.HasFocus() && doc.cursor_state != CSTATE_ASCII;
	bool ascii_active = doc.HasFocus() && doc.cursor_state == CSTATE_ASCII;
	
	off_t cursor_pos = doc.get_cursor_position();
	
	for(auto di = data.begin();;)
	{
		int hex_base_x = x;
		int hex_x      = hex_base_x;
		int hex_x_char = 0;
		
		alternate_row = !alternate_row;
		
		if(doc.offset_column)
		{
			/* Draw the offsets to the left */
			char offset_str[64];
			snprintf(offset_str, sizeof(offset_str), "%08X:%08X",
				(unsigned)((cur_off & 0xFFFFFFFF00000000) >> 32),
				(unsigned)(cur_off & 0xFFFFFFFF));
			
			normal_text_colour();
			dc.DrawText(offset_str, x, y);
			
			hex_base_x += doc.offset_column_width;
			hex_x      += doc.offset_column_width;
		}
		
		int ascii_base_x = x + doc.ascii_text_x;
		int ascii_x      = ascii_base_x;
		int ascii_x_char = 0;
		
		wxString hex_str, ascii_string;
		
		for(unsigned int c = 0; c < doc.bytes_per_line_calc && di != data.end(); ++c)
		{
			if(c > 0 && (c % doc.bytes_per_group) == 0)
			{
				hex_str.append(1, ' ');
				
				hex_x = hex_base_x + doc.hf_string_width(++hex_x_char);
			}
			
			unsigned char byte        = *(di++);
			unsigned char high_nibble = (byte & 0xF0) >> 4;
			unsigned char low_nibble  = (byte & 0x0F);
			
			auto highlight = NestedOffsetLengthMap_get(doc.highlights, cur_off);
			
			auto draw_nibble = [&hex_x,y,&dc,&doc,&hex_str,&inverted_text_colour,&selected_text_colour,&highlighted_text_colour,&cur_off,&hex_active,&hex_base_x,&hex_x_char,&highlight](unsigned char nibble, bool invert)
			{
				const char *nibble_to_hex = "0123456789ABCDEF";
				
				if(invert && doc.cursor_visible)
				{
					inverted_text_colour();
					
					char str[] = { nibble_to_hex[nibble], '\0' };
					dc.DrawText(str, hex_x, y);
					
					hex_str.append(1, ' ');
				}
				else if(cur_off >= doc.selection_off
					&& cur_off < (doc.selection_off + doc.selection_length)
					&& hex_active)
				{
					selected_text_colour();
					
					char str[] = { nibble_to_hex[nibble], '\0' };
					dc.DrawText(str, hex_x, y);
					
					hex_str.append(1, ' ');
				}
				else if(highlight != doc.highlights.end() && hex_active)
				{
					highlighted_text_colour(highlight->second);
					
					char str[] = { nibble_to_hex[nibble], '\0' };
					dc.DrawText(str, hex_x, y);
					
					hex_str.append(1, ' ');
				}
				else{
					hex_str.append(1, nibble_to_hex[nibble]);
				}
				
				hex_x = hex_base_x + doc.hf_string_width(++hex_x_char);
			};
			
			bool inv_high, inv_low;
			if(cur_off == cursor_pos && hex_active)
			{
				if(doc.cursor_state == CSTATE_HEX)
				{
					inv_high = !doc.insert_mode;
					inv_low  = !doc.insert_mode;
				}
				else /* if(doc.cursor_state == CSTATE_HEX_MID) */
				{
					inv_high = false;
					inv_low  = true;
				}
			}
			else{
				inv_high = false;
				inv_low  = false;
			}
			
			if(cur_off >= doc.selection_off && cur_off < (doc.selection_off + doc.selection_length) && !hex_active)
			{
				dc.SetPen(selected_bg_1px);
				
				if(cur_off == doc.selection_off || c == 0)
				{
					/* Draw vertical line left of selection. */
					dc.DrawLine(hex_x, y, hex_x, (y + doc.hf_height));
				}
				
				if(cur_off == (doc.selection_off + doc.selection_length - 1) || c == (doc.bytes_per_line_calc - 1))
				{
					/* Draw vertical line right of selection. */
					dc.DrawLine((hex_x + doc.hf_string_width(2) - 1), y, (hex_x + doc.hf_string_width(2) - 1), (y + doc.hf_height));
				}
				
				if(cur_off < (doc.selection_off + doc.bytes_per_line_calc))
				{
					/* Draw horizontal line above selection. */
					dc.DrawLine(hex_x, y, (hex_x + doc.hf_string_width(2)), y);
				}
				
				if(cur_off > doc.selection_off && cur_off <= (doc.selection_off + doc.bytes_per_line_calc) && c > 0 && (c % doc.bytes_per_group) == 0)
				{
					/* Draw horizontal line above gap along top of selection. */
					dc.DrawLine((hex_x - doc.hf_char_width()), y, hex_x, y);
				}
				
				if(cur_off >= (doc.selection_off + doc.selection_length - doc.bytes_per_line_calc))
				{
					/* Draw horizontal line below selection. */
					dc.DrawLine(hex_x, (y + doc.hf_height - 1), (hex_x + doc.hf_string_width(2)), (y + doc.hf_height - 1));
					
					if(c > 0 && (c % doc.bytes_per_group) == 0)
					{
						/* Draw horizontal line below gap along bottom of selection. */
						dc.DrawLine((hex_x - doc.hf_char_width()), (y + doc.hf_height - 1), hex_x, (y + doc.hf_height - 1));
					}
				}
			}
			else if(highlight != doc.highlights.end() && !hex_active)
			{
				dc.SetPen(wxPen(pal.get_highlight_bg(highlight->second), 1));
				
				off_t highlight_off    = highlight->first.offset;
				off_t highlight_length = highlight->first.length;
				
				if(cur_off == highlight_off || c == 0)
				{
					/* Draw vertical line left of highlight. */
					dc.DrawLine(hex_x, y, hex_x, (y + doc.hf_height));
				}
				
				if(cur_off == (highlight_off + highlight_length - 1) || c == (doc.bytes_per_line_calc - 1))
				{
					/* Draw vertical line right of highlight. */
					dc.DrawLine((hex_x + doc.hf_string_width(2) - 1), y, (hex_x + doc.hf_string_width(2) - 1), (y + doc.hf_height));
				}
				
				if(cur_off < (highlight_off + doc.bytes_per_line_calc))
				{
					/* Draw horizontal line above highlight. */
					dc.DrawLine(hex_x, y, (hex_x + doc.hf_string_width(2)), y);
				}
				
				if(cur_off > highlight_off && cur_off <= (highlight_off + doc.bytes_per_line_calc) && c > 0 && (c % doc.bytes_per_group) == 0)
				{
					/* Draw horizontal line above gap along top of highlight. */
					dc.DrawLine((hex_x - doc.hf_char_width()), y, hex_x, y);
				}
				
				if(cur_off >= (highlight_off + highlight_length - doc.bytes_per_line_calc))
				{
					/* Draw horizontal line below highlight. */
					dc.DrawLine(hex_x, (y + doc.hf_height - 1), (hex_x + doc.hf_string_width(2)), (y + doc.hf_height - 1));
					
					if(c > 0 && (c % doc.bytes_per_group) == 0)
					{
						/* Draw horizontal line below gap along bottom of highlight. */
						dc.DrawLine((hex_x - doc.hf_char_width()), (y + doc.hf_height - 1), hex_x, (y + doc.hf_height - 1));
					}
				}
			}
			
			if(cur_off == cursor_pos && doc.insert_mode && ((doc.cursor_visible && doc.cursor_state == CSTATE_HEX) || !hex_active))
			{
				/* Draw insert cursor. */
				dc.SetPen(norm_fg_1px);
				dc.DrawLine(hex_x, y, hex_x, y + doc.hf_height);
			}
			
			if(cur_off == cursor_pos && !doc.insert_mode && !hex_active)
			{
				/* Draw inactive overwrite cursor. */
				dc.SetPen(norm_fg_1px);
				
				if(doc.cursor_state == CSTATE_HEX_MID)
				{
					dc.DrawRectangle(hex_x + doc.hf_char_width(), y, doc.hf_char_width(), doc.hf_height);
				}
				else{
					dc.DrawRectangle(hex_x, y, doc.hf_string_width(2), doc.hf_height);
				}
			}
			
			draw_nibble(high_nibble, inv_high);
			draw_nibble(low_nibble,  inv_low);
			
			if(doc.show_ascii)
			{
				char ascii_byte = isasciiprint(byte)
					? byte
					: '.';
				
				if(ascii_active)
				{
					if(cur_off == cursor_pos && !doc.insert_mode && doc.cursor_visible)
					{
						inverted_text_colour();
						
						char str[] = { ascii_byte, '\0' };
						dc.DrawText(str, ascii_x, y);
						
						ascii_string.append(" ");
					}
					else if(cur_off >= doc.selection_off && cur_off < (doc.selection_off + doc.selection_length))
					{
						selected_text_colour();
						
						char str[] = { ascii_byte, '\0' };
						dc.DrawText(str, ascii_x, y);
						
						ascii_string.append(" ");
					}
					else if(highlight != doc.highlights.end())
					{
						highlighted_text_colour(highlight->second);
						
						char str[] = { ascii_byte, '\0' };
						dc.DrawText(str, ascii_x, y);
						
						ascii_string.append(" ");
					}
					else{
						ascii_string.append(1, ascii_byte);
					}
				}
				else{
					ascii_string.append(1, ascii_byte);
					
					if(cur_off == cursor_pos && !doc.insert_mode)
					{
						dc.SetPen(norm_fg_1px);
						dc.DrawRectangle(ascii_x, y, doc.hf_char_width(), doc.hf_height);
					}
					else if(cur_off >= doc.selection_off && cur_off < (doc.selection_off + doc.selection_length))
					{
						dc.SetPen(selected_bg_1px);
						
						if(cur_off == doc.selection_off || c == 0)
						{
							/* Draw vertical line left of selection. */
							dc.DrawLine(ascii_x, y, ascii_x, (y + doc.hf_height));
						}
						
						if(cur_off == (doc.selection_off + doc.selection_length - 1) || c == (doc.bytes_per_line_calc - 1))
						{
							/* Draw vertical line right of selection. */
							dc.DrawLine((ascii_x + doc.hf_char_width() - 1), y, (ascii_x + doc.hf_char_width() - 1), (y + doc.hf_height));
						}
						
						if(cur_off < (doc.selection_off + doc.bytes_per_line_calc))
						{
							/* Draw horizontal line above selection. */
							dc.DrawLine(ascii_x, y, (ascii_x + doc.hf_char_width()), y);
						}
						
						if(cur_off >= (doc.selection_off + doc.selection_length - doc.bytes_per_line_calc))
						{
							/* Draw horizontal line below selection. */
							dc.DrawLine(ascii_x, (y + doc.hf_height - 1), (ascii_x + doc.hf_char_width()), (y + doc.hf_height - 1));
						}
					}
					else if(highlight != doc.highlights.end())
					{
						dc.SetPen(wxPen(pal.get_highlight_bg(highlight->second), 1));
						
						off_t highlight_off    = highlight->first.offset;
						off_t highlight_length = highlight->first.length;
						
						if(cur_off == highlight_off || c == 0)
						{
							/* Draw vertical line left of highlight. */
							dc.DrawLine(ascii_x, y, ascii_x, (y + doc.hf_height));
						}
						
						if(cur_off == (highlight_off + highlight_length - 1) || c == (doc.bytes_per_line_calc - 1))
						{
							/* Draw vertical line right of highlight. */
							dc.DrawLine((ascii_x + doc.hf_char_width() - 1), y, (ascii_x + doc.hf_char_width() - 1), (y + doc.hf_height));
						}
						
						if(cur_off < (highlight_off + doc.bytes_per_line_calc))
						{
							/* Draw horizontal line above highlight. */
							dc.DrawLine(ascii_x, y, (ascii_x + doc.hf_char_width()), y);
						}
						
						if(cur_off >= (highlight_off + highlight_length - doc.bytes_per_line_calc))
						{
							/* Draw horizontal line below highlight. */
							dc.DrawLine(ascii_x, (y + doc.hf_height - 1), (ascii_x + doc.hf_char_width()), (y + doc.hf_height - 1));
						}
					}
				}
				
				if(cur_off == cursor_pos && doc.insert_mode && (doc.cursor_visible || !ascii_active))
				{
					dc.SetPen(norm_fg_1px);
					dc.DrawLine(ascii_x, y, ascii_x, y + doc.hf_height);
				}
				
				ascii_x = ascii_base_x + doc.hf_string_width(++ascii_x_char);
			}
			
			++cur_off;
		}
		
		if(cur_off == cursor_pos && cur_off == doc.buffer->length())
		{
			/* Draw the insert cursor past the end of the line if we've just written
			 * the last byte to the screen.
			 *
			 * TODO: Draw on next line if we're at the end of one.
			*/
			
			if(doc.insert_mode)
			{
				dc.SetPen(norm_fg_1px);
				dc.DrawLine(hex_x, y, hex_x, y + doc.hf_height);
			}
			else{
				/* Draw the cursor in red if trying to overwrite at an invalid
				 * position. Should only happen in empty files.
				*/
				dc.SetPen(*wxRED_PEN);
				dc.DrawLine(hex_x, y, hex_x, y + doc.hf_height);
			}
		}
		
		normal_text_colour();
		
		dc.DrawText(hex_str, hex_base_x, y);
		
		if(doc.show_ascii)
		{
			dc.DrawText(ascii_string, ascii_base_x, y);
		}
		
		y += doc.hf_height;
		
		if(di == data.end())
		{
			break;
		}
	}
}

off_t REHex::Document::Region::Data::offset_at_xy_hex(REHex::Document &doc, int mouse_x_px, uint64_t mouse_y_lines)
{
	if(mouse_x_px < (int)(doc.offset_column_width))
	{
		return -1;
	}
	
	mouse_x_px -= doc.offset_column_width;
	
	/* Calculate the offset within the Buffer of the first byte on this line
	 * and the offset (plus one) of the last byte on this line.
	*/
	off_t line_data_begin = d_offset + ((off_t)(doc.bytes_per_line_calc) * mouse_y_lines);
	off_t line_data_end   = std::min((line_data_begin + doc.bytes_per_line_calc), (d_offset + d_length));
	
	unsigned int char_offset = doc.hf_char_at_x(mouse_x_px);
	if(((char_offset + 1) % ((doc.bytes_per_group * 2) + 1)) == 0)
	{
		/* Click was over a space between byte groups. */
		return -1;
	}
	else{
		unsigned int char_offset_sub_spaces = char_offset - (char_offset / ((doc.bytes_per_group * 2) + 1));
		unsigned int line_offset_bytes      = char_offset_sub_spaces / 2;
		off_t clicked_offset                = line_data_begin + line_offset_bytes;
		
		if(clicked_offset < line_data_end)
		{
			/* Clicked on a byte */
			return clicked_offset;
		}
		else{
			/* Clicked past the end of the line */
			return -1;
		}
	}
}

off_t REHex::Document::Region::Data::offset_at_xy_ascii(REHex::Document &doc, int mouse_x_px, uint64_t mouse_y_lines)
{
	if(!doc.show_ascii || mouse_x_px < (int)(doc.ascii_text_x))
	{
		return -1;
	}
	
	mouse_x_px -= doc.ascii_text_x;
	
	/* Calculate the offset within the Buffer of the first byte on this line
	 * and the offset (plus one) of the last byte on this line.
	*/
	off_t line_data_begin = d_offset + ((off_t)(doc.bytes_per_line_calc) * mouse_y_lines);
	off_t line_data_end   = std::min((line_data_begin + doc.bytes_per_line_calc), (d_offset + d_length));
	
	unsigned int char_offset = doc.hf_char_at_x(mouse_x_px);
	off_t clicked_offset     = line_data_begin + char_offset;
	
	if(clicked_offset < line_data_end)
	{
		/* Clicked on a character */
		return clicked_offset;
	}
	else{
		/* Clicked past the end of the line */
		return -1;
	}
}

off_t REHex::Document::Region::Data::offset_near_xy_hex(REHex::Document &doc, int mouse_x_px, uint64_t mouse_y_lines)
{
	/* Calculate the offset within the Buffer of the first byte on this line
	 * and the offset (plus one) of the last byte on this line.
	*/
	off_t line_data_begin = d_offset + ((off_t)(doc.bytes_per_line_calc) * mouse_y_lines);
	off_t line_data_end   = std::min((line_data_begin + doc.bytes_per_line_calc), (d_offset + d_length));
	
	if(mouse_x_px < (int)(doc.offset_column_width))
	{
		/* Mouse is in offset area, return offset of last byte of previous line. */
		return line_data_begin - 1;
	}
	
	mouse_x_px -= doc.offset_column_width;
	
	unsigned int char_offset = doc.hf_char_at_x(mouse_x_px);
	
	unsigned int char_offset_sub_spaces = char_offset - (char_offset / ((doc.bytes_per_group * 2)));
	unsigned int line_offset_bytes      = char_offset_sub_spaces / 2;
	off_t clicked_offset                = line_data_begin + line_offset_bytes;
	
	if(clicked_offset < line_data_end)
	{
		/* Mouse is on a byte. */
		return clicked_offset;
	}
	else{
		/* Mouse is past end of line, return last byte of this line. */
		return line_data_end - 1;
	}
}

off_t REHex::Document::Region::Data::offset_near_xy_ascii(REHex::Document &doc, int mouse_x_px, uint64_t mouse_y_lines)
{
	/* Calculate the offset within the Buffer of the first byte on this line
	 * and the offset (plus one) of the last byte on this line.
	*/
	off_t line_data_begin = d_offset + ((off_t)(doc.bytes_per_line_calc) * mouse_y_lines);
	off_t line_data_end   = std::min((line_data_begin + doc.bytes_per_line_calc), (d_offset + d_length));
	
	if(!doc.show_ascii || mouse_x_px < (int)(doc.ascii_text_x))
	{
		/* Mouse is left of ASCII area, return last byte of previous line. */
		return line_data_begin - 1;
	}
	
	mouse_x_px -= doc.ascii_text_x;
	
	unsigned int char_offset = doc.hf_char_at_x(mouse_x_px);
	off_t clicked_offset     = line_data_begin + char_offset;
	
	if(clicked_offset < line_data_end)
	{
		/* Mouse is on a character. */
		return clicked_offset;
	}
	else{
		/* Mouse is beyond end of line, return last byte of this line. */
		return line_data_end - 1;
	}
}

REHex::Document::Region::Comment::Comment(off_t c_offset, const wxString &c_text):
	c_offset(c_offset), c_text(c_text) {}

void REHex::Document::Region::Comment::update_lines(REHex::Document &doc, wxDC &dc)
{
	unsigned int row_chars = doc.hf_char_at_x(doc.client_width) - 1;
	if(row_chars == 0)
	{
		/* Zero columns of width. Probably still initialising. */
		this->y_lines = 1;
	}
	else{
		auto comment_lines = _format_text(c_text, row_chars);
		this->y_lines  = comment_lines.size() + 1;
	}
}

void REHex::Document::Region::Comment::draw(REHex::Document &doc, wxDC &dc, int x, int64_t y)
{
	/* Comments are currently drawn at the width of the client area, always being fully visible
	 * (along their X axis) and not scrolling with the file data.
	*/
	x = 0;
	
	dc.SetFont(*(doc.hex_font));
	
	unsigned int row_chars = doc.hf_char_at_x(doc.client_width) - 1;
	if(row_chars == 0)
	{
		/* Zero columns of width. Probably still initialising. */
		return;
	}
	
	auto lines = _format_text(c_text, row_chars);
	
	{
		int box_x = x + (doc.hf_char_width() / 4);
		int box_y = y + (doc.hf_height / 4);
		
		unsigned int box_w = doc.client_width - (doc.hf_char_width() / 2);
		unsigned int box_h = (lines.size() * doc.hf_height) + (doc.hf_height / 2);
		
		dc.SetPen(wxPen(*wxBLACK, 1));
		dc.SetBrush(*wxLIGHT_GREY_BRUSH);
		
		dc.DrawRectangle(box_x, box_y, box_w, box_h);
	}
	
	y += doc.hf_height / 2;
	
	dc.SetTextForeground(*wxBLACK);
	dc.SetBackgroundMode(wxTRANSPARENT);
	
	for(auto li = lines.begin(); li != lines.end(); ++li)
	{
		dc.DrawText(*li, (x + (doc.hf_char_width() / 2)), y);
		y += doc.hf_height;
	}
}
