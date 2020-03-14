/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2020 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <algorithm>
#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <iterator>
#include <jansson.h>
#include <limits>
#include <map>
#include <stack>
#include <string>
#include <wx/clipbrd.h>
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
	ID_SELECT_TIMER,
	ID_CLEAR_HIGHLIGHT,
	ID_EDIT_COMMENT,
	ID_DELETE_COMMENT,
	ID_COPY_COMMENT,
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
	EVT_MENU(ID_CLEAR_HIGHLIGHT, REHex::Document::OnClearHighlight)
END_EVENT_TABLE()

wxDEFINE_EVENT(REHex::EV_CURSOR_MOVED,      wxCommandEvent);
wxDEFINE_EVENT(REHex::EV_INSERT_TOGGLED,    wxCommandEvent);
wxDEFINE_EVENT(REHex::EV_SELECTION_CHANGED, wxCommandEvent);
wxDEFINE_EVENT(REHex::EV_COMMENT_MODIFIED,  wxCommandEvent);
wxDEFINE_EVENT(REHex::EV_DATA_MODIFIED,     wxCommandEvent);
wxDEFINE_EVENT(REHex::EV_UNDO_UPDATE,       wxCommandEvent);
wxDEFINE_EVENT(REHex::EV_BECAME_DIRTY,      wxCommandEvent);
wxDEFINE_EVENT(REHex::EV_BECAME_CLEAN,      wxCommandEvent);

REHex::Document::Document(wxWindow *parent):
	wxControl(),
	redraw_cursor_timer(this, ID_REDRAW_CURSOR),
	mouse_select_timer(this, ID_SELECT_TIMER)
{
	dirty = false;
	
	_ctor_pre(parent);
	
	buffer = new REHex::Buffer();
	title  = "Untitled";
	
	_reinit_regions();
	
	_ctor_post();
}

REHex::Document::Document(wxWindow *parent, const std::string &filename):
	wxControl(),
	filename(filename),
	redraw_cursor_timer(this, ID_REDRAW_CURSOR),
	mouse_select_timer(this, ID_SELECT_TIMER)
{
	dirty = false;
	
	_ctor_pre(parent);
	
	buffer = new REHex::Buffer(filename);
	
	size_t last_slash = filename.find_last_of("/\\");
	title = (last_slash != std::string::npos ? filename.substr(last_slash + 1) : filename);
	
	std::string meta_filename = filename + ".rehex-meta";
	if(wxFileExists(meta_filename))
	{
		_load_metadata(meta_filename);
	}
	
	_reinit_regions();
	
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
	
	set_dirty(false);
}

void REHex::Document::save(const std::string &filename)
{
	buffer->write_inplace(filename);
	this->filename = filename;
	
	size_t last_slash = filename.find_last_of("/\\");
	title = (last_slash != std::string::npos ? filename.substr(last_slash + 1) : filename);
	
	_save_metadata(filename + ".rehex-meta");
	
	set_dirty(false);
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

REHex::Document::InlineCommentMode REHex::Document::get_inline_comment_mode()
{
	return inline_comment_mode;
}

void REHex::Document::set_inline_comment_mode(InlineCommentMode mode)
{
	inline_comment_mode = mode;
	
	_reinit_regions();
	
	wxClientDC dc(this);
	_recalc_regions(dc);
	
	_update_vscroll();
	Refresh();
}

bool REHex::Document::get_highlight_selection_match()
{
	return highlight_selection_match;
}

void REHex::Document::set_highlight_selection_match(bool highlight_selection_match)
{
	this->highlight_selection_match = highlight_selection_match;
	Refresh();
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
	
	/* TODO: Limit paint to affected area */
	Refresh();
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
	
	if(length <= 0 || mouse_shift_initial < off || mouse_shift_initial > (off + length))
	{
		mouse_shift_initial = -1;
	}
	
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

void REHex::Document::overwrite_data(off_t offset, const void *data, off_t length)
{
	_tracked_overwrite_data("change data", offset, (const unsigned char*)(data), length, get_cursor_position(), cursor_state);
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

const REHex::NestedOffsetLengthMap<REHex::Document::Comment> &REHex::Document::get_comments() const
{
	return comments;
}

bool REHex::Document::set_comment(off_t offset, off_t length, const Comment &comment)
{
	assert(offset >= 0);
	assert(length >= 0);
	
	if(NestedOffsetLengthMap_set(comments, offset, length, comment))
	{
		_reinit_regions();
		
		wxClientDC dc(this);
		_recalc_regions(dc);
		
		_raise_comment_modified();
		
		return true;
	}
	
	return false;
}

bool REHex::Document::erase_comment(off_t offset, off_t length)
{
	if(comments.erase(NestedOffsetLengthMapKey(offset, length)) > 0)
	{
		_reinit_regions();
		
		wxClientDC dc(this);
		_recalc_regions(dc);
		
		_raise_comment_modified();
		
		return true;
	}
	
	return false;
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

/* Maximum size of the string that would be returned by handle_copy() with the current selection.
 * The actual string may be shorter as unprintable characters are skipped in ASCII mode.
*/
size_t REHex::Document::copy_upper_limit()
{
	if(selection_length > 0)
	{
		if(cursor_state == CSTATE_ASCII)
		{
			return selection_length;
		}
		else{
			return selection_length * 2;
		}
	}
	else{
		/* Nothing selected */
		return 0;
	}
}

void REHex::Document::handle_paste(const NestedOffsetLengthMap<Document::Comment> &clipboard_comments)
{
	off_t cursor_pos = get_cursor_position();
	off_t buffer_length = this->buffer_length();
	
	for(auto cc = clipboard_comments.begin(); cc != clipboard_comments.end(); ++cc)
	{
		if((cursor_pos + cc->first.offset + cc->first.length) >= buffer_length)
		{
			wxMessageBox("Cannot paste comment(s) - would extend beyond end of file", "Error", (wxOK | wxICON_ERROR), this);
			return;
		}
		
		if(comments.find(NestedOffsetLengthMapKey(cursor_pos + cc->first.offset, cc->first.length)) != comments.end()
			|| !NestedOffsetLengthMap_can_set(comments, cursor_pos + cc->first.offset, cc->first.length))
		{
			wxMessageBox("Cannot paste comment(s) - would overwrite one or more existing", "Error", (wxOK | wxICON_ERROR), this);
			return;
		}
	}
	
	_tracked_change("paste comment(s)",
		[this, cursor_pos, clipboard_comments]()
		{
			for(auto cc = clipboard_comments.begin(); cc != clipboard_comments.end(); ++cc)
			{
				NestedOffsetLengthMap_set(comments, cursor_pos + cc->first.offset, cc->first.length, cc->second);
			}
			
			set_dirty(true);
			
			_reinit_regions();
			
			wxClientDC dc(this);
			_recalc_regions(dc);
			
			_raise_comment_modified();
		},
		[this]()
		{
			/* Comments are restored implicitly. */
			_raise_comment_modified();
		});
}

void REHex::Document::undo()
{
	if(!undo_stack.empty())
	{
		auto &act = undo_stack.back();
		act.undo();
		
		cpos_off     = act.old_cpos_off;
		cursor_state = act.old_cursor_state;
		comments     = act.old_comments;
		highlights   = act.old_highlights;
		
		_reinit_regions();
		
		wxClientDC dc(this);
		_recalc_regions(dc);
		
		redo_stack.push_back(act);
		undo_stack.pop_back();
		
		_raise_undo_update();
		
		Refresh();
	}
}

const char *REHex::Document::undo_desc()
{
	if(!undo_stack.empty())
	{
		return undo_stack.back().desc;
	}
	else{
		return NULL;
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
		
		_raise_undo_update();
		
		Refresh();
	}
}

const char *REHex::Document::redo_desc()
{
	if(!redo_stack.empty())
	{
		return redo_stack.back().desc;
	}
	else{
		return NULL;
	}
}

void REHex::Document::OnPaint(wxPaintEvent &event)
{
	wxBufferedPaintDC dc(this);
	
	dc.SetFont(*hex_font);
	
	dc.SetBackground(wxBrush((*active_palette)[Palette::PAL_NORMAL_TEXT_BG]));
	dc.Clear();
	
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
	
	/* Clamp to 1 if window is too small to display a single whole line, to avoid edge casey
	 * crashing in the scrolling code.
	*/
	visible_lines = std::max((client_height / hf_height), 1);
	
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
	
	auto calc_row_width = [this](unsigned int line_bytes, const REHex::Document::Region::Data *dr)
	{
		return offset_column_width
			/* indentation */
			+ (_indent_width(dr->indent_depth) * 2)
			
			/* hex data */
			+ hf_string_width(line_bytes * 2)
			+ hf_string_width((line_bytes - 1) / bytes_per_group)
			
			/* ASCII data */
			+ (show_ascii * hf_char_width())
			+ (show_ascii * hf_string_width(line_bytes));
	};
	
	virtual_width = 0;
	
	for(auto r = regions.begin(); r != regions.end(); ++r)
	{
		REHex::Document::Region::Data *dr = dynamic_cast<REHex::Document::Region::Data*>(*r);
		if(dr != NULL)
		{
			/* Decide how many bytes to display per line */
			
			if(bytes_per_line == 0) /* 0 is "as many as will fit in the window" */
			{
				/* TODO: Can I do this algorithmically? */
				
				dr->bytes_per_line_actual = 1;
				
				while(calc_row_width((dr->bytes_per_line_actual + 1), dr) <= client_width)
				{
					++(dr->bytes_per_line_actual);
				}
			}
			else{
				dr->bytes_per_line_actual = bytes_per_line;
			}
			
			int dr_min_width = calc_row_width(dr->bytes_per_line_actual, dr);
			if(dr_min_width > virtual_width)
			{
				virtual_width = dr_min_width;
			}
		}
	}
	
	if(virtual_width < client_width)
	{
		/* Raise virtual_width to client_width, so that things drawn relative to the right
		 * edge of the virtual client area don't end up in the middle.
		*/
		virtual_width = client_width;
	}
	
	/* TODO: Preserve/scale the position as the window size changes. */
	SetScrollbar(wxHORIZONTAL, 0, client_width, virtual_width);
	
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
	
	if((modifiers & wxMOD_CONTROL) && (key != WXK_HOME && key != WXK_END))
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
	else if((modifiers == wxMOD_NONE || modifiers == wxMOD_SHIFT || ((modifiers & ~wxMOD_SHIFT) == wxMOD_CONTROL && (key == WXK_HOME || key == WXK_END)))
		&& (key == WXK_LEFT || key == WXK_RIGHT || key == WXK_UP || key == WXK_DOWN || key == WXK_HOME || key == WXK_END))
	{
		off_t new_cursor_pos = cursor_pos;
		
		if(key == WXK_LEFT)
		{
			new_cursor_pos = cursor_pos - (cursor_pos > 0);
		}
		else if(key == WXK_RIGHT)
		{
			off_t max_pos = std::max((buffer_length() - !get_insert_mode()), (off_t)(0));
			new_cursor_pos = std::min((cursor_pos + 1), max_pos);
		}
		else if(key == WXK_UP)
		{
			auto cur_region = _data_region_by_offset(cursor_pos);
			assert(cur_region != NULL);
			
			off_t offset_within_cur = cursor_pos - cur_region->d_offset;
			
			if(offset_within_cur >= cur_region->bytes_per_line_actual)
			{
				/* We are at least on the second line of the current
				 * region, can jump to the previous one.
				*/
				new_cursor_pos = cursor_pos - cur_region->bytes_per_line_actual;
			}
			else if(cur_region->d_offset > 0)
			{
				/* We are on the first line of the current region, but there is at
				 * last one region before us.
				*/
				auto prev_region = _data_region_by_offset(cur_region->d_offset - 1);
				assert(prev_region != NULL);
				
				/* How many bytes on the last line of prev_region? */
				off_t pr_last_line_len = (prev_region->d_length % prev_region->bytes_per_line_actual);
				if(pr_last_line_len == 0)
				{
					pr_last_line_len = prev_region->bytes_per_line_actual;
				}
				
				if(pr_last_line_len > offset_within_cur)
				{
					/* The last line of the previous block is at least long
					 * enough to have a byte above the current cursor position
					 * on the screen.
					*/
					
					new_cursor_pos = (cursor_pos - offset_within_cur) - (pr_last_line_len - offset_within_cur);
				}
				else{
					/* The last line of the previous block falls short of the
					 * horizontal position of the cursor, just jump to the end
					 * of it.
					*/
					
					new_cursor_pos = cur_region->d_offset - 1;
				}
			}
			
			if(cursor_state == CSTATE_HEX_MID)
			{
				cursor_state = CSTATE_HEX;
			}
		}
		else if(key == WXK_DOWN)
		{
			auto cur_region = _data_region_by_offset(cursor_pos);
			assert(cur_region != NULL);
			
			off_t offset_within_cur = cursor_pos - cur_region->d_offset;
			off_t remain_within_cur = cur_region->d_length - offset_within_cur;
			
			off_t last_line_within_cur = cur_region->d_length
				- (((cur_region->d_length % cur_region->bytes_per_line_actual) == 0)
					? cur_region->bytes_per_line_actual
					: (cur_region->d_length % cur_region->bytes_per_line_actual));
			
			if(remain_within_cur > cur_region->bytes_per_line_actual)
			{
				/* There is at least one more line's worth of bytes in the
				 * current region, can just skip ahead.
				*/
				new_cursor_pos = cursor_pos + cur_region->bytes_per_line_actual;
			}
			else if(offset_within_cur < last_line_within_cur)
			{
				/* There is another line in the current region which falls short of
				 * the cursor's horizontal position, jump to its end.
				*/
				new_cursor_pos = cur_region->d_offset + cur_region->d_length - 1;
			}
			else{
				auto next_region = _data_region_by_offset(cur_region->d_offset + cur_region->d_length);
				
				if(next_region != NULL && cur_region != next_region)
				{
					/* There is another region after this one, jump to the same
					 * it, offset by our offset in the current line.
					*/
					new_cursor_pos = next_region->d_offset + (offset_within_cur % cur_region->bytes_per_line_actual);
					
					/* Clamp to the end of the next region. */
					off_t max_pos = (next_region->d_offset + next_region->d_length - 1);
					new_cursor_pos = std::min(max_pos, new_cursor_pos);
				}
			}
			
			if(cursor_state == CSTATE_HEX_MID)
			{
				cursor_state = CSTATE_HEX;
			}
		}
		else if(key == WXK_HOME && (modifiers & wxMOD_CONTROL))
		{
			new_cursor_pos = 0;
			
			if(cursor_state == CSTATE_HEX_MID)
			{
				cursor_state = CSTATE_HEX;
			}
		}
		else if(key == WXK_HOME)
		{
			auto cur_region = _data_region_by_offset(cursor_pos);
			assert(cur_region != NULL);
			
			off_t offset_within_cur  = cursor_pos - cur_region->d_offset;
			off_t offset_within_line = (offset_within_cur % cur_region->bytes_per_line_actual);
			
			new_cursor_pos = cursor_pos - offset_within_line;
			
			if(cursor_state == CSTATE_HEX_MID)
			{
				cursor_state = CSTATE_HEX;
			}
		}
		else if(key == WXK_END && (modifiers & wxMOD_CONTROL))
		{
			new_cursor_pos = buffer->length() - (off_t)(!insert_mode);
			
			if(cursor_state == CSTATE_HEX_MID)
			{
				cursor_state = CSTATE_HEX;
			}
		}
		else if(key == WXK_END)
		{
			auto cur_region = _data_region_by_offset(cursor_pos);
			assert(cur_region != NULL);
			
			off_t offset_within_cur  = cursor_pos - cur_region->d_offset;
			off_t offset_within_line = (offset_within_cur % cur_region->bytes_per_line_actual);
			
			new_cursor_pos = std::min(
				(cursor_pos + ((cur_region->bytes_per_line_actual - offset_within_line) - 1)),
				((cur_region->d_offset + cur_region->d_length) - 1));
			
			if(cursor_state == CSTATE_HEX_MID)
			{
				cursor_state = CSTATE_HEX;
			}
		}
		
		set_cursor_position(new_cursor_pos);
		
		if(modifiers & wxMOD_SHIFT)
		{
			off_t selection_end = selection_off + selection_length;
			
			if(new_cursor_pos < cursor_pos)
			{
				if(selection_length > 0)
				{
					if(selection_off >= cursor_pos)
					{
						assert(selection_end >= new_cursor_pos);
						set_selection(new_cursor_pos, (selection_end - new_cursor_pos));
					}
					else{
						if(new_cursor_pos < selection_off)
						{
							set_selection(new_cursor_pos, (selection_off - new_cursor_pos));
						}
						else{
							set_selection(selection_off, (new_cursor_pos - selection_off));
						}
					}
				}
				else{
					set_selection(new_cursor_pos, (cursor_pos - new_cursor_pos));
				}
			}
			else if(new_cursor_pos > cursor_pos)
			{
				if(selection_length > 0)
				{
					if(selection_off >= cursor_pos)
					{
						if(new_cursor_pos >= selection_end)
						{
							set_selection(selection_end, (new_cursor_pos - selection_end));
						}
						else{
							set_selection(new_cursor_pos, (selection_end - new_cursor_pos));
						}
					}
					else{
						set_selection(selection_off, (new_cursor_pos - selection_off));
					}
				}
				else{
					set_selection(cursor_pos, (new_cursor_pos - cursor_pos));
				}
			}
		}
		else{
			clear_selection();
		}
	}
	else if(modifiers == wxMOD_NONE)
	{
		if(key == WXK_INSERT)
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
			if(cursor_pos < buffer->length())
			{
				edit_comment_popup(cursor_pos, 0);
			}
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
			else if(show_ascii && rel_x >= dr->ascii_text_x)
			{
				/* Click was within the ASCII area */
				
				off_t clicked_offset = dr->offset_near_xy_ascii(*this, rel_x, line_off);
				if(clicked_offset >= 0)
				{
					/* Clicked on a character */
					
					if(event.ShiftDown())
					{
						off_t old_position = (mouse_shift_initial >= 0 ? mouse_shift_initial : get_cursor_position());
						_set_cursor_position(clicked_offset, CSTATE_ASCII);
						
						if(clicked_offset > old_position)
						{
							set_selection(old_position, (clicked_offset - old_position));
						}
						else{
							set_selection(clicked_offset, (old_position - clicked_offset));
						}
						
						mouse_shift_initial  = old_position;
						mouse_down_at_offset = clicked_offset;
						mouse_down_at_x      = rel_x;
						mouse_down_in_ascii  = true;
					}
					else{
						_set_cursor_position(clicked_offset, CSTATE_ASCII);
						
						clear_selection();
						
						mouse_down_at_offset = clicked_offset;
						mouse_down_at_x      = rel_x;
						mouse_down_in_ascii  = true;
					}
					
					CaptureMouse();
					mouse_select_timer.Start(MOUSE_SELECT_INTERVAL, wxTIMER_CONTINUOUS);
					
					/* TODO: Limit paint to affected area */
					Refresh();
				}
			}
			else{
				/* Click was within the hex area */
				
				off_t clicked_offset = dr->offset_near_xy_hex(*this, rel_x, line_off);
				if(clicked_offset >= 0)
				{
					/* Clicked on a byte */
					
					if(event.ShiftDown())
					{
						off_t old_position = (mouse_shift_initial >= 0 ? mouse_shift_initial : get_cursor_position());
						_set_cursor_position(clicked_offset, CSTATE_HEX);
						
						if(clicked_offset > old_position)
						{
							set_selection(old_position, (clicked_offset - old_position));
						}
						else{
							set_selection(clicked_offset, (old_position - clicked_offset));
						}
						
						mouse_shift_initial  = old_position;
						mouse_down_at_offset = old_position;
						mouse_down_at_x      = rel_x;
						mouse_down_in_hex    = true;
					}
					else{
						_set_cursor_position(clicked_offset, CSTATE_HEX);
						
						clear_selection();
						
						mouse_down_at_offset = clicked_offset;
						mouse_down_at_x      = rel_x;
						mouse_down_in_hex    = true;
					}
					
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
			int indent_width = _indent_width(cr->indent_depth);
			
			if(
				(line_off > 0 || (mouse_y % hf_height) >= (hf_height / 4)) /* Not above top edge. */
				&& (line_off < (cr->y_lines - 1) || (mouse_y % hf_height) <= ((hf_height / 4) * 3)) /* Not below bottom edge. */
				&& rel_x >= (indent_width + (hf_width / 4)) /* Not left of left edge. */
				&& rel_x < ((virtual_width - (hf_width / 4)) - indent_width)) /* Not right of right edge. */
			{
				edit_comment_popup(cr->c_offset, cr->c_length);
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
			else if(show_ascii && rel_x >= dr->ascii_text_x)
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
			
			menu.Append(wxID_CUT, "Cu&t");
			menu.Enable(wxID_CUT,  (selection_length > 0));
			
			menu.Append(wxID_COPY,  "&Copy");
			menu.Enable(wxID_COPY, (selection_length > 0));
			
			menu.Append(wxID_PASTE, "&Paste");
			
			menu.AppendSeparator();
			
			off_t cursor_pos = get_cursor_position();
			
			auto comments_at_cur = NestedOffsetLengthMap_get_all(comments, cursor_pos);
			for(auto i = comments_at_cur.begin(); i != comments_at_cur.end(); ++i)
			{
				NestedOffsetLengthMap<Comment>::const_iterator ci = *i;
				
				wxString text = ci->second.menu_preview();
				wxMenuItem *itm = menu.Append(wxID_ANY, wxString("Edit \"") + text + "\"...");
				
				menu.Bind(wxEVT_MENU, [this, ci](wxCommandEvent &event)
				{
					edit_comment_popup(ci->first.offset, ci->first.length);
				}, itm->GetId(), itm->GetId());
			}
			
			if(comments.find(NestedOffsetLengthMapKey(cursor_pos, 0)) == comments.end()
				&& cursor_pos < buffer->length())
			{
				wxMenuItem *itm = menu.Append(wxID_ANY, "Insert comment here...");
				
				menu.Bind(wxEVT_MENU, [this, cursor_pos](wxCommandEvent &event)
				{
					edit_comment_popup(cursor_pos, 0);
				}, itm->GetId(), itm->GetId());
			}
			
			if(selection_length > 0
				&& comments.find(NestedOffsetLengthMapKey(selection_off, selection_length)) == comments.end()
				&& NestedOffsetLengthMap_can_set(comments, selection_off, selection_length))
			{
				char menu_label[64];
				snprintf(menu_label, sizeof(menu_label), "Set comment on %lld bytes...", (long long)(selection_length));
				wxMenuItem *itm =  menu.Append(wxID_ANY, menu_label);
				
				menu.Bind(wxEVT_MENU, [this](wxCommandEvent &event)
				{
					edit_comment_popup(selection_off, selection_length);
				}, itm->GetId(), itm->GetId());
			}
			
			menu.AppendSeparator();
			
			/* We need to maintain bitmap instances for lifespan of menu. */
			std::list<wxBitmap> bitmaps;
			
			off_t highlight_off;
			off_t highlight_length = 0;
			
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
				
				for(int i = 0; i < Palette::NUM_HIGHLIGHT_COLOURS; ++i)
				{
					wxMenuItem *itm = new wxMenuItem(hlmenu, wxID_ANY, " ");
					
					wxColour bg_colour = active_palette->get_highlight_bg(i);
					
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
		
		REHex::Document::Region::Comment *cr = dynamic_cast<REHex::Document::Region::Comment*>(*region);
		if(cr != NULL)
		{
			/* Mouse was clicked within a Comment region, ensure we are within the border drawn around the
			 * comment text.
			*/
			
			int hf_width = hf_char_width();
			int indent_width = _indent_width(cr->indent_depth);
			
			if(
				(line_off > 0 || (mouse_y % hf_height) >= (hf_height / 4)) /* Not above top edge. */
				&& (line_off < (cr->y_lines - 1) || (mouse_y % hf_height) <= ((hf_height / 4) * 3)) /* Not below bottom edge. */
				&& rel_x >= (indent_width + (hf_width / 4)) /* Not left of left edge. */
				&& rel_x < ((virtual_width - (hf_width / 4)) - indent_width)) /* Not right of right edge. */
			{
				wxMenu menu;
				
				menu.Append(ID_EDIT_COMMENT, "&Edit comment");
				menu.Bind(wxEVT_MENU, [this, cr](wxCommandEvent &event)
				{
					edit_comment_popup(cr->c_offset, cr->c_length);
				}, ID_EDIT_COMMENT, ID_EDIT_COMMENT);
				
				menu.Append(ID_DELETE_COMMENT, "&Delete comment");
				menu.Bind(wxEVT_MENU, [this, cr](wxCommandEvent &event)
				{
					_tracked_change("delete comment",
						[this, cr]()
						{
							wxClientDC dc(this);
							_delete_comment(dc, cr->c_offset, cr->c_length);
							_raise_comment_modified();
						},
						[this]()
						{
							/* Comments are restored implicitly. */
							_raise_comment_modified();
						});
				}, ID_DELETE_COMMENT, ID_DELETE_COMMENT);
				
				menu.AppendSeparator();
				
				menu.Append(ID_COPY_COMMENT,  "&Copy comment(s)");
				menu.Bind(wxEVT_MENU, [this, cr](wxCommandEvent &event)
				{
					ClipboardGuard cg;
					if(cg)
					{
						auto selected_comments = NestedOffsetLengthMap_get_recursive(comments, NestedOffsetLengthMapKey(cr->c_offset, cr->c_length));
						assert(selected_comments.size() > 0);
						
						wxTheClipboard->SetData(new CommentsDataObject(selected_comments, cr->c_offset));
					}
				}, ID_COPY_COMMENT, ID_COPY_COMMENT);
				
				PopupMenu(&menu);
			}
		}
	}
	
	/* Document takes focus when clicked. */
	SetFocus();
}

void REHex::Document::OnMotion(wxMouseEvent &event)
{
	int mouse_x = event.GetX();
	int mouse_y = event.GetY();
	
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
	
	wxCursor cursor = wxNullCursor;
	
	if(region != regions.end())
	{
		cursor = (*region)->cursor_for_point(*this, rel_x, line_off, (mouse_y % hf_height));
	}
	
	SetCursor(cursor);
	
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
		REHex::Document::Region::Comment *cr;
		if(dr != NULL)
		{
			if(mouse_down_in_hex)
			{
				/* Started dragging in hex area */
				
				off_t select_to_offset = dr->offset_near_xy_hex(*this, rel_x, line_off);
				if(select_to_offset >= 0)
				{
					off_t new_sel_off, new_sel_len;
					
					if(select_to_offset >= mouse_down_at_offset)
					{
						new_sel_off = mouse_down_at_offset;
						new_sel_len = (select_to_offset - mouse_down_at_offset) + 1;
					}
					else{
						new_sel_off = select_to_offset;
						new_sel_len = (mouse_down_at_offset - select_to_offset) + 1;
					}
					
					if(new_sel_len == 1 && abs(rel_x - mouse_down_at_x) < hf_char_width())
					{
						clear_selection();
					}
					else{
						set_selection(new_sel_off, new_sel_len);
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
					off_t new_sel_off, new_sel_len;
					
					if(select_to_offset >= mouse_down_at_offset)
					{
						new_sel_off = mouse_down_at_offset;
						new_sel_len = (select_to_offset - mouse_down_at_offset) + 1;
					}
					else{
						new_sel_off = select_to_offset;
						new_sel_len = (mouse_down_at_offset - select_to_offset) + 1;
					}
					
					if(new_sel_len == 1 && abs(rel_x - mouse_down_at_x) < (hf_char_width() / 2))
					{
						clear_selection();
					}
					else{
						set_selection(new_sel_off, new_sel_len);
					}
					
					/* TODO: Limit paint to affected area */
					Refresh();
				}
			}
		}
		else if((cr = dynamic_cast<REHex::Document::Region::Comment*>(*region)) != NULL)
		{
			if(mouse_down_in_hex || mouse_down_in_ascii)
			{
				off_t select_to_offset = cr->c_offset;
				off_t new_sel_off, new_sel_len;
				
				if(select_to_offset >= mouse_down_at_offset)
				{
					new_sel_off = mouse_down_at_offset;
					new_sel_len = select_to_offset - mouse_down_at_offset;
				}
				else{
					new_sel_off = select_to_offset;
					new_sel_len = (mouse_down_at_offset - select_to_offset) + 1;
				}
				
				if(new_sel_len == 1 && abs(rel_x - mouse_down_at_x) < (hf_char_width() / 2))
				{
					clear_selection();
				}
				else{
					set_selection(new_sel_off, new_sel_len);
				}
				
				/* TODO: Limit paint to affected area */
				Refresh();
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
	
	client_width      = 0;
	client_height     = 0;
	visible_lines     = 1;
	bytes_per_line    = 0;
	bytes_per_group   = 4;
	show_ascii        = true;
	inline_comment_mode = ICM_FULL_INDENT;
	highlight_selection_match = false;
	scroll_xoff       = 0;
	scroll_yoff       = 0;
	scroll_yoff_max   = 0;
	scroll_ydiv       = 1;
	wheel_vert_accum  = 0;
	wheel_horiz_accum = 0;
	selection_off     = 0;
	selection_length  = 0;
	cursor_visible    = true;
	mouse_down_in_hex = false;
	mouse_down_in_ascii = false;
	mouse_shift_initial = -1;
	cursor_state      = CSTATE_HEX;
	
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
}

void REHex::Document::_ctor_post()
{
	redraw_cursor_timer.Start(750, wxTIMER_CONTINUOUS);
	
	/* SetDoubleBuffered() isn't implemented on all platforms. */
	#if defined(__WXMSW__) || defined(__WXGTK__)
	SetDoubleBuffered(true);
	#endif
	
	SetMinClientSize(wxSize(hf_string_width(60), (hf_height * 20)));
}

void REHex::Document::_reinit_regions()
{
	regions.clear();
	
	if(inline_comment_mode == ICM_HIDDEN)
	{
		/* Inline comments are hidden, just have everything in a single Data region. */
		
		regions.push_back(new REHex::Document::Region::Data(0, buffer->length(), 0));
		++data_regions_count;
		
		/* Force initialisation of bytes_per_line_actual and horizontal scrollbar update. */
		_handle_width_change();
		
		return;
	}
	
	/* Construct a list of interlaced comment/data regions. */
	
	data_regions_count = 0;
	
	auto offset_base = comments.begin();
	off_t next_data = 0, remain_data = buffer->length();
	
	/* Stack of comment ranges around the current position. */
	std::list<REHex::Document::Region::Comment*> parents;
	
	while(remain_data > 0)
	{
		off_t dr_length = remain_data;
		
		assert(offset_base == comments.end() || offset_base->first.offset >= next_data);
		
		/* Pop any comments off parents which we have gone past the end of. */
		while(!parents.empty() && (parents.back()->c_offset + parents.back()->c_length) <= next_data)
		{
			if(parents.back()->final_descendant != NULL)
			{
				++(parents.back()->final_descendant->indent_final);
			}
			
			parents.pop_back();
		}
		
		/* We process any comments at the same offset from largest to smallest, ensuring
		 * smaller comments are parented to the next-larger one at the same offset.
		 *
		 * This could be optimised by changing the order of keys in the comments map, but
		 * that'll probably break something...
		*/
		
		if(offset_base != comments.end() && offset_base->first.offset == next_data)
		{
			auto next_offset = offset_base;
			while(next_offset != comments.end() && next_offset->first.offset == offset_base->first.offset)
			{
				++next_offset;
			}
			
			auto c = next_offset;
			do {
				--c;
				
				regions.push_back(new REHex::Document::Region::Comment(c->first.offset, c->first.length, *(c->second.text), parents.size()));
				
				for(auto p = parents.begin(); p != parents.end(); ++p)
				{
					(*p)->final_descendant = regions.back();
				}
				
				if((inline_comment_mode == ICM_SHORT_INDENT || inline_comment_mode == ICM_FULL_INDENT)
					&& c->first.length > 0)
				{
					parents.push_back((REHex::Document::Region::Comment*)(regions.back()));
				}
			} while(c != offset_base);
			
			offset_base = next_offset;
		}
		
		if(offset_base != comments.end())
		{
			dr_length = offset_base->first.offset - next_data;
		}
		
		if(!parents.empty() && (parents.back()->c_offset + parents.back()->c_length) < (next_data + dr_length))
		{
			dr_length = (parents.back()->c_offset + parents.back()->c_length) - next_data;
		}
		
		regions.push_back(new REHex::Document::Region::Data(next_data, dr_length, parents.size()));
		++data_regions_count;
		
		for(auto p = parents.begin(); p != parents.end(); ++p)
		{
			(*p)->final_descendant = regions.back();
		}
		
		next_data   += dr_length;
		remain_data -= dr_length;
	}
	
	while(!parents.empty())
	{
		if(parents.back()->final_descendant != NULL)
		{
			++(parents.back()->final_descendant->indent_final);
		}
		
		parents.pop_back();
	}
	
	if(regions.empty())
	{
		/* Empty buffers need a data region too! */
		
		assert(buffer->length() == 0);
		
		regions.push_back(new REHex::Document::Region::Data(0, 0, 0));
		++data_regions_count;
	}
	
	/* Force initialisation of bytes_per_line_actual and horizontal scrollbar update. */
	_handle_width_change();
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
		set_dirty(true);
		_raise_data_modified();
	}
}

/* Insert some data into the Buffer and update our own data structures. */
void REHex::Document::_UNTRACKED_insert_data(wxDC &dc, off_t offset, const unsigned char *data, off_t length)
{
	bool ok = buffer->insert_data(offset, data, length);
	assert(ok);
	
	if(ok)
	{
		set_dirty(true);
		
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
		
		_update_vscroll();
		
		_raise_data_modified();
		
		if(NestedOffsetLengthMap_data_inserted(comments, offset, length) > 0)
		{
			_raise_comment_modified();
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
		set_dirty(true);
		
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
		
		_raise_data_modified();
		
		assert(to_shift == length);
		assert(to_shrink == 0);
		
		if(NestedOffsetLengthMap_data_erased(comments, offset, length) > 0)
		{
			_raise_comment_modified();
		}
		
		NestedOffsetLengthMap_data_erased(highlights, offset, length);
	}
}

void REHex::Document::_tracked_overwrite_data(const char *change_desc, off_t offset, const unsigned char *data, off_t length, off_t new_cursor_pos, CursorState new_cursor_state)
{
	std::vector<unsigned char> old_data = read_data(offset, length);
	assert(old_data.size() == (size_t)(length));
	
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
	assert(erase_data.size() == (size_t)(length));
	
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
	change.old_comments     = comments;
	change.old_highlights   = highlights;
	
	do_func();
	
	while(undo_stack.size() >= UNDO_MAX)
	{
		undo_stack.pop_front();
	}
	
	undo_stack.push_back(change);
	redo_stack.clear();
	
	_raise_undo_update();
}

void REHex::Document::_set_comment_text(wxDC &dc, off_t offset, off_t length, const wxString &text)
{
	assert(offset >= 0);
	assert(length >= 0);
	
	if(NestedOffsetLengthMap_set(comments, offset, length, Comment(text)))
	{
		set_dirty(true);
		
		_reinit_regions();
		_recalc_regions(dc);
	}
}

void REHex::Document::_delete_comment(wxDC &dc, off_t offset, off_t length)
{
	if(comments.erase(NestedOffsetLengthMapKey(offset, length)) > 0)
	{
		set_dirty(true);
		
		_reinit_regions();
		_recalc_regions(dc);
	}
}

void REHex::Document::edit_comment_popup(off_t offset, off_t length)
{
	auto ci = comments.find(NestedOffsetLengthMapKey(offset, length));
	wxString old_comment = ci != comments.end()
		? *(ci->second.text)
		: "";
	
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
				[this, offset, length]()
				{
					wxClientDC dc(this);
					_delete_comment(dc, offset, length);
					_raise_comment_modified();
				},
				[this]()
				{
					/* Comments are restored implicitly. */
					_raise_comment_modified();
				});
		}
		else if(old_comment.empty())
		{
			_tracked_change("insert comment",
				[this, offset, length, new_comment]()
				{
					wxClientDC dc(this);
					_set_comment_text(dc, offset, length, new_comment);
					_raise_comment_modified();
				},
				[this]()
				{
					/* Comments are restored implicitly. */
					_raise_comment_modified();
				});
		}
		else{
			_tracked_change("modify comment",
				[this, offset, length, new_comment]()
				{
					wxClientDC dc(this);
					_set_comment_text(dc, offset, length, new_comment);
					_raise_comment_modified();
				},
				[this]()
				{
					/* Comments are restored implicitly. */
					_raise_comment_modified();
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
	
	for(auto c = this->comments.begin(); c != this->comments.end(); ++c)
	{
		const wxScopedCharBuffer utf8_text = c->second.text->utf8_str();
		
		json_t *comment = json_object();
		if(json_array_append(comments, comment) == -1
			|| json_object_set_new(comment, "offset", json_integer(c->first.offset)) == -1
			|| json_object_set_new(comment, "length", json_integer(c->first.length)) == -1
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
	/* TODO: Atomically replace file. */
	
	json_t *meta = _dump_metadata();
	int res = json_dump_file(meta, filename.c_str(), JSON_INDENT(2));
	json_decref(meta);
	
	if(res != 0)
	{
		throw std::runtime_error("Unable to write " + filename);
	}
}

REHex::NestedOffsetLengthMap<REHex::Document::Comment> REHex::Document::_load_comments(const json_t *meta, off_t buffer_length)
{
	NestedOffsetLengthMap<Comment> comments;
	
	json_t *j_comments = json_object_get(meta, "comments");
	
	size_t index;
	json_t *value;
	
	json_array_foreach(j_comments, index, value)
	{
		off_t offset  = json_integer_value(json_object_get(value, "offset"));
		off_t length  = json_integer_value(json_object_get(value, "length"));
		wxString text = wxString::FromUTF8(json_string_value(json_object_get(value, "text")));
		
		if(offset >= 0 && offset < buffer_length
			&& length >= 0 && (offset + length) <= buffer_length)
		{
			NestedOffsetLengthMap_set(comments, offset, length, Comment(text));
		}
	}
	
	return comments;
}

REHex::NestedOffsetLengthMap<int> REHex::Document::_load_highlights(const json_t *meta, off_t buffer_length)
{
	NestedOffsetLengthMap<int> highlights;
	
	json_t *j_highlights = json_object_get(meta, "highlights");
	
	size_t index;
	json_t *value;
	
	json_array_foreach(j_highlights, index, value)
	{
		off_t offset = json_integer_value(json_object_get(value, "offset"));
		off_t length = json_integer_value(json_object_get(value, "length"));
		int   colour = json_integer_value(json_object_get(value, "colour-idx"));
		
		if(offset >= 0 && offset < buffer_length
			&& length > 0 && (offset + length) <= buffer_length
			&& colour >= 0 && colour < Palette::NUM_HIGHLIGHT_COLOURS)
		{
			NestedOffsetLengthMap_set(highlights, offset, length, colour);
		}
	}
	
	return highlights;
}

void REHex::Document::_load_metadata(const std::string &filename)
{
	/* TODO: Report errors */
	
	json_error_t json_err;
	json_t *meta = json_load_file(filename.c_str(), 0, &json_err);
	
	comments = _load_comments(meta, buffer_length());
	highlights = _load_highlights(meta, buffer_length());
	
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
	
	uint64_t region_line = dr->y_offset + (region_offset / dr->bytes_per_line_actual);
	_make_line_visible(region_line);
	
	off_t line_off = region_offset % dr->bytes_per_line_actual;
	
	if(cursor_state == CSTATE_HEX || cursor_state == CSTATE_HEX_MID)
	{
		unsigned int line_x = offset_column_width
			+ hf_string_width(line_off * 2)
			+ hf_string_width(line_off / bytes_per_group);
		_make_x_visible(line_x, hf_string_width(2));
	}
	else if(cursor_state == CSTATE_ASCII)
	{
		off_t byte_x = dr->ascii_text_x + hf_string_width(line_off);
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

int REHex::Document::_indent_width(int depth)
{
	return hf_char_width() * depth;
}

void REHex::Document::_raise_moved()
{
	wxCommandEvent event(REHex::EV_CURSOR_MOVED);
	event.SetEventObject(this);
	
	wxPostEvent(this, event);
}

void REHex::Document::_raise_comment_modified()
{
	wxCommandEvent event(REHex::EV_COMMENT_MODIFIED);
	event.SetEventObject(this);
	
	wxPostEvent(this, event);
}

void REHex::Document::_raise_data_modified()
{
	wxCommandEvent event(REHex::EV_DATA_MODIFIED);
	event.SetEventObject(this);
	
	wxPostEvent(this, event);
}

void REHex::Document::_raise_undo_update()
{
	wxCommandEvent event(REHex::EV_UNDO_UPDATE);
	event.SetEventObject(this);
	
	wxPostEvent(this, event);
}

void REHex::Document::_raise_dirty()
{
	wxCommandEvent event(REHex::EV_BECAME_DIRTY);
	event.SetEventObject(this);
	
	wxPostEvent(this, event);
}

void REHex::Document::_raise_clean()
{
	wxCommandEvent event(REHex::EV_BECAME_CLEAN);
	event.SetEventObject(this);
	
	wxPostEvent(this, event);
}

void REHex::Document::set_dirty(bool dirty)
{
	if(this->dirty == dirty)
	{
		return;
	}
	
	this->dirty = dirty;
	
	if(dirty)
	{
		_raise_dirty();
	}
	else{
		_raise_clean();
	}
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
	if(length == 0)
	{
		return 0;
	}
	
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

REHex::Document::Comment::Comment(const wxString &text):
	text(new wxString(text)) {}

/* Get a preview of the comment suitable for use as a wxMenuItem label. */
wxString REHex::Document::Comment::menu_preview() const
{
	/* Get the first line of the comment. */
	size_t line_len = text->find_first_of("\r\n");
	wxString first_line = text->substr(0, line_len);
	
	/* Escape any ampersands in the comment. */
	for(size_t i = 0; (i = first_line.find_first_of("&", i)) < first_line.length();)
	{
		/* TODO: Make this actually be an ampersand. Posts suggest &&
		 * should work, but others say not portable.
		*/
		first_line.replace(i, 1, "_");
	}
	
	/* Remove any control characters from the first line. */
	
	wxString ctrl_chars;
	for(char i = 0; i < 32; ++i)
	{
		ctrl_chars.append(1, i);
	}
	
	for(size_t i = 0; (i = first_line.find_first_of(ctrl_chars, i)) < first_line.length();)
	{
		first_line.erase(i, 1);
	}
	
	/* TODO: Truncate on characters rather than bytes. */
	
	static const int MAX_CHARS = 32;
	if(first_line.length() > MAX_CHARS)
	{
		return first_line.substr(0, MAX_CHARS) + "...";
	}
	else{
		return first_line;
	}
}

REHex::Document::Region::Region():
	indent_depth(0), indent_final(0) {}

REHex::Document::Region::~Region() {}

wxCursor REHex::Document::Region::cursor_for_point(REHex::Document &doc, int x, int64_t y_lines, int y_px)
{
	return wxNullCursor;
}

void REHex::Document::Region::draw_container(REHex::Document &doc, wxDC &dc, int x, int64_t y)
{
	if(indent_depth > 0)
	{
		int cw = doc.hf_char_width();
		int ch = doc.hf_height;
		
		int64_t skip_lines = (y < 0 ? (-y / ch) : 0);
		
		int     box_y  = y + (skip_lines * (int64_t)(ch));
		int64_t box_h  = (y_lines - skip_lines) * (int64_t)(ch);
		int     box_hc = std::min(box_h, (int64_t)(doc.client_height));
		
		int box_x = x + (cw / 4);
		int box_w = doc.virtual_width - (cw / 2);
		
		dc.SetPen(*wxTRANSPARENT_PEN);
		dc.SetBrush(wxBrush((*active_palette)[Palette::PAL_NORMAL_TEXT_BG]));
		
		dc.DrawRectangle(0, box_y, doc.client_width, box_hc);
		
		dc.SetPen(wxPen((*active_palette)[Palette::PAL_NORMAL_TEXT_FG]));
		
		for(int i = 0; i < indent_depth; ++i)
		{
			if(box_h < (int64_t)(doc.client_height) && (i + indent_final) == indent_depth)
			{
				box_h  -= ch / 2;
				box_hc -= ch / 2;
			}
			
			dc.DrawLine(box_x, box_y, box_x, (box_y + box_hc));
			dc.DrawLine((box_x + box_w - 1), box_y, (box_x + box_w - 1), (box_y + box_hc));
			
			if(box_h < (int64_t)(doc.client_height) && (i + indent_final) >= indent_depth)
			{
				dc.DrawLine(box_x, (box_y + box_h), (box_x + box_w - 1), (box_y + box_h));
				
				box_h  -= ch;
				box_hc -= ch;
			}
			
			box_x += cw;
			box_w -= cw * 2;
		}
	}
}

REHex::Document::Region::Data::Data(off_t d_offset, off_t d_length, int indent_depth):
	d_offset(d_offset), d_length(d_length), bytes_per_line_actual(1)
{
	assert(d_offset >= 0);
	assert(d_length >= 0);
	
	this->indent_depth = indent_depth;
}

void REHex::Document::Region::Data::update_lines(REHex::Document &doc, wxDC &dc)
{
	int indent_width = doc._indent_width(indent_depth);
	
	offset_text_x = indent_width;
	hex_text_x    = indent_width + doc.offset_column_width;
	ascii_text_x  = (doc.virtual_width - indent_width) - doc.hf_string_width(bytes_per_line_actual);
	
	/* Height of the region is simply the number of complete lines of data plus an incomplete
	 * one if the data isn't a round number of lines.
	*/
	y_lines = (d_length / bytes_per_line_actual) + !!(d_length % bytes_per_line_actual) + indent_final;
	
	if((d_offset + d_length) == doc.buffer_length() && (d_length % bytes_per_line_actual) == 0)
	{
		/* This is the last data region in the document. Make it one row taller if the last
		 * row is full so there is always somewhere to draw the insert cursor.
		*/
		++y_lines;
	}
}

void REHex::Document::Region::Data::draw(REHex::Document &doc, wxDC &dc, int x, int64_t y)
{
	draw_container(doc, dc, x, y);
	
	dc.SetFont(*(doc.hex_font));
	
	wxPen norm_fg_1px((*active_palette)[Palette::PAL_NORMAL_TEXT_FG], 1);
	wxPen selected_bg_1px((*active_palette)[Palette::PAL_SELECTED_TEXT_BG], 1);
	dc.SetBrush(*wxTRANSPARENT_BRUSH);
	
	bool alternate_row = true;
	
	auto normal_text_colour = [&dc,&alternate_row]()
	{
		dc.SetTextForeground((*active_palette)[alternate_row ? Palette::PAL_ALTERNATE_TEXT_FG : Palette::PAL_NORMAL_TEXT_FG ]);
		dc.SetBackgroundMode(wxTRANSPARENT);
	};
	
	auto inverted_text_colour = [&dc]()
	{
		dc.SetTextForeground((*active_palette)[Palette::PAL_INVERT_TEXT_FG]);
		dc.SetTextBackground((*active_palette)[Palette::PAL_INVERT_TEXT_BG]);
		dc.SetBackgroundMode(wxSOLID);
	};
	
	auto selected_text_colour = [&dc]()
	{
		dc.SetTextForeground((*active_palette)[Palette::PAL_SELECTED_TEXT_FG]);
		dc.SetTextBackground((*active_palette)[Palette::PAL_SELECTED_TEXT_BG]);
		dc.SetBackgroundMode(wxSOLID);
	};
	
	auto secondary_selected_text_colour = [&dc]()
	{
		dc.SetTextForeground((*active_palette)[Palette::PAL_SECONDARY_SELECTED_TEXT_FG]);
		dc.SetTextBackground((*active_palette)[Palette::PAL_SECONDARY_SELECTED_TEXT_BG]);
		dc.SetBackgroundMode(wxSOLID);
	};
	
	auto highlighted_text_colour = [&dc](int highlight_idx)
	{
		dc.SetTextForeground(active_palette->get_highlight_fg(highlight_idx));
		dc.SetTextBackground(active_palette->get_highlight_bg(highlight_idx));
		dc.SetBackgroundMode(wxSOLID);
	};
	
	/* If we are scrolled part-way into a data region, don't render data above the client area
	 * as it would get expensive very quickly with large files.
	*/
	int64_t skip_lines = (y < 0 ? (-y / doc.hf_height) : 0);
	off_t skip_bytes  = skip_lines * bytes_per_line_actual;
	
	if(skip_lines >= (y_lines - indent_final))
	{
		/* All of our data is past the top of the client area, all that needed to be
		 * rendered is the bottom of the container around it.
		*/
		return;
	}
	
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
	off_t max_bytes = (off_t)(max_lines) * (off_t)(bytes_per_line_actual);
	
	if((int64_t)(max_lines) > (y_lines - indent_final - skip_lines))
	{
		max_lines = (y_lines - indent_final - skip_lines);
	}
	
	if(doc.offset_column)
	{
		int offset_vl_x = (x + offset_text_x + doc.offset_column_width) - (doc.hf_char_width() / 2);
		
		dc.SetPen(norm_fg_1px);
		dc.DrawLine(offset_vl_x, y, offset_vl_x, y + (max_lines * doc.hf_height));
	}
	
	if(doc.show_ascii)
	{
		int ascii_vl_x = (x + ascii_text_x) - (doc.hf_char_width() / 2);
		
		dc.SetPen(norm_fg_1px);
		dc.DrawLine(ascii_vl_x, y, ascii_vl_x, y + (max_lines * doc.hf_height));
	}
	
	/* Fetch the data to be drawn. */
	std::vector<unsigned char> data;
	bool data_err = false;
	
	try {
		data = doc.buffer->read_data(d_offset + skip_bytes, std::min(max_bytes, (d_length - std::min(skip_bytes, d_length))));
	}
	catch(const std::exception &e)
	{
		fprintf(stderr, "Exception in REHex::Document::Region::Data::draw: %s\n", e.what());
		
		data.insert(data.end(), std::min(max_bytes, (d_length - std::min(skip_bytes, d_length))), '?');
		data_err = true;
	}
	
	std::vector<unsigned char> selection_data;
	if(doc.highlight_selection_match && doc.selection_length > 0)
	{
		try {
			selection_data = doc.buffer->read_data(doc.selection_off, doc.selection_length);
		}
		catch(const std::exception &e)
		{
			fprintf(stderr, "Exception in REHex::Document::Region::Data::draw: %s\n", e.what());
		}
	}
	
	/* The offset of the character in the Buffer currently being drawn. */
	off_t cur_off = d_offset + skip_bytes;
	
	bool hex_active   = doc.HasFocus() && doc.cursor_state != CSTATE_ASCII;
	bool ascii_active = doc.HasFocus() && doc.cursor_state == CSTATE_ASCII;
	
	off_t cursor_pos = doc.get_cursor_position();
	
	size_t secondary_selection_remain = 0;
	
	for(auto di = data.begin();;)
	{
		alternate_row = !alternate_row;
		
		if(doc.offset_column)
		{
			/* Draw the offsets to the left */
			char offset_str[64];
			snprintf(offset_str, sizeof(offset_str), "%08X:%08X",
				(unsigned)((cur_off & 0xFFFFFFFF00000000) >> 32),
				(unsigned)(cur_off & 0xFFFFFFFF));
			
			normal_text_colour();
			dc.DrawText(offset_str, (x + offset_text_x), y);
		}
		
		int hex_base_x = x + hex_text_x;
		int hex_x      = hex_base_x;
		int hex_x_char = 0;
		
		int ascii_base_x = x + ascii_text_x;
		int ascii_x      = ascii_base_x;
		int ascii_x_char = 0;
		
		auto draw_end_cursor = [&]()
		{
			if((doc.cursor_visible && doc.cursor_state == CSTATE_HEX) || !hex_active)
			{
				if(doc.insert_mode || !hex_active)
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
			
			if(doc.show_ascii && ((doc.cursor_visible && doc.cursor_state == CSTATE_ASCII) || !ascii_active))
			{
				if(doc.insert_mode || !ascii_active)
				{
					dc.SetPen(norm_fg_1px);
					dc.DrawLine(ascii_x, y, ascii_x, y + doc.hf_height);
				}
				else{
					/* Draw the cursor in red if trying to overwrite at an invalid
					 * position. Should only happen in empty files.
					*/
					dc.SetPen(*wxRED_PEN);
					dc.DrawLine(ascii_x, y, ascii_x, y + doc.hf_height);
				}
			}
		};
		
		if(di == data.end())
		{
			if(cur_off == cursor_pos)
			{
				draw_end_cursor();
			}
			
			break;
		}
		
		wxString hex_str, ascii_string;
		
		for(unsigned int c = 0; c < bytes_per_line_actual && di != data.end(); ++c)
		{
			if(c > 0 && (c % doc.bytes_per_group) == 0)
			{
				hex_str.append(1, ' ');
				
				hex_x = hex_base_x + doc.hf_string_width(++hex_x_char);
			}
			
			if(secondary_selection_remain == 0
				&& (size_t)(data.end() - di) >= selection_data.size()
				&& std::equal(selection_data.begin(), selection_data.end(), di))
			{
				secondary_selection_remain = selection_data.size();
			}
			
			unsigned char byte        = *(di++);
			unsigned char high_nibble = (byte & 0xF0) >> 4;
			unsigned char low_nibble  = (byte & 0x0F);
			
			auto highlight = NestedOffsetLengthMap_get(doc.highlights, cur_off);
			
			auto draw_nibble = [&](unsigned char nibble, bool invert)
			{
				const char *nibble_to_hex = data_err
					? "????????????????"
					: "0123456789ABCDEF";
				
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
				else if(secondary_selection_remain > 0 && !(cur_off >= doc.selection_off && cur_off < (doc.selection_off + doc.selection_length)))
				{
					secondary_selected_text_colour();
					
					char str[] = { nibble_to_hex[nibble], '\0' };
					dc.DrawText(str, hex_x, y);
					
					hex_str.append(1, ' ');
				}
				else if(highlight != doc.highlights.end())
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
			
			/* Need the current hex_x value for drawing any boxes or insert cursors
			 * below, before it gets updated by draw_nibble().
			*/
			const int pd_hx = hex_x;
			
			draw_nibble(high_nibble, inv_high);
			draw_nibble(low_nibble,  inv_low);
			
			if(cur_off >= doc.selection_off && cur_off < (doc.selection_off + doc.selection_length) && !hex_active)
			{
				dc.SetPen(selected_bg_1px);
				
				if(cur_off == doc.selection_off || c == 0)
				{
					/* Draw vertical line left of selection. */
					dc.DrawLine(pd_hx, y, pd_hx, (y + doc.hf_height));
				}
				
				if(cur_off == (doc.selection_off + doc.selection_length - 1) || c == (bytes_per_line_actual - 1))
				{
					/* Draw vertical line right of selection. */
					dc.DrawLine((pd_hx + doc.hf_string_width(2) - 1), y, (pd_hx + doc.hf_string_width(2) - 1), (y + doc.hf_height));
				}
				
				if(cur_off < (doc.selection_off + bytes_per_line_actual))
				{
					/* Draw horizontal line above selection. */
					dc.DrawLine(pd_hx, y, (pd_hx + doc.hf_string_width(2)), y);
				}
				
				if(cur_off > doc.selection_off && cur_off <= (doc.selection_off + bytes_per_line_actual) && c > 0 && (c % doc.bytes_per_group) == 0)
				{
					/* Draw horizontal line above gap along top of selection. */
					dc.DrawLine((pd_hx - doc.hf_char_width()), y, pd_hx, y);
				}
				
				if(cur_off >= (doc.selection_off + doc.selection_length - bytes_per_line_actual))
				{
					/* Draw horizontal line below selection. */
					dc.DrawLine(pd_hx, (y + doc.hf_height - 1), (pd_hx + doc.hf_string_width(2)), (y + doc.hf_height - 1));
					
					if(c > 0 && (c % doc.bytes_per_group) == 0 && cur_off > doc.selection_off)
					{
						/* Draw horizontal line below gap along bottom of selection. */
						dc.DrawLine((pd_hx - doc.hf_char_width()), (y + doc.hf_height - 1), pd_hx, (y + doc.hf_height - 1));
					}
				}
			}
			
			if(cur_off == cursor_pos && doc.insert_mode && ((doc.cursor_visible && doc.cursor_state == CSTATE_HEX) || !hex_active))
			{
				/* Draw insert cursor. */
				dc.SetPen(norm_fg_1px);
				dc.DrawLine(pd_hx, y, pd_hx, y + doc.hf_height);
			}
			
			if(cur_off == cursor_pos && !doc.insert_mode && !hex_active)
			{
				/* Draw inactive overwrite cursor. */
				dc.SetPen(norm_fg_1px);
				
				if(doc.cursor_state == CSTATE_HEX_MID)
				{
					dc.DrawRectangle(pd_hx + doc.hf_char_width(), y, doc.hf_char_width(), doc.hf_height);
				}
				else{
					dc.DrawRectangle(pd_hx, y, doc.hf_string_width(2), doc.hf_height);
				}
			}
			
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
					else if(secondary_selection_remain > 0)
					{
						secondary_selected_text_colour();
						
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
					if(secondary_selection_remain > 0 && !(cur_off >= doc.selection_off && cur_off < (doc.selection_off + doc.selection_length)) && !ascii_active)
					{
						secondary_selected_text_colour();
						
						char str[] = { ascii_byte, '\0' };
						dc.DrawText(str, ascii_x, y);
						
						ascii_string.append(" ");
					}
					else if(highlight != doc.highlights.end() && !ascii_active)
					{
						highlighted_text_colour(highlight->second);
						
						char str[] = { ascii_byte, '\0' };
						dc.DrawText(str, ascii_x, y);
						
						ascii_string.append(" ");
					}
					else{
						ascii_string.append(1, ascii_byte);
					}
					
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
						
						if(cur_off == (doc.selection_off + doc.selection_length - 1) || c == (bytes_per_line_actual - 1))
						{
							/* Draw vertical line right of selection. */
							dc.DrawLine((ascii_x + doc.hf_char_width() - 1), y, (ascii_x + doc.hf_char_width() - 1), (y + doc.hf_height));
						}
						
						if(cur_off < (doc.selection_off + bytes_per_line_actual))
						{
							/* Draw horizontal line above selection. */
							dc.DrawLine(ascii_x, y, (ascii_x + doc.hf_char_width()), y);
						}
						
						if(cur_off >= (doc.selection_off + doc.selection_length - bytes_per_line_actual))
						{
							/* Draw horizontal line below selection. */
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
			
			if(secondary_selection_remain > 0)
			{
				--secondary_selection_remain;
			}
		}
		
		normal_text_colour();
		
		dc.DrawText(hex_str, hex_base_x, y);
		
		if(doc.show_ascii)
		{
			dc.DrawText(ascii_string, ascii_base_x, y);
		}
		
		if(cur_off == cursor_pos && cur_off == doc.buffer_length() && (d_length % bytes_per_line_actual) != 0)
		{
			draw_end_cursor();
		}
		
		y += doc.hf_height;
		
		if(di == data.end() && (cur_off < doc.buffer_length() || (d_length % bytes_per_line_actual) != 0))
		{
			break;
		}
	}
}

wxCursor REHex::Document::Region::Data::cursor_for_point(REHex::Document &doc, int x, int64_t y_lines, int y_px)
{
	if(x >= hex_text_x)
	{
		return wxCursor(wxCURSOR_IBEAM);
	}
	else{
		return wxNullCursor;
	}
}

off_t REHex::Document::Region::Data::offset_at_xy_hex(REHex::Document &doc, int mouse_x_px, uint64_t mouse_y_lines)
{
	if(mouse_x_px < hex_text_x)
	{
		return -1;
	}
	
	mouse_x_px -= hex_text_x;
	
	/* Calculate the offset within the Buffer of the first byte on this line
	 * and the offset (plus one) of the last byte on this line.
	*/
	off_t line_data_begin = d_offset + ((off_t)(bytes_per_line_actual) * mouse_y_lines);
	off_t line_data_end   = std::min((line_data_begin + bytes_per_line_actual), (d_offset + d_length));
	
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
	if(!doc.show_ascii || mouse_x_px < ascii_text_x)
	{
		return -1;
	}
	
	mouse_x_px -= ascii_text_x;
	
	/* Calculate the offset within the Buffer of the first byte on this line
	 * and the offset (plus one) of the last byte on this line.
	*/
	off_t line_data_begin = d_offset + ((off_t)(bytes_per_line_actual) * mouse_y_lines);
	off_t line_data_end   = std::min((line_data_begin + bytes_per_line_actual), (d_offset + d_length));
	
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
	off_t line_data_begin = d_offset + ((off_t)(bytes_per_line_actual) * mouse_y_lines);
	off_t line_data_end   = std::min((line_data_begin + bytes_per_line_actual), (d_offset + d_length));
	
	if(mouse_x_px < hex_text_x)
	{
		/* Mouse is in offset area, return offset of last byte of previous line. */
		return line_data_begin - 1;
	}
	
	mouse_x_px -= hex_text_x;
	
	unsigned int char_offset = doc.hf_char_at_x(mouse_x_px);
	
	unsigned int char_offset_sub_spaces = char_offset - (char_offset / ((doc.bytes_per_group * 2) + 1));
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
	off_t line_data_begin = d_offset + ((off_t)(bytes_per_line_actual) * mouse_y_lines);
	off_t line_data_end   = std::min((line_data_begin + bytes_per_line_actual), (d_offset + d_length));
	
	if(!doc.show_ascii || mouse_x_px < ascii_text_x)
	{
		/* Mouse is left of ASCII area, return last byte of previous line. */
		return line_data_begin - 1;
	}
	
	mouse_x_px -= ascii_text_x;
	
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

REHex::Document::Region::Comment::Comment(off_t c_offset, off_t c_length, const wxString &c_text, int indent_depth):
	c_offset(c_offset), c_length(c_length), c_text(c_text), final_descendant(NULL) { this->indent_depth = indent_depth; }

void REHex::Document::Region::Comment::update_lines(REHex::Document &doc, wxDC &dc)
{
	if(doc.get_inline_comment_mode() == ICM_SHORT || doc.get_inline_comment_mode() == ICM_SHORT_INDENT)
	{
		y_lines = 2 + indent_final;
		return;
	}
	
	unsigned int row_chars = doc.hf_char_at_x(doc.virtual_width - (2 * doc._indent_width(indent_depth))) - 1;
	if(row_chars == 0)
	{
		/* Zero columns of width. Probably still initialising. */
		this->y_lines = 1 + indent_final;
	}
	else{
		auto comment_lines = _format_text(c_text, row_chars);
		this->y_lines  = comment_lines.size() + 1 + indent_final;
	}
}

void REHex::Document::Region::Comment::draw(REHex::Document &doc, wxDC &dc, int x, int64_t y)
{
	draw_container(doc, dc, x, y);
	
	int indent_width = doc._indent_width(indent_depth);
	x += indent_width;
	
	dc.SetFont(*(doc.hex_font));
	
	unsigned int row_chars = doc.hf_char_at_x(doc.virtual_width - (2 * indent_width)) - 1;
	if(row_chars == 0)
	{
		/* Zero columns of width. Probably still initialising. */
		return;
	}
	
	auto lines = _format_text(c_text, row_chars);
	
	if((doc.get_inline_comment_mode() == ICM_SHORT || doc.get_inline_comment_mode() == ICM_SHORT_INDENT) && lines.size() > 1)
	{
		wxString &first_line = lines.front();
		if(first_line.length() < row_chars)
		{
			first_line += L"\u2026";
		}
		else{
			first_line.Last() = L'\u2026';
		}
		
		lines.erase(std::next(lines.begin()), lines.end());
	}
	
	{
		int box_x = x + (doc.hf_char_width() / 4);
		int box_y = y + (doc.hf_height / 4);
		
		unsigned int box_w = (doc.virtual_width - (indent_depth * doc.hf_char_width() * 2)) - (doc.hf_char_width() / 2);
		unsigned int box_h = (lines.size() * doc.hf_height) + (doc.hf_height / 2);
		
		dc.SetPen(wxPen((*active_palette)[Palette::PAL_NORMAL_TEXT_FG], 1));
		dc.SetBrush(wxBrush((*active_palette)[Palette::PAL_COMMENT_BG]));
		
		dc.DrawRectangle(box_x, box_y, box_w, box_h);
		
		if(final_descendant != NULL)
		{
			dc.DrawLine(box_x, (box_y + box_h), box_x, (box_y + box_h + doc.hf_height));
			dc.DrawLine((box_x + box_w - 1), (box_y + box_h), (box_x + box_w - 1), (box_y + box_h + doc.hf_height));
		}
	}
	
	y += doc.hf_height / 2;
	
	dc.SetTextForeground((*active_palette)[Palette::PAL_COMMENT_FG]);
	dc.SetBackgroundMode(wxTRANSPARENT);
	
	for(auto li = lines.begin(); li != lines.end(); ++li)
	{
		dc.DrawText(*li, (x + (doc.hf_char_width() / 2)), y);
		y += doc.hf_height;
	}
}

wxCursor REHex::Document::Region::Comment::cursor_for_point(REHex::Document &doc, int x, int64_t y_lines, int y_px)
{
	int hf_width = doc.hf_char_width();
	int indent_width = doc._indent_width(indent_depth);
	
	if(
		(y_lines > 0 || y_px >= (doc.hf_height / 4)) /* Not above top edge. */
		&& (y_lines < (this->y_lines - 1) || y_px <= ((doc.hf_height / 4) * 3)) /* Not below bottom edge. */
		&& x >= (indent_width + (hf_width / 4)) /* Not left of left edge. */
		&& x < ((doc.virtual_width - (hf_width / 4)) - indent_width)) /* Not right of right edge. */
	{
		return wxCursor(wxCURSOR_HAND);
	}
	else{
		return wxNullCursor;
	}
}

const wxDataFormat REHex::CommentsDataObject::format("rehex/comments/v1");

REHex::CommentsDataObject::CommentsDataObject():
	wxCustomDataObject(format) {}

REHex::CommentsDataObject::CommentsDataObject(const std::list<NestedOffsetLengthMap<REHex::Document::Comment>::const_iterator> &comments, off_t base):
	wxCustomDataObject(format)
{
	set_comments(comments, base);
}

REHex::NestedOffsetLengthMap<REHex::Document::Comment> REHex::CommentsDataObject::get_comments() const
{
	REHex::NestedOffsetLengthMap<REHex::Document::Comment> comments;
	
	const unsigned char *data = (const unsigned char*)(GetData());
	const unsigned char *end = data + GetSize();
	const Header *header;
	
	while(data + sizeof(Header) < end && (header = (const Header*)(data)), (data + sizeof(Header) + header->text_length <= end))
	{
		wxString text(wxString::FromUTF8((const char*)(header + 1), header->text_length));
		
		bool x = NestedOffsetLengthMap_set(comments, header->file_offset, header->file_length, REHex::Document::Comment(text));
		assert(x); /* TODO: Raise some kind of error. Beep? */
		
		data += sizeof(Header) + header->text_length;
	}
	
	return comments;
}

void REHex::CommentsDataObject::set_comments(const std::list<NestedOffsetLengthMap<REHex::Document::Comment>::const_iterator> &comments, off_t base)
{
	size_t size = 0;
	
	for(auto i = comments.begin(); i != comments.end(); ++i)
	{
		size += sizeof(Header) + (*i)->second.text->utf8_str().length();
	}
	
	void *data = Alloc(size); /* Wrapper around new[] - throws on failure */
	
	char *outp = (char*)(data);
	
	for(auto i = comments.begin(); i != comments.end(); ++i)
	{
		Header *header = (Header*)(outp);
		outp += sizeof(Header);
		
		const wxScopedCharBuffer utf8_text = (*i)->second.text->utf8_str();
		
		header->file_offset = (*i)->first.offset - base;
		header->file_length = (*i)->first.length;
		header->text_length = utf8_text.length();
		
		memcpy(outp, utf8_text.data(), utf8_text.length());
		outp += utf8_text.length();
	}
	
	assert(((char*)(data) + size) == outp);
	
	TakeData(size, data);
}
