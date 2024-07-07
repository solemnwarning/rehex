/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <iterator>
#include <jansson.h>
#include <limits>
#include <map>
#include <numeric>
#include <stack>
#include <string>
#include <tuple>
#include <unictype.h>
#include <unistr.h>
#include <wx/clipbrd.h>
#include <wx/dcbuffer.h>

#include "App.hpp"
#include "CharacterEncoder.hpp"
#include "DataType.hpp"
#include "document.hpp"
#include "DocumentCtrl.hpp"
#include "Events.hpp"
#include "FastRectangleFiller.hpp"
#include "Palette.hpp"
#include "profile.hpp"
#include "textentrydialog.hpp"
#include "ThreadPool.hpp"
#include "UnsortedMapVector.hpp"
#include "util.hpp"

static_assert(std::numeric_limits<json_int_t>::max() >= std::numeric_limits<off_t>::max(),
	"json_int_t must be large enough to store any offset in an off_t");

enum {
	ID_REDRAW_CURSOR = 1,
	ID_SELECT_TIMER,
};

BEGIN_EVENT_TABLE(REHex::DocumentCtrl, wxControl)
	EVT_PAINT(REHex::DocumentCtrl::OnPaint)
	EVT_ERASE_BACKGROUND(REHex::DocumentCtrl::OnErase)
	EVT_SIZE(REHex::DocumentCtrl::OnSize)
	EVT_SCROLLWIN(REHex::DocumentCtrl::OnScroll)
	EVT_MOUSEWHEEL(REHex::DocumentCtrl::OnWheel)
	EVT_CHAR(REHex::DocumentCtrl::OnChar)
	EVT_LEFT_DOWN(REHex::DocumentCtrl::OnLeftDown)
	EVT_LEFT_UP(REHex::DocumentCtrl::OnLeftUp)
	EVT_RIGHT_DOWN(REHex::DocumentCtrl::OnRightDown)
	EVT_MOTION(REHex::DocumentCtrl::OnMotion)
	EVT_TIMER(ID_SELECT_TIMER, REHex::DocumentCtrl::OnSelectTick)
	EVT_TIMER(ID_REDRAW_CURSOR, REHex::DocumentCtrl::OnRedrawCursor)
	EVT_IDLE(REHex::DocumentCtrl::OnIdle)
END_EVENT_TABLE()

static unsigned int pack_colour(const wxColour &colour)
{
	return (unsigned int)(colour.Red()) | ((unsigned int)(colour.Blue()) << 8) | ((unsigned int)(colour.Green()) << 16);
}

REHex::DocumentCtrl::DocumentCtrl(wxWindow *parent, SharedDocumentPointer &doc, long style):
	wxControl(),
	doc(doc),
	hex_font(wxFontInfo().FaceName(wxGetApp().get_font_name())),
	linked_scroll_prev(NULL),
	linked_scroll_next(NULL),
	selection_begin(BitOffset::INVALID),
	selection_end(BitOffset::INVALID),
	redraw_cursor_timer(this, ID_REDRAW_CURSOR),
	mouse_select_timer(this, ID_SELECT_TIMER),
	hf_gte_cache(GETTEXTEXTENT_CACHE_SIZE)

#ifdef REHEX_CACHE_CHARACTER_BITMAPS
	,hf_char_bitmap_cache(HF_CHAR_BITMAP_CACHE_SIZE)
#endif

#ifdef REHEX_CACHE_STRING_BITMAPS
	,hf_string_bitmap_cache(HF_STRING_BITMAP_CACHE_SIZE)
#endif
{
	App &app = wxGetApp();
	
	app.Bind(FONT_SIZE_ADJUSTMENT_CHANGED, &REHex::DocumentCtrl::OnFontSizeAdjustmentChanged, this);
	
	int font_size_adjustment = app.get_font_size_adjustment();
	
	while(font_size_adjustment > 0) { hex_font.MakeLarger(); --font_size_adjustment; }
	while(font_size_adjustment < 0) { hex_font.MakeSmaller(); ++font_size_adjustment; }
	
	/* The background style MUST be set before the control is created. */
	SetBackgroundStyle(wxBG_STYLE_PAINT);
	Create(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize,
		(wxVSCROLL | wxHSCROLL | wxWANTS_CHARS | style));
	
	client_width      = 0;
	client_height     = 0;
	visible_lines     = 1;
	bytes_per_line    = BYTES_PER_LINE_FIT_BYTES;
	bytes_per_group   = 4;
	offset_display_base = OFFSET_BASE_HEX;
	show_ascii        = true;
	highlight_selection_match = false;
	scroll_xoff       = 0;
	scroll_yoff       = 0;
	scroll_yoff_max   = 0;
	scroll_ydiv       = 1;
	wheel_vert_accum  = 0;
	wheel_horiz_accum = 0;
	cursor_visible    = true;
	mouse_down_area   = GenericDataRegion::SA_NONE;
	mouse_shift_initial = BitOffset::INVALID;
	cursor_state      = Document::CSTATE_HEX;
	
	assert(hex_font.IsFixedWidth());
	
	{
		wxClientDC dc(this);
		dc.SetFont(hex_font);
		
		wxSize hf_char_size = dc.GetTextExtent("X");
		hf_height           = hf_char_size.GetHeight();
		
		/* Precompute widths for hf_string_width() */
		
		for(unsigned int i = 0; i < PRECOMP_HF_STRING_WIDTH_TO; ++i)
		{
			hf_string_width_precomp[i]
				= dc.GetTextExtent(std::string((i + 1), 'X')).GetWidth();
		}
	}
	
	int caret_on_time = wxGetApp().get_caret_on_time_ms();
	if(caret_on_time > 0)
	{
		redraw_cursor_timer.Start(caret_on_time, wxTIMER_ONE_SHOT);
	}
	
	/* SetDoubleBuffered() isn't implemented on all platforms. */
	#if defined(__WXMSW__) || defined(__WXGTK__)
	SetDoubleBuffered(true);
	#endif
	
	SetMinClientSize(wxSize(hf_string_width(10), (hf_height * 20)));
}

REHex::DocumentCtrl::~DocumentCtrl()
{
	if(linked_scroll_prev != NULL || linked_scroll_next != NULL)
	{
		linked_scroll_remove_self();
	}
	
	for(auto region = regions.begin(); region != regions.end(); ++region)
	{
		delete *region;
	}
	
	wxGetApp().Unbind(FONT_SIZE_ADJUSTMENT_CHANGED, &REHex::DocumentCtrl::OnFontSizeAdjustmentChanged, this);
}

void REHex::DocumentCtrl::OnFontSizeAdjustmentChanged(FontSizeAdjustmentEvent &event)
{
	hex_font = wxFont(wxFontInfo().FaceName(wxGetApp().get_font_name()));
	
	for(int i = 0; i < event.font_size_adjustment; ++i) { hex_font.MakeLarger(); }
	for(int i = 0; i > event.font_size_adjustment; --i) { hex_font.MakeSmaller(); }
	
	assert(hex_font.IsFixedWidth());
	
	{
		wxClientDC dc(this);
		dc.SetFont(hex_font);
		
		hf_height = dc.GetTextExtent("X").GetHeight();
		
		/* Precompute widths for hf_string_width() */
		
		for(unsigned int i = 0; i < PRECOMP_HF_STRING_WIDTH_TO; ++i)
		{
			hf_string_width_precomp[i]
				= dc.GetTextExtent(std::string((i + 1), 'X')).GetWidth();
		}
	}
	
	hf_gte_cache.clear();

#ifdef REHEX_CACHE_CHARACTER_BITMAPS
	hf_char_bitmap_cache.clear();
#endif

#ifdef REHEX_CACHE_STRING_BITMAPS
	hf_string_bitmap_cache.clear();
#endif
	
	_handle_width_change();
	
	event.Skip();
}

int REHex::DocumentCtrl::get_bytes_per_line()
{
	return bytes_per_line;
}

void REHex::DocumentCtrl::set_bytes_per_line(int bytes_per_line)
{
	this->bytes_per_line = bytes_per_line;
	_handle_width_change();
}

unsigned int REHex::DocumentCtrl::get_bytes_per_group()
{
	return bytes_per_group;
}

void REHex::DocumentCtrl::set_bytes_per_group(unsigned int bytes_per_group)
{
	this->bytes_per_group = bytes_per_group;
	_handle_width_change();

	wxCommandEvent event(REHex::EV_DISP_SETTING_CHANGED);
	event.SetEventObject(this);

	wxPostEvent(this, event);
}

bool REHex::DocumentCtrl::get_show_offsets()
{
	return offset_column;
}

void REHex::DocumentCtrl::set_show_offsets(bool show_offsets)
{
	offset_column = show_offsets;
	_handle_width_change();
}

REHex::OffsetBase REHex::DocumentCtrl::get_offset_display_base() const
{
	return offset_display_base;
}

void REHex::DocumentCtrl::set_offset_display_base(REHex::OffsetBase offset_display_base)
{
	this->offset_display_base = offset_display_base;
	_handle_width_change();
	
	wxCommandEvent event(REHex::EV_DISP_SETTING_CHANGED);
	event.SetEventObject(this);
	
	wxPostEvent(this, event);
}

bool REHex::DocumentCtrl::get_show_ascii()
{
	return show_ascii;
}

void REHex::DocumentCtrl::set_show_ascii(bool show_ascii)
{
	this->show_ascii = show_ascii;
	_handle_width_change();
}

bool REHex::DocumentCtrl::get_highlight_selection_match()
{
	return highlight_selection_match;
}

void REHex::DocumentCtrl::set_highlight_selection_match(bool highlight_selection_match)
{
	this->highlight_selection_match = highlight_selection_match;
	Refresh();
}

std::shared_ptr<const REHex::ByteColourMap> REHex::DocumentCtrl::get_byte_colour_map() const
{
	return byte_colour_map;
}

void REHex::DocumentCtrl::set_byte_colour_map(const std::shared_ptr<const ByteColourMap> &map)
{
	byte_colour_map = map;
}

REHex::BitOffset REHex::DocumentCtrl::get_cursor_position() const
{
	return this->cpos_off;
}

REHex::Document::CursorState REHex::DocumentCtrl::get_cursor_state() const
{
	return cursor_state;
}

bool REHex::DocumentCtrl::hex_view_active() const
{
	return cursor_state == Document::CSTATE_HEX;
}

bool REHex::DocumentCtrl::ascii_view_active() const
{
	return cursor_state == Document::CSTATE_ASCII;
}

bool REHex::DocumentCtrl::special_view_active() const
{
	return cursor_state == Document::CSTATE_SPECIAL;
}

void REHex::DocumentCtrl::set_cursor_position(BitOffset position, Document::CursorState cursor_state)
{
	/* Clamp the cursor position to the valid ranges defined by the data regions. */
	
	GenericDataRegion *first_dr = data_regions.front();
	GenericDataRegion *last_dr = data_regions.back();
	
	if(_data_region_by_offset(position) == data_regions.end())
	{
		position = first_dr->d_offset;
	}
	
	if(!insert_mode && position > last_dr->d_offset && position == (last_dr->d_offset + last_dr->d_length))
	{
		position -= BitOffset(1, 0);
	}
	
	if(cursor_state == Document::CSTATE_GOTO)
	{
		cursor_state = this->cursor_state;
	}
	
	/* Clamp cursor state to states valid at the new position. */
	
	GenericDataRegion *region = data_region_by_offset(position);
	assert(region != NULL);
	
	GenericDataRegion::ScreenArea valid_areas = region->screen_areas_at_offset(position, this);
	assert((valid_areas & (GenericDataRegion::SA_HEX | GenericDataRegion::SA_ASCII | GenericDataRegion::SA_SPECIAL)) != 0);
	
	if((cursor_state == Document::CSTATE_HEX && (valid_areas & GenericDataRegion::SA_HEX) == 0)
		|| (cursor_state == Document::CSTATE_ASCII && (valid_areas & GenericDataRegion::SA_ASCII) == 0)
		|| (cursor_state == Document::CSTATE_SPECIAL && (valid_areas & GenericDataRegion::SA_SPECIAL) == 0))
	{
		/* Requested cursor state is not valid. Pick something that is. */
		
		if((valid_areas & GenericDataRegion::SA_HEX) != 0)
		{
			cursor_state = Document::CSTATE_HEX;
		}
		else if((valid_areas & GenericDataRegion::SA_ASCII) != 0)
		{
			cursor_state = Document::CSTATE_ASCII;
		}
		else if((valid_areas & GenericDataRegion::SA_SPECIAL) != 0)
		{
			cursor_state = Document::CSTATE_SPECIAL;
		}
	}
	
	/* Blink cursor to visibility and reset timer */
	cursor_visible = true;
	
	int caret_on_time = wxGetApp().get_caret_on_time_ms();
	if(caret_on_time > 0)
	{
		redraw_cursor_timer.Start(caret_on_time, wxTIMER_ONE_SHOT);
	}
	
	if(cpos_off != position)
	{
		if(cpos_prev.empty() || cpos_prev.back() != cpos_off)
		{
			cpos_prev.push_back(cpos_off);
		}
		
		if(cpos_prev.size() > CPOS_HISTORY_LIMIT)
		{
			/* Erase from start of cpos_prev to bring its size down. */
			cpos_prev.erase(cpos_prev.begin(), std::next(cpos_prev.begin(), (cpos_prev.size() - CPOS_HISTORY_LIMIT)));
		}
		
		cpos_next.clear();
	}
	
	cpos_off = position;
	this->cursor_state = cursor_state;
	
	_make_byte_visible(cpos_off);
	save_scroll_position();
	
	/* TODO: Limit paint to affected area */
	Refresh();
}

void REHex::DocumentCtrl::_set_cursor_position(BitOffset position, REHex::Document::CursorState cursor_state, bool preserve_cpos_hist)
{
	BitOffset old_cursor_pos               = get_cursor_position();
	Document::CursorState old_cursor_state = get_cursor_state();
	
	std::vector<BitOffset> old_cpos_prev = cpos_prev;
	std::vector<BitOffset> old_cpos_next = cpos_next;
	
	set_cursor_position(position, cursor_state);
	
	if(preserve_cpos_hist)
	{
		cpos_prev = old_cpos_prev;
		cpos_next = old_cpos_next;
	}
	
	BitOffset new_cursor_pos               = get_cursor_position();
	Document::CursorState new_cursor_state = get_cursor_state();
	
	if(old_cursor_pos != new_cursor_pos || old_cursor_state != new_cursor_state)
	{
		CursorUpdateEvent cursor_update_event(this, new_cursor_pos, new_cursor_state);
		ProcessWindowEvent(cursor_update_event);
	}
}

bool REHex::DocumentCtrl::has_prev_cursor_position() const
{
	return !cpos_prev.empty();
}

void REHex::DocumentCtrl::goto_prev_cursor_position()
{
	if(cpos_prev.empty())
	{
		return;
	}
	
	BitOffset goto_pos = cpos_prev.back();
	cpos_prev.pop_back();
	
	cpos_next.push_back(get_cursor_position());
	
	_set_cursor_position(goto_pos, get_cursor_state(), true);
}

bool REHex::DocumentCtrl::has_next_cursor_position() const
{
	return !cpos_next.empty();
}

void REHex::DocumentCtrl::goto_next_cursor_position()
{
	if(cpos_next.empty())
	{
		return;
	}
	
	BitOffset goto_pos = cpos_next.back();
	cpos_next.pop_back();
	
	cpos_prev.push_back(get_cursor_position());
	
	_set_cursor_position(goto_pos, get_cursor_state(), true);
}

REHex::DocumentCtrl::GenericDataRegion::ScreenArea REHex::DocumentCtrl::_get_screen_area_for_cursor_state()
{
	switch(cursor_state)
	{
		case Document::CSTATE_HEX:
			return GenericDataRegion::SA_HEX;
			
		case Document::CSTATE_ASCII:
			return GenericDataRegion::SA_ASCII;
			
		case Document::CSTATE_SPECIAL:
			return GenericDataRegion::SA_SPECIAL;
			
		default:
			return GenericDataRegion::SA_NONE;
	}
}

bool REHex::DocumentCtrl::get_insert_mode()
{
	return this->insert_mode;
}

void REHex::DocumentCtrl::set_insert_mode(bool enabled)
{
	if(insert_mode == enabled)
	{
		return;
	}
	
	insert_mode = enabled;
	
	BitOffset cursor_pos = get_cursor_position();
	if(!insert_mode && cursor_pos > BitOffset::ZERO && cursor_pos == BitOffset(doc->buffer_length(), 0))
	{
		/* Move cursor back if going from insert to overwrite mode and it
		 * was at the end of the file.
		*/
		
		_set_cursor_position(region_cursor_left(cursor_pos, _get_screen_area_for_cursor_state()), Document::CSTATE_GOTO);
	}
	
	wxCommandEvent event(REHex::EV_INSERT_TOGGLED);
	event.SetEventObject(this);
	wxPostEvent(this, event);
	
	/* TODO: Limit paint to affected area */
	this->Refresh();
}

void REHex::DocumentCtrl::linked_scroll_insert_self_after(DocumentCtrl *p)
{
	assert(linked_scroll_prev == NULL);
	assert(linked_scroll_next == NULL);
	
	/* Insert ourself into the linked scroll list after p. */
	
	linked_scroll_prev = p;
	
	if(p->linked_scroll_next != NULL)
	{
		p->linked_scroll_next->linked_scroll_prev = this;
		linked_scroll_next = p->linked_scroll_next;
	}
	
	p->linked_scroll_next = this;
}

void REHex::DocumentCtrl::linked_scroll_remove_self()
{
	assert(linked_scroll_prev != NULL || linked_scroll_next != NULL);
	
	if(linked_scroll_prev != NULL)
	{
		linked_scroll_prev->linked_scroll_next = linked_scroll_next;
	}
	
	if(linked_scroll_next != NULL)
	{
		linked_scroll_next->linked_scroll_prev = linked_scroll_prev;
	}
	
	linked_scroll_prev = NULL;
	linked_scroll_next = NULL;
}

void REHex::DocumentCtrl::linked_scroll_visit_others(const std::function<void(DocumentCtrl*)> &func)
{
	for(DocumentCtrl *p = linked_scroll_prev; p != NULL; p = p->linked_scroll_prev)
	{
		func(p);
	}
	
	for(DocumentCtrl *p = linked_scroll_next; p != NULL; p = p->linked_scroll_next)
	{
		func(p);
	}
}

bool REHex::DocumentCtrl::set_selection_raw(BitOffset begin, BitOffset end)
{
	assert(begin >= BitOffset::ZERO);
	assert(end >= BitOffset::ZERO);
	
	{
		auto begin_region = _data_region_by_offset(begin);
		auto end_region = _data_region_by_offset(end);
		
		if(begin_region == data_regions.end()
			|| end_region == data_regions.end()
			|| begin_region > end_region
			|| (begin_region == end_region && begin > end)
			/* Don't allow selecting the imaginary byte after the end. */
			|| end == ((*end_region)->d_offset + (*end_region)->d_length))
		{
			return false;
		}
	}
	
	selection_begin = begin;
	selection_end = end;
	
	if(mouse_shift_initial < begin || mouse_shift_initial > end)
	{
		mouse_shift_initial = BitOffset::INVALID;
	}
	
	{
		wxCommandEvent event(REHex::EV_SELECTION_CHANGED);
		event.SetEventObject(this);
		
		wxPostEvent(this, event);
	}
	
	Refresh();
	
	return true;
}

void REHex::DocumentCtrl::clear_selection()
{
	selection_begin = BitOffset::INVALID;
	selection_end   = BitOffset::INVALID;
	
	mouse_shift_initial = BitOffset::INVALID;
	
	{
		wxCommandEvent event(REHex::EV_SELECTION_CHANGED);
		event.SetEventObject(this);
		
		wxPostEvent(this, event);
	}
	
	Refresh();
}

bool REHex::DocumentCtrl::has_selection()
{
	assert((selection_begin < BitOffset::ZERO) == (selection_end < BitOffset::ZERO));
	return !(selection_begin < BitOffset::ZERO || selection_end < BitOffset::ZERO);
}

std::pair<REHex::BitOffset, REHex::BitOffset> REHex::DocumentCtrl::get_selection_raw()
{
	if(selection_begin < BitOffset::ZERO)
	{
		/* No selection. */
		return std::make_pair(BitOffset::INVALID, BitOffset::INVALID);
	}
	else{
		return std::make_pair(selection_begin, selection_end);
	}
}

REHex::OrderedBitRangeSet REHex::DocumentCtrl::get_selection_ranges()
{
	if(!has_selection())
	{
		return OrderedBitRangeSet();
	}
	
	return region_range_expand(selection_begin, selection_end);
}

REHex::OrderedBitRangeSet REHex::DocumentCtrl::region_range_expand(BitOffset begin_offset, BitOffset end_offset_incl)
{
	OrderedBitRangeSet selected_ranges;
	
	auto region = _data_region_by_offset(begin_offset);
	BitOffset region_select_begin = begin_offset;
	
	while(region != data_regions.end())
	{
		assert(region_select_begin >= (*region)->d_offset);
		assert(region_select_begin <= ((*region)->d_offset + (*region)->d_length));
		
		if((*region)->d_offset <= end_offset_incl && ((*region)->d_length + (*region)->d_offset) > end_offset_incl)
		{
			/* Last byte of selection is within this region. */
			if(end_offset_incl >= region_select_begin)
			{
				selected_ranges.set_range(region_select_begin, (end_offset_incl - region_select_begin) + BitOffset::BITS(1));
			}
			
			break;
		}
		else{
			/* Last byte of selection is beyond the end of this range. */
			selected_ranges.set_range(region_select_begin, ((*region)->d_offset + (*region)->d_length) - region_select_begin);
		}
		
		++region;
		
		if(region != data_regions.end())
		{
			region_select_begin = (*region)->d_offset;
		}
	}
	
	return selected_ranges;
}

std::pair<REHex::BitOffset, REHex::BitOffset> REHex::DocumentCtrl::get_selection_in_region(GenericDataRegion *region)
{
	if(selection_begin < BitOffset::ZERO)
	{
		/* No selection. */
		return std::make_pair(BitOffset::INVALID, BitOffset::INVALID);
	}
	
	auto region_iter = _data_region_by_offset(region->d_offset);
	assert(region_iter != data_regions.end());
	
	auto sel_begin_iter = _data_region_by_offset(selection_begin);
	assert(sel_begin_iter != data_regions.end());
	
	auto sel_end_iter = _data_region_by_offset(selection_end);
	assert(sel_end_iter != data_regions.end());
	
	if(sel_begin_iter > region_iter || sel_end_iter < region_iter)
	{
		/* Selection doesn't overlap region. */
		return std::make_pair(BitOffset::INVALID, BitOffset::INVALID);
	}
	
	BitOffset region_selection_offset = (sel_begin_iter < region_iter)
		? region->d_offset
		: selection_begin;
	
	BitOffset region_selection_length = (sel_end_iter > region_iter)
		? (region->d_length - (region_selection_offset - region->d_offset))
		: (selection_end - region_selection_offset) + BitOffset::BITS(1);
	
	return std::make_pair(region_selection_offset, region_selection_length);
}

std::pair<REHex::BitOffset, REHex::BitOffset> REHex::DocumentCtrl::get_selection_linear()
{
	if(has_selection() && region_range_linear(selection_begin, selection_end))
	{
		return std::make_pair(selection_begin, (selection_end - selection_begin) + BitOffset::BITS(1));
	}
	else{
		return std::make_pair(BitOffset::INVALID, BitOffset::ZERO);
	}
}

void REHex::DocumentCtrl::OnPaint(wxPaintEvent &event)
{
	wxBufferedPaintDC dc(this);
	
	dc.SetFont(hex_font);
	
	dc.SetBackground(wxBrush((*active_palette)[Palette::PAL_NORMAL_TEXT_BG]));
	dc.Clear();
	
	/* Find the region containing the first visible line. */
	auto base_region = region_by_y_offset(scroll_yoff);
	int64_t yo_end = scroll_yoff + visible_lines + 1;
	
	/* Iterate over the visible regions and draw them. */
	for(auto region = base_region; region != regions.end() && (*region)->y_offset < yo_end; ++region)
	{
		int x_px = 0 - scroll_xoff;
		
		int64_t y_px = (*region)->y_offset;
		assert(y_px >= 0);
		
		y_px -= scroll_yoff;
		y_px *= hf_height;
		
		(*region)->draw(*this, dc, x_px, y_px);
	}
	
	/* Iterate over the visible regions again and give them a chance to do any processing. */
	
	bool width_changed = false;
	bool height_changed = false;
	bool redraw = false;
	
	for(auto region = base_region; region != regions.end() && (*region)->y_offset < yo_end; ++region)
	{
		if(std::find_if(processing_regions.begin(), processing_regions.end(),
			[&](const Region *r) { return r == *region; }) != processing_regions.end())
		{
			/* This region is already in processing_regions - will be checked on next idle. */
			continue;
		}
		
		unsigned int state = (*region)->check();
		
		if(state & Region::PROCESSING)
		{
			processing_regions.push_back(*region);
		}
		
		if(state & Region::WIDTH_CHANGE)  { width_changed = true; }
		if(state & Region::HEIGHT_CHANGE) { height_changed = true; }
		if(state & Region::REDRAW)        { redraw = true; }
	}
	
	if(width_changed || height_changed)
	{
		_handle_width_change();
	}
	else if(redraw)
	{
		Refresh();
	}
}

void REHex::DocumentCtrl::OnErase(wxEraseEvent &event)
{
	// Left blank to disable erase
}

void REHex::DocumentCtrl::OnSize(wxSizeEvent &event)
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

void REHex::DocumentCtrl::_handle_width_change()
{
	PROFILE_BLOCK("REHex::DocumentCtrl::_handle_width_change");
	
	/* Calculate how much space (if any) to reserve for the offsets to the left. */
	
	if(offset_column)
	{
		/* Offset column width includes the vertical line between it and the hex area, so
		 * size is calculated for n+1 characters.
		*/
		
		if(end_virt_offset > 0xFFFFFFFF)
		{
			if(offset_display_base == OFFSET_BASE_HEX)
			{
				offset_column_width = hf_string_width(18 + 3);
			}
			else{
				offset_column_width = hf_string_width(20 + 3);
			}
		}
		else{
			if(offset_display_base == OFFSET_BASE_HEX)
			{
				offset_column_width = hf_string_width(10 + 3);
			}
			else{
				offset_column_width = hf_string_width(11 + 3);
			}
		}
	}
	else{
		offset_column_width = 0;
	}
	
	{
		PROFILE_INNER_BLOCK("calc widths");
		
		virtual_width = 0;
		
		for(auto r = regions.begin(); r != regions.end(); ++r)
		{
			int r_min_width = (*r)->calc_width(*this);
			if(r_min_width > virtual_width)
			{
				virtual_width = r_min_width;
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
	
	/* Recalculate the height and y offset of each region. */
	
	{
		PROFILE_INNER_BLOCK("calc heights");
		
		static const size_t CALC_HEIGHTS_PER_CHUNK = 1000;
		std::atomic<size_t> next_chunk_to_calc(0);
		
		ThreadPool::TaskHandle a = wxGetApp().thread_pool->queue_task([&]()
		{
			size_t base = next_chunk_to_calc.fetch_add(CALC_HEIGHTS_PER_CHUNK);
			size_t end = std::min((base + CALC_HEIGHTS_PER_CHUNK), regions.size());
			
			for(size_t i = base; i < end; ++i)
			{
				regions[i]->calc_height(*this);
			}
			
			return base >= regions.size();
		}, -1, ThreadPool::TaskPriority::UI);
		
		a.join();
	}
	
	{
		PROFILE_INNER_BLOCK("calc offsets");
		
		int64_t next_yo = 0;
		
		for(auto i = regions.begin(); i != regions.end(); ++i)
		{
			(*i)->y_offset = next_yo;
			next_yo += (*i)->y_lines;
		}
	}

	/* TODO: Preserve/scale the position as the window size changes. */
	
	if((GetWindowStyle() & DCTRL_LOCK_SCROLL) == 0)
	{
		SetScrollbar(wxHORIZONTAL, 0, client_width, virtual_width);
	}
	else{
		SetScrollbar(wxHORIZONTAL, 0, 0, 0);
	}
	
	/* Update vertical scrollbar, since we just recalculated the height of the document. */
	_update_vscroll();
	
	/* Force a redraw of the whole control since resizing can change pretty much the entire
	 * thing depending on rendering settings.
	*/
	Refresh();
}

void REHex::DocumentCtrl::_handle_height_change()
{
	/* Update vertical scrollbar, since the client area height has changed. */
	_update_vscroll();
	
	/* Force a redraw of the whole control since resizing can change pretty much the entire
	 * thing depending on rendering settings.
	*/
	Refresh();
}

void REHex::DocumentCtrl::_update_vscroll()
{
	static const int MAX_STEPS = 10000;

	if((GetWindowStyle() & DCTRL_LOCK_SCROLL) != 0)
	{
		SetScrollbar(wxVERTICAL, 0, 0, 0);

		scroll_yoff = 0;
		scroll_yoff_max = 0;

		return;
	}
	
	uint64_t total_lines = regions.back()->y_offset + regions.back()->y_lines;
	
	if(total_lines > visible_lines)
	{
		int64_t new_scroll_yoff_max = total_lines - visible_lines;
		
		restore_scroll_position();
		
		/* Clamp scroll_yoff set by restore_scroll_position() to new scroll_yoff_max value. */
		scroll_yoff = std::min(scroll_yoff, new_scroll_yoff_max);
		
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
		
		scroll_yoff = 0;
		scroll_yoff_max = 0;
	}
	
	linked_scroll_visit_others([this](DocumentCtrl *other)
	{
		other->scroll_yoff = scroll_yoff;
		if(other->scroll_yoff > other->scroll_yoff_max)
		{
			other->scroll_yoff = other->scroll_yoff_max;
		}
		
		other->_update_vscroll_pos(false);
		other->save_scroll_position();
		other->Refresh();
	});
}

void REHex::DocumentCtrl::_update_vscroll_pos(bool update_linked_scroll_others)
{
	if((GetWindowStyle() & DCTRL_LOCK_SCROLL) != 0)
	{
		return;
	}
	
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
	
	if(update_linked_scroll_others)
	{
		linked_scroll_visit_others([this](DocumentCtrl *other)
		{
			other->scroll_yoff = scroll_yoff;
			if(other->scroll_yoff > other->scroll_yoff_max)
			{
				other->scroll_yoff = other->scroll_yoff_max;
			}
			
			other->_update_vscroll_pos(false);
			other->save_scroll_position();
			other->Refresh();
		});
	}
}

REHex::DocumentCtrl::FuzzyScrollPosition REHex::DocumentCtrl::get_scroll_position_fuzzy()
{
	FuzzyScrollPosition fsp;
	
	if(regions.empty())
	{
		/* We are being called during initialisation. */
		return fsp;
	}
	
	if(scroll_yoff >= (regions.back()->y_offset + regions.back()->y_lines))
	{
		/* This can happen in obscure cases where the DocumentCtrl is "empty", e.g. the
		 * data backing a DiffWindow range is erased. Avoid an assertion failure within
		 * the region_by_y_offset() call.
		*/
		
		return fsp;
	}
	
	auto base_region = region_by_y_offset(scroll_yoff);
	
	fsp.region_idx       = base_region - regions.begin();
	fsp.region_idx_line  = (*base_region)->y_offset - scroll_yoff;
	fsp.region_idx_valid = true;
	
	/* Figure out where the cursor is in screen space. */
	
	BitOffset cursor_pos = get_cursor_position();
	
	GenericDataRegion *cursor_dr = data_region_by_offset(cursor_pos);
	assert(cursor_dr != NULL);
	
	Rect cursor_rect = cursor_dr->calc_offset_bounds(cursor_pos, this);
	
	if(cursor_rect.y >= scroll_yoff && cursor_rect.y < (scroll_yoff + visible_lines))
	{
		/* Cursor is on-screen, use it as the scroll position anchor. */
		
		fsp.data_offset       = cursor_pos;
		fsp.data_offset_line  = cursor_rect.y - scroll_yoff;
		fsp.data_offset_valid = true;
	}
	else{
		/* Cursor isn't on-screen, use first visible line of data (if any) as the scroll
		 * position anchor.
		*/
		
		for(auto r = base_region; r != regions.end() && (*r)->y_offset < (scroll_yoff + visible_lines); ++r)
		{
			GenericDataRegion *dr = dynamic_cast<GenericDataRegion*>(*r);
			if(dr == NULL)
			{
				continue;
			}
			
			if(dr->y_offset >= scroll_yoff)
			{
				fsp.data_offset       = dr->nth_row_nearest_column(0, 0);
				fsp.data_offset_line  = dr->y_offset - scroll_yoff;
				fsp.data_offset_valid = true;
			}
			else{
				fsp.data_offset       = dr->nth_row_nearest_column((scroll_yoff - dr->y_offset), 0);
				fsp.data_offset_line  = 0;
				fsp.data_offset_valid = true;
			}
			
			break;
		}
	}
	
	return fsp;
}

void REHex::DocumentCtrl::set_scroll_position_fuzzy(const FuzzyScrollPosition &fsp)
{
	if(fsp.data_offset_valid)
	{
		auto dr = _data_region_by_offset(fsp.data_offset);
		if(dr != data_regions.end())
		{
			Rect byte_rect = (*dr)->calc_offset_bounds(fsp.data_offset, this);
			set_scroll_yoff_clamped(byte_rect.y - fsp.data_offset_line);
			
			return;
		}
	}
	
	if(fsp.region_idx_valid)
	{
		if(regions.size() > fsp.region_idx)
		{
			Region *r = regions[fsp.region_idx];
			set_scroll_yoff_clamped(r->y_offset - fsp.region_idx_line);
			
			return;
		}
	}
}

void REHex::DocumentCtrl::save_scroll_position()
{
	saved_scroll_position = get_scroll_position_fuzzy();
}

void REHex::DocumentCtrl::restore_scroll_position()
{
	set_scroll_position_fuzzy(saved_scroll_position);
}

void REHex::DocumentCtrl::OnScroll(wxScrollWinEvent &event)
{
	if((GetWindowStyle() & DCTRL_LOCK_SCROLL) != 0)
	{
		return;
	}
	
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
		
		save_scroll_position();
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

void REHex::DocumentCtrl::OnWheel(wxMouseEvent &event)
{
	if((GetWindowStyle() & DCTRL_LOCK_SCROLL) != 0)
	{
		return;
	}
	
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
		
		save_scroll_position();
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

void REHex::DocumentCtrl::OnChar(wxKeyEvent &event)
{
	int key       = event.GetKeyCode();
	int modifiers = event.GetModifiers();
	
	BitOffset cursor_pos = get_cursor_position();
	
	if(region_OnChar(event))
	{
		/* Key press handled by cursor region. */
		return;
	}
	
	if(key == WXK_TAB && modifiers == wxMOD_NONE)
	{
		GenericDataRegion *cur_region = data_region_by_offset(cursor_pos);
		assert(cur_region != NULL);
		
		GenericDataRegion::ScreenArea valid_areas = cur_region->screen_areas_at_offset(cursor_pos, this);
		assert((valid_areas & (GenericDataRegion::SA_HEX | GenericDataRegion::SA_ASCII | GenericDataRegion::SA_SPECIAL)) != 0);
		
		switch(cursor_state)
		{
			case Document::CSTATE_HEX:
				if((valid_areas & GenericDataRegion::SA_SPECIAL) != 0)
				{
					/* Focus "special" view. */
					_set_cursor_position(cursor_pos, Document::CSTATE_SPECIAL);
					break;
				}
				
			case Document::CSTATE_SPECIAL:
				if((valid_areas & GenericDataRegion::SA_ASCII) != 0)
				{
					/* Focus ASCII view. */
					_set_cursor_position(cursor_pos, Document::CSTATE_ASCII);
					break;
				}
				
			default:
				/* Let wxWidgets handle the event and focus the next control. */
				HandleAsNavigationKey(event);
		}
		
		return;
	}
	else if(key == WXK_TAB && modifiers == wxMOD_SHIFT)
	{
		GenericDataRegion *cur_region = data_region_by_offset(cursor_pos);
		assert(cur_region != NULL);
		
		GenericDataRegion::ScreenArea valid_areas = cur_region->screen_areas_at_offset(cursor_pos, this);
		assert((valid_areas & (GenericDataRegion::SA_HEX | GenericDataRegion::SA_ASCII | GenericDataRegion::SA_SPECIAL)) != 0);
		
		switch(cursor_state)
		{
			case Document::CSTATE_ASCII:
				if((valid_areas & GenericDataRegion::SA_SPECIAL) != 0)
				{
					/* Focus "special" view. */
					_set_cursor_position(cursor_pos, Document::CSTATE_SPECIAL);
					break;
				}
				
			case Document::CSTATE_SPECIAL:
				if((valid_areas & GenericDataRegion::SA_HEX) != 0)
				{
					/* Focus hex view. */
					_set_cursor_position(cursor_pos, Document::CSTATE_HEX);
					break;
				}
				
			default:
				/* Let wxWidgets handle the event and focus the previous control. */
				HandleAsNavigationKey(event);
		}
		
		return;
	}
	else if((modifiers == wxMOD_NONE || modifiers == wxMOD_SHIFT || ((modifiers & ~wxMOD_SHIFT) == wxMOD_CONTROL && (key == WXK_HOME || key == WXK_END)))
		&& (key == WXK_LEFT || key == WXK_RIGHT || key == WXK_UP || key == WXK_DOWN || key == WXK_HOME || key == WXK_END || key == WXK_PAGEUP || key == WXK_PAGEDOWN))
	{
		BitOffset new_cursor_pos = cursor_pos;
		
		bool update_scrollpos = false;
		int64_t new_scroll_yoff;
		
		auto cur_region = _data_region_by_offset(cursor_pos);
		assert(cur_region != data_regions.end());
		
		if(key == WXK_LEFT)
		{
			new_cursor_pos = region_cursor_left(new_cursor_pos, _get_screen_area_for_cursor_state());
		}
		else if(key == WXK_RIGHT)
		{
			new_cursor_pos = region_cursor_right(new_cursor_pos, _get_screen_area_for_cursor_state());
		}
		else if(key == WXK_UP)
		{
			new_cursor_pos = (*cur_region)->cursor_up_from(new_cursor_pos, _get_screen_area_for_cursor_state(), this);
			
			if(new_cursor_pos == GenericDataRegion::CURSOR_PREV_REGION)
			{
				int cur_column = (*cur_region)->cursor_column(cursor_pos);
				
				if(cur_region != data_regions.begin())
				{
					auto prev_region = std::prev(cur_region);
					
					new_cursor_pos = (*prev_region)->last_row_nearest_column(cur_column);
					
					assert(new_cursor_pos >= (*prev_region)->d_offset);
					assert(new_cursor_pos <= (*prev_region)->d_offset + (*prev_region)->d_length);
				}
				else{
					/* No previous region. Nowhere to go. */
					new_cursor_pos = cursor_pos;
				}
			}
			else{
				assert(new_cursor_pos.byte() >= 0);
			}
		}
		else if(key == WXK_DOWN)
		{
			new_cursor_pos = (*cur_region)->cursor_down_from(new_cursor_pos, _get_screen_area_for_cursor_state(), this);
			
			if(new_cursor_pos == GenericDataRegion::CURSOR_NEXT_REGION)
			{
				int cur_column = (*cur_region)->cursor_column(cursor_pos);
				
				auto next_region = std::next(cur_region);
				if(next_region != data_regions.end())
				{
					new_cursor_pos = (*next_region)->first_row_nearest_column(cur_column);
					assert(new_cursor_pos.byte() >= 0);
				}
				else if(get_insert_mode())
				{
					/* Special case: Can move one past the end of the final
					 * data region in insert mode.
					*/
					
					new_cursor_pos = (*cur_region)->d_offset + (*cur_region)->d_length;
				}
				else{
					/* No further region. Nowhere to go. */
					new_cursor_pos = cursor_pos;
				}
			}
			else{
				assert(new_cursor_pos.byte() >= 0);
			}
		}
		else if(key == WXK_HOME && (modifiers & wxMOD_CONTROL))
		{
			/* Move cursor to first position in first region. */
			
			assert(!data_regions.empty());
			GenericDataRegion *first_dr = data_regions.front();
			
			new_cursor_pos = first_dr->first_row_nearest_column(0);
		}
		else if(key == WXK_HOME)
		{
			/* Move cursor to start of line. */
			new_cursor_pos = (*cur_region)->cursor_home_from(new_cursor_pos, _get_screen_area_for_cursor_state(), this);
		}
		else if(key == WXK_END && (modifiers & wxMOD_CONTROL))
		{
			/* Move cursor to last position in last region, or one past the end if we
			 * are in insert mode.
			*/
			
			assert(!data_regions.empty());
			GenericDataRegion *last_dr = data_regions.back();
			
			if(get_insert_mode())
			{
				new_cursor_pos = last_dr->d_offset + last_dr->d_length;
			}
			else{
				new_cursor_pos = last_dr->last_row_nearest_column(INT_MAX);
			}
		}
		else if(key == WXK_END)
		{
			/* Move cursor to end of line. */
			new_cursor_pos = (*cur_region)->cursor_end_from(new_cursor_pos, _get_screen_area_for_cursor_state(), this);
			
			/* Special case: If "end" is pressed on the last line of the final data
			 * region when in insert mode, jump past it.
			*/
			if(get_insert_mode() && (*cur_region)->last_row_nearest_column(INT_MAX) == new_cursor_pos)
			{
				auto next_region = std::next(cur_region);
				if(next_region == data_regions.end())
				{
					new_cursor_pos = (*cur_region)->d_offset + (*cur_region)->d_length;
				}
			}
		}
		else if (key == WXK_PAGEUP)
		{
			/* Scroll the screen up one full times its height and reposition the cursor
			 * to the first visible data region line on screen (if there are any).
			*/
			
			new_scroll_yoff = std::max<int64_t>((scroll_yoff - (int64_t)(visible_lines)), 0);
			int cur_column = (*cur_region)->cursor_column(cursor_pos);
			
			auto region = region_by_y_offset(new_scroll_yoff);
			
			while(region != regions.end() && (*region)->y_offset < (new_scroll_yoff + (int64_t)(visible_lines)))
			{
				GenericDataRegion *dr = dynamic_cast<GenericDataRegion*>(*region);
				if(dr != NULL)
				{
					int64_t cursor_to_line_rel = std::max<int64_t>((new_scroll_yoff - dr->y_offset), 0);
					new_cursor_pos = dr->nth_row_nearest_column(cursor_to_line_rel, cur_column);
					
					break;
				}
				
				++region;
			}
			
			update_scrollpos = true;
		}
		else if (key == WXK_PAGEDOWN)
		{
			/* Scroll the screen down one full times its height and reposition the
			 * cursor to the last data region line visible on screen (if any).
			*/
			
			new_scroll_yoff = std::min((scroll_yoff + (int64_t)(visible_lines)), scroll_yoff_max);
			int cur_column = (*cur_region)->cursor_column(cursor_pos);
			
			auto region = region_by_y_offset(new_scroll_yoff);
			
			while(region != regions.end() && (*region)->y_offset < (new_scroll_yoff + (int64_t)(visible_lines)))
			{
				GenericDataRegion *dr = dynamic_cast<GenericDataRegion*>(*region);
				if(dr != NULL)
				{
					int64_t cursor_to_line_abs = std::min(
						(dr->y_offset + dr->y_lines - 1),
						(new_scroll_yoff + (int64_t)(visible_lines) - 1));
					
					new_cursor_pos = dr->nth_row_nearest_column((cursor_to_line_abs - dr->y_offset), cur_column);
				}
				
				++region;
			}
			
			update_scrollpos = true;
		}
		
		_set_cursor_position(new_cursor_pos, Document::CSTATE_GOTO);
		
		if (update_scrollpos && (GetWindowStyle() & DCTRL_LOCK_SCROLL) == 0)
		{
			scroll_yoff = new_scroll_yoff;
			_update_vscroll_pos();
			save_scroll_position();
			Refresh();
		}

		if(modifiers & wxMOD_SHIFT)
		{
			if(region_offset_cmp(new_cursor_pos, cursor_pos) < BitOffset::ZERO)
			{
				/* Cursor moved backwards. */
				
				if(has_selection())
				{
					if(region_offset_cmp(selection_begin, cursor_pos) >= BitOffset::ZERO)
					{
						set_selection_raw(new_cursor_pos, selection_end);
					}
					else{
						if(region_offset_cmp(new_cursor_pos, selection_begin) < BitOffset::ZERO)
						{
							set_selection_raw(new_cursor_pos, region_offset_sub(selection_begin, BitOffset::BITS(1)));
						}
						else if(region_offset_cmp(selection_begin, new_cursor_pos) < BitOffset::ZERO)
						{
							set_selection_raw(selection_begin, region_offset_sub(new_cursor_pos, BitOffset::BITS(1)));
						}
						else{
							clear_selection();
						}
					}
				}
				else{
					set_selection_raw(new_cursor_pos, region_offset_sub(cursor_pos, BitOffset::BITS(1)));
				}
			}
			else if(region_offset_cmp(new_cursor_pos, cursor_pos) > BitOffset::ZERO)
			{
				/* Cursor moved forwards. */
				
				if(has_selection())
				{
					if(region_offset_cmp(selection_begin, cursor_pos) >= BitOffset::ZERO)
					{
						/* Selected backwards, now going forwards back over selection. */
						
						if(region_offset_cmp(new_cursor_pos, selection_end) <= BitOffset::ZERO)
						{
							set_selection_raw(new_cursor_pos, selection_end);
						}
						else if(region_offset_cmp(region_cursor_right(selection_end, _get_screen_area_for_cursor_state()), new_cursor_pos) == BitOffset::ZERO)
						{
							clear_selection();
						}
						else{
							set_selection_raw(region_cursor_right(selection_end, _get_screen_area_for_cursor_state()), region_cursor_left(new_cursor_pos, _get_screen_area_for_cursor_state()));
						}
					}
					else{
						set_selection_raw(selection_begin, region_offset_sub(new_cursor_pos, BitOffset::BITS(1)));
					}
				}
				else{
					set_selection_raw(cursor_pos, region_offset_sub(new_cursor_pos, BitOffset::BITS(1)));
				}
			}
		}
		else{
			clear_selection();
		}
		
		return;
	}
	else if(key == WXK_LEFT && modifiers == wxMOD_ALT)
	{
		goto_prev_cursor_position();
		return;
	}
	else if(key == WXK_RIGHT && modifiers == wxMOD_ALT)
	{
		goto_next_cursor_position();
		return;
	}
	
	/* Unhandled key press - propagate to parent. */
	event.Skip();
}

void REHex::DocumentCtrl::OnLeftDown(wxMouseEvent &event)
{
	wxClientDC dc(this);
	
	int mouse_x = event.GetX();
	int rel_x   = mouse_x + this->scroll_xoff;
	int mouse_y = event.GetY();
	
	/* Find the region containing the first visible line. */
	auto region = region_by_y_offset(scroll_yoff);
	
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
		GenericDataRegion *dr = dynamic_cast<GenericDataRegion*>(*region);
		CommentRegion     *cr = dynamic_cast<CommentRegion*>    (*region);
		
		if(dr != NULL)
		{
			BitOffset clicked_offset;
			GenericDataRegion::ScreenArea clicked_area;
			
			std::tie(clicked_offset, clicked_area) = dr->offset_near_xy(*this, rel_x, line_off, GenericDataRegion::SA_NONE);
			
			if(clicked_offset >= BitOffset(0, 0))
			{
				assert(clicked_area != GenericDataRegion::SA_NONE);
				
				BitOffset old_position = (mouse_shift_initial >= BitOffset::ZERO ? mouse_shift_initial : get_cursor_position());
				
				switch(clicked_area)
				{
					case GenericDataRegion::SA_HEX:
						_set_cursor_position(clicked_offset, Document::CSTATE_HEX);
						break;
						
					case GenericDataRegion::SA_ASCII:
						_set_cursor_position(clicked_offset, Document::CSTATE_ASCII);
						break;
						
					case GenericDataRegion::SA_SPECIAL:
						_set_cursor_position(clicked_offset, Document::CSTATE_SPECIAL);
						break;
						
					default:
						_set_cursor_position(clicked_offset, Document::CSTATE_GOTO);
						break;
				}
				
				if(event.ShiftDown())
				{
					if(region_offset_cmp(clicked_offset, old_position) > 0)
					{
						set_selection_raw(old_position, clicked_offset);
					}
					else{
						set_selection_raw(clicked_offset, old_position);
					}
					
					mouse_shift_initial  = old_position;
					mouse_down_at_offset = old_position;
					mouse_down_at_x      = rel_x;
					mouse_down_area      = clicked_area;
				}
				else{
					clear_selection();
					
					mouse_down_at_offset = clicked_offset;
					mouse_down_at_x      = rel_x;
					mouse_down_area      = clicked_area;
				}
				
				CaptureMouse();
				mouse_select_timer.Start(MOUSE_SELECT_INTERVAL, wxTIMER_CONTINUOUS);
				
				/* TODO: Limit paint to affected area */
				Refresh();
			}
		}
		else if(cr != NULL)
		{
			/* Mouse was clicked within a Comment region, ensure we are within the border drawn around the
			 * comment text.
			*/
			
			int hf_width = hf_char_width();
			int indent_width = this->indent_width(cr->indent_depth);
			
			if(
				(line_off > 0 || (mouse_y % hf_height) >= (hf_height / 4)) /* Not above top edge. */
				&& (line_off < (cr->y_lines - 1) || (mouse_y % hf_height) <= ((hf_height / 4) * 3)) /* Not below bottom edge. */
				&& rel_x >= (indent_width + (hf_width / 4)) /* Not left of left edge. */
				&& rel_x < ((virtual_width - (hf_width / 4)) - indent_width)) /* Not right of right edge. */
			{
				BitRangeEvent event(this, COMMENT_LEFT_CLICK, cr->c_offset, cr->c_length);
				ProcessWindowEvent(event);
			}
		}
	}
	
	/* Document takes focus when clicked. */
	SetFocus();
}

void REHex::DocumentCtrl::OnLeftUp(wxMouseEvent &event)
{
	if(mouse_down_area != GenericDataRegion::SA_NONE)
	{
		mouse_select_timer.Stop();
		ReleaseMouse();
	}
	
	mouse_down_area = GenericDataRegion::SA_NONE;
	
	Refresh();
}

void REHex::DocumentCtrl::OnRightDown(wxMouseEvent &event)
{
	/* If the user right clicks while selecting, and then releases the left button over the
	 * menu, we never receive the EVT_LEFT_UP event. Release the mouse and cancel the selection
	 * now, else we wind up keeping the mouse grabbed and stop it interacting with any other
	 * windows...
	*/
	
	if(mouse_down_area != GenericDataRegion::SA_NONE)
	{
		mouse_select_timer.Stop();
		ReleaseMouse();
		
		mouse_down_area = GenericDataRegion::SA_NONE;
	}
	
	wxClientDC dc(this);
	
	int mouse_x = event.GetX();
	int rel_x   = mouse_x + this->scroll_xoff;
	int mouse_y = event.GetY();
	
	/* Find the region containing the first visible line. */
	auto region = region_by_y_offset(scroll_yoff);
	
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
		GenericDataRegion *dr = dynamic_cast<GenericDataRegion*>(*region);
		CommentRegion *cr = dynamic_cast<CommentRegion*>(*region);
		
		if(dr != NULL)
		{
			BitOffset clicked_offset;
			GenericDataRegion::ScreenArea clicked_area;
			
			std::tie(clicked_offset, clicked_area) = dr->offset_at_xy(*this, rel_x, line_off);
			
			if(clicked_offset >= BitOffset(0, 0))
			{
				if(clicked_area == GenericDataRegion::SA_HEX)
				{
					_set_cursor_position(clicked_offset, Document::CSTATE_HEX);
				}
				else if(clicked_area == GenericDataRegion::SA_ASCII)
				{
					_set_cursor_position(clicked_offset, Document::CSTATE_ASCII);
				}
				else if(clicked_area == GenericDataRegion::SA_SPECIAL)
				{
					_set_cursor_position(clicked_offset, Document::CSTATE_SPECIAL);
				}
				else{
					_set_cursor_position(clicked_offset, Document::CSTATE_GOTO);
				}
				
				if(has_selection() && (clicked_offset < selection_begin || clicked_offset > selection_end))
				{
					clear_selection();
				}
				
				/* TODO: Limit paint to affected area */
				Refresh();
			}
			
			wxCommandEvent event(DATA_RIGHT_CLICK, GetId());
			event.SetEventObject(this);
			
			ProcessWindowEvent(event);
		}
		else if(cr != NULL)
		{
			/* Mouse was clicked within a Comment region, ensure we are within the border drawn around the
			 * comment text.
			*/
			
			int hf_width = hf_char_width();
			int indent_width = this->indent_width(cr->indent_depth);
			
			if(
				(line_off > 0 || (mouse_y % hf_height) >= (hf_height / 4)) /* Not above top edge. */
				&& (line_off < (cr->y_lines - 1) || (mouse_y % hf_height) <= ((hf_height / 4) * 3)) /* Not below bottom edge. */
				&& rel_x >= (indent_width + (hf_width / 4)) /* Not left of left edge. */
				&& rel_x < ((virtual_width - (hf_width / 4)) - indent_width)) /* Not right of right edge. */
			{
				BitRangeEvent event(this, COMMENT_RIGHT_CLICK, cr->c_offset, cr->c_length);
				ProcessWindowEvent(event);
			}
		}
	}
	
	/* Document takes focus when clicked. */
	SetFocus();
}

void REHex::DocumentCtrl::OnMotion(wxMouseEvent &event)
{
	int mouse_x = event.GetX();
	int mouse_y = event.GetY();
	
	int rel_x = mouse_x + scroll_xoff;
	
	/* Find the region containing the first visible line. */
	auto region = region_by_y_offset(scroll_yoff);
	
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

void REHex::DocumentCtrl::OnSelectTick(wxTimerEvent &event)
{
	wxPoint window_pos = GetScreenPosition();
	wxPoint mouse_pos  = wxGetMousePosition();
	
	OnMotionTick((mouse_pos.x - window_pos.x), (mouse_pos.y - window_pos.y));
}

void REHex::DocumentCtrl::OnMotionTick(int mouse_x, int mouse_y)
{
	if(mouse_down_area == GenericDataRegion::SA_NONE)
	{
		return;
	}
	
	wxClientDC dc(this);
	
	if((GetWindowStyle() & DCTRL_LOCK_SCROLL) == 0)
	{
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
		
		save_scroll_position();
	}
	
	int rel_x = mouse_x + scroll_xoff;
	
	/* Find the region containing the first visible line. */
	auto region = region_by_y_offset(scroll_yoff);
	
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
		GenericDataRegion *dr = dynamic_cast<GenericDataRegion*>(*region);
		CommentRegion *cr;
		if(dr != NULL)
		{
			BitOffset select_to_offset = dr->offset_near_xy(*this, rel_x, line_off, mouse_down_area).first;
			
			if(select_to_offset >= BitOffset::ZERO)
			{
				BitOffset new_sel_begin, new_sel_end;
				
				if(select_to_offset >= mouse_down_at_offset)
				{
					new_sel_begin = mouse_down_at_offset;
					new_sel_end   = select_to_offset;
				}
				else{
					new_sel_begin = select_to_offset;
					new_sel_end   = mouse_down_at_offset;
				}
				
				GenericDataRegion *end_dr = data_region_by_offset(new_sel_end);
				assert(end_dr != NULL);
				
				BitOffset end_plus_one = end_dr->cursor_right_from(new_sel_end, mouse_down_area, this);
				if(end_plus_one == GenericDataRegion::CURSOR_NEXT_REGION)
				{
					new_sel_end = end_dr->d_offset + end_dr->d_length - BitOffset(0, (end_dr->d_length > 0 ? 1 : 0));
				}
				else{
					new_sel_end = end_plus_one - BitOffset::BITS(1);
				}
				
				if(new_sel_begin == new_sel_end && abs(rel_x - mouse_down_at_x) < (hf_char_width() / 2))
				{
					clear_selection();
				}
				else{
					set_selection_raw(new_sel_begin, new_sel_end);
				}
				
				/* TODO: Limit paint to affected area */
				Refresh();
			}
		}
		else if((cr = dynamic_cast<REHex::DocumentCtrl::CommentRegion*>(*region)) != NULL && cr->c_offset >= 0)
		{
			if(mouse_down_area != GenericDataRegion::SA_NONE)
			{
				BitOffset select_to_offset = cr->c_offset;
				BitOffset new_sel_begin, new_sel_end;
				
				if(select_to_offset > mouse_down_at_offset)
				{
					new_sel_begin = mouse_down_at_offset;
					new_sel_end   = region_offset_sub(select_to_offset, BitOffset::BITS(1));
				}
				else{
					new_sel_begin = select_to_offset;
					new_sel_end   = mouse_down_at_offset;
				}
				
				if(new_sel_begin == new_sel_end && abs(rel_x - mouse_down_at_x) < (hf_char_width() / 2))
				{
					clear_selection();
				}
				else{
					set_selection_raw(new_sel_begin, new_sel_end);
				}
				
				/* TODO: Limit paint to affected area */
				Refresh();
			}
		}
	}
}

void REHex::DocumentCtrl::OnRedrawCursor(wxTimerEvent &event)
{
	cursor_visible = !cursor_visible;
	
	int time_until_flip = cursor_visible
		? wxGetApp().get_caret_on_time_ms()
		: wxGetApp().get_caret_off_time_ms();
	
	if(time_until_flip > 0)
	{
		redraw_cursor_timer.Start(time_until_flip, wxTIMER_ONE_SHOT);
	}
	
	/* TODO: Limit paint to cursor area */
	Refresh();
}

void REHex::DocumentCtrl::OnIdle(wxIdleEvent &event)
{
	bool width_changed = false;
	bool height_changed = false;
	bool redraw = false;
	
	for(auto r = processing_regions.begin(); r != processing_regions.end();)
	{
		unsigned int status = (*r)->check();
		
		if(status & Region::WIDTH_CHANGE)
		{
			width_changed = true;
		}
		
		if(status & Region::HEIGHT_CHANGE)
		{
			height_changed = true;
		}
		
		if(status & Region::REDRAW)
		{
			redraw = true;
		}
		
		if(status & Region::PROCESSING)
		{
			++r;
		}
		else{
			r = processing_regions.erase(r);
		}
	}
	
	if(width_changed || height_changed)
	{
		_handle_width_change();
	}
	else if(redraw)
	{
		Refresh();
	}
	
	if(!processing_regions.empty())
	{
		event.RequestMore();
	}
}

std::vector<REHex::DocumentCtrl::GenericDataRegion*>::iterator REHex::DocumentCtrl::_data_region_by_offset(BitOffset offset)
{
	/* Find region that encompasses the given offset using binary search. */
	
	class StubRegion: public GenericDataRegion
	{
		public:
			StubRegion(BitOffset offset):
				GenericDataRegion(offset, 0, 0, 0) {}
				
				virtual std::pair<BitOffset, ScreenArea> offset_at_xy(DocumentCtrl &doc, int mouse_x_px, int64_t mouse_y_lines) override { abort(); }
				virtual std::pair<BitOffset, ScreenArea> offset_near_xy(DocumentCtrl &doc, int mouse_x_px, int64_t mouse_y_lines, ScreenArea type_hint) override { abort(); }
				virtual BitOffset cursor_left_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl) override { abort(); }
				virtual BitOffset cursor_right_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl) override { abort(); }
				virtual BitOffset cursor_up_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl) override { abort(); }
				virtual BitOffset cursor_down_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl) override { abort(); }
				virtual BitOffset cursor_home_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl) override { abort(); }
				virtual BitOffset cursor_end_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl) override { abort(); }
				virtual int cursor_column(BitOffset pos) override { abort(); }
				virtual BitOffset first_row_nearest_column(int column) override { abort(); }
				virtual BitOffset last_row_nearest_column(int column) override { abort(); }
				virtual BitOffset nth_row_nearest_column(int64_t row, int column) override { abort(); }
				virtual Rect calc_offset_bounds(BitOffset offset, DocumentCtrl *doc_ctrl) override { abort(); }
				virtual ScreenArea screen_areas_at_offset(BitOffset offset, DocumentCtrl *doc_ctrl) override { abort(); }
				
				virtual void calc_height(REHex::DocumentCtrl &doc) override { abort(); }
				virtual void draw(REHex::DocumentCtrl &doc, wxDC &dc, int x, int64_t y) override { abort(); }
				virtual wxCursor cursor_for_point(REHex::DocumentCtrl &doc, int x, int64_t y_lines, int y_px) override { abort(); }
	};
	
	const StubRegion d_offset_to_find(offset);
	std::vector<GenericDataRegion*> d_offset_to_find_vec({ (GenericDataRegion*)(&d_offset_to_find) });
	
	auto cmp_by_d_offset = [](std::vector<GenericDataRegion*>::iterator lhs, std::vector<GenericDataRegion*>::iterator rhs)
	{
		return (*lhs)->d_offset < (*rhs)->d_offset;
	};
	
	/* std::upper_bound() will give us the first element whose d_offset is greater than the one
	 * we're looking for...
	*/
	auto region = std::upper_bound(data_regions_sorted.begin(), data_regions_sorted.end(), d_offset_to_find_vec.begin(), cmp_by_d_offset);
	
	if(region == data_regions_sorted.begin())
	{
		/* No region encompassing the requested offset. */
		return data_regions.end();
	}
	
	/* ...so step backwards to get to the correct element. */
	--region;
	
	if((**region)->d_offset <= offset
		/* Requested offset must be within region range to match, or one past the end if
		 * this is the last data region.
		*/
		&& ((**region)->d_offset + (**region)->d_length + (*region == std::prev(data_regions.end())) > offset))
	{
		return *region;
	}
	else{
		return data_regions.end();
	}
}

std::vector<REHex::DocumentCtrl::GenericDataRegion*>::iterator REHex::DocumentCtrl::_data_region_by_virt_offset(BitOffset virt_offset)
{
	/* Find region that encompasses the given offset using binary search. */
	
	class StubRegion: public GenericDataRegion
	{
		public:
			StubRegion(BitOffset virt_offset):
				GenericDataRegion(0, 0, virt_offset, 0) {}
				
				virtual std::pair<BitOffset, ScreenArea> offset_at_xy(DocumentCtrl &doc, int mouse_x_px, int64_t mouse_y_lines) override { abort(); }
				virtual std::pair<BitOffset, ScreenArea> offset_near_xy(DocumentCtrl &doc, int mouse_x_px, int64_t mouse_y_lines, ScreenArea type_hint) override { abort(); }
				virtual BitOffset cursor_left_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl) override { abort(); }
				virtual BitOffset cursor_right_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl) override { abort(); }
				virtual BitOffset cursor_up_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl) override { abort(); }
				virtual BitOffset cursor_down_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl) override { abort(); }
				virtual BitOffset cursor_home_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl) override { abort(); }
				virtual BitOffset cursor_end_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl) override { abort(); }
				virtual int cursor_column(BitOffset pos) override { abort(); }
				virtual BitOffset first_row_nearest_column(int column) override { abort(); }
				virtual BitOffset last_row_nearest_column(int column) override { abort(); }
				virtual BitOffset nth_row_nearest_column(int64_t row, int column) override { abort(); }
				virtual Rect calc_offset_bounds(BitOffset offset, DocumentCtrl *doc_ctrl) override { abort(); }
				virtual ScreenArea screen_areas_at_offset(BitOffset offset, DocumentCtrl *doc_ctrl) override { abort(); }
				
				virtual void calc_height(REHex::DocumentCtrl &doc) override { abort(); }
				virtual void draw(REHex::DocumentCtrl &doc, wxDC &dc, int x, int64_t y) override { abort(); }
				virtual wxCursor cursor_for_point(REHex::DocumentCtrl &doc, int x, int64_t y_lines, int y_px) override { abort(); }
	};
	
	const StubRegion virt_offset_to_find(virt_offset);
	std::vector<GenericDataRegion*> virt_offset_to_find_vec({ (GenericDataRegion*)(&virt_offset_to_find) });
	
	auto cmp_by_virt_offset = [](std::vector<GenericDataRegion*>::iterator lhs, std::vector<GenericDataRegion*>::iterator rhs)
	{
		return (*lhs)->virt_offset < (*rhs)->virt_offset;
	};
	
	/* std::upper_bound() will give us the first element whose virt_offset is greater than the
	 * one we're looking for...
	*/
	auto region = std::upper_bound(data_regions_sorted_virt.begin(), data_regions_sorted_virt.end(), virt_offset_to_find_vec.begin(), cmp_by_virt_offset);
	
	if(region == data_regions_sorted_virt.begin())
	{
		/* No region encompassing the requested offset. */
		return data_regions.end();
	}
	
	/* ...so step backwards to get to the correct element. */
	--region;
	
	if((**region)->virt_offset <= virt_offset
		/* Requested offset must be within region range to match, or one past the end if
		 * this is the last data region.
		*/
		&& ((**region)->virt_offset + (**region)->d_length + (*region == std::prev(data_regions.end())) > virt_offset))
	{
		return *region;
	}
	else{
		return data_regions.end();
	}
}

std::vector<REHex::DocumentCtrl::Region*>::iterator REHex::DocumentCtrl::region_by_y_offset(int64_t y_offset)
{
	/* Find region that encompasses the given line using binary search. */
	
	class StubRegion: public Region
	{
		public:
			StubRegion(int64_t y_offset):
				Region(0, 0)
			{
				this->y_offset = y_offset;
			}
			
			virtual void calc_height(REHex::DocumentCtrl &doc) override
			{
				abort();
			}
			
			virtual void draw(REHex::DocumentCtrl &doc, wxDC &dc, int x, int64_t y) override
			{
				abort();
			}
			
			virtual wxCursor cursor_for_point(REHex::DocumentCtrl &doc, int x, int64_t y_lines, int y_px) override
			{
				abort();
			}
	};
	
	const StubRegion y_offset_to_find(y_offset);
	
	auto cmp_by_y_offset = [](const Region *lhs, const Region *rhs)
	{
		return lhs->y_offset < rhs->y_offset;
	};
	
	/* std::upper_bound() will give us the first element whose y_offset is greater than the one
	 * we're looking for...
	*/
	auto region = std::upper_bound(regions.begin(), regions.end(), &y_offset_to_find, cmp_by_y_offset);
	
	/* ...by definition that can't be the first element... */
	assert(region != regions.begin());
	
	/* ...so step backwards to get to the correct element. */
	--region;
	
	assert((*region)->y_offset <= y_offset);
	assert(((*region)->y_offset + (*region)->y_lines) > y_offset || *region == regions.back());
	
	return region;
}

REHex::BitOffset REHex::DocumentCtrl::region_offset_cmp(BitOffset a, BitOffset b)
{
	auto ra = _data_region_by_offset(a);
	auto rb = _data_region_by_offset(b);
	
	if(ra == data_regions.end() || rb == data_regions.end())
	{
		throw std::invalid_argument("Invalid offset passed to REHex::DocumentCtrl::region_offset_cmp()");
	}
	
	if(ra == rb)
	{
		return a - b;
	}
	else if(ra < rb)
	{
		BitOffset delta = std::accumulate(ra, rb,
			BitOffset::ZERO, [](BitOffset sum, const GenericDataRegion *region) { return sum - region->d_length; });
		
		delta += (a - (*ra)->d_offset);
		delta -= (b - (*rb)->d_offset);
		
		assert(delta < BitOffset::ZERO);
		
		return delta;
	}
	else if(ra > rb)
	{
		BitOffset delta = std::accumulate(rb, ra,
			BitOffset::ZERO, [](BitOffset sum, const GenericDataRegion *region) { return sum + region->d_length; });
		
		delta += a - (*ra)->d_offset;
		delta -= b - (*rb)->d_offset;
		
		assert(delta > BitOffset::ZERO);
		
		return delta;
	}
	else{
		/* Unreachable. */
		abort();
	}
}

REHex::BitOffset REHex::DocumentCtrl::region_offset_add(BitOffset base, BitOffset add)
{
	auto r = _data_region_by_offset(base);
	if(r == data_regions.end())
	{
		/* Base offset is invalid. */
		return -1;
	}
	
	if(add > BitOffset::ZERO)
	{
		/* Increment base by walking forwards from base's data region until we've covered
		 * the requested number of bytes, or run out of regions.
		*/
		
		while(r != data_regions.end())
		{
			assert(base >= (*r)->d_offset);
			
			BitOffset remaining_in_r = (*r)->d_length - (base - (*r)->d_offset);
			
			if(remaining_in_r <= add)
			{
				++r;
				
				if(r == data_regions.end())
				{
					if(remaining_in_r == add)
					{
						/* Special case: Last region in document includes
						 * one byte past its end (for inserting at end).
						*/
						
						return base + add;
					}
				}
				else{
					base = (*r)->d_offset;
					add -= remaining_in_r;
				}
			}
			else{
				return base + add;
			}
		}
	}
	else if(add < BitOffset::ZERO)
	{
		/* Decrement by walking backwards from base's data region until we've subtracted
		 * the requested number of bytes, or ran out of regions and failed.
		*/
		
		BitOffset sub = -add;
		
		while(true)
		{
			assert(base >= (*r)->d_offset);
			
			BitOffset remaining_in_r = base - (*r)->d_offset;
			
			if(remaining_in_r < sub)
			{
				/* Current region doesn't have enough bytes left before base to
				 * fulfil subtraction requirement. Count what it has and jump to
				 * end of previous region.
				*/
				
				if(r == data_regions.begin())
				{
					/* No more regions. Fail. */
					break;
				}
				else{
					--r;
					
					assert((*r)->d_length > 0);
					
					base = (*r)->d_offset + (*r)->d_length - BitOffset::BITS(1);
					sub -= remaining_in_r + BitOffset::BITS(1);
				}
			}
			else{
				return base - sub;
			}
		}
	}
	else if(add == BitOffset::ZERO)
	{
		/* Nothing to add - just return base. */
		return base;
	}
	
	/* Ran out of regions while adding/subtracting above. */
	return BitOffset::INVALID;
}

REHex::BitOffset REHex::DocumentCtrl::region_offset_sub(BitOffset base, BitOffset sub)
{
	return region_offset_add(base, -sub);
}

bool REHex::DocumentCtrl::region_range_linear(BitOffset begin_offset, BitOffset end_offset_incl)
{
	BitOffset at = begin_offset;
	auto r = _data_region_by_offset(at);
	
	if(r == data_regions.end())
	{
		return false;
	}
	
	while(true)
	{
		at += (*r)->d_length - (at - (*r)->d_offset);
		++r;
		
		if(at > end_offset_incl)
		{
			return true;
		}
		
		if(r == data_regions.end() || (*r)->d_offset != at)
		{
			return false;
		}
	}
}

REHex::BitOffset REHex::DocumentCtrl::region_offset_to_virt(BitOffset offset)
{
	auto di = _data_region_by_offset(offset);
	if(di == data_regions.end())
	{
		return -1;
	}
	
	return (*di)->virt_offset + (offset - (*di)->d_offset);
}

REHex::BitOffset REHex::DocumentCtrl::region_virt_to_offset(BitOffset virt_offset)
{
	auto di = _data_region_by_virt_offset(virt_offset);
	if(di == data_regions.end())
	{
		return -1;
	}
	
	return (*di)->d_offset + (virt_offset - (*di)->virt_offset);
}

REHex::BitOffset REHex::DocumentCtrl::region_cursor_left(BitOffset cursor_pos, GenericDataRegion::ScreenArea area)
{
	auto region = _data_region_by_offset(cursor_pos);
	assert(region != data_regions.end());
	
	BitOffset new_cursor_pos = (*region)->cursor_left_from(cursor_pos, area, this);
	
	if(new_cursor_pos == GenericDataRegion::CURSOR_PREV_REGION)
	{
		/* Cursor is at the start of this region. Move to the last byte in
		 * the previous region.
		*/
		
		if(region != data_regions.begin())
		{
			auto prev_region = std::prev(region);
			
			new_cursor_pos = (*prev_region)->last_row_nearest_column(INT_MAX);
			assert(new_cursor_pos.byte() >= 0);
		}
		else{
			/* No previous region. Nowhere to go. */
			new_cursor_pos = cursor_pos;
		}
	}
	else{
		assert(new_cursor_pos.byte() >= 0);
	}
	
	return new_cursor_pos;
}

REHex::BitOffset REHex::DocumentCtrl::region_cursor_right(BitOffset cursor_pos, GenericDataRegion::ScreenArea area)
{
	auto region = _data_region_by_offset(cursor_pos);
	assert(region != data_regions.end());
	
	BitOffset new_cursor_pos = (*region)->cursor_right_from(cursor_pos, area, this);
	
	if(new_cursor_pos == GenericDataRegion::CURSOR_NEXT_REGION)
	{
		auto next_region = std::next(region);
		if(next_region != data_regions.end())
		{
			new_cursor_pos = (*next_region)->first_row_nearest_column(0);
			assert(new_cursor_pos.byte() >= 0);
		}
		else if(get_insert_mode())
		{
			/* Special case: Can move one past the end of the final
			 * data region in insert mode.
			*/
			
			new_cursor_pos = (*region)->d_offset + (*region)->d_length;
		}
		else{
			/* No further region. Nowhere to go. */
			new_cursor_pos = cursor_pos;
		}
	}
	else{
		assert(new_cursor_pos.byte() >= 0);
	}
	
	return new_cursor_pos;
}

/* Scroll the Document vertically to make the given line visible.
 * Does nothing if the line is already on-screen.
*/
void REHex::DocumentCtrl::_make_line_visible(int64_t line)
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
void REHex::DocumentCtrl::_make_x_visible(int x_px, int width_px)
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
void REHex::DocumentCtrl::_make_byte_visible(BitOffset offset)
{
	if((GetWindowStyle() & DCTRL_LOCK_SCROLL) != 0)
	{
		return;
	}
	
	auto dr = _data_region_by_offset(offset);
	assert(dr != data_regions.end());
	
	Rect bounds = (*dr)->calc_offset_bounds(offset, this);
	assert(bounds.h == 1);
	
	_make_line_visible(bounds.y);
	_make_x_visible(bounds.x, bounds.w);
}

std::list<wxString> REHex::DocumentCtrl::wrap_text(const wxString &text, unsigned int cols)
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
	
	return lines;
}

int REHex::DocumentCtrl::wrap_text_height(const wxString &text, unsigned int cols)
{
	assert(cols > 0);
	
	int height = 0;
	
	for(size_t at = 0; at < text.size();)
	{
		size_t newline_at = text.find_first_of('\n', at);
		
		if(newline_at != std::string::npos && newline_at <= (at + cols))
		{
			/* There is a newline within one row's worth of text of our current position.
			 * Add all the text up to it and continue from after it.
			*/
			++height;
			at = newline_at + 1;
		}
		else{
			/* The line is too long, just wrap it at whatever character is on the boundary.
			 *
			 * std::string::substr() will clamp the length if it goes beyond the end of
			 * the string.
			*/
			++height;
			at += cols;
		}
	}
	
	return height;
}

int REHex::DocumentCtrl::indent_width(int depth)
{
	return hf_char_width() * depth;
}

int REHex::DocumentCtrl::get_offset_column_width()
{
	return offset_column_width;
}

int REHex::DocumentCtrl::get_virtual_width()
{
	return virtual_width;
}

bool REHex::DocumentCtrl::get_cursor_visible()
{
	if((GetWindowStyle() & DCTRL_HIDE_CURSOR) != 0)
	{
		return false;
	}
	
	return cursor_visible;
}

bool REHex::DocumentCtrl::is_selection_hidden() const
{
	return (mouse_down_area == GenericDataRegion::SA_NONE) && ((GetWindowStyle() & DCTRL_HIDE_CURSOR) != 0);
}

REHex::BitOffset REHex::DocumentCtrl::get_end_virt_offset() const
{
	return end_virt_offset;
}

/* Calculate the width of a character in hex_font. */
int REHex::DocumentCtrl::hf_char_width()
{
	return hf_string_width(1);
}

int REHex::DocumentCtrl::hf_char_height()
{
	return hf_height;
}

/* Calculate the bounding box for a string which is length characters long when
 * rendered using hex_font. The string should fit within the box.
 *
 * We can't just multiply the width of a single character because certain
 * platforms *cough* *OSX* use subpixel co-ordinates for character spacing.
*/
int REHex::DocumentCtrl::hf_string_width(int length)
{
	if(length == 0)
	{
		return 0;
	}
	
	int string_width = 0;
	
	if(length > PRECOMP_HF_STRING_WIDTH_TO)
	{
		int div = (length - 1) / PRECOMP_HF_STRING_WIDTH_TO;
		
		string_width += div * hf_string_width_precomp[PRECOMP_HF_STRING_WIDTH_TO - 1];
		length -= div * PRECOMP_HF_STRING_WIDTH_TO;
	}
	
	string_width += hf_string_width_precomp[length - 1];
	
	return string_width;
}

/* Calculate the character at the pixel offset relative to the start of the string. */
int REHex::DocumentCtrl::hf_char_at_x(int x_px)
{
	if(hf_string_width_precomp[PRECOMP_HF_STRING_WIDTH_TO - 1] > (unsigned int)(x_px))
	{
		auto it = std::upper_bound(
			hf_string_width_precomp,
			hf_string_width_precomp + PRECOMP_HF_STRING_WIDTH_TO,
			(unsigned int)(x_px));
		
		return std::distance(hf_string_width_precomp, it);
	}
	else{
		for(int i = PRECOMP_HF_STRING_WIDTH_TO;; ++i)
		{
			int w = hf_string_width(i + 1);
			if(w > x_px)
			{
				return i;
			}
		}
	}
}

#ifdef REHEX_CACHE_CHARACTER_BITMAPS
wxBitmap REHex::DocumentCtrl::hf_char_bitmap(const wxString &wx_char, ucs4_t unicode_char, const wxSize &char_size, const wxColour &foreground_colour, const wxColour &background_colour)
{
	PROFILE_BLOCK("REHex::DocumentCtrl::hf_char_bitmap");
	
	auto cache_key = std::make_tuple(unicode_char, pack_colour(foreground_colour), pack_colour(background_colour));
	
	const wxBitmap *cached_bitmap;
	{
		PROFILE_INNER_BLOCK("cache lookup");
		cached_bitmap = hf_char_bitmap_cache.get(cache_key);
	}
	
	if(cached_bitmap == NULL)
	{
		PROFILE_INNER_BLOCK("generate char bitmap");
		
		/* I (briefly) tried getting this working with 1bpp bitmaps, but couldn't get the
		 * background behaving correctly then found this tidbit on the web:
		 *
		 * > Support for monochrome bitmaps is very limited in wxWidgets. And
		 * > wxNativePixelData is designed for 24bit RGB data, so i doubt it will give the
		 * > expected results for monochrome bitmaps.
		 * >
		 * > Even if it's a waste of memory, i would suggest to work with 24bit RGB bitmaps
		 * > and only at the very end convert it to a 1bit bitmap.
		 * - https://forums.wxwidgets.org/viewtopic.php?p=185332#p185332
		*/

		wxBitmap char_bitmap(char_size, wxBITMAP_SCREEN_DEPTH);
		wxMemoryDC mdc(char_bitmap);

		mdc.SetFont(hex_font);

		mdc.SetBackground(wxBrush(background_colour));
		mdc.Clear();

		mdc.SetTextForeground(foreground_colour);
		mdc.SetBackgroundMode(wxTRANSPARENT);
		mdc.DrawText(wx_char, 0, 0);

		mdc.SelectObject(wxNullBitmap);

		cached_bitmap = hf_char_bitmap_cache.set(cache_key, char_bitmap);
	}

	/* wxBitmap internally does refcounting and CoW, returning a thin wxBitmap copy rather than a
	 * pointer into the cache stops the caller from having to worry about the returned wxColour
	 * being invalidated in the future.
	*/
	return *cached_bitmap;
}
#endif

#ifdef REHEX_CACHE_STRING_BITMAPS
wxBitmap REHex::DocumentCtrl::hf_string_bitmap(const std::vector<AlignedCharacter> &characters, int base_col, const wxColour &foreground_colour, const wxColour &background_colour)
{
	PROFILE_BLOCK("REHex::DocumentCtrl::hf_string_bitmap");
	
	StringBitmapCacheKey cache_key(base_col, characters, pack_colour(foreground_colour), pack_colour(background_colour));

	const wxBitmap *cached_string;
	{
		PROFILE_INNER_BLOCK("cache lookup");
		cached_string = hf_string_bitmap_cache.get(cache_key);
	}
	
	if(cached_string == NULL)
	{
		PROFILE_INNER_BLOCK("generate string bitmap");
		
		std::vector<wxBitmap> char_bitmaps;
		char_bitmaps.reserve(characters.size());

		int string_h = -1;
		const AlignedCharacter *max_col = NULL;

		for(auto c = characters.begin(); c != characters.end(); ++c)
		{
			PROFILE_INNER_BLOCK("get char bitmap");
			
			char_bitmaps.push_back(hf_char_bitmap(c->wx_char, c->unicode_char, c->char_size, foreground_colour, background_colour));
			
			if(c->char_size.GetHeight() > string_h)
			{
				string_h = c->char_size.GetHeight();
			}

			if(max_col == NULL || c->column > max_col->column)
			{
				max_col = &(*c);
			}
		}

		int base_x = hf_string_width(base_col);
		int string_w = (hf_string_width(max_col->column) - base_x) + max_col->char_size.GetWidth();

		wxBitmap string_bitmap(string_w, string_h, wxBITMAP_SCREEN_DEPTH);
		wxMemoryDC mdc(string_bitmap);

		mdc.SetBackground(wxBrush(background_colour));
		mdc.Clear();

		auto c_bitmap = char_bitmaps.begin();
		for(auto c = characters.begin(); c != characters.end(); ++c, ++c_bitmap)
		{
			PROFILE_INNER_BLOCK("draw char bitmap");
			mdc.DrawBitmap(*c_bitmap, (hf_string_width(c->column) - base_x), 0, true);
		}

		mdc.SelectObject(wxNullBitmap);

		/* In addition to not working on macOS, creating a mask is expensive. */
		#ifndef __APPLE__
		string_bitmap.SetMask(new wxMask(string_bitmap, background_colour));
		#endif

		cached_string = hf_string_bitmap_cache.set(cache_key, string_bitmap);
	}

	return *cached_string;
}
#endif

const std::vector<REHex::DocumentCtrl::Region*> &REHex::DocumentCtrl::get_regions() const
{
	return regions;
}

const std::vector<REHex::DocumentCtrl::GenericDataRegion*> &REHex::DocumentCtrl::get_data_regions() const
{
	return data_regions;
}

void REHex::DocumentCtrl::replace_all_regions(std::vector<Region*> &new_regions)
{
	PROFILE_BLOCK("REHex::DocumentCtrl::replace_all_regions");
	
	FuzzyScrollPosition scroll_position = get_scroll_position_fuzzy();
	
	assert(!new_regions.empty());
	
	/* Erase the old regions and swap the contents of the new list in. */
	
	{
		PROFILE_INNER_BLOCK("replace regions");
		
		for(auto r = regions.begin(); r != regions.end(); ++r)
		{
			delete *r;
		}
		
		regions.clear();
		
		regions.swap(new_regions);
	}
	
	{
		PROFILE_INNER_BLOCK("indenting and fill data_regions");
		
		/* Initialise the indent_depth and indent_final counters. */
		
		ThreadPool::TaskHandle a = wxGetApp().thread_pool->queue_task([&]()
		{
			std::list<BitOffset> indent_to;
			
			for(auto r = regions.begin(), p = r; r != regions.end(); ++r)
			{
				assert((*r)->indent_offset >= (*p)->indent_offset);
				
				while(!indent_to.empty() && indent_to.back() <= (*r)->indent_offset)
				{
					++((*p)->indent_final);
					indent_to.pop_back();
				}
				
				(*r)->indent_depth = indent_to.size();
				(*r)->indent_final = 0;
				
				if((*r)->indent_length > 0)
				{
					if(!indent_to.empty())
					{
						assert(((*r)->indent_offset + (*r)->indent_length) <= indent_to.back());
					}
					
					indent_to.push_back((*r)->indent_offset + (*r)->indent_length);
				}
				
				/* Advance p from second iteration. */
				if(p != r)
				{
					++p;
				}
			}
			
			regions.back()->indent_final = indent_to.size();
		}, ThreadPool::TaskPriority::UI);
		
		/* Clear and repopulate data_regions with the GenericDataRegion regions. */
		
		ThreadPool::TaskHandle b = wxGetApp().thread_pool->queue_task([&]()
		{
			data_regions.clear();
			end_virt_offset = -1;
			
			for(auto r = regions.begin(); r != regions.end(); ++r)
			{
				GenericDataRegion *dr = dynamic_cast<GenericDataRegion*>(*r);
				if(dr != NULL)
				{
					data_regions.push_back(dr);
					
					BitOffset dr_end_virt_offset = dr->virt_offset + dr->d_length;
					if(dr_end_virt_offset > end_virt_offset)
					{
						end_virt_offset = dr_end_virt_offset;
					}
				}
			}
		}, ThreadPool::TaskPriority::UI);
		
		a.join();
		b.join();
	}
	
	{
		PROFILE_INNER_BLOCK("fill region sub-lists");
		
		/* Clear and repopulate data_regions_sorted with iterators to each element in data_regions
		* sorted by d_offset.
		*/
		
		ThreadPool::TaskHandle a = wxGetApp().thread_pool->queue_task([&]()
		{
			data_regions_sorted.clear();
			data_regions_sorted.reserve(data_regions.size());
			
			for(auto r = data_regions.begin(); r != data_regions.end(); ++r)
			{
				data_regions_sorted.push_back(r);
			}
			
			std::sort(data_regions_sorted.begin(), data_regions_sorted.end(),
				[](const std::vector<GenericDataRegion*>::iterator &lhs, const std::vector<GenericDataRegion*>::iterator &rhs)
				{
					return (*lhs)->d_offset < (*rhs)->d_offset;
				});
		}, ThreadPool::TaskPriority::UI);
		
		/* Clear and repopulate data_regions_sorted_virt with iterators to each element in
		* data_regions sorted by virt_offset.
		*/
		
		ThreadPool::TaskHandle b = wxGetApp().thread_pool->queue_task([&]()
		{
			data_regions_sorted_virt.clear();
			data_regions_sorted_virt.reserve(data_regions.size());
			
			for(auto r = data_regions.begin(); r != data_regions.end(); ++r)
			{
				data_regions_sorted_virt.push_back(r);
			}
			
			std::sort(data_regions_sorted_virt.begin(), data_regions_sorted_virt.end(),
				[](const std::vector<GenericDataRegion*>::iterator &lhs, const std::vector<GenericDataRegion*>::iterator &rhs)
				{
					return (*lhs)->virt_offset < (*rhs)->virt_offset;
				});
		}, ThreadPool::TaskPriority::UI);
		
		/* Clear and repopulate processing_regions with the regions which have some background work to do. */
		
		ThreadPool::TaskHandle c = wxGetApp().thread_pool->queue_task([&]()
		{
			processing_regions.clear();
			
			for(auto r = regions.begin(); r != regions.end(); ++r)
			{
				unsigned int status = (*r)->check();
				
				if(status & Region::PROCESSING)
				{
					processing_regions.push_back(*r);
				}
			}
		}, ThreadPool::TaskPriority::UI);
		
		a.join();
		b.join();
		c.join();
	}
	
	/* Recalculates region widths/heights and updates scroll bars */
	
	{
		PROFILE_INNER_BLOCK("_handle_width_change");
		_handle_width_change();
	}
	
	/* Update the cursor position/state if not valid within the new regions. */
	
	{
		PROFILE_INNER_BLOCK("_set_cursor_position");
		_set_cursor_position(get_cursor_position(), get_cursor_state());
	}
	
	set_scroll_position_fuzzy(scroll_position);
	save_scroll_position();
}

bool REHex::DocumentCtrl::region_OnChar(wxKeyEvent &event)
{
	BitOffset cursor_pos = get_cursor_position();
	
	auto cur_region = _data_region_by_offset(cursor_pos);
	assert(cur_region != data_regions.end());
	
	return (*cur_region)->OnChar(this, event);
}

REHex::DocumentCtrl::GenericDataRegion *REHex::DocumentCtrl::data_region_by_offset(BitOffset offset)
{
	auto region = _data_region_by_offset(offset);
	return region != data_regions.end() ? *region : NULL;
}

wxFont &REHex::DocumentCtrl::get_font()
{
	return hex_font;
}

int64_t REHex::DocumentCtrl::get_scroll_yoff() const
{
	return scroll_yoff;
}

void REHex::DocumentCtrl::set_scroll_yoff(int64_t scroll_yoff, bool update_linked_scroll_others)
{
	set_scroll_yoff_clamped(scroll_yoff);
	
	_update_vscroll_pos(update_linked_scroll_others);
	save_scroll_position();
	Refresh();
}

void REHex::DocumentCtrl::set_scroll_yoff_clamped(int64_t scroll_yoff)
{
	if((GetWindowStyle() & DCTRL_LOCK_SCROLL) != 0)
	{
		return;
	}
	
	if(scroll_yoff < 0)
	{
		scroll_yoff = 0;
	}
	else if(scroll_yoff > scroll_yoff_max)
	{
		scroll_yoff = scroll_yoff_max;
	}
	
	this->scroll_yoff = scroll_yoff;
}

REHex::DocumentCtrl::Region::Region(BitOffset indent_offset, BitOffset indent_length):
	indent_depth(0),
	indent_final(0),
	indent_offset(indent_offset),
	indent_length(indent_length)  {}

REHex::DocumentCtrl::Region::~Region() {}

unsigned int REHex::DocumentCtrl::Region::check()
{
	return StateFlag::IDLE;
}

int REHex::DocumentCtrl::Region::calc_width(REHex::DocumentCtrl &doc)
{
	return 0;
}

wxCursor REHex::DocumentCtrl::Region::cursor_for_point(REHex::DocumentCtrl &doc, int x, int64_t y_lines, int y_px)
{
	return wxNullCursor;
}

void REHex::DocumentCtrl::Region::draw_container(REHex::DocumentCtrl &doc, wxDC &dc, int x, int64_t y)
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
			if(box_h <= (int64_t)(doc.client_height) && (i + indent_final) == indent_depth)
			{
				box_h  -= ch / 2;
				box_hc -= ch / 2;
			}
			
			dc.DrawLine(box_x, box_y, box_x, (box_y + box_hc));
			dc.DrawLine((box_x + box_w - 1), box_y, (box_x + box_w - 1), (box_y + box_hc));
			
			if(box_h <= (int64_t)(doc.client_height) && (i + indent_final) >= indent_depth)
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

void REHex::DocumentCtrl::Region::draw_full_height_line(DocumentCtrl *doc_ctrl, wxDC &dc, int x, int64_t y)
{
	int ch = doc_ctrl->hf_height;
	
	int64_t skip_lines = (y < 0 ? (-y / ch) : 0);
	
	int     box_y  = y + (skip_lines * (int64_t)(ch));
	int64_t box_h  = (y_lines - skip_lines) * (int64_t)(ch);
	int     box_hc = std::min(box_h, (int64_t)(doc_ctrl->client_height));
	
	dc.SetPen(wxPen((*active_palette)[Palette::PAL_NORMAL_TEXT_FG]));
	
	dc.DrawLine(x, box_y, x, (box_y + box_hc));
}

REHex::DocumentCtrl::GenericDataRegion::GenericDataRegion(BitOffset d_offset, BitOffset d_length, BitOffset virt_offset, BitOffset indent_offset):
	Region(indent_offset, 0),
	d_offset(d_offset),
	d_length(d_length),
	virt_offset(virt_offset)
{
	assert(d_offset >= BitOffset::ZERO);
	assert(d_length >= BitOffset::ZERO);
}

bool REHex::DocumentCtrl::GenericDataRegion::OnChar(DocumentCtrl *doc_ctrl, wxKeyEvent &event)
{
	return false;
}

wxDataObject *REHex::DocumentCtrl::GenericDataRegion::OnCopy(DocumentCtrl &doc_ctrl)
{
	return NULL;
}

bool REHex::DocumentCtrl::GenericDataRegion::OnPaste(DocumentCtrl *doc_ctrl)
{
	return false;
}

REHex::DocumentCtrl::DataRegion::DataRegion(SharedDocumentPointer &document, BitOffset d_offset, BitOffset d_length, BitOffset virt_offset):
	GenericDataRegion(d_offset, d_length, virt_offset, virt_offset),
	document(document),
	bytes_per_line_actual(1) {}

int REHex::DocumentCtrl::DataRegion::calc_width(REHex::DocumentCtrl &doc)
{
	/* Decide how many bytes to display per line */
	
	if(doc.bytes_per_line == BYTES_PER_LINE_FIT_BYTES)
	{
		/* TODO: Can I do this algorithmically? */
		
		bytes_per_line_actual = 1;
		
		while(calc_width_for_bytes(doc, bytes_per_line_actual + 1) <= doc.client_width)
		{
			++bytes_per_line_actual;
		}
		
		first_line_pad_bytes = 0;
	}
	else if(doc.bytes_per_line == BYTES_PER_LINE_FIT_GROUPS)
	{
		bytes_per_line_actual = doc.bytes_per_group;
		
		while(calc_width_for_bytes(doc, bytes_per_line_actual + doc.bytes_per_group) <= doc.client_width)
		{
			bytes_per_line_actual += doc.bytes_per_group;
		}
		
		first_line_pad_bytes = 0;
	}
	else{
		bytes_per_line_actual = doc.bytes_per_line;
		
		first_line_pad_bytes = d_offset.byte() % bytes_per_line_actual;
	}
	
	return calc_width_for_bytes(doc, bytes_per_line_actual);
}

int REHex::DocumentCtrl::DataRegion::calc_width_for_bytes(DocumentCtrl &doc_ctrl, unsigned int line_bytes) const
{
	return calc_width_for_bytes(doc_ctrl, line_bytes, indent_depth);
}

int REHex::DocumentCtrl::DataRegion::calc_width_for_bytes(DocumentCtrl &doc_ctrl, unsigned int line_bytes, int indent_depth)
{
	return doc_ctrl.offset_column_width
		/* indentation */
		+ (doc_ctrl.indent_width(indent_depth) * 2)
		
		/* hex data */
		+ doc_ctrl.hf_string_width(line_bytes * 2)
		+ doc_ctrl.hf_string_width((line_bytes - 1) / doc_ctrl.bytes_per_group)
		
		/* ASCII data */
		+ (doc_ctrl.show_ascii * doc_ctrl.hf_char_width())
		+ (doc_ctrl.show_ascii * doc_ctrl.hf_string_width(line_bytes));
}

void REHex::DocumentCtrl::DataRegion::calc_height(REHex::DocumentCtrl &doc)
{
	int indent_width = doc.indent_width(indent_depth);
	
	offset_text_x = indent_width;
	hex_text_x    = indent_width + doc.offset_column_width;
	ascii_text_x  = (doc.virtual_width - indent_width) - doc.hf_string_width(bytes_per_line_actual);
	
	/* If we are rendering the first line of the region, then we offset it to (mostly)
	 * preserve column alignment between regions.
	*/
	
	off_t effective_length = d_length.byte() + first_line_pad_bytes;
	
	/* Height of the region is simply the number of complete lines of data plus an incomplete
	 * one if the data isn't a round number of lines.
	*/
	y_lines = (effective_length / bytes_per_line_actual) + !!(effective_length % bytes_per_line_actual) + indent_final;
	
	if((d_offset + d_length) == doc.doc->buffer_length() && (effective_length % bytes_per_line_actual) == 0)
	{
		/* This is the last data region in the document. Make it one row taller if the last
		 * row is full so there is always somewhere to draw the insert cursor.
		*/
		++y_lines;
	}
}

void REHex::DocumentCtrl::DataRegion::draw(REHex::DocumentCtrl &doc, wxDC &dc, int x, int64_t y)
{
	PROFILE_BLOCK("REHex::DocumentCtrl::DataRegion::Draw");
	
	draw_container(doc, dc, x, y);
	
	/* If we are scrolled part-way into a data region, don't render data above the client area
	 * as it would get expensive very quickly with large files.
	*/
	int64_t skip_lines = (y < 0 ? (-y / doc.hf_height) : 0);
	off_t skip_bytes  = skip_lines * bytes_per_line_actual;
	
	wxPen norm_fg_1px((*active_palette)[Palette::PAL_NORMAL_TEXT_FG], 1);
	
	bool alternate_row = ((y_offset + skip_lines) % 2) != 0;
	
	auto normal_text_colour = [&dc,&alternate_row]()
	{
		dc.SetTextForeground((*active_palette)[alternate_row ? Palette::PAL_ALTERNATE_TEXT_FG : Palette::PAL_NORMAL_TEXT_FG ]);
		dc.SetBackgroundMode(wxTRANSPARENT);
	};
	
	if(skip_bytes > 0)
	{
		assert(skip_bytes > first_line_pad_bytes);
		skip_bytes -= first_line_pad_bytes;
	}
	
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
	
	static const int SECONDARY_SELECTION_MAX = 4096;
	
	BitOffset linear_selection_off, linear_selection_len;
	std::tie(linear_selection_off, linear_selection_len) = doc.get_selection_linear();
	
	std::vector<unsigned char> selection_data;
	if(doc.get_highlight_selection_match() && linear_selection_len.byte() > 0 && linear_selection_len.byte() <= SECONDARY_SELECTION_MAX && linear_selection_len.byte_aligned())
	{
		try {
			selection_data = doc.doc->read_data(linear_selection_off, linear_selection_len.byte());
		}
		catch(const std::exception &e)
		{
			fprintf(stderr, "Exception in REHex::Document::Region::Data::draw: %s\n", e.what());
		}
	}
	
	/* Fetch the data to be drawn. */
	BitOffset data_base;
	std::vector<unsigned char> data;
	bool data_err = false;
	
	BitRangeSet ranges_matching_selection;
	
	const unsigned char *data_p = NULL;
	size_t data_remain;
	
	off_t hsm_pre = std::max<off_t>(selection_data.size(), MAX_CHAR_SIZE);
	hsm_pre = std::min<off_t>(hsm_pre, (d_offset + skip_bytes).byte()); /* Clamp to avoid offset going negative. */
	
	off_t hsm_post = std::max<off_t>(selection_data.size(), MAX_CHAR_SIZE);
	
	try {
		data_base = d_offset + BitOffset::BYTES(skip_bytes - hsm_pre);
		off_t data_to_draw = std::min(max_bytes, (d_length.byte() - std::min(skip_bytes, d_length.byte())));
		
		data = doc.doc->read_data(data_base, data_to_draw + hsm_pre + hsm_post);
		
		data_p = data.data() + hsm_pre;
		data_remain = std::min<size_t>((data.size() - hsm_pre), data_to_draw);
		
		if(!selection_data.empty())
		{
			for(size_t i = 0; (i + selection_data.size()) <= data.size();)
			{
				if(memcmp((data.data() + i), selection_data.data(), selection_data.size()) == 0)
				{
					ranges_matching_selection.set_range(data_base + BitOffset(i, 0), selection_data.size());
					i += selection_data.size();
				}
				else{
					++i;
				}
			}
		}
	}
	catch(const std::exception &e)
	{
		fprintf(stderr, "Exception in REHex::DocumentCtrl::DataRegion::draw: %s\n", e.what());
		
		data.insert(data.end(), std::min(max_bytes, (d_length.byte() - std::min(skip_bytes, d_length.byte()))), '?');
		data_err = true;
		data_p = NULL;
	}
	
	/* The offset of the character in the Buffer currently being drawn. */
	BitOffset cur_off = d_offset + BitOffset::BYTES(skip_bytes);
	
	wxSize client_size = doc.GetClientSize();
	
	auto highlight_func = [&](BitOffset offset)
	{
		if(ranges_matching_selection.isset(offset))
		{
			return Highlight(
				(*active_palette)[Palette::PAL_SECONDARY_SELECTED_TEXT_FG],
				(*active_palette)[Palette::PAL_SECONDARY_SELECTED_TEXT_BG]);
		}
		else{
			Highlight h = highlight_at_off(offset);
			if(h.enable)
			{
				return h;
			}
			
			auto byte_colour_map = doc.get_byte_colour_map();
			if(byte_colour_map)
			{
				BitOffset offset_within_data = offset - data_base;
				assert(offset_within_data >= BitOffset::ZERO);
				
				if(offset_within_data.byte() < data.size())
				{
					unsigned char byte = data[offset_within_data.byte()];
					
					return Highlight(
						byte_colour_map->get_colour(byte),
						(*active_palette)[Palette::PAL_NORMAL_TEXT_BG]);
				}
			}
			
			return Highlight(NoHighlight());
		}
	};
	
	BitOffset scoped_selection_offset, scoped_selection_length;
	std::tie(scoped_selection_offset, scoped_selection_length) = doc.get_selection_in_region(this);
	
	const Highlight hex_selection_highlight(
		(*active_palette)[Palette::PAL_SELECTED_TEXT_FG],
		(doc.hex_view_active()
			? (*active_palette)[Palette::PAL_SELECTED_TEXT_BG]
			: active_palette->get_average_colour(Palette::PAL_SELECTED_TEXT_BG, Palette::PAL_NORMAL_TEXT_BG)));
	
	bool selection_hidden = doc.is_selection_hidden();
	
	auto hex_highlight_func = [&](BitOffset offset)
	{
		if(!selection_hidden && offset >= scoped_selection_offset && offset < (scoped_selection_offset + scoped_selection_length))
		{
			return hex_selection_highlight;
		}
		else{
			return highlight_func(offset);
		}
	};
	
	const Highlight ascii_selection_highlight(
		(*active_palette)[Palette::PAL_SELECTED_TEXT_FG],
		(doc.ascii_view_active()
			? (*active_palette)[Palette::PAL_SELECTED_TEXT_BG]
			: active_palette->get_average_colour(Palette::PAL_SELECTED_TEXT_BG, Palette::PAL_NORMAL_TEXT_BG)));
	
	auto ascii_highlight_func = [&](BitOffset offset)
	{
		if(!selection_hidden && offset >= scoped_selection_offset && offset < (scoped_selection_offset + scoped_selection_length))
		{
			return ascii_selection_highlight;
		}
		else{
			return highlight_func(offset);
		}
	};
	
	int64_t cur_line = y_offset + skip_lines;
	
	bool is_last_data_region = (doc.get_data_regions().back() == this);
	
	while(y < client_size.GetHeight() && cur_line < (y_offset + y_lines - indent_final))
	{
		if(doc.offset_column)
		{
			/* Draw the offsets to the left */
			
			BitOffset offset_within_region = cur_off - d_offset;
			BitOffset display_offset = virt_offset + offset_within_region;
			
			std::string offset_str = format_offset(display_offset, doc.offset_display_base, doc.end_virt_offset);
			
			normal_text_colour();
			dc.DrawText(offset_str.c_str(), (x + offset_text_x), y);
		}
		
		/* If we are rendering the first line of the region, then we offset it to (mostly)
		 * preserve column alignment between regions.
		*/
		
		unsigned int line_pad_bytes = (cur_off == d_offset)
			? first_line_pad_bytes
			: 0;
		
		const unsigned char *line_data = data_err ? NULL : data_p;
		size_t line_data_len = std::min<size_t>(data_remain, (bytes_per_line_actual - line_pad_bytes));
		
		bool is_last_line = is_last_data_region && (cur_line + 1) == (y_offset + y_lines - indent_final);
		
		draw_hex_line(&doc, dc, x + hex_text_x, y, line_data, line_data_len, line_pad_bytes, cur_off, alternate_row, hex_highlight_func, is_last_line);
		
		if(doc.show_ascii)
		{
			size_t line_data_extra_pre = std::min<size_t>((data_p - data.data()), MAX_CHAR_SIZE);
			size_t line_data_extra_post = data_remain - line_data_len;
			
			BitOffset start_char_off;
			off_t start_char_len;
			std::tie(start_char_off, start_char_len) = get_char_at(cur_off);
			
			size_t trailing_bytes = (start_char_off >= BitOffset::ZERO)
				? (cur_off - start_char_off).byte()
				: 0;
			
			draw_ascii_line(&doc, dc, x + ascii_text_x, y, (start_char_off >= 0 ? line_data + trailing_bytes : NULL), line_data_len - trailing_bytes, line_data_extra_pre, line_data_extra_post, line_pad_bytes + trailing_bytes, cur_off + (off_t)(trailing_bytes), alternate_row, ascii_highlight_func, is_last_line);
		}
		
		cur_off += line_data_len;
		
		data_p += line_data_len;
		data_remain -= line_data_len;
		
		y += doc.hf_height;
		++cur_line;
		
		alternate_row = !alternate_row;
	}
}

void REHex::DocumentCtrl::Region::draw_hex_line(DocumentCtrl *doc_ctrl, wxDC &dc, int x, int y, const unsigned char *data, size_t data_len, unsigned int pad_bytes, BitOffset base_off, bool alternate_row, const std::function<Highlight(BitOffset)> &highlight_at_off, bool is_last_line)
{
	PROFILE_BLOCK("REHex::DocumentCtrl:Region::draw_hex_line");
	
	int hex_base_x = x;                                                          /* Base X co-ordinate to draw hex characters from */
	int hex_x_char = (pad_bytes * 2) + (pad_bytes / doc_ctrl->bytes_per_group);  /* Column of current hex character */
	int hex_x      = hex_base_x + doc_ctrl->hf_string_width(hex_x_char);         /* X co-ordinate of current hex character */
	
	BitOffset cur_off = base_off;
	
	dc.SetFont(doc_ctrl->hex_font);
	
	wxPen norm_fg_1px((*active_palette)[Palette::PAL_NORMAL_TEXT_FG], 1);
	wxPen selected_bg_1px((*active_palette)[Palette::PAL_SELECTED_TEXT_BG], 1);
	dc.SetBrush(*wxTRANSPARENT_BRUSH);
	
	FastRectangleFiller frf(dc);
	
	bool hex_active = doc_ctrl->HasFocus() && doc_ctrl->hex_view_active();
	
	BitOffset cursor_pos = doc_ctrl->get_cursor_position();
	
	auto normal_text_colour = [&dc,&alternate_row]()
	{
		dc.SetTextForeground((*active_palette)[alternate_row ? Palette::PAL_ALTERNATE_TEXT_FG : Palette::PAL_NORMAL_TEXT_FG ]);
		dc.SetBackgroundMode(wxTRANSPARENT);
	};
	
	const wxPen *insert_cursor_pen = NULL;
	wxPoint insert_cursor_pt1, insert_cursor_pt2;
	
	/* Calling wxDC::DrawText() for each individual character on the screen is
	 * painfully slow, so we batch up the wxDC::DrawText() calls for each colour and
	 * area on a per-line basis.
	 *
	 * The key of the deferred_drawtext map is the X co-ordinate to render the string
	 * at (hex_base_x or ascii_base_x) and the foreground colour to use.
	 *
	 * The draw_char_deferred() function adds a character to be drawn to the map, while
	 * prefixing it with any spaces necessary to pad it to the correct column from the
	 * base X co-ordinate.
	*/
	
	UnsortedMapVector<wxColour, std::string> deferred_drawtext;
	
	auto draw_char_deferred = [&](const wxColour &fg_colour, int col, char ch)
	{
		PROFILE_INNER_BLOCK("draw_char_deferred");
		
		std::string &str = deferred_drawtext[fg_colour];
		
		assert(str.length() <= (size_t)(col));
		
		str.append((col - str.length()), ' ');
		str.append(1, ch);
	};
	
	/* Because we need to minimise wxDC::DrawText() calls (see above), we draw any
	 * background colours ourselves and set the background mode to transparent when
	 * drawing text, which enables us to skip over characters that shouldn't be
	 * touched by that particular wxDC::DrawText() call by inserting spaces.
	*/
	
	auto fill_char_bg = [&](int char_x, const wxColour &bg_colour)
	{
		PROFILE_INNER_BLOCK("fill_char_bg");
		
		/* Abandoned dithering experiment. */
		#if 0
		wxBitmap bitmap(2, 2);
		
		{
			wxMemoryDC imagememDC;
			imagememDC.SelectObject(bitmap);
			
			wxBrush bg_brush((*active_palette)[Palette::PAL_NORMAL_TEXT_BG]);
			wxBrush fg_brush((*active_palette)[colour_idx]);
			
			imagememDC.SetBackground(bg_brush);
			imagememDC.Clear();
			
			imagememDC.SetBrush(fg_brush);
			imagememDC.SetPen(*wxTRANSPARENT_PEN);
			
			if(strong)
			{
				imagememDC.DrawRectangle(wxRect(0, 0, 2, 2));
			}
			else{
				imagememDC.DrawRectangle(wxRect(0, 0, 1, 1));
				imagememDC.DrawRectangle(wxRect(1, 1, 1, 1));
			}
		}
		
		wxBrush bg_brush(bitmap);
		#endif
		
		frf.fill_rectangle(char_x, y, doc_ctrl->hf_char_width(), doc_ctrl->hf_height, bg_colour);
	};
	
	for(size_t c = pad_bytes, i = 0; i < data_len; ++c, ++i)
	{
		if(c > pad_bytes && (c % doc_ctrl->bytes_per_group) == 0)
		{
			hex_x = hex_base_x + doc_ctrl->hf_string_width(++hex_x_char);
		}
		
		unsigned char byte        = (data != NULL) ? data[i] : '?';
		unsigned char high_nibble = (byte & 0xF0) >> 4;
		unsigned char low_nibble  = (byte & 0x0F);
		
		auto highlight_high = highlight_at_off(cur_off);
		auto highlight_low  = highlight_at_off(cur_off + BitOffset(0, 4));
		
		auto draw_nibble = [&](unsigned char nibble, bool invert, Highlight highlight)
		{
			const char *nibble_to_hex = (data != NULL)
				? "0123456789ABCDEF"
				: "????????????????";
			
			if(invert && doc_ctrl->get_cursor_visible())
			{
				fill_char_bg(hex_x, (*active_palette)[Palette::PAL_INVERT_TEXT_BG]);
				draw_char_deferred((*active_palette)[Palette::PAL_INVERT_TEXT_FG], hex_x_char, nibble_to_hex[nibble]);
			}
			else if(highlight.enable)
			{
				fill_char_bg(hex_x, highlight.bg_colour);
				draw_char_deferred(highlight.fg_colour, hex_x_char, nibble_to_hex[nibble]);
			}
			else{
				draw_char_deferred((*active_palette)[alternate_row ? Palette::PAL_ALTERNATE_TEXT_FG : Palette::PAL_NORMAL_TEXT_FG], hex_x_char, nibble_to_hex[nibble]);
			}
			
			hex_x = hex_base_x + doc_ctrl->hf_string_width(++hex_x_char);
		};
		
		bool inv_high = false, inv_low = false;
		if(hex_active)
		{
			if(cursor_pos == (cur_off + BitOffset(0, 4)))
			{
				inv_low = true;
			}
			else if(!doc_ctrl->insert_mode && cursor_pos == cur_off)
			{
				inv_high = true;
				
				if(wxGetApp().settings->get_cursor_nav_mode() == CursorNavMode::BYTE)
				{
					inv_low  = true;
				}
			}
		}
		
		/* Need the current hex_x value for drawing any boxes or insert cursors
		 * below, before it gets updated by draw_nibble().
		*/
		const int pd_hx = hex_x;
		
		draw_nibble(high_nibble, inv_high, highlight_high);
		draw_nibble(low_nibble,  inv_low,  highlight_low);
		
		if(cur_off == cursor_pos && doc_ctrl->insert_mode && ((doc_ctrl->get_cursor_visible() && doc_ctrl->cursor_state == Document::CSTATE_HEX) || !hex_active))
		{
			/* Draw insert cursor. */
			insert_cursor_pen = &norm_fg_1px;
			insert_cursor_pt1 = wxPoint(pd_hx, y);
			insert_cursor_pt2 = wxPoint(pd_hx, y + doc_ctrl->hf_height);
		}
		
		if((cur_off == cursor_pos || (cur_off + BitOffset(0, 4)) == cursor_pos) && !doc_ctrl->insert_mode && !hex_active)
		{
			/* Draw inactive overwrite cursor. */
			dc.SetBrush(*wxTRANSPARENT_BRUSH);
			dc.SetPen(norm_fg_1px);
			
			if((cur_off + BitOffset(0, 4)) == cursor_pos)
			{
				dc.DrawRectangle(pd_hx + doc_ctrl->hf_char_width(), y, doc_ctrl->hf_char_width(), doc_ctrl->hf_height);
			}
			else{
				dc.DrawRectangle(pd_hx, y, doc_ctrl->hf_string_width(2), doc_ctrl->hf_height);
			}
		}
		
		cur_off += BitOffset::BYTES(1);
	}
	
	if(is_last_line && cur_off == cursor_pos)
	{
		/* Draw cursor at the end of the file (i.e. after the last byte). */
		
		if((doc_ctrl->get_cursor_visible() && doc_ctrl->hex_view_active()) || !hex_active)
		{
			if(doc_ctrl->insert_mode || !hex_active)
			{
				insert_cursor_pen = &norm_fg_1px;
				insert_cursor_pt1 = wxPoint(hex_x, y);
				insert_cursor_pt2 = wxPoint(hex_x, y + doc_ctrl->hf_height);
			}
			else{
				/* Draw the cursor in red if trying to overwrite at an invalid
				 * position. Should only happen in empty files.
				*/
				
				insert_cursor_pen = wxRED_PEN;
				insert_cursor_pt1 = wxPoint(hex_x, y);
				insert_cursor_pt2 = wxPoint(hex_x, y + doc_ctrl->hf_height);
			}
		}
	}
	
	frf.flush();
	
	normal_text_colour();
	
	for(auto dd = deferred_drawtext.begin(); dd != deferred_drawtext.end(); ++dd)
	{
		PROFILE_INNER_BLOCK("drawing text");
		
		dc.SetTextForeground(dd->first);
		dc.SetBackgroundMode(wxTRANSPARENT);
		
		dc.DrawText(dd->second, hex_base_x, y);
	}
	
	if(insert_cursor_pen != NULL)
	{
		dc.SetPen(*insert_cursor_pen);
		dc.DrawLine(insert_cursor_pt1, insert_cursor_pt2);
	}
}

void REHex::DocumentCtrl::Region::draw_ascii_line(DocumentCtrl *doc_ctrl, wxDC &dc, int x, int y, const unsigned char *data, size_t data_len, size_t data_extra_pre, size_t data_extra_post, unsigned int pad_bytes, BitOffset base_off, bool alternate_row, const std::function<Highlight(BitOffset)> &highlight_at_off, bool is_last_line)
{
	PROFILE_BLOCK("REHex::DocumentCtrl:Region::draw_ascii_line");
	
	int ascii_base_x = x;                                                       /* Base X co-ordinate to draw ASCII characters from */
	int ascii_x_char = pad_bytes;                                               /* Column of current ASCII character */
	int ascii_x      = ascii_base_x + doc_ctrl->hf_string_width(ascii_x_char);  /* X co-ordinate of current ASCII character */
	
	dc.SetFont(doc_ctrl->hex_font);
	
	wxPen norm_fg_1px((*active_palette)[Palette::PAL_NORMAL_TEXT_FG], 1);
	wxPen selected_bg_1px((*active_palette)[Palette::PAL_SELECTED_TEXT_BG], 1);
	dc.SetBrush(*wxTRANSPARENT_BRUSH);
	
	FastRectangleFiller frf(dc);
	
	BitOffset cur_off = base_off;
	
	bool ascii_active = doc_ctrl->HasFocus() && doc_ctrl->ascii_view_active();
	
	BitOffset cursor_pos = doc_ctrl->get_cursor_position();
	
	auto normal_text_colour = [&dc,&alternate_row]()
	{
		dc.SetTextForeground((*active_palette)[alternate_row ? Palette::PAL_ALTERNATE_TEXT_FG : Palette::PAL_NORMAL_TEXT_FG ]);
		dc.SetBackgroundMode(wxTRANSPARENT);
	};
	
	const wxPen *insert_cursor_pen = NULL;
	wxPoint insert_cursor_pt1, insert_cursor_pt2;
	
	const BitRangeMap<Document::TypeInfo> &types = doc_ctrl->doc->get_data_types();
	
	size_t consume_chars = 0;
	
	/* Calling wxDC::DrawText() for each individual character on the screen is
	 * painfully slow, so we batch up the wxDC::DrawText() calls for each colour and
	 * area on a per-line basis.
	 *
	 * The key of the deferred_drawtext maps is the X co-ordinate to render the string
	 * at (hex_base_x or ascii_base_x plus an optional offset) and the foreground colour to
	 * use.
	 *
	 * The value of the deferred_drawtext_fast map is the string to be drawn and the number
	 * of fixed-width CHARACTERS that have been added so far.
	 *
	 * Characters that aren't exactly one character wide (e.g. wide characters) are rendered
	 * via the deferred_drawtext_slow mechanism instead - they are rendered alone using
	 * individual DrawText() calls, with platform-dependant caching to reduce the overhead.
	*/

	struct DeferredDrawTextFastValue
	{
		wxString string;
		int num_chars;
	};
	
	struct DeferredDrawTextSlowKey
	{
		int base_col;
		wxColour fg_colour;
		wxColour bg_colour;
		
		DeferredDrawTextSlowKey(int base_col, const wxColour &fg_colour, const wxColour &bg_colour):
			base_col(base_col),
			fg_colour(fg_colour),
			bg_colour(bg_colour) {}
		
		bool operator==(const DeferredDrawTextSlowKey &rhs) const
		{
			return base_col == rhs.base_col
				&& fg_colour == rhs.fg_colour
				&& bg_colour == rhs.bg_colour;
		}
	};

	struct DeferredDrawTextSlowValue
	{
		std::vector<AlignedCharacter> chars;
	};
	
	UnsortedMapVector<wxColour, DeferredDrawTextFastValue> deferred_drawtext_fast;
	UnsortedMapVector<DeferredDrawTextSlowKey, DeferredDrawTextSlowValue> deferred_drawtext_slow;
	
	#ifdef __APPLE__
	const DeferredDrawTextSlowKey *deferred_drawtext_slow_last_key = NULL;
	#endif
	
	auto draw_char_deferred = [&](const wxColour &fg_colour, int col, const void *data, size_t data_len, wxColour bg_colour)
	{
		PROFILE_INNER_BLOCK("draw_char_deferred");
		
		auto defer_monospace_char = [&](const wxString &c)
		{
			PROFILE_INNER_BLOCK("defer_monospace_char");
			
			#ifdef __APPLE__
			deferred_drawtext_slow_last_key = NULL;
			#endif
			
			DeferredDrawTextFastValue &v = deferred_drawtext_fast[fg_colour];

			assert(v.num_chars <= col);

			/* Add padding to skip to requested column. */
			v.string.append((col - v.num_chars), ' ');
			v.num_chars += col - v.num_chars;

			v.string.append(c);
			++v.num_chars;
		};

		auto defer_variable_pitch_char = [&](const wxString &wx_char, ucs4_t unicode_char, wxSize char_size)
		{
			PROFILE_INNER_BLOCK("defer_variable_pitch_char");
			
			DeferredDrawTextSlowKey k(0, fg_colour, bg_colour);
			#ifdef __APPLE__
			/* Okay... wxBitmap masks/transparency don't work on macOS, so if we draw multiple
			 * contiguous lines interleaved, relying on spaces in the string not being drawn
			 * what we instead get is the background colour of the most recently drawn line
			 * overwriting any behind it.
			 *
			 * So, on macOS we instead break up deferred_drawtext_slow into chunks of
			 * contiguous characters, starting a new chunk after changing bg/fg colour or
			 * drawing characters using the fast path.
			 *
			 * Wheeee.
			*/
			if(deferred_drawtext_slow_last_key != NULL
				&& deferred_drawtext_slow_last_key->fg_colour == fg_colour
				&& deferred_drawtext_slow_last_key->bg_colour == bg_colour)
			{
				k.base_col = deferred_drawtext_slow_last_key->base_col;
			}
			else{
				k.base_col = col;
			}
			
			bool inserted;
			UnsortedMapVector<DeferredDrawTextSlowKey, DeferredDrawTextSlowValue>::iterator ki;
			std::tie(ki, inserted) = deferred_drawtext_slow.insert(std::make_pair(k, DeferredDrawTextSlowValue()));
			
			deferred_drawtext_slow_last_key = &(ki->first);
			DeferredDrawTextSlowValue &v = ki->second;
			#else
			DeferredDrawTextSlowValue &v = deferred_drawtext_slow[k];
			#endif

			v.chars.push_back(AlignedCharacter(wx_char, unicode_char, char_size, col));
		};
		
		wxRect char_bbox(
			(ascii_base_x + doc_ctrl->hf_string_width(col)), y,
			doc_ctrl->hf_char_width(), doc_ctrl->hf_char_height());
		
		if(consume_chars > 0)
		{
			/* This is the tail end of a multibyte character. */
			
			--consume_chars;
			
			return char_bbox;
		}
		
		auto type_at_off = types.get_range(cur_off);
		assert(type_at_off != types.end());
		
		// TODO: Advance to start of next character if not aligned
		//BitOffset encoding_base = type_at_off->first.offset;
		//assert(encoding_base <= cur_off);
		
		static REHex::CharacterEncoderASCII ascii_encoder;
		const CharacterEncoder *encoder = &ascii_encoder;
		if(type_at_off->second.name != "")
		{
			auto type = DataTypeRegistry::get_type(type_at_off->second.name, type_at_off->second.options);
			assert(type != NULL);
			
			if(type->encoder != NULL)
			{
				encoder = type->encoder;
			}
		}
		
		EncodedCharacter ec = encoder->decode(data, data_len);
		if(ec.valid)
		{
			wxString wx_char = wxString::FromUTF8(ec.utf8_char().c_str());
			if (wx_char != "")
			{
				ucs4_t c;
				u8_mbtouc_unsafe(&c, (const uint8_t*)(ec.utf8_char().data()), ec.utf8_char().size());

				/* If the character is a control character, or the on-screen size reported
				 * by the font doesn't match that of "normal" characters, then we don't try
				 * drawing it.
				*/

				bool skip = uc_is_property_iso_control(c)
					|| uc_is_property_ignorable_control(c)
					|| uc_is_property_unassigned_code_value(c)
					|| uc_is_property_not_a_character(c);

				wxSize decoded_char_size;

				if (!skip && c >= 0x7F /* Assume anything in ASCII is really a fixed-width character in the fixed-width font */)
				{
					const wxSize* s = doc_ctrl->hf_gte_cache.get(c);
					if (s)
					{
						decoded_char_size = *s;
					}
					else {
						decoded_char_size = dc.GetTextExtent(wx_char);
						doc_ctrl->hf_gte_cache.set(c, decoded_char_size);
					}

					if (decoded_char_size.GetWidth() == 0 || decoded_char_size.GetHeight() == 0 /* Character doesn't occupy any space. */
						|| decoded_char_size.GetWidth() > doc_ctrl->hf_string_width(ec.encoded_char().size())) /* Character won't fit into available screen space. */
					{
						skip = true;
					}

					char_bbox.width = doc_ctrl->hf_string_width(ec.encoded_char().size());
					char_bbox.height = decoded_char_size.GetHeight();
				}

				if (!skip)
				{
					if (c > 0x7F)
					{
						/* If the character isn't in ASCII, fall back to drawing it
						 * by itself rather than part of a line - we can't trust
						 * the font not to lie about its width and render the whole
						 * line wonkily if we start putting any "weird" characters
						 * in it and I don't know of a better heuristic.
						*/

						defer_variable_pitch_char(wx_char, c, decoded_char_size);
					}
					else {
						defer_monospace_char(wx_char);
					}
				}
				else {
					/* Doesn't match the width of "normal" characters in the font.
					 *
					 * Could be a full-width character, or a control character, or
					 * maybe an emoji, or maybe even one of The Great Old Ones given
					 * form by the Unicode Consortium, either way, its gonna mess up
					 * our text alignment if we try drawing it.
					*/

					defer_monospace_char(".");
				}
			}
			else {
				/* wxWidgets can't decode the (valid) character for some reason.
				 * Yes, this actually happens for some of them.
				*/

				defer_monospace_char(".");
			}
			
			consume_chars = ec.encoded_char().size() - 1;
		}
		else{
			/* Couldn't decode the character in the selected encoding.
			 * TODO: Highlight this in the interface?
			*/
			
			defer_monospace_char(".");
		}
		
		return char_bbox;
	};
	
	/* Because we need to minimise wxDC::DrawText() calls (see above), we draw any
	 * background colours ourselves and set the background mode to transparent when
	 * drawing text, which enables us to skip over characters that shouldn't be
	 * touched by that particular wxDC::DrawText() call by inserting spaces.
	*/
	
	auto fill_char_bg = [&](wxRect char_bbox, const wxColour &bg_colour)
	{
		frf.fill_rectangle(char_bbox, bg_colour);
	};
	
	for(size_t c = pad_bytes, i = 0; i < data_len; ++c, ++i)
	{
		const void *c_data = (data != NULL) ? (const void*)(data + i)          : (const void*)("?");
		size_t c_data_len  = (data != NULL) ? (data_len - i) + data_extra_post : 1;
		
		auto highlight = highlight_at_off(cur_off);
		
		wxRect char_bbox;
		if(ascii_active)
		{
			if(cur_off == cursor_pos && !doc_ctrl->insert_mode && doc_ctrl->get_cursor_visible())
			{
				char_bbox = draw_char_deferred((*active_palette)[Palette::PAL_INVERT_TEXT_FG], ascii_x_char, c_data, c_data_len, (*active_palette)[Palette::PAL_INVERT_TEXT_BG]);
				fill_char_bg(char_bbox, (*active_palette)[Palette::PAL_INVERT_TEXT_BG]);
			}
			else if(highlight.enable)
			{
				char_bbox = draw_char_deferred(highlight.fg_colour, ascii_x_char, c_data, c_data_len, highlight.bg_colour);
				fill_char_bg(char_bbox, highlight.bg_colour);
			}
			else{
				char_bbox = draw_char_deferred((*active_palette)[alternate_row ? Palette::PAL_ALTERNATE_TEXT_FG : Palette::PAL_NORMAL_TEXT_FG], ascii_x_char, c_data, c_data_len, (*active_palette)[Palette::PAL_NORMAL_TEXT_BG]);
			}
		}
		else{
			if(highlight.enable)
			{
				char_bbox = draw_char_deferred(highlight.fg_colour, ascii_x_char, c_data, c_data_len, highlight.bg_colour);
				fill_char_bg(char_bbox, highlight.bg_colour);
			}
			else{
				char_bbox = draw_char_deferred((*active_palette)[alternate_row ? Palette::PAL_ALTERNATE_TEXT_FG : Palette::PAL_NORMAL_TEXT_FG], ascii_x_char, c_data, c_data_len, (*active_palette)[Palette::PAL_NORMAL_TEXT_BG]);
			}
			
			if(cur_off == cursor_pos && !doc_ctrl->insert_mode)
			{
				dc.SetBrush(*wxTRANSPARENT_BRUSH);
				dc.SetPen(norm_fg_1px);
				
				dc.DrawRectangle(char_bbox);
			}
		}
		
		if(cur_off == cursor_pos && doc_ctrl->insert_mode && (doc_ctrl->get_cursor_visible() || !ascii_active))
		{
			insert_cursor_pen = &norm_fg_1px;
			insert_cursor_pt1 = wxPoint(ascii_x, y);
			insert_cursor_pt2 = wxPoint(ascii_x, y + doc_ctrl->hf_height);
		}
		
		ascii_x = ascii_base_x + doc_ctrl->hf_string_width(++ascii_x_char);
		
		cur_off += BitOffset::BYTES(1);
	}
	
	if(is_last_line && cur_off == cursor_pos)
	{
		/* Draw cursor at the end of the file (i.e. after the last byte). */
		
		if((doc_ctrl->get_cursor_visible() && doc_ctrl->ascii_view_active()) || !ascii_active)
		{
			if(doc_ctrl->insert_mode || !ascii_active)
			{
				insert_cursor_pen = &norm_fg_1px;
				insert_cursor_pt1 = wxPoint(ascii_x, y);
				insert_cursor_pt2 = wxPoint(ascii_x, y + doc_ctrl->hf_height);
			}
			else{
				/* Draw the cursor in red if trying to overwrite at an invalid
				 * position. Should only happen in empty files.
				*/
				
				insert_cursor_pen = wxRED_PEN;
				insert_cursor_pt1 = wxPoint(ascii_x, y);
				insert_cursor_pt2 = wxPoint(ascii_x, y + doc_ctrl->hf_height);
			}
		}
	}
	
	frf.flush();
	
	normal_text_colour();

	/* Fast text rendering path - render fixed-width characters using a single wxDC.DrawText()
	 * call per foreground colour, leaving gaps for characters drawn in other passes using
	 * space characters.
	*/
	
	for(auto dd = deferred_drawtext_fast.begin(); dd != deferred_drawtext_fast.end(); ++dd)
	{
		PROFILE_INNER_BLOCK("drawing text (fast path)");
		
		const wxColour &fg_colour = dd->first;

		dc.SetTextForeground(fg_colour);
		dc.SetBackgroundMode(wxTRANSPARENT);

		dc.DrawText(dd->second.string, ascii_base_x, y);
	}

	/* Slow text rendering path - render variable-width characters using a single
	 * wxDC.DrawText() call for each character so we can align them to the grid of normal
	 * characters in the font.
	 *
	 * There are two (optional) optimisations here:
	 *
	 * REHEX_CACHE_CHARACTER_BITMAPS
	 *
	 *   Renders the characters into a secondary wxBitmap and caches it so future draws of the
	 *   same character are just a bitmap blit rather than rendering text every time.
	 *
	 *   This offers a significant performance boost on Windows, macOS and Linux and is enabled
	 *   on all platforms.
	 *
	 * REHEX_CACHE_STRING_BITMAPS
	 *
	 *   In addition to REHEX_CACHE_CHARACTER_BITMAPS, the individual character bitmaps in each
	 *   deferred_drawtext_slow are copied into another secondary bitmap, which is again cached
	 *   and blitted to the DC as a whole line in the future.
	 *
	 *   This adds another significant speed boost on Windows and macOS, where it is enabled.
	 *   There is no significant improvement on Linux, so it isn't enabled there.
	*/
	
	for(auto dd = deferred_drawtext_slow.begin(); dd != deferred_drawtext_slow.end(); ++dd)
	{
		PROFILE_INNER_BLOCK("drawing text (slow path)");
		
		wxColour fg_colour = dd->first.fg_colour;
		wxColour bg_colour = dd->first.bg_colour;

		dc.SetTextForeground(fg_colour);
		dc.SetBackgroundMode(wxTRANSPARENT);

#if defined(REHEX_CACHE_CHARACTER_BITMAPS) && defined(REHEX_CACHE_STRING_BITMAPS)
		wxBitmap string_bitmap = doc_ctrl->hf_string_bitmap(dd->second.chars, dd->first.base_col, fg_colour, bg_colour);
		int string_x = ascii_base_x + doc_ctrl->hf_string_width(dd->first.base_col);
		
		dc.DrawBitmap(string_bitmap, string_x, y, true);
#elif defined(REHEX_CACHE_CHARACTER_BITMAPS)
		for(auto c = dd->second.chars.begin(); c != dd->second.chars.end(); ++c)
		{
			wxBitmap char_bitmap = doc_ctrl->hf_char_bitmap(c->wx_char, c->unicode_char, c->char_size, fg_colour, bg_colour);
			int char_x = ascii_base_x + doc_ctrl->hf_string_width(dd->first.base_col + c->column);
			
			dc.DrawBitmap(char_bitmap, char_x, y);
		}
#else
		for(auto c = dd->second.chars.begin(); c != dd->second.chars.end(); ++c)
		{
			int char_x = ascii_base_x + doc_ctrl->hf_string_width(dd->first.base_col + c->column);
			
			dc.DrawText(c->wx_char, char_x, y);
		}
#endif
	}
	
	if(insert_cursor_pen != NULL)
	{
		dc.SetPen(*insert_cursor_pen);
		dc.DrawLine(insert_cursor_pt1, insert_cursor_pt2);
	}
}

void REHex::DocumentCtrl::Region::draw_bin_line(DocumentCtrl *doc_ctrl, wxDC &dc, int x, int y, const std::vector<bool> &data, BitOffset data_len, unsigned int pad_bytes, BitOffset base_off, bool alternate_row, const std::function<Highlight(BitOffset)> &highlight_at_off, bool is_last_line)
{
	PROFILE_BLOCK("REHex::DocumentCtrl:Region::draw_bin_line");
	
	unsigned int bits_per_group = doc_ctrl->get_bytes_per_group() * 2;
	
	int hex_base_x = x;                                                     /* Base X co-ordinate to draw hex characters from */
	int hex_x_char = (pad_bytes * 8) + ((pad_bytes * 8) / bits_per_group);  /* Column of current hex character */
	int hex_x      = hex_base_x + doc_ctrl->hf_string_width(hex_x_char);    /* X co-ordinate of current hex character */
	
	BitOffset cur_off = base_off;
	
	dc.SetFont(doc_ctrl->hex_font);
	
	wxPen norm_fg_1px((*active_palette)[Palette::PAL_NORMAL_TEXT_FG], 1);
	wxPen selected_bg_1px((*active_palette)[Palette::PAL_SELECTED_TEXT_BG], 1);
	dc.SetBrush(*wxTRANSPARENT_BRUSH);
	
	FastRectangleFiller frf(dc);
	
	bool hex_active = doc_ctrl->HasFocus() && doc_ctrl->special_view_active();
	
	BitOffset cursor_pos = doc_ctrl->get_cursor_position();
	
	auto normal_text_colour = [&dc,&alternate_row]()
	{
		dc.SetTextForeground((*active_palette)[alternate_row ? Palette::PAL_ALTERNATE_TEXT_FG : Palette::PAL_NORMAL_TEXT_FG ]);
		dc.SetBackgroundMode(wxTRANSPARENT);
	};
	
	const wxPen *insert_cursor_pen = NULL;
	wxPoint insert_cursor_pt1, insert_cursor_pt2;
	
	/* Calling wxDC::DrawText() for each individual character on the screen is
	 * painfully slow, so we batch up the wxDC::DrawText() calls for each colour and
	 * area on a per-line basis.
	 *
	 * The key of the deferred_drawtext map is the X co-ordinate to render the string
	 * at (hex_base_x or ascii_base_x) and the foreground colour to use.
	 *
	 * The draw_char_deferred() function adds a character to be drawn to the map, while
	 * prefixing it with any spaces necessary to pad it to the correct column from the
	 * base X co-ordinate.
	*/
	
	UnsortedMapVector<wxColour, std::string> deferred_drawtext;
	
	auto draw_char_deferred = [&](const wxColour &fg_colour, int col, char ch)
	{
		PROFILE_INNER_BLOCK("draw_char_deferred");
		
		std::string &str = deferred_drawtext[fg_colour];
		
		assert(str.length() <= (size_t)(col));
		
		str.append((col - str.length()), ' ');
		str.append(1, ch);
	};
	
	/* Because we need to minimise wxDC::DrawText() calls (see above), we draw any
	 * background colours ourselves and set the background mode to transparent when
	 * drawing text, which enables us to skip over characters that shouldn't be
	 * touched by that particular wxDC::DrawText() call by inserting spaces.
	*/
	
	auto fill_char_bg = [&](int char_x, const wxColour &bg_colour)
	{
		PROFILE_INNER_BLOCK("fill_char_bg");
		frf.fill_rectangle(char_x, y, doc_ctrl->hf_char_width(), doc_ctrl->hf_height, bg_colour);
	};
	
	BitOffset data_offset(0, 0);
	
	for(size_t c = pad_bytes; data_offset < data_len; ++c)
	{
		if(c > pad_bytes && (c % bits_per_group) == 0)
		{
			hex_x = hex_base_x + doc_ctrl->hf_string_width(++hex_x_char);
		}
		
		auto highlight = highlight_at_off(cur_off);
		
		/* Need the current hex_x value for drawing any boxes or insert cursors
		 * below, before it gets updated by draw_nibble().
		*/
		const int pd_hx = hex_x;
		
		bool invert = (cur_off == cursor_pos && hex_active)
			? !doc_ctrl->insert_mode || !cur_off.byte_aligned()
			: false;
		
		char bit_s;
		if(data.size() <= (size_t)(data_offset.total_bits()))
		{
			bit_s = '?';
		}
		else if(data[data_offset.total_bits()])
		{
			bit_s = '1';
		}
		else{
			bit_s = '0';
		}
		
		if(invert && doc_ctrl->get_cursor_visible())
		{
			fill_char_bg(hex_x, (*active_palette)[Palette::PAL_INVERT_TEXT_BG]);
			draw_char_deferred((*active_palette)[Palette::PAL_INVERT_TEXT_FG], hex_x_char, bit_s);
		}
		else if(highlight.enable)
		{
			fill_char_bg(hex_x, highlight.bg_colour);
			draw_char_deferred(highlight.fg_colour, hex_x_char, bit_s);
		}
		else{
			draw_char_deferred((*active_palette)[alternate_row ? Palette::PAL_ALTERNATE_TEXT_FG : Palette::PAL_NORMAL_TEXT_FG], hex_x_char, bit_s);
		}
		
		hex_x = hex_base_x + doc_ctrl->hf_string_width(++hex_x_char);
		
		if(cur_off == cursor_pos && doc_ctrl->insert_mode && doc_ctrl->get_cursor_visible() && doc_ctrl->cursor_state == Document::CSTATE_SPECIAL && cur_off.byte_aligned())
		{
			/* Draw insert cursor. */
			insert_cursor_pen = &norm_fg_1px;
			insert_cursor_pt1 = wxPoint(pd_hx, y);
			insert_cursor_pt2 = wxPoint(pd_hx, y + doc_ctrl->hf_height);
		}
		
		if(cur_off == cursor_pos && !doc_ctrl->insert_mode && !hex_active)
		{
			/* Draw inactive overwrite cursor. */
			dc.SetBrush(*wxTRANSPARENT_BRUSH);
			dc.SetPen(norm_fg_1px);
			
			dc.DrawRectangle(pd_hx, y, doc_ctrl->hf_char_width(), doc_ctrl->hf_char_height());
		}
		
		cur_off += BitOffset::BITS(1);
		data_offset += BitOffset::BITS(1);
	}
	
	if(is_last_line && cur_off == cursor_pos)
	{
		/* Draw cursor at the end of the file (i.e. after the last byte). */
		
		if((doc_ctrl->get_cursor_visible() && doc_ctrl->hex_view_active()) || !hex_active)
		{
			if(doc_ctrl->insert_mode || !hex_active)
			{
				insert_cursor_pen = &norm_fg_1px;
				insert_cursor_pt1 = wxPoint(hex_x, y);
				insert_cursor_pt2 = wxPoint(hex_x, y + doc_ctrl->hf_height);
			}
			else{
				/* Draw the cursor in red if trying to overwrite at an invalid
				 * position. Should only happen in empty files.
				*/
				
				insert_cursor_pen = wxRED_PEN;
				insert_cursor_pt1 = wxPoint(hex_x, y);
				insert_cursor_pt2 = wxPoint(hex_x, y + doc_ctrl->hf_height);
			}
		}
	}
	
	frf.flush();
	
	normal_text_colour();
	
	for(auto dd = deferred_drawtext.begin(); dd != deferred_drawtext.end(); ++dd)
	{
		PROFILE_INNER_BLOCK("drawing text");
		
		dc.SetTextForeground(dd->first);
		dc.SetBackgroundMode(wxTRANSPARENT);
		
		dc.DrawText(dd->second, hex_base_x, y);
	}
	
	if(insert_cursor_pen != NULL)
	{
		dc.SetPen(*insert_cursor_pen);
		dc.DrawLine(insert_cursor_pt1, insert_cursor_pt2);
	}
}

wxCursor REHex::DocumentCtrl::DataRegion::cursor_for_point(REHex::DocumentCtrl &doc, int x, int64_t y_lines, int y_px)
{
	if(x >= hex_text_x)
	{
		return wxCursor(wxCURSOR_IBEAM);
	}
	else{
		return wxNullCursor;
	}
}

REHex::BitOffset REHex::DocumentCtrl::DataRegion::offset_at_xy_hex(REHex::DocumentCtrl &doc, int mouse_x_px, uint64_t mouse_y_lines)
{
	if(mouse_x_px < hex_text_x)
	{
		return -1;
	}
	
	mouse_x_px -= hex_text_x;
	
	/* Calculate the offset within the Buffer of the first byte on this line
	 * and the offset (plus one) of the last byte on this line.
	*/
	BitOffset line_data_begin = (d_offset - BitOffset::BYTES(first_line_pad_bytes)) + BitOffset::BYTES((off_t)(bytes_per_line_actual) * mouse_y_lines);
	BitOffset line_data_end   = std::min((line_data_begin + BitOffset::BYTES(bytes_per_line_actual)), (d_offset + d_length));
	
	unsigned int char_offset = doc.hf_char_at_x(mouse_x_px);
	if(((char_offset + 1) % ((doc.bytes_per_group * 2) + 1)) == 0)
	{
		/* Click was over a space between byte groups. */
		return -1;
	}
	else{
		unsigned int char_offset_sub_spaces = char_offset - (char_offset / ((doc.bytes_per_group * 2) + 1));
		BitOffset line_offset_bytes         = BitOffset((char_offset_sub_spaces / 2), ((char_offset_sub_spaces % 2) * 4));
		
		if(wxGetApp().settings->get_cursor_nav_mode() == CursorNavMode::BYTE)
		{
			line_offset_bytes = BitOffset(line_offset_bytes.byte(), 0);
		}
		
		BitOffset clicked_offset = line_data_begin + line_offset_bytes;
		
		if(clicked_offset < d_offset)
		{
			/* Clicked in padding on first line. */
			return BitOffset::INVALID;
		}
		else if(clicked_offset < line_data_end)
		{
			/* Clicked on a byte */
			return clicked_offset;
		}
		else{
			/* Clicked past the end of the line */
			return BitOffset::INVALID;
		}
	}
}

int REHex::DocumentCtrl::Region::offset_at_x_hex(DocumentCtrl *doc_ctrl, int rel_x)
{
	if(rel_x < 0)
	{
		return -1;
	}
	
	unsigned int bytes_per_group = doc_ctrl->get_bytes_per_group();
	
	unsigned int char_offset = doc_ctrl->hf_char_at_x(rel_x);
	if(((char_offset + 1) % ((bytes_per_group * 2) + 1)) == 0)
	{
		/* Click was over a space between byte groups. */
		return -1;
	}
	else{
		unsigned int char_offset_sub_spaces = char_offset - (char_offset / ((bytes_per_group * 2) + 1));
		int line_offset_bytes = char_offset_sub_spaces / 2;
		
		return line_offset_bytes;
	}
}

REHex::BitOffset REHex::DocumentCtrl::DataRegion::offset_at_xy_ascii(REHex::DocumentCtrl &doc, int mouse_x_px, uint64_t mouse_y_lines)
{
	if(!doc.show_ascii || mouse_x_px < ascii_text_x)
	{
		return -1;
	}
	
	mouse_x_px -= ascii_text_x;
	
	/* Calculate the offset within the Buffer of the first byte on this line
	 * and the offset (plus one) of the last byte on this line.
	*/
	BitOffset line_data_begin = (d_offset - BitOffset::BYTES(first_line_pad_bytes)) + BitOffset::BYTES((off_t)(bytes_per_line_actual) * mouse_y_lines);
	BitOffset line_data_end   = std::min((line_data_begin + BitOffset::BYTES(bytes_per_line_actual)), (d_offset + d_length));
	
	unsigned int char_offset = doc.hf_char_at_x(mouse_x_px);
	BitOffset clicked_offset = line_data_begin + BitOffset::BYTES(char_offset);
	
	if(clicked_offset < d_offset)
	{
		/* Clicked in padding on first line. */
		return BitOffset::INVALID;
	}
	else if(clicked_offset < line_data_end)
	{
		/* Clicked on a character */
		
		auto char_at_pos = get_char_at(clicked_offset);
		if(char_at_pos.first >= 0)
		{
			clicked_offset = char_at_pos.first;
		}
		
		return clicked_offset;
	}
	else{
		/* Clicked past the end of the line */
		return BitOffset::INVALID;
	}
}

REHex::BitOffset REHex::DocumentCtrl::DataRegion::offset_near_xy_hex(REHex::DocumentCtrl &doc, int mouse_x_px, uint64_t mouse_y_lines)
{
	/* Calculate the offset within the Buffer of the first byte on this line
	 * and the offset (plus one) of the last byte on this line.
	*/
	BitOffset line_data_begin = (d_offset - BitOffset::BYTES(first_line_pad_bytes)) + BitOffset::BYTES((off_t)(bytes_per_line_actual) * mouse_y_lines);
	BitOffset line_data_end   = std::min((line_data_begin + BitOffset::BYTES(bytes_per_line_actual)), (d_offset + d_length));
	
	if(mouse_x_px < hex_text_x)
	{
		/* Mouse is in offset area, return offset of last byte of previous line. */
		return line_data_begin - 1;
	}
	
	mouse_x_px -= hex_text_x;
	
	unsigned int char_offset = doc.hf_char_at_x(mouse_x_px);
	
	unsigned int char_offset_sub_spaces = char_offset - (char_offset / ((doc.bytes_per_group * 2) + 1));
	BitOffset line_offset_bytes         = BitOffset((char_offset_sub_spaces / 2), ((char_offset_sub_spaces % 2) * 4));
	
	if(wxGetApp().settings->get_cursor_nav_mode() == CursorNavMode::BYTE)
	{
		line_offset_bytes = BitOffset(line_offset_bytes.byte(), 0);
	}
	
	BitOffset clicked_offset = line_data_begin + line_offset_bytes;
	
	if(clicked_offset < d_offset)
	{
		/* Mouse is in padding area on first line, return offset of last byte of previous line. */
		return d_offset - BitOffset::BYTES(1);
	}
	else if(clicked_offset < line_data_end)
	{
		/* Mouse is on a byte. */
		return clicked_offset;
	}
	else{
		/* Mouse is past end of line, return last byte of this line. */
		return line_data_end - wxGetApp().settings->get_cursor_nav_alignment();
	}
}

int REHex::DocumentCtrl::Region::offset_near_x_hex(DocumentCtrl *doc_ctrl, int rel_x)
{
	if(rel_x < 0)
	{
		return -1;
	}
	
	unsigned int bytes_per_group = doc_ctrl->get_bytes_per_group();
	
	unsigned int char_offset = doc_ctrl->hf_char_at_x(rel_x);
	
	unsigned int char_offset_sub_spaces = char_offset - (char_offset / ((bytes_per_group * 2) + 1));
	int line_offset_bytes = char_offset_sub_spaces / 2;
	
	return line_offset_bytes;
}

REHex::BitOffset REHex::DocumentCtrl::DataRegion::offset_near_xy_ascii(REHex::DocumentCtrl &doc, int mouse_x_px, uint64_t mouse_y_lines)
{
	/* Calculate the offset within the Buffer of the first byte on this line
	 * and the offset (plus one) of the last byte on this line.
	*/
	BitOffset line_data_begin = (d_offset - BitOffset::BYTES(first_line_pad_bytes)) + BitOffset::BYTES((off_t)(bytes_per_line_actual) * mouse_y_lines);
	BitOffset line_data_end   = std::min((line_data_begin + BitOffset::BYTES(bytes_per_line_actual)), (d_offset + d_length));
	
	if(!doc.show_ascii || mouse_x_px < ascii_text_x)
	{
		/* Mouse is left of ASCII area, return last byte of previous line. */
		return line_data_begin - BitOffset::BYTES(1);
	}
	
	mouse_x_px -= ascii_text_x;
	
	unsigned int char_offset = doc.hf_char_at_x(mouse_x_px);
	BitOffset clicked_offset = line_data_begin + BitOffset::BYTES(char_offset);
	
	if(clicked_offset < d_offset)
	{
		/* Mouse is in padding area on first line, return offset of last byte of previous line. */
		return d_offset - BitOffset::BYTES(1);
	}
	else if(clicked_offset < line_data_end)
	{
		/* Mouse is on a character. */
		
		auto char_at_pos = get_char_at(clicked_offset);
		if(char_at_pos.first >= 0)
		{
			clicked_offset = char_at_pos.first;
		}
		
		return clicked_offset;
	}
	else{
		/* Mouse is beyond end of line, return last byte of this line. */
		return line_data_end - BitOffset::BYTES(1);
	}
}

std::pair<REHex::BitOffset, REHex::DocumentCtrl::GenericDataRegion::ScreenArea> REHex::DocumentCtrl::DataRegion::offset_at_xy(DocumentCtrl &doc, int mouse_x_px, int64_t mouse_y_lines)
{
	if(doc.show_ascii && mouse_x_px >= ascii_text_x)
	{
		BitOffset off = offset_at_xy_ascii(doc, mouse_x_px, mouse_y_lines);
		return std::make_pair(off, (off >= BitOffset::ZERO ? SA_ASCII : SA_NONE));
	}
	else if(mouse_x_px >= hex_text_x)
	{
		BitOffset off = offset_at_xy_hex(doc, mouse_x_px, mouse_y_lines);
		return std::make_pair(off, (off >= BitOffset::ZERO ? SA_HEX : SA_NONE));
	}
	else{
		return std::make_pair(BitOffset::INVALID, SA_NONE);
	}
}

std::pair<REHex::BitOffset, REHex::DocumentCtrl::GenericDataRegion::ScreenArea> REHex::DocumentCtrl::DataRegion::offset_near_xy(DocumentCtrl &doc, int mouse_x_px, int64_t mouse_y_lines, ScreenArea type_hint)
{
	if(type_hint == SA_ASCII)
	{
		if(doc.show_ascii)
		{
			BitOffset off = offset_near_xy_ascii(doc, mouse_x_px, mouse_y_lines);
			return std::make_pair(off, (off >= BitOffset::ZERO ? SA_ASCII : SA_NONE));
		}
		else{
			return std::make_pair(BitOffset::INVALID, SA_NONE);
		}
	}
	else if(type_hint == SA_HEX)
	{
		BitOffset off = offset_near_xy_hex(doc, mouse_x_px, mouse_y_lines);
		return std::make_pair(off, (off >= BitOffset::ZERO ? SA_HEX : SA_NONE));
	}
	
	if(doc.show_ascii && mouse_x_px >= ascii_text_x)
	{
		BitOffset off = offset_near_xy_ascii(doc, mouse_x_px, mouse_y_lines);
		return std::make_pair(off, (off >= BitOffset::ZERO ? SA_ASCII : SA_NONE));
	}
	else if(mouse_x_px >= hex_text_x)
	{
		BitOffset off = offset_near_xy_hex(doc, mouse_x_px, mouse_y_lines);
		return std::make_pair(off, (off >= BitOffset::ZERO ? SA_HEX : SA_NONE));
	}
	else{
		return std::make_pair(BitOffset::INVALID, SA_NONE);
	}
}

REHex::BitOffset REHex::DocumentCtrl::DataRegion::cursor_left_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	/* Round cursor down to correct alignment relative to d_offset. */
	pos -= (pos - d_offset) % wxGetApp().settings->get_cursor_nav_alignment();
	
	BitOffset new_pos = pos - wxGetApp().settings->get_cursor_nav_alignment();
	
	if(new_pos >= d_offset && new_pos < (d_offset + d_length))
	{
		if(active_type == SA_ASCII)
		{
			BitOffset char_at_pos_off;
			off_t char_at_pos_len;
			std::tie(char_at_pos_off, char_at_pos_len) = get_char_at(new_pos);
			
			if(char_at_pos_off >= BitOffset::ZERO)
			{
				assert(char_at_pos_len > 0);
				new_pos = char_at_pos_off;
			}
		}
		
		return new_pos;
	}
	else{
		return CURSOR_PREV_REGION;
	}
}

REHex::BitOffset REHex::DocumentCtrl::DataRegion::cursor_right_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	/* Round cursor down to correct alignment relative to d_offset. */
	pos -= (pos - d_offset) % wxGetApp().settings->get_cursor_nav_alignment();
	
	BitOffset new_pos = pos + wxGetApp().settings->get_cursor_nav_alignment();
	
	if(active_type == SA_ASCII)
	{
		BitOffset char_at_pos_off;
		off_t char_at_pos_len;
		std::tie(char_at_pos_off, char_at_pos_len) = get_char_at(pos);
		
		if(char_at_pos_off >= BitOffset::ZERO)
		{
			assert(char_at_pos_len > 0);
			new_pos = char_at_pos_off + BitOffset::BYTES(char_at_pos_len);
		}
	}
	
	if(new_pos >= d_offset && new_pos < (d_offset + d_length))
	{
		return new_pos;
	}
	else{
		return CURSOR_NEXT_REGION;
	}
}

REHex::BitOffset REHex::DocumentCtrl::DataRegion::cursor_up_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	/* Round cursor down to correct alignment relative to d_offset. */
	pos -= (pos - d_offset) % wxGetApp().settings->get_cursor_nav_alignment();
	
	BitOffset new_pos = pos - BitOffset::BYTES(bytes_per_line_actual);
	
	if(new_pos < d_offset && new_pos >= (d_offset - BitOffset::BYTES(first_line_pad_bytes)))
	{
		/* Moving from second line to first line, but first line is padded past this column. */
		new_pos = d_offset;
	}
	
	if(new_pos >= d_offset && new_pos < (d_offset + d_length))
	{
		if(active_type == SA_ASCII)
		{
			BitOffset char_at_pos_off;
			off_t char_at_pos_len;
			std::tie(char_at_pos_off, char_at_pos_len) = get_char_at(new_pos);
			
			if(char_at_pos_off >= BitOffset::ZERO)
			{
				assert(char_at_pos_len > 0);
				new_pos = char_at_pos_off;
			}
		}
		
		return new_pos;
	}
	else{
		return CURSOR_PREV_REGION;
	}
}

REHex::BitOffset REHex::DocumentCtrl::DataRegion::cursor_down_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	/* Round cursor down to correct alignment relative to d_offset. */
	pos -= (pos - d_offset) % wxGetApp().settings->get_cursor_nav_alignment();
	
	BitOffset new_pos = pos + BitOffset::BYTES(bytes_per_line_actual);
	
	BitOffset visual_offset = d_offset - BitOffset::BYTES(first_line_pad_bytes);
	BitOffset visual_length = d_length + BitOffset::BYTES(first_line_pad_bytes);
	
	BitOffset last_row_off = visual_offset + BitOffset::BYTES(((visual_length.byte() - 1) / bytes_per_line_actual) * bytes_per_line_actual);
	
	if(pos < last_row_off && new_pos >= (d_offset + d_length))
	{
		/* There is a line below the current line, but it isn't as long as this one, so
		 * jump to the end of it.
		*/
		return d_offset + d_length - BitOffset::BYTES(1);
	}
	
	if(new_pos >= d_offset && new_pos < (d_offset + d_length))
	{
		if(active_type == SA_ASCII)
		{
			BitOffset char_at_pos_off;
			off_t char_at_pos_len;
			std::tie(char_at_pos_off, char_at_pos_len) = get_char_at(new_pos);
			
			if(char_at_pos_off >= BitOffset::ZERO)
			{
				assert(char_at_pos_len > 0);
				new_pos = char_at_pos_off;
			}
		}
		
		return new_pos;
	}
	else{
		return CURSOR_NEXT_REGION;
	}
}

REHex::BitOffset REHex::DocumentCtrl::DataRegion::cursor_home_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	BitOffset visual_offset = d_offset - BitOffset::BYTES(first_line_pad_bytes);
	BitOffset bytes_from_start_of_visual_line = (pos - visual_offset) % BitOffset(bytes_per_line_actual, 0);
	
	BitOffset new_pos = std::max(
		(pos - bytes_from_start_of_visual_line),
		d_offset);
	
	if(active_type == SA_ASCII)
	{
		BitOffset char_at_pos_off;
		off_t char_at_pos_len;
		std::tie(char_at_pos_off, char_at_pos_len) = get_char_at(new_pos);
		
		if(char_at_pos_off >= BitOffset::ZERO)
		{
			assert(char_at_pos_len > 0);
			
			if(char_at_pos_off < new_pos && (char_at_pos_off + BitOffset::BYTES(char_at_pos_len)) <= (d_offset + d_length))
			{
				/* There is a character spanning the last byte(s) of the previous
				 * row and the first byte(s) of this one, advance the cursor to the
				 * first complete character on this row.
				*/
				
				new_pos = char_at_pos_off + char_at_pos_len;
			}
		}
	}
	
	return new_pos;
}

REHex::BitOffset REHex::DocumentCtrl::DataRegion::cursor_end_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	BitOffset visual_offset = d_offset - BitOffset::BYTES(first_line_pad_bytes);
	BitOffset bytes_from_start_of_visual_line = (pos - visual_offset) % BitOffset(bytes_per_line_actual, 0);
	
	if(bytes_from_start_of_visual_line == (bytes_per_line_actual - 1) || pos == (d_offset + d_length))
	{
		/* Already at the end of the line. */
		return pos;
	}
	
	BitOffset new_pos = std::min(
		(pos + ((BitOffset(bytes_per_line_actual, 0) - bytes_from_start_of_visual_line) - wxGetApp().settings->get_cursor_nav_alignment())),
		(d_offset + d_length - BitOffset::BYTES(1)));
	
	if(active_type == SA_ASCII)
	{
		BitOffset char_at_pos_off;
		off_t char_at_pos_len;
		std::tie(char_at_pos_off, char_at_pos_len) = get_char_at(new_pos);
		
		if(char_at_pos_off >= BitOffset::ZERO)
		{
			assert(char_at_pos_len > 0);
			new_pos = char_at_pos_off;
		}
	}
	
	return new_pos;
}

int REHex::DocumentCtrl::DataRegion::cursor_column(BitOffset pos)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	BitOffset visual_offset = d_offset - BitOffset::BYTES(first_line_pad_bytes);
	BitOffset region_offset = pos - visual_offset;
	
	int column = ((region_offset.byte() % bytes_per_line_actual) * 2) + (region_offset.bit() / 4);
	
	return column;
}

REHex::BitOffset REHex::DocumentCtrl::DataRegion::first_row_nearest_column(int column)
{
	assert(d_length.byte_aligned());
	
	BitOffset visual_offset = d_offset - BitOffset(first_line_pad_bytes, 0);
	
	BitOffset offset_at_col = visual_offset + BitOffset((column / 2), ((column % 2) * 4));
	
	offset_at_col = std::max(offset_at_col, d_offset);
	offset_at_col = std::min(offset_at_col, (visual_offset + BitOffset::BYTES(bytes_per_line_actual - 1)));
	offset_at_col = std::min(offset_at_col, (d_offset + d_length - BitOffset::BYTES(d_length > 0)));
	
	assert(offset_at_col >= d_offset);
	assert(offset_at_col < (d_offset + d_length + (d_length == 0)));
	
	return offset_at_col;
}

REHex::BitOffset REHex::DocumentCtrl::DataRegion::last_row_nearest_column(int column)
{
	assert(d_length.byte_aligned());
	
	BitOffset visual_offset = d_offset - BitOffset(first_line_pad_bytes, 0);
	BitOffset visual_length = d_length + BitOffset(first_line_pad_bytes, 0);
	
	BitOffset last_row_off = visual_offset + BitOffset::BYTES(((visual_length.byte() - 1) / bytes_per_line_actual) * bytes_per_line_actual);
	
	BitOffset offset_at_col = last_row_off + BitOffset((column / 2), ((column % 2) * 4));
	
	offset_at_col = std::max(offset_at_col, d_offset);
	offset_at_col = std::max(offset_at_col, last_row_off);
	offset_at_col = std::min(offset_at_col, (d_offset + d_length - BitOffset((d_length > 0), 0)));
	
	assert(offset_at_col >= d_offset);
	assert(offset_at_col < (d_offset + d_length + (d_length == 0)));
	
	return offset_at_col;
}

REHex::BitOffset REHex::DocumentCtrl::DataRegion::nth_row_nearest_column(int64_t row, int column)
{
	assert(row >= 0);
	assert(row < y_lines);
	
	BitOffset visual_offset = d_offset - BitOffset(first_line_pad_bytes, 0);
	
	BitOffset offset_at_col = visual_offset + BitOffset((column / 2), ((column % 2) * 4)) + BitOffset::BYTES((off_t)(row) * (off_t)(bytes_per_line_actual));
	
	/* Clamp to data range. */
	offset_at_col = std::max(offset_at_col, d_offset);
	offset_at_col = std::min(offset_at_col, (d_offset + d_length - (d_length > BitOffset::ZERO ? BitOffset::BYTES(1) : BitOffset::ZERO)));
	
	return offset_at_col;
}

REHex::DocumentCtrl::Rect REHex::DocumentCtrl::DataRegion::calc_offset_bounds(BitOffset offset, DocumentCtrl *doc_ctrl)
{
	assert(offset >= d_offset);
	assert(offset <= (d_offset + d_length + BitOffset(1, 0)));
	
	BitOffset visual_offset = d_offset - BitOffset(first_line_pad_bytes, 0);
	off_t region_offset = (offset - visual_offset).byte();
	
	uint64_t region_line = y_offset + (region_offset / bytes_per_line_actual);
	
	off_t line_off = region_offset % bytes_per_line_actual;
	
	Document::CursorState cursor_state = doc_ctrl->get_cursor_state();
	
	if(cursor_state == Document::CSTATE_ASCII)
	{
		int byte_x = ascii_text_x + doc_ctrl->hf_string_width(line_off);
		
		return Rect(
			byte_x,                     /* x */
			region_line,                /* y */
			doc_ctrl->hf_char_width(),  /* w */
			1);                         /* h */
	}
	else{
		unsigned int bytes_per_group = doc_ctrl->get_bytes_per_group();
		int line_x = hex_text_x + doc_ctrl->hf_string_width((line_off * 2) + (line_off / bytes_per_group));
		
		return Rect(
			line_x,                        /* x */
			region_line,                   /* y */
			doc_ctrl->hf_string_width(2),  /* w */
			1);                            /* h */
	}
}

REHex::DocumentCtrl::GenericDataRegion::ScreenArea REHex::DocumentCtrl::DataRegion::screen_areas_at_offset(BitOffset offset, DocumentCtrl *doc_ctrl)
{
	assert(offset >= d_offset);
	assert(offset <= (d_offset + d_length + BitOffset(1, 0)));
	
	if(doc_ctrl->get_show_ascii())
	{
		return (ScreenArea)(SA_HEX | SA_ASCII);
	}
	else{
		return SA_HEX;
	}
}

REHex::DocumentCtrl::DataRegion::Highlight REHex::DocumentCtrl::DataRegion::highlight_at_off(BitOffset off) const
{
	return NoHighlight();
}

REHex::DocumentCtrl::DataRegionDocHighlight::DataRegionDocHighlight(SharedDocumentPointer &document, BitOffset d_offset, BitOffset d_length, BitOffset virt_offset):
	DataRegion(document, d_offset, d_length, virt_offset) {}

REHex::DocumentCtrl::DataRegion::Highlight REHex::DocumentCtrl::DataRegionDocHighlight::highlight_at_off(BitOffset off) const
{
	const BitRangeMap<int> &highlights = document->get_highlights();
	
	auto highlight = highlights.get_range(off);
	if(highlight != highlights.end())
	{
		const HighlightColourMap &highlight_colours = document->get_highlight_colours();
		
		auto hc = highlight_colours.find(highlight->second);
		if(hc != highlight_colours.end())
		{
			return Highlight(hc->second.secondary_colour, hc->second.primary_colour);
		}
	}
	
	if(document->is_byte_dirty(off))
	{
		return Highlight(
			(*active_palette)[Palette::PAL_DIRTY_TEXT_FG],
			(*active_palette)[Palette::PAL_DIRTY_TEXT_BG]);
	}
	
	return NoHighlight();
}

REHex::DocumentCtrl::CommentRegion::CommentRegion(BitOffset c_offset, BitOffset c_length, const wxString &c_text, bool truncate, BitOffset indent_offset, BitOffset indent_length):
	Region(indent_offset, indent_length),
	c_offset(c_offset),
	c_length(c_length),
	c_text(c_text),
	truncate(truncate) {}

void REHex::DocumentCtrl::CommentRegion::calc_height(REHex::DocumentCtrl &doc)
{
	if(truncate)
	{
		y_lines = 2 + indent_final;
		return;
	}
	
	unsigned int row_chars = doc.hf_char_at_x(doc.virtual_width - (2 * doc.indent_width(indent_depth))) - 1;
	if(row_chars == 0)
	{
		/* Zero columns of width. Probably still initialising. */
		this->y_lines = 1 + indent_final;
	}
	else{
		int comment_lines = wrap_text_height(c_text, row_chars);
		this->y_lines  = comment_lines + 1 + indent_final;
	}
}

void REHex::DocumentCtrl::CommentRegion::draw(REHex::DocumentCtrl &doc, wxDC &dc, int x, int64_t y)
{
	draw_container(doc, dc, x, y);
	
	int indent_width = doc.indent_width(indent_depth);
	x += indent_width;
	
	dc.SetFont(doc.hex_font);
	
	unsigned int row_chars = doc.hf_char_at_x(doc.virtual_width - (2 * indent_width)) - 1;
	if(row_chars == 0)
	{
		/* Zero columns of width. Probably still initialising. */
		return;
	}
	
	auto lines = wrap_text(c_text, row_chars);
	
	if(truncate && lines.size() > 1)
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
		
		if(indent_length > 0)
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

wxCursor REHex::DocumentCtrl::CommentRegion::cursor_for_point(REHex::DocumentCtrl &doc, int x, int64_t y_lines, int y_px)
{
	int hf_width = doc.hf_char_width();
	int indent_width = doc.indent_width(indent_depth);
	
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

std::pair<REHex::BitOffset, off_t> REHex::DocumentCtrl::DataRegion::get_char_at(BitOffset offset)
{
	assert(offset >= d_offset && offset <= (d_offset + d_length));
	
	if(offset == (d_offset + d_length))
	{
		return std::make_pair(BitOffset::INVALID, -1);
	}
	
	const BitRangeMap<Document::TypeInfo> &types = document->get_data_types();
	
	/* If the offset isn't aligned to the bounds of a multibyte character and the decoder can
	 * detect the start/end of characters, then we can walk backwards to find where the
	 * character began, otherwise we have to use CharacterFinder to find the characters by
	 * linearly scanning from the start of the region...
	*/
	
	auto type_at_base = types.get_range(offset);
	assert(type_at_base != types.end());
	
	BitOffset encoding_base = type_at_base->first.offset;
	assert(encoding_base <= offset);
	
	static REHex::CharacterEncoderASCII ascii_encoder;
	const CharacterEncoder *encoder = &ascii_encoder;
	if(type_at_base->second.name != "")
	{
		auto type = DataTypeRegistry::get_type(type_at_base->second.name, type_at_base->second.options);
		assert(type != NULL);
		
		if(type->encoder != NULL)
		{
			encoder = type->encoder;
		}
	}
	
	if(encoder->mid_char_safe)
	{
		/* Step back if necessary to align to word size. */
		BitOffset at_offset = offset - ((offset - encoding_base) % encoder->word_size);
		
		BitOffset min_offset = std::max((at_offset - BitOffset::BYTES(MAX_CHAR_SIZE)), d_offset);
		
		std::vector<unsigned char> data;
		try {
			data = document->read_data(min_offset, (MAX_CHAR_SIZE * 2));
		}
		catch(const std::exception &e)
		{
			wxGetApp().printf_error("Exception in REHex::Document::Region::Data::draw: %s\n", e.what());
			return std::make_pair(BitOffset::INVALID, -1);
		}
		
		ssize_t data_offset = (at_offset - min_offset).byte();
		
		while(at_offset >= min_offset && data_offset < (ssize_t)(data.size()) && data_offset >= 0)
		{
			EncodedCharacter ec = encoder->decode((data.data() + data_offset), (data.size() - data_offset));
			if(ec.valid && (at_offset + (off_t)(ec.encoded_char().size())) > offset)
			{
				return std::make_pair(at_offset, ec.encoded_char().size());
			}
			
			--data_offset;
			at_offset -= BitOffset::BYTES(1);
		}
		
		return std::make_pair(offset, 1);
	}
	else{
		if(!char_finder)
		{
			char_finder.reset(new CharacterFinder(document, d_offset, d_length.byte()));
		}
		
		return char_finder->get_char_range(offset);
	}
}
