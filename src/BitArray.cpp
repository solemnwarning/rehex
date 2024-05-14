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

#include "App.hpp"
#include "BitArray.hpp"
#include "DataType.hpp"

static REHex::DocumentCtrl::Region *BitArrayRegion_factory(REHex::SharedDocumentPointer &doc, REHex::BitOffset offset, REHex::BitOffset length, REHex::BitOffset virt_offset)
{
	return new REHex::BitArrayRegion(doc, offset, length, virt_offset);
}

static REHex::StaticDataTypeRegistration BitArrayTypeReg(
	"bitarray", "Bit array", {},
	REHex::DataType()
		.WithWordSize(REHex::BitOffset(0, 1))
		.WithVariableSizeRegion(&BitArrayRegion_factory));
	
REHex::BitArrayRegion::BitArrayRegion(SharedDocumentPointer &doc, BitOffset offset, BitOffset length, BitOffset virt_offset):
	GenericDataRegion(offset, length, virt_offset, virt_offset),
	doc(doc),
	offset_text_x(-1),
	data_text_x(-1),
	bytes_per_line_actual(8) /* Arbitrary initial value */
{}

int REHex::BitArrayRegion::calc_width(DocumentCtrl &doc_ctrl)
{
	int indent_width = doc_ctrl.indent_width(indent_depth);
	
	int offset_column_width = doc_ctrl.get_show_offsets()
		? doc_ctrl.get_offset_column_width()
		: 0;
	
	int bytes_per_line = doc_ctrl.get_bytes_per_line();
	int client_width = doc_ctrl.GetClientSize().GetWidth();
	
	offset_text_x = indent_width;
	data_text_x   = indent_width + offset_column_width;
	
	if(bytes_per_line == DocumentCtrl::BYTES_PER_LINE_FIT_BYTES)
	{
		bytes_per_line_actual = 1;
		
		while(DocumentCtrl::DataRegion::calc_width_for_bytes(doc_ctrl, ((bytes_per_line_actual + 1) * 4), indent_depth) <= client_width)
		{
			++bytes_per_line_actual;
		}
	}
	else if(bytes_per_line == DocumentCtrl::BYTES_PER_LINE_FIT_GROUPS)
	{
		int bytes_per_group = doc_ctrl.get_bytes_per_group();
		bytes_per_line_actual = bytes_per_group / 4;
		
		while(DocumentCtrl::DataRegion::calc_width_for_bytes(doc_ctrl, ((bytes_per_line_actual + bytes_per_group) * 4), indent_depth) <= client_width)
		{
			bytes_per_line_actual += bytes_per_group;
		}
		
		if(bytes_per_line_actual < 1)
		{
			bytes_per_line_actual = 1;
		}
	}
	else{
		bytes_per_line_actual = std::max((bytes_per_line / 4), 1);
	}
	
	return (2 * indent_width)
		+ offset_column_width
		+ doc_ctrl.hf_string_width(bytes_per_line_actual * 8);
}

void REHex::BitArrayRegion::calc_height(DocumentCtrl &doc_ctrl)
{
	y_lines = indent_final + ((d_length.byte_round_up() + bytes_per_line_actual - 1) / bytes_per_line_actual);
}

void REHex::BitArrayRegion::draw(DocumentCtrl &doc_ctrl, wxDC &dc, int x, int64_t y)
{
	BitOffset data_base = d_offset;
	BitOffset data_length = d_length;
	BitOffset virt_base = virt_offset;
	
	draw_container(doc_ctrl, dc, x, y);
	
	int64_t skip_lines = (y < 0 ? (-y / doc_ctrl.hf_char_height()) : 0);
	off_t skip_bytes  = skip_lines * bytes_per_line_actual;
	
	y += skip_lines * doc_ctrl.hf_char_height();
	
	data_base   += BitOffset::BYTES(skip_bytes);
	data_length -= BitOffset::BYTES(skip_bytes);
	virt_base   += BitOffset::BYTES(skip_bytes);
	
	wxSize client_size = doc_ctrl.GetClientSize();
	off_t max_data_in_client_area = bytes_per_line_actual * ((client_size.GetHeight() / doc_ctrl.hf_char_height()) + 1);
	
	if(data_length.byte() > max_data_in_client_area)
	{
		data_length = BitOffset(max_data_in_client_area, 0);
	}
	
	std::vector<bool> data;
	try {
		data = doc->read_bits(data_base, ((data_length.byte() * 8) + data_length.bit()));
	}
	catch(const std::exception &e)
	{
		wxGetApp().printf_error("Exception in REHex::BitArrayRegion::draw: %s\n", e.what());
	}
	
	
	BitOffset data_cur = data_base;
	BitOffset data_remain = data_length;
	BitOffset virt_cur = virt_base;
	
	bool alternate_row = ((y_offset + skip_lines) % 2) != 0;
	
	auto normal_text_colour = [&dc,&alternate_row]()
	{
		dc.SetTextForeground((*active_palette)[alternate_row ? Palette::PAL_ALTERNATE_TEXT_FG : Palette::PAL_NORMAL_TEXT_FG ]);
		dc.SetBackgroundMode(wxTRANSPARENT);
	};
	
	/* TODO: Display all highlights/selections properly. */
	
	BitOffset scoped_selection_offset, scoped_selection_length;
	std::tie(scoped_selection_offset, scoped_selection_length) = doc_ctrl.get_selection_in_region(this);
	
	const Highlight hex_selection_highlight(
		(*active_palette)[Palette::PAL_SELECTED_TEXT_FG],
		(doc_ctrl.special_view_active()
			? (*active_palette)[Palette::PAL_SELECTED_TEXT_BG]
			: active_palette->get_average_colour(Palette::PAL_SELECTED_TEXT_BG, Palette::PAL_NORMAL_TEXT_BG)));
	
	auto highlight_func = [&](BitOffset offset)
	{
		const BitRangeMap<int> &highlights = doc->get_highlights();
		auto highlight = highlights.get_range(offset);
		
		if(offset >= scoped_selection_offset && offset < (scoped_selection_offset + scoped_selection_length))
		{
			return hex_selection_highlight;
		}
		
		if(highlight != highlights.end())
		{
			const HighlightColourMap &highlight_colours = doc->get_highlight_colours();
			
			auto hc = highlight_colours.find(highlight->second);
			if(hc != highlight_colours.end())
			{
				return Highlight(hc->second.secondary_colour, hc->second.primary_colour);
			}
		}
		
		if(doc->is_byte_dirty(offset.byte())) /* Check if the byte containing the bit is dirty, not the "byte" starting from this bit. */
		{
			return Highlight(
				(*active_palette)[Palette::PAL_DIRTY_TEXT_FG],
				(*active_palette)[Palette::PAL_DIRTY_TEXT_BG]);
		}
		
		return Highlight(NoHighlight());
	};
	
	while(y < client_size.GetHeight() && data_remain > BitOffset::ZERO)
	{
		normal_text_colour();
		
		if(doc_ctrl.get_show_offsets())
		{
			/* Draw the offsets to the left */
			
			std::string offset_str = format_offset(virt_cur, doc_ctrl.get_offset_display_base(), doc_ctrl.get_end_virt_offset());
			
			dc.DrawText(offset_str, (x + offset_text_x), y);
			
			int offset_vl_x = x + data_text_x - (doc_ctrl.hf_char_width() / 2);
			
			wxPen norm_fg_1px((*active_palette)[Palette::PAL_NORMAL_TEXT_FG], 1);
			
			dc.SetPen(norm_fg_1px);
			dc.DrawLine(offset_vl_x, y, offset_vl_x, y + doc_ctrl.hf_char_height());
		}
		
		BitOffset line_len = std::min(data_remain, BitOffset(bytes_per_line_actual, 0));
		
		off_t data_offset = (data_cur - data_base).total_bits();
		assert(data_offset >= 0);
		
		off_t data_avail = (off_t)(data.size()) - data_offset;
		
		std::vector<bool> line_data;
		if(data_avail >= 0)
		{
			auto begin = std::next(data.begin(), data_offset);
			auto end = std::next(begin, std::min(line_len.total_bits(), data_avail));
			
			line_data.insert(line_data.end(), begin, end);
		}
		
		draw_bin_line(&doc_ctrl, dc, (x + data_text_x), y, line_data, line_len, 0, data_cur, alternate_row, highlight_func, false);
		
		data_cur    += line_len;
		data_remain -= line_len;
		virt_cur    += line_len;
		
		y += doc_ctrl.hf_char_height();
		
		alternate_row = !alternate_row;
	}
}

std::pair<REHex::BitOffset, REHex::DocumentCtrl::GenericDataRegion::ScreenArea> REHex::BitArrayRegion::offset_near_or_at_xy(DocumentCtrl &doc_ctrl, int mouse_x_px, int64_t mouse_y_lines, bool exact)
{
	BitOffset mouse_line_base = d_offset + BitOffset((mouse_y_lines * bytes_per_line_actual), 0);
	
	unsigned int bits_per_group = doc_ctrl.get_bytes_per_group() * 2;
	int bin_base_x = data_text_x;
	
	if(mouse_x_px < bin_base_x)
	{
		/* Pointer is to the left of data. */
		if(exact || mouse_y_lines <= 0)
		{
			return std::make_pair(BitOffset::INVALID, SA_NONE);
		}
		else{
			return std::make_pair(mouse_line_base - BitOffset::BITS(1), SA_SPECIAL);
		}
	}
	
	int mouse_x_chars = doc_ctrl.hf_char_at_x(mouse_x_px - bin_base_x);
	
	if(bits_per_group > 0)
	{
		if(mouse_x_chars > 0 && ((mouse_x_chars + 1) % (bits_per_group + 1)) == 0)
		{
			/* Pointer is over the space between groups. */
			
			if(exact)
			{
				return std::make_pair(BitOffset::INVALID, SA_NONE);
			}
		}
		
		mouse_x_chars -= mouse_x_chars / (bits_per_group + 1);
	}
	
	int mouse_x_bytes = mouse_x_chars / 8;
	int mouse_x_bits = mouse_x_chars % 8;
	
	BitOffset mouse_position = mouse_line_base + BitOffset(mouse_x_bytes, mouse_x_bits);
	
	if(mouse_x_bytes >= bytes_per_line_actual)
	{
		/* Pointer is beyond end of line. */
		
		if(exact)
		{
			return std::make_pair(BitOffset::INVALID, SA_NONE);
		}
	}
	
	if(mouse_position >= (d_offset + d_length))
	{
		/* Clamp to end of region. */
		mouse_position = d_offset + d_length - BitOffset::BITS(1);
	}
	else if(mouse_position >= (mouse_line_base + BitOffset::BYTES(bytes_per_line_actual)))
	{
		/* Clamp to end of line. */
		mouse_position = mouse_line_base + BitOffset::BYTES(bytes_per_line_actual) - BitOffset::BITS(1);
	}
	
	return std::make_pair(mouse_position, SA_SPECIAL);
}

std::pair<REHex::BitOffset, REHex::DocumentCtrl::GenericDataRegion::ScreenArea> REHex::BitArrayRegion::offset_at_xy(DocumentCtrl &doc_ctrl, int mouse_x_px, int64_t mouse_y_lines)
{
	return offset_near_or_at_xy(doc_ctrl, mouse_x_px, mouse_y_lines, true);
}

std::pair<REHex::BitOffset, REHex::DocumentCtrl::GenericDataRegion::ScreenArea> REHex::BitArrayRegion::offset_near_xy(DocumentCtrl &doc_ctrl, int mouse_x_px, int64_t mouse_y_lines, ScreenArea type_hint)
{
	return offset_near_or_at_xy(doc_ctrl, mouse_x_px, mouse_y_lines, false);
}

REHex::BitOffset REHex::BitArrayRegion::cursor_left_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	pos -= BitOffset::BITS(1);
	
	if(pos < d_offset)
	{
		return CURSOR_PREV_REGION;
	}
	else{
		return pos;
	}
}

REHex::BitOffset REHex::BitArrayRegion::cursor_right_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	pos += BitOffset::BITS(1);
	
	if(pos >= (d_offset + d_length))
	{
		return CURSOR_NEXT_REGION;
	}
	else{
		return pos;
	}
}

REHex::BitOffset REHex::BitArrayRegion::cursor_up_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	if(pos >= (d_offset + BitOffset(bytes_per_line_actual, 0)))
	{
		return pos - BitOffset::BYTES(bytes_per_line_actual);
	}
	else{
		return CURSOR_PREV_REGION;
	}
}

REHex::BitOffset REHex::BitArrayRegion::cursor_down_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	if((pos + BitOffset(bytes_per_line_actual, 0)) < (d_offset + d_length))
	{
		return pos + BitOffset::BYTES(bytes_per_line_actual);
	}
	else if(pos < calc_last_line_offset())
	{
		return d_offset + d_length - BitOffset(0, 1);
	}
	else{
		return CURSOR_NEXT_REGION;
	}
}

REHex::BitOffset REHex::BitArrayRegion::cursor_home_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	off_t line_offset = ((pos - d_offset).byte() / bytes_per_line_actual) * bytes_per_line_actual;
	
	return d_offset + BitOffset(line_offset, 0);
}

REHex::BitOffset REHex::BitArrayRegion::cursor_end_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	off_t line_offset = ((pos - d_offset).byte() / bytes_per_line_actual) * bytes_per_line_actual;
	BitOffset line_end = std::min((d_offset + d_length), (d_offset + BitOffset((line_offset + bytes_per_line_actual), 0)));
	
	return line_end - BitOffset::BITS(1);
}

int REHex::BitArrayRegion::cursor_column(BitOffset pos)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	BitOffset offset_in_region = pos - d_offset;
	BitOffset offset_in_line = offset_in_region % BitOffset(bytes_per_line_actual);
	
	return offset_in_line.total_bits();
}

REHex::BitOffset REHex::BitArrayRegion::first_row_nearest_column(int column)
{
	BitOffset first_line_last = std::min(
		(d_offset + d_length - BitOffset(0, 1)),
		(d_offset + BitOffset(bytes_per_line_actual) - BitOffset(0, 1)));
	
	return std::min(first_line_last, (d_offset + BitOffset::from_int64(column)));
}

REHex::BitOffset REHex::BitArrayRegion::last_row_nearest_column(int column)
{
	BitOffset last_row_offset = calc_last_line_offset();
	BitOffset last_row_last   = calc_line_end(last_row_offset) - BitOffset(0, 1);
	
	BitOffset result = last_row_offset + BitOffset::from_int64(column);
	result = std::min(result, last_row_last);
	
	return result;
}

REHex::BitOffset REHex::BitArrayRegion::nth_row_nearest_column(int64_t row, int column)
{
	BitOffset last_row_offset = calc_last_line_offset();
	
	BitOffset nth_row_offset = std::min(
		(d_offset + BitOffset((row * bytes_per_line_actual), 0)),
		last_row_offset);
	
	BitOffset nth_row_last = std::min(
		(nth_row_offset + BitOffset(bytes_per_line_actual) - BitOffset(0, 1)),
		(d_offset + d_length - BitOffset(0, 1)));
	
	BitOffset result = nth_row_offset + BitOffset::from_int64(column);
	result = std::min(result, nth_row_last);
	
	return result;
}

REHex::BitOffset REHex::BitArrayRegion::calc_last_line_offset() const
{
	return d_offset + BitOffset((((d_length.byte_round_up() - 1) / bytes_per_line_actual) * bytes_per_line_actual), 0);
}

REHex::BitOffset REHex::BitArrayRegion::calc_line_offset(BitOffset offset_within_line) const
{
	assert(offset_within_line >= d_offset);
	assert(offset_within_line <= (d_offset + d_length));
	
	return offset_within_line - ((offset_within_line - d_offset) % BitOffset(bytes_per_line_actual, 0));
}

REHex::BitOffset REHex::BitArrayRegion::calc_line_end(BitOffset offset_within_line) const
{
	assert(offset_within_line >= d_offset);
	assert(offset_within_line <= (d_offset + d_length));
	
	BitOffset line_offset = calc_line_offset(offset_within_line);
	
	return std::min(
		(line_offset + BitOffset(bytes_per_line_actual, 0)),
		(d_offset + d_length));
}

REHex::DocumentCtrl::Rect REHex::BitArrayRegion::calc_offset_bounds(BitOffset offset, DocumentCtrl *doc_ctrl)
{
	assert(offset >= d_offset);
	assert(offset <= (d_offset + d_length));
	
	BitOffset line_offset = calc_line_offset(offset);
	BitOffset offset_within_line = offset - line_offset;
	
	int     bit_pos_x_px    = data_text_x + doc_ctrl->hf_string_width(offset_within_line.total_bits());
	int64_t bit_pos_y_lines = y_offset + ((line_offset - d_offset).byte() / bytes_per_line_actual);
	
	return DocumentCtrl::Rect(
			bit_pos_x_px,               /* x (pixels) */
			bit_pos_y_lines,            /* y (lines) */
			doc_ctrl->hf_char_width(),  /* w (pixels) */
			1);                         /* h (lines) */
}

REHex::DocumentCtrl::GenericDataRegion::ScreenArea REHex::BitArrayRegion::screen_areas_at_offset(BitOffset offset, DocumentCtrl *doc_ctrl)
{
	assert(offset >= d_offset);
	assert(offset <= (d_offset + d_length));
	
	return SA_SPECIAL;
}

bool REHex::BitArrayRegion::OnChar(DocumentCtrl *doc_ctrl, wxKeyEvent &event)
{
	int key = event.GetKeyCode();
	int modifiers = event.GetModifiers();
	
	if(modifiers == wxMOD_NONE && (key == '0' || key == '1'))
	{
		BitOffset cursor_position = doc_ctrl->get_cursor_position();
		
		try {
			std::vector<bool> bit = { (key == '1') };
			doc->overwrite_bits(cursor_position, bit, (cursor_position + BitOffset(0, 1)));
		}
		catch(const std::exception &e)
		{
			wxGetApp().printf_error("Exception in REHex::BitArrayRegion::OnChar: %s\n", e.what());
		}
		
		return true;
	}
	
	return false;
}

wxDataObject *REHex::BitArrayRegion::OnCopy(DocumentCtrl &doc_ctrl)
{
	BitOffset selection_first, selection_last;
	std::tie(selection_first, selection_last) = doc_ctrl.get_selection_raw();
	
	assert(selection_first >= d_offset);
	assert(selection_last < (d_offset + d_length));
	
	if(doc_ctrl.special_view_active())
	{
		try {
			std::vector<bool> data = doc->read_bits(selection_first, ((selection_last - selection_first).total_bits() + 1));
			
			std::string data_string;
			data_string.reserve(data.size());
			
			for(auto p = data.begin(); p != data.end(); ++p)
			{
				data_string.append(1, (*p ? '1' : '0'));
			}
			
			return new wxTextDataObject(data_string);
		}
		catch(const std::exception &e)
		{
			fprintf(stderr, "Exception in REHex::NumericDataTypeRegion::OnCopy: %s\n", e.what());
			return NULL;
		}
	}
	
	/* Fall back to default handling - copy selected bytes. */
	return NULL;
}
