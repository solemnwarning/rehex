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

#include "BitArray.hpp"
#include "DataType.hpp"

static REHex::DocumentCtrl::Region *BitArrayRegion_factory(REHex::SharedDocumentPointer &doc, off_t offset, off_t length, off_t virt_offset)
{
	return new REHex::BitArrayRegion(doc, offset, length, virt_offset);
}

static REHex::DataTypeRegistration BitArrayType("bitarray", "Bit array", &BitArrayRegion_factory);

REHex::BitArrayRegion::BitArrayRegion(SharedDocumentPointer &doc, off_t offset, off_t length, off_t virt_offset):
	GenericDataRegion(offset, length, virt_offset, virt_offset),
	doc(doc),
	offset_text_x(-1),
	data_text_x(-1)
{}

int REHex::BitArrayRegion::calc_width(DocumentCtrl &doc_ctrl)
{
	int indent_width = doc_ctrl.indent_width(indent_depth);
	
	int offset_column_width = doc_ctrl.get_show_offsets()
		? doc_ctrl.get_offset_column_width()
		: 0;
	
	offset_text_x = indent_width;
	data_text_x   = indent_width + offset_column_width;
	
	return (2 * indent_width)
		+ offset_column_width
		+ doc_ctrl.hf_string_width(BSR_BYTES_PER_LINE * 8);
}

void REHex::BitArrayRegion::calc_height(DocumentCtrl &doc_ctrl)
{
	y_lines = indent_final + (d_length / BSR_BYTES_PER_LINE);
}

void REHex::BitArrayRegion::draw(DocumentCtrl &doc_ctrl, wxDC &dc, int x, int64_t y)
{
	off_t data_base = d_offset;
	off_t data_length = d_length;
	off_t virt_base = virt_offset;
	
	draw_container(doc_ctrl, dc, x, y);
	
	int64_t skip_lines = (y < 0 ? (-y / doc_ctrl.hf_char_height()) : 0);
	off_t skip_bytes  = skip_lines * BSR_BYTES_PER_LINE;
	
	y += skip_lines * doc_ctrl.hf_char_height();
	
	data_base += skip_bytes;
	data_length -= skip_bytes;
	virt_base += skip_bytes;
	
	wxSize client_size = doc_ctrl.GetClientSize();
	off_t max_data_in_client_area = BSR_BYTES_PER_LINE * ((client_size.GetHeight() / doc_ctrl.hf_char_height()) + 1);
	
	if(data_length > max_data_in_client_area)
	{
		data_length = max_data_in_client_area;
	}
	
	std::vector<unsigned char> data;
	if(data_length > 0)
	{
		data = doc->read_data(data_base, data_length);
	}
	
	off_t data_cur = data_base;
	off_t data_remain = data_length;
	off_t virt_cur = virt_base;
	
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
		if(offset >= scoped_selection_offset && offset < (scoped_selection_offset + scoped_selection_length))
		{
			return hex_selection_highlight;
		}
		else{
			return Highlight(NoHighlight());
		}
	};
	
	while(y < client_size.GetHeight() && data_remain > 0)
	{
		normal_text_colour();
		
		if(doc_ctrl.get_show_offsets())
		{
			/* Draw the offsets to the left */
			
			std::string offset_str = format_offset(virt_cur, doc_ctrl.get_offset_display_base(), doc_ctrl.get_end_virt_offset());
			
			dc.DrawText(offset_str, (x + offset_text_x), y);
			
			int offset_vl_x = x + offset_text_x - (doc_ctrl.hf_char_width() / 2);
			
			wxPen norm_fg_1px((*active_palette)[Palette::PAL_NORMAL_TEXT_FG], 1);
			
			dc.SetPen(norm_fg_1px);
			dc.DrawLine(offset_vl_x, y, offset_vl_x, y + doc_ctrl.hf_char_height());
		}
		
		off_t line_len = std::min<off_t>(data_remain, BSR_BYTES_PER_LINE);
		
		draw_bin_line(&doc_ctrl, dc, (x + data_text_x), y, data.data() + (data_cur - data_base), line_len, 0, data_cur, alternate_row, highlight_func, false);
		
		data_cur += line_len;
		data_remain -= line_len;
		virt_cur += line_len;
		
		y += doc_ctrl.hf_char_height();
		
		alternate_row = !alternate_row;
	}
}

std::pair<REHex::BitOffset, REHex::DocumentCtrl::GenericDataRegion::ScreenArea> REHex::BitArrayRegion::offset_near_or_at_xy(DocumentCtrl &doc_ctrl, int mouse_x_px, int64_t mouse_y_lines, bool exact)
{
	off_t mouse_line_base = d_offset + (mouse_y_lines * BSR_BYTES_PER_LINE);
	
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
			return std::make_pair(BitOffset((mouse_line_base - 1), 7), SA_SPECIAL);
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
	
	BitOffset mouse_position((mouse_line_base + mouse_x_bytes), mouse_x_bits);
	
	if(mouse_x_bytes >= BSR_BYTES_PER_LINE)
	{
		/* Pointer is beyond end of line. */
		
		if(exact)
		{
			return std::make_pair(BitOffset::INVALID, SA_NONE);
		}
	}
	
	if(mouse_position.byte() >= (d_offset + d_length))
	{
		/* Clamp to end of region. */
		mouse_position = BitOffset((d_offset + d_length - 1), 7);
	}
	else if(mouse_position.byte() >= (mouse_line_base + BSR_BYTES_PER_LINE))
	{
		/* Clamp to end of line. */
		mouse_position = BitOffset((mouse_line_base + BSR_BYTES_PER_LINE - 1), 7);
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

REHex::BitOffset REHex::BitArrayRegion::cursor_left_from(BitOffset pos, ScreenArea active_type)
{
	assert(pos.byte() >= d_offset);
	assert(pos.byte() <= (d_offset + d_length));
	
	pos -= BitOffset::BITS(1);
	
	if(pos.byte() < d_offset)
	{
		return CURSOR_PREV_REGION;
	}
	else{
		return pos;
	}
}

REHex::BitOffset REHex::BitArrayRegion::cursor_right_from(BitOffset pos, ScreenArea active_type)
{
	assert(pos.byte() >= d_offset);
	assert(pos.byte() <= (d_offset + d_length));
	
	pos += BitOffset::BITS(1);
	
	if(pos.byte() >= (d_offset + d_length))
	{
		return CURSOR_NEXT_REGION;
	}
	else{
		return pos;
	}
}

REHex::BitOffset REHex::BitArrayRegion::cursor_up_from(BitOffset pos, ScreenArea active_type)
{
	assert(pos.byte() >= d_offset);
	assert(pos.byte() <= (d_offset + d_length));
	
	if(pos.byte() >= (d_offset + BSR_BYTES_PER_LINE))
	{
		return pos - BitOffset::BYTES(BSR_BYTES_PER_LINE);
	}
	else{
		return CURSOR_PREV_REGION;
	}
}

REHex::BitOffset REHex::BitArrayRegion::cursor_down_from(BitOffset pos, ScreenArea active_type)
{
	assert(pos.byte() >= d_offset);
	assert(pos.byte() <= (d_offset + d_length));
	
	if((pos.byte() + BSR_BYTES_PER_LINE) < (d_offset + d_length))
	{
		return pos + BitOffset::BYTES(BSR_BYTES_PER_LINE);
	}
	else{
		return CURSOR_NEXT_REGION;
	}
}

REHex::BitOffset REHex::BitArrayRegion::cursor_home_from(BitOffset pos, ScreenArea active_type)
{
	assert(pos.byte() >= d_offset);
	assert(pos.byte() <= (d_offset + d_length));
	
	off_t line_off = (pos.byte() - d_offset) % BSR_BYTES_PER_LINE;
	
	return BitOffset((pos.byte() - line_off), 0);
}

REHex::BitOffset REHex::BitArrayRegion::cursor_end_from(BitOffset pos, ScreenArea active_type)
{
	assert(pos.byte() >= d_offset);
	assert(pos.byte() <= (d_offset + d_length));
	
	off_t line_off = (pos.byte() - d_offset) % BSR_BYTES_PER_LINE;
	off_t line_begin = pos.byte() - line_off;
	off_t line_end = std::min((d_offset + d_length), (line_begin + BSR_BYTES_PER_LINE));
	
	return BitOffset(line_end - 1, 7);
}

int REHex::BitArrayRegion::cursor_column(off_t pos)
{
	/* TODO */
	
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	return 0;
}

off_t REHex::BitArrayRegion::first_row_nearest_column(int column)
{
	/* TODO */
	return d_offset;
}

off_t REHex::BitArrayRegion::last_row_nearest_column(int column)
{
	/* TODO */
	return d_offset;
}

off_t REHex::BitArrayRegion::nth_row_nearest_column(int64_t row, int column)
{
	/* TODO */
	return d_offset;
}

REHex::DocumentCtrl::Rect REHex::BitArrayRegion::calc_offset_bounds(off_t offset, DocumentCtrl *doc_ctrl)
{
	/* TODO */
	
	assert(offset >= d_offset);
	assert(offset <= (d_offset + d_length));
	
	return DocumentCtrl::Rect(
			0,                                   /* x */
			y_offset,                                      /* y */
			1,  /* w */
			1);                                            /* h */
}

REHex::DocumentCtrl::GenericDataRegion::ScreenArea REHex::BitArrayRegion::screen_areas_at_offset(off_t offset, DocumentCtrl *doc_ctrl)
{
	assert(offset >= d_offset);
	assert(offset <= (d_offset + d_length));
	
	return SA_SPECIAL;
}

bool REHex::BitArrayRegion::OnChar(DocumentCtrl *doc_ctrl, wxKeyEvent &event)
{
	int key = event.GetKeyCode();
	
	if(key == '0' || key == '1')
	{
		return true;
	}
	
	return false;
}
