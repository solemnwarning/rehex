/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include "FixedSizeValueRegion.hpp"

void REHex::FixedSizeValueRegion::activate()
{
	if(input_active)
	{
		/* Already active. */
		return;
	}
	
	assert(input_buf.empty());
	assert(input_pos == 0);
	
	input_active = true;
}

void REHex::FixedSizeValueRegion::commit()
{
	if(!store_value(input_buf))
	{
		wxBell();
	}
	
	input_pos = 0;
	input_buf.clear();
	input_active = false;
}

bool REHex::FixedSizeValueRegion::partially_selected(DocumentCtrl *doc_ctrl)
{
	BitOffset total_selection_first, total_selection_last;
	std::tie(total_selection_first, total_selection_last) = doc_ctrl->get_selection_raw();
	
	BitOffset region_selection_offset, region_selection_length;
	std::tie(region_selection_offset, region_selection_length) = doc_ctrl->get_selection_in_region(this);
	
	return region_selection_length > BitOffset::ZERO
		&& (total_selection_first != d_offset || (total_selection_last + BitOffset(0, 1)) != (d_offset + d_length));
}

REHex::FixedSizeValueRegion::FixedSizeValueRegion(SharedDocumentPointer &doc, BitOffset offset, BitOffset length, BitOffset virt_offset, const std::string &type_label):
	GenericDataRegion(offset, length, virt_offset, virt_offset),
	doc(doc),
	type_label(type_label),
	offset_text_x(-1),
	data_text_x(-1),
	input_active(false),
	input_pos(0) {}

int REHex::FixedSizeValueRegion::calc_width(DocumentCtrl &doc_ctrl)
{
	int indent_width = doc_ctrl.indent_width(indent_depth);
	
	int offset_column_width = doc_ctrl.get_show_offsets()
		? doc_ctrl.get_offset_column_width()
		: 0;
	
	offset_text_x = indent_width;
	data_text_x   = indent_width + offset_column_width;
	
	return (2 * indent_width)
		+ offset_column_width
		+ doc_ctrl.hf_string_width(TYPE_X_CHAR + TYPE_MAX_LEN + 2 /* <> characters */);
}

void REHex::FixedSizeValueRegion::calc_height(DocumentCtrl &doc_ctrl)
{
	y_lines = indent_final + 1;
}

void REHex::FixedSizeValueRegion::draw(DocumentCtrl &doc_ctrl, wxDC &dc, int x, int64_t y)
{
	BitOffset cursor_pos = doc_ctrl.get_cursor_position();
	
	if(input_active && (cursor_pos < d_offset || cursor_pos >= (d_offset + d_length)))
	{
		/* Filthy hack - using the draw() function to detect the cursor
		 * moving off and comitting the in-progress edit.
		*/
		
		commit();
	}
	
	draw_container(doc_ctrl, dc, x, y);
	
	dc.SetFont(doc_ctrl.get_font());
	dc.SetBackgroundMode(wxSOLID);
	
	auto normal_text = [&]()
	{
		dc.SetTextForeground((*active_palette)[Palette::PAL_NORMAL_TEXT_FG]);
		dc.SetTextBackground((*active_palette)[Palette::PAL_NORMAL_TEXT_BG]);
	};
	
	auto selected_text = [&]()
	{
		dc.SetTextForeground((*active_palette)[Palette::PAL_SELECTED_TEXT_FG]);
		dc.SetTextBackground((*active_palette)[Palette::PAL_SELECTED_TEXT_BG]);
	};
	
	auto inverted_text = [&]()
	{
		dc.SetTextForeground((*active_palette)[Palette::PAL_INVERT_TEXT_FG]);
		dc.SetTextBackground((*active_palette)[Palette::PAL_INVERT_TEXT_BG]);
	};
	
	x += offset_text_x;
	
	if(doc_ctrl.get_show_offsets())
	{
		/* Draw the offsets to the left */
		
		std::string offset_str = format_offset(virt_offset, doc_ctrl.get_offset_display_base(), doc_ctrl.get_end_virt_offset());
		
		normal_text();
		dc.DrawText(offset_str, x, y);
		
		x += (data_text_x - offset_text_x);
		
		int offset_vl_x = x - (doc_ctrl.hf_char_width() / 2);
		
		wxPen norm_fg_1px((*active_palette)[Palette::PAL_NORMAL_TEXT_FG], 1);
		
		dc.SetPen(norm_fg_1px);
		dc.DrawLine(offset_vl_x, y, offset_vl_x, y + doc_ctrl.hf_char_height());
	}
	
	auto get_string_to_draw = [&]()
	{
		std::string data_string;
		
		try {
			return load_value();
		}
		catch(const std::exception &e)
		{
			wxGetApp().printf_error("Exception in REHex::FixedSizeValueRegion::draw: %s\n", e.what());
			return std::string("???");
		}
	};
	
	BitOffset total_selection_first, total_selection_last;
	std::tie(total_selection_first, total_selection_last) = doc_ctrl.get_selection_raw();
	
	BitOffset region_selection_offset, region_selection_length;
	std::tie(region_selection_offset, region_selection_length) = doc_ctrl.get_selection_in_region(this);
	
	BitOffset region_selection_end = region_selection_offset + region_selection_length;
	
	if(input_active)
	{
		normal_text();
		dc.DrawText("[" + input_buf + "]", x, y);
		
		if(doc_ctrl.get_cursor_visible())
		{
			int cursor_x = x + doc_ctrl.hf_string_width(1 + input_pos);
			dc.DrawLine(cursor_x, y, cursor_x, y + doc_ctrl.hf_char_height());
		}
	}
	else if(partially_selected(&doc_ctrl) && d_length.byte_aligned())
	{
		/* Selection encompasses *some* of our bytes and/or stretches
		 * beyond either end. Render the underlying hex bytes.
		*/
		
		bool data_err = false;
		std::vector<unsigned char> data;
		std::string data_string;
		
		try {
			data = doc->read_data(d_offset, d_length.byte());
		}
		catch(const std::exception &e)
		{
			wxGetApp().printf_error("Exception in REHex::NumericDataTypeRegion::draw: %s\n", e.what());
			
			data_err = true;
			data.insert(data.end(), d_length.byte(), '?');
		}
		
		unsigned int bytes_per_group = doc_ctrl.get_bytes_per_group();
		unsigned int col = 0;
		
		for(size_t i = 0; i < data.size(); ++i)
		{
			if(i > 0 && (i % bytes_per_group) == 0)
			{
				++col;
			}
			
			const char *nibble_to_hex = data_err
				? "????????????????"
				: "0123456789ABCDEF";
			
			const char hex_str[] = {
				nibble_to_hex[ (data[i] & 0xF0) >> 4 ],
				nibble_to_hex[ data[i] & 0x0F ],
				'\0'
			};
			
			if(region_selection_offset <= (d_offset + BitOffset(i, 0)) && region_selection_end > (d_offset + BitOffset(i, 0)))
			{
				selected_text();
			}
			else{
				normal_text();
			}
			
			dc.DrawText(hex_str, x + doc_ctrl.hf_string_width(col), y);
			col += 2;
		}
	}
	else if(cursor_pos >= d_offset && cursor_pos < (d_offset + d_length) && doc_ctrl.get_cursor_visible())
	{
		/* Invert colour for cursor position/blink. */
		
		std::string data_string = get_string_to_draw();
		
		normal_text();
		dc.DrawText("[", x, y);
		
		inverted_text();
		dc.DrawText(data_string, (x + doc_ctrl.hf_char_width()), y);
		
		normal_text();
		dc.DrawText("]", (x + doc_ctrl.hf_string_width(data_string.length() + 1)), y);
	}
	else if(region_selection_length > BitOffset::ZERO)
	{
		/* Selection matches our range exactly. Render value using selected
		 * text colours.
		*/
		
		std::string data_string = get_string_to_draw();
		
		normal_text();
		dc.DrawText("[", x, y);
		
		selected_text();
		dc.DrawText(data_string, (x + doc_ctrl.hf_char_width()), y);
		
		normal_text();
		dc.DrawText("]", (x + doc_ctrl.hf_string_width(data_string.length() + 1)), y);
	}
	else{
		/* No data in our range is selected. Render normally. */
		
		std::string data_string = get_string_to_draw();
		
		normal_text();
		dc.DrawText("[" + data_string + "]", x, y);
	}
	
	x += doc_ctrl.hf_string_width(TYPE_X_CHAR);
	
	std::string type_string = std::string("<") + type_label + ">";
	
	normal_text();
	dc.DrawText(type_string, x, y);
}

std::pair<REHex::BitOffset, REHex::DocumentCtrl::GenericDataRegion::ScreenArea> REHex::FixedSizeValueRegion::offset_at_xy(DocumentCtrl &doc_ctrl, int mouse_x_px, int64_t mouse_y_lines)
{
	BitOffset total_selection_first, total_selection_last;
	std::tie(total_selection_first, total_selection_last) = doc_ctrl.get_selection_raw();
	
	BitOffset region_selection_offset, region_selection_length;
	std::tie(region_selection_offset, region_selection_length) = doc_ctrl.get_selection_in_region(this);
	
	if(region_selection_length > BitOffset::ZERO && (total_selection_first != d_offset || total_selection_last != (d_offset + d_length - BitOffset::BITS(1))))
	{
		/* Our data is partially selected. We are displaying hex bytes. */
		
		if(mouse_x_px < data_text_x)
		{
			/* Click was left of data area. */
			return std::make_pair(BitOffset::INVALID, SA_NONE);
		}
		
		mouse_x_px -= data_text_x;
		
		unsigned int bytes_per_group = doc_ctrl.get_bytes_per_group();
		
		unsigned int char_offset = doc_ctrl.hf_char_at_x(mouse_x_px);
		if(((char_offset + 1) % ((bytes_per_group * 2) + 1)) == 0)
		{
			/* Click was over a space between byte groups. */
			return std::make_pair(BitOffset::INVALID, SA_NONE);
		}
		else{
			unsigned int char_offset_sub_spaces = char_offset - (char_offset / ((bytes_per_group * 2) + 1));
			unsigned int line_offset_bytes      = char_offset_sub_spaces / 2;
			BitOffset clicked_offset            = d_offset + BitOffset::BYTES(line_offset_bytes);
			
			if(clicked_offset < (d_offset + d_length))
			{
				/* Clicked on a byte */
				return std::make_pair(clicked_offset, SA_HEX);
			}
			else{
				/* Clicked past the end of the line */
				return std::make_pair(BitOffset::INVALID, SA_NONE);
			}
		}
	}
	else{
		/* We are displaying normally (i.e. the value in square brackets) */
		
		std::string data_string;
		
		try {
			data_string = load_value();
		}
		catch(const std::exception &e)
		{
			wxGetApp().printf_error("Exception in REHex::NumericDataTypeRegion::offset_at_xy: %s\n", e.what());
			return std::make_pair<off_t, ScreenArea>(-1, SA_NONE);
		}
		
		mouse_x_px -= data_text_x + doc_ctrl.hf_char_width() /* [ character */;
		unsigned int char_offset = doc_ctrl.hf_char_at_x(mouse_x_px);
		
		if(mouse_x_px >= 0 && char_offset < data_string.length())
		{
			/* Within screen area of data_string. */
			return std::make_pair(d_offset, SA_SPECIAL);
		}
		else{
			return std::make_pair(BitOffset::INVALID, SA_NONE);
		}
	}
}

std::pair<REHex::BitOffset, REHex::DocumentCtrl::GenericDataRegion::ScreenArea> REHex::FixedSizeValueRegion::offset_near_xy(DocumentCtrl &doc_ctrl, int mouse_x_px, int64_t mouse_y_lines, ScreenArea type_hint)
{
	if(partially_selected(&doc_ctrl))
	{
		mouse_x_px -= data_text_x + doc_ctrl.hf_char_width() /* [ character */;
		mouse_x_px = std::max(mouse_x_px, 0);
		
		BitOffset mouse_x_bytes = std::min(
			(d_offset + BitOffset::BYTES(mouse_x_px / doc_ctrl.hf_string_width(2))),
			(d_offset + d_length - BitOffset::BITS(1)));
		
		return std::make_pair(mouse_x_bytes, SA_SPECIAL);
	}
	else{
		return std::make_pair(d_offset, SA_SPECIAL);
	}
}

REHex::BitOffset REHex::FixedSizeValueRegion::cursor_left_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	return CURSOR_PREV_REGION;
}

REHex::BitOffset REHex::FixedSizeValueRegion::cursor_right_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	if(partially_selected(doc_ctrl))
	{
		if((pos + BitOffset(1, 0)) < (d_offset + d_length))
		{
			return pos + BitOffset(1, 0);
		}
		else{
			return CURSOR_NEXT_REGION;
		}
	}
	else{
		return CURSOR_NEXT_REGION;
	}
}

REHex::BitOffset REHex::FixedSizeValueRegion::cursor_up_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	return CURSOR_PREV_REGION;
}

REHex::BitOffset REHex::FixedSizeValueRegion::cursor_down_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	return CURSOR_NEXT_REGION;
}

REHex::BitOffset REHex::FixedSizeValueRegion::cursor_home_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	return d_offset;
}

REHex::BitOffset REHex::FixedSizeValueRegion::cursor_end_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	return d_offset;
}

int REHex::FixedSizeValueRegion::cursor_column(BitOffset pos)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	return 0;
}

REHex::BitOffset REHex::FixedSizeValueRegion::first_row_nearest_column(int column)
{
	return d_offset;
}

REHex::BitOffset REHex::FixedSizeValueRegion::last_row_nearest_column(int column)
{
	return d_offset;
}

REHex::BitOffset REHex::FixedSizeValueRegion::nth_row_nearest_column(int64_t row, int column)
{
	return d_offset;
}

REHex::DocumentCtrl::Rect REHex::FixedSizeValueRegion::calc_offset_bounds(BitOffset offset, DocumentCtrl *doc_ctrl)
{
	assert(offset >= d_offset);
	assert(offset <= (d_offset + d_length));
	
	BitOffset total_selection_first, total_selection_last;
	std::tie(total_selection_first, total_selection_last) = doc_ctrl->get_selection_raw();
	
	BitOffset region_selection_offset, region_selection_length;
	std::tie(region_selection_offset, region_selection_length) = doc_ctrl->get_selection_in_region(this);
	
	if(region_selection_length > BitOffset::ZERO && (total_selection_first != d_offset || total_selection_last != (d_offset + d_length - BitOffset::BITS(1))))
	{
		/* Our data is partially selected. We are displaying hex bytes. */
		
		off_t rel_offset = (offset - d_offset).byte();
		
		unsigned int bytes_per_group = doc_ctrl->get_bytes_per_group();
		int line_x = data_text_x + doc_ctrl->hf_string_width((rel_offset * 2) + (rel_offset / bytes_per_group));
		
		return DocumentCtrl::Rect(
			line_x,                        /* x */
			y_offset,                      /* y */
			doc_ctrl->hf_string_width(2),  /* w */
			1);                            /* h */
	}
	else{
		/* We are displaying normally (i.e. the value in square brackets) */
		
		std::vector<unsigned char> data;
		
		return DocumentCtrl::Rect(
			data_text_x,                                   /* x */
			y_offset,                                      /* y */
			doc_ctrl->hf_string_width(MAX_INPUT_LEN + 2),  /* w */
			1);                                            /* h */
	}
}

REHex::DocumentCtrl::GenericDataRegion::ScreenArea REHex::FixedSizeValueRegion::screen_areas_at_offset(BitOffset offset, DocumentCtrl *doc_ctrl)
{
	assert(offset >= d_offset);
	assert(offset <= (d_offset + d_length));
	
	return SA_HEX; /* We currently don't make use of the SA_SPECIAL
			* screen area for our numeric values and
			* selectively render them in the hex area instead.
			*/
}

bool REHex::FixedSizeValueRegion::OnChar(DocumentCtrl *doc_ctrl, wxKeyEvent &event)
{
	int key = event.GetKeyCode();
	
	if((key >= '0' && key <= '9')
		|| (key >= 'a' && key <= 'z')
		|| (key >= 'A' && key <= 'Z')
		|| key == '.')
	{
		activate();
		
		if(input_buf.length() < MAX_INPUT_LEN)
		{
			input_buf.insert(input_pos, 1, key);
			++input_pos;
			
			doc_ctrl->Refresh();
		}
		else{
			wxBell();
		}
		
		return true;
	}
	else if(key == '-' || key == '+')
	{
		if(input_pos == 0)
		{
			activate();
			
			input_buf.insert(input_pos, 1, key);
			++input_pos;
			
			doc_ctrl->Refresh();
		}
		
		return true;
	}
	else if(key == WXK_DELETE)
	{
		activate();
		
		if(input_pos < input_buf.length())
		{
			input_buf.erase(input_pos, 1);
		}
		
		doc_ctrl->Refresh();
		
		return true;
	}
	else if(key == WXK_BACK) /* Backspace */
	{
		activate();
		
		if(input_pos > 0)
		{
			--input_pos;
			input_buf.erase(input_pos, 1);
		}
		
		doc_ctrl->Refresh();
		
		return true;
	}
	else if(key == WXK_F2)
	{
		/* Activate input mode with current string value. */
		
		std::string data_string;
		
		try {
			data_string = load_value();
		}
		catch(const std::exception &e)
		{
			wxGetApp().printf_error("Exception in REHex::FixedSizeValueRegion::OnChar: %s\n", e.what());
			return true;
		}
		
		activate();
		
		input_buf = data_string;
		input_pos = input_buf.length();
		
		doc_ctrl->Refresh();
		
		return true;
	}
	else if(key == WXK_ESCAPE)
	{
		input_pos = 0;
		input_buf.clear();
		input_active = false;
		
		doc_ctrl->Refresh();
		
		return true;
	}
	else if(key == WXK_RETURN)
	{
		if(input_active)
		{
			commit();
			doc_ctrl->Refresh();
		}
		
		return true;
	}
	else if(key == WXK_LEFT && input_pos > 0)
	{
		--input_pos;
		doc_ctrl->Refresh();
		
		return true;
	}
	else if(key == WXK_RIGHT && input_pos < input_buf.length())
	{
		++input_pos;
		doc_ctrl->Refresh();
		
		return true;
	}
	else if(key == WXK_HOME)
	{
		if(input_active)
		{
			input_pos = 0;
			doc_ctrl->Refresh();
		}
		
		return true;
	}
	else if(key == WXK_END)
	{
		if(input_active)
		{
			input_pos = input_buf.length();
			doc_ctrl->Refresh();
		}
		
		return true;
	}
	
	return false;
}

wxDataObject *REHex::FixedSizeValueRegion::OnCopy(DocumentCtrl &doc_ctrl)
{
	BitOffset selection_first, selection_last;
	std::tie(selection_first, selection_last) = doc_ctrl.get_selection_raw();
	
	assert(selection_first >= d_offset);
	assert(selection_last < (d_offset + d_length));
	
	if(selection_first == d_offset && selection_last == (d_offset + d_length - BitOffset::BITS(1)))
	{
		/* Selection matches our data range. Copy stringified numeric value to clipboard. */
		
		try {
			return new wxTextDataObject(load_value());
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

bool REHex::FixedSizeValueRegion::OnPaste(DocumentCtrl *doc_ctrl)
{
	BitOffset selection_first, selection_last;
	std::tie(selection_first, selection_last) = doc_ctrl->get_selection_raw();
	
	if(doc_ctrl->has_selection() && (selection_first != d_offset || selection_last != (d_offset + d_length - BitOffset::BYTES(1))))
	{
		/* There is a selection and it doesn't exactly match our
			* data range. Fall back to default handling.
		*/
		
		return false;
	}
	
	if(wxTheClipboard->IsSupported(wxDF_TEXT))
	{
		/* Clipboard contains text. Act like it was typed in. */
		
		wxTextDataObject clipboard_data;
		wxTheClipboard->GetData(clipboard_data);
		
		std::string clipboard_text = clipboard_data.GetText().ToStdString();
		
		activate();
		
		input_buf.insert(input_pos, clipboard_text);
		input_pos += clipboard_text.length();
		
		if(input_buf.length() > MAX_INPUT_LEN)
		{
			/* Clipboard text is too long. */
			
			input_buf.erase(MAX_INPUT_LEN);
			wxBell();
		}
		
		doc_ctrl->Refresh();
		
		return true;
	}
	
	return false;
}
