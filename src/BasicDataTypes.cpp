/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "DataType.hpp"
#include "document.hpp"
#include "DocumentCtrl.hpp"
#include "SharedDocumentPointer.hpp"

/* This MUST come after the wxWidgets headers have been included, else we pull in windows.h BEFORE the wxWidgets
 * headers when building on Windows and this causes unicode-flavoured pointer conversion errors.
*/
#include <portable_endian.h>

template<typename T> class NumericDataTypeRegion: public REHex::DocumentCtrl::GenericDataRegion
{
	private:
		REHex::SharedDocumentPointer doc;
		
		std::string type_label;
		
		std::function<std::string(const T*)> to_string;
		
	public:
		NumericDataTypeRegion(REHex::SharedDocumentPointer &doc, off_t offset, off_t length, const std::function<std::string(const T*)> &to_string, const std::string &type_label):
			GenericDataRegion(offset, length),
			doc(doc),
			type_label(type_label),
			to_string(to_string)
		{
			assert(length == sizeof(T));
			
			indent_offset = offset;
		}
		
	protected:
		virtual int calc_width(REHex::DocumentCtrl &doc_ctrl) override
		{
			/* TODO */
			return 50;
		}
		
		virtual void calc_height(REHex::DocumentCtrl &doc_ctrl, wxDC &dc) override
		{
			y_lines = indent_final + 1;
		}
		
		virtual void draw(REHex::DocumentCtrl &doc_ctrl, wxDC &dc, int x, int64_t y) override
		{
			draw_container(doc_ctrl, dc, x, y);
			
			int indent_width = doc_ctrl.indent_width(indent_depth);
			x += indent_width;
			
			dc.SetFont(doc_ctrl.get_font());
			dc.SetBackgroundMode(wxSOLID);
			
			dc.SetTextForeground((*REHex::active_palette)[REHex::Palette::PAL_NORMAL_TEXT_FG]);
			dc.SetTextBackground((*REHex::active_palette)[REHex::Palette::PAL_NORMAL_TEXT_BG]);
			
			if(doc_ctrl.get_show_offsets())
			{
				/* Draw the offsets to the left */
				
				std::string offset_str = REHex::format_offset(d_offset, doc_ctrl.get_offset_display_base(), doc->buffer_length());
				
				dc.DrawText(offset_str, x, y);
				
				x += doc_ctrl.get_offset_column_width();
				
				int offset_vl_x = x - (doc_ctrl.hf_char_width() / 2);
				
				wxPen norm_fg_1px((*REHex::active_palette)[REHex::Palette::PAL_NORMAL_TEXT_FG], 1);
				
				dc.SetPen(norm_fg_1px);
				dc.DrawLine(offset_vl_x, y, offset_vl_x, y + doc_ctrl.hf_char_height());
			}
			
			std::vector<unsigned char> data = doc->read_data(d_offset, d_length);
			assert(data.size() == sizeof(T));
			
			off_t cursor_pos = doc->get_cursor_position();
			
			off_t selection_off, selection_length;
			std::tie(selection_off, selection_length) = doc_ctrl.get_selection();
			
			off_t selection_end = selection_off + selection_length;
			off_t d_end = d_offset + d_length;
			
			if(selection_length > 0
				&& (selection_off != d_offset || selection_length != d_length)
				&& selection_off < d_end && d_offset < selection_end)
			{
				/* Selection encompasses *some* of our bytes and/or stretches
				 * beyond either end. Render the underlying hex bytes.
				*/
				
				unsigned int bytes_per_group = doc_ctrl.get_bytes_per_group();
				unsigned int col = 0;
				
				for(size_t i = 0; i < data.size(); ++i)
				{
					if(i > 0 && (i % bytes_per_group) == 0)
					{
						++col;
					}
					
					const char *nibble_to_hex = "0123456789ABCDEF";
					
					const char hex_str[] = {
						nibble_to_hex[ (data[i] & 0xF0) >> 4 ],
						nibble_to_hex[ data[i] & 0x0F ],
						'\0'
					};
					
					if(selection_off <= (d_offset + (off_t)(i)) && selection_end > (d_offset + (off_t)(i)))
					{
						dc.SetTextForeground((*REHex::active_palette)[REHex::Palette::PAL_SELECTED_TEXT_FG]);
						dc.SetTextBackground((*REHex::active_palette)[REHex::Palette::PAL_SELECTED_TEXT_BG]);
					}
					else{
						dc.SetTextForeground((*REHex::active_palette)[REHex::Palette::PAL_NORMAL_TEXT_FG]);
						dc.SetTextBackground((*REHex::active_palette)[REHex::Palette::PAL_NORMAL_TEXT_BG]);
					}
					
					dc.DrawText(hex_str, x + doc_ctrl.hf_string_width(col), y);
					col += 2;
				}
			}
			else if(cursor_pos == d_offset && doc_ctrl.get_cursor_visible())
			{
				/* Invert colour for cursor position/blink. */
				
				dc.SetTextForeground((*REHex::active_palette)[REHex::Palette::PAL_INVERT_TEXT_FG]);
				dc.SetTextBackground((*REHex::active_palette)[REHex::Palette::PAL_INVERT_TEXT_BG]);
				
				std::string data_string = to_string((const T*)(data.data()));
				dc.DrawText(data_string, x, y);
			}
			else if(selection_length > 0 && (selection_off == d_offset && selection_length == d_length))
			{
				/* Selection matches our range exactly. Render value using selected
				 * text colours.
				*/
				
				dc.SetTextForeground((*REHex::active_palette)[REHex::Palette::PAL_SELECTED_TEXT_FG]);
				dc.SetTextBackground((*REHex::active_palette)[REHex::Palette::PAL_SELECTED_TEXT_BG]);
				
				std::string data_string = to_string((const T*)(data.data()));
				dc.DrawText(data_string, x, y);
			}
			else{
				/* No data in our range is selected. Render normally. */
				
				std::string data_string = to_string((const T*)(data.data()));
				dc.DrawText(data_string, x, y);
			}
			
			dc.SetTextForeground((*REHex::active_palette)[REHex::Palette::PAL_NORMAL_TEXT_FG]);
			dc.SetTextBackground((*REHex::active_palette)[REHex::Palette::PAL_NORMAL_TEXT_BG]);
			
			x += doc_ctrl.hf_string_width(22);
			
			std::string type_string = std::string("<") + type_label + ">";
			dc.DrawText(type_string, x, y);
		}
		
		virtual off_t offset_at_xy_hex(REHex::DocumentCtrl &doc, int mouse_x_px, uint64_t mouse_y_lines) override
		{
			return -1;
		}
		
		virtual off_t offset_at_xy_ascii(REHex::DocumentCtrl &doc, int mouse_x_px, uint64_t mouse_y_lines) override
		{
			return -1;
		}
		
		virtual off_t offset_near_xy_hex(REHex::DocumentCtrl &doc, int mouse_x_px, uint64_t mouse_y_lines) override
		{
			return d_offset;
		}
		
		virtual off_t offset_near_xy_ascii(REHex::DocumentCtrl &doc, int mouse_x_px, uint64_t mouse_y_lines) override
		{
			return d_offset;
		}
		
		virtual off_t cursor_left_from(off_t pos) override
		{
			assert(pos >= d_offset);
			assert(pos < (d_offset + d_length));
			
			return CURSOR_PREV_REGION;
		}
		
		virtual off_t cursor_right_from(off_t pos) override
		{
			assert(pos >= d_offset);
			assert(pos < (d_offset + d_length));
			
			return CURSOR_NEXT_REGION;
		}
		
		virtual off_t cursor_up_from(off_t pos) override
		{
			assert(pos >= d_offset);
			assert(pos < (d_offset + d_length));
			
			return CURSOR_PREV_REGION;
		}
		
		virtual off_t cursor_down_from(off_t pos) override
		{
			assert(pos >= d_offset);
			assert(pos < (d_offset + d_length));
			
			return CURSOR_NEXT_REGION;
		}
		
		virtual off_t cursor_home_from(off_t pos) override
		{
			assert(pos >= d_offset);
			assert(pos < (d_offset + d_length));
			
			return d_offset;
		}
		
		virtual off_t cursor_end_from(off_t pos) override
		{
			assert(pos >= d_offset);
			assert(pos < (d_offset + d_length));
			
			return d_offset;
		}
		
		virtual int cursor_column(off_t pos) override
		{
			assert(pos >= d_offset);
			assert(pos < (d_offset + d_length));
			
			return 0;
		}
		
		virtual off_t first_row_nearest_column(int column) override
		{
			return d_offset;
		}
		
		virtual off_t last_row_nearest_column(int column) override
		{
			return d_offset;
		}
};

static REHex::DocumentCtrl::Region *u16le_factory(REHex::SharedDocumentPointer &doc, off_t offset, off_t length)
{
	return new NumericDataTypeRegion<uint16_t>(doc, offset, length, [](const uint16_t *data)
	{
		char buf[128];
		snprintf(buf, sizeof(buf), "%" PRIu16, le16toh(*data));
		
		return std::string(buf);
	}, "unsigned 16-bit (little endian)");
}

static REHex::DocumentCtrl::Region *u16be_factory(REHex::SharedDocumentPointer &doc, off_t offset, off_t length)
{
	return new NumericDataTypeRegion<uint16_t>(doc, offset, length, [](const uint16_t *data)
	{
		char buf[128];
		snprintf(buf, sizeof(buf), "%" PRIu16, be16toh(*data));
		
		return std::string(buf);
	}, "unsigned 16-bit (big endian)");
}

static REHex::DocumentCtrl::Region *s16le_factory(REHex::SharedDocumentPointer &doc, off_t offset, off_t length)
{
	return new NumericDataTypeRegion<int16_t>(doc, offset, length, [](const int16_t *data)
	{
		char buf[128];
		snprintf(buf, sizeof(buf), "%" PRId16, le16toh(*data));
		
		return std::string(buf);
	}, "signed 16-bit (little endian)");
}

static REHex::DocumentCtrl::Region *s16be_factory(REHex::SharedDocumentPointer &doc, off_t offset, off_t length)
{
	return new NumericDataTypeRegion<int16_t>(doc, offset, length, [](const int16_t *data)
	{
		char buf[128];
		snprintf(buf, sizeof(buf), "%" PRIu16, be16toh(*data));
		
		return std::string(buf);
	}, "signed 16-bit (big endian)");
}

REHex::DataTypeRegistration u16le_dtr("u16le", "unsigned 16-bit (little endian)", &u16le_factory, sizeof(uint16_t), sizeof(uint16_t));
REHex::DataTypeRegistration u16be_dtr("u16be", "unsigned 16-bit (big endian)",    &u16be_factory, sizeof(uint16_t), sizeof(uint16_t));
REHex::DataTypeRegistration s16le_dtr("s16le", "signed 16-bit (little endian)",   &s16le_factory, sizeof(int16_t), sizeof(int16_t));
REHex::DataTypeRegistration s16be_dtr("s16be", "signed 16-bit (big endian)",      &s16be_factory, sizeof(int16_t), sizeof(int16_t));

static REHex::DocumentCtrl::Region *u32le_factory(REHex::SharedDocumentPointer &doc, off_t offset, off_t length)
{
	return new NumericDataTypeRegion<uint32_t>(doc, offset, length, [](const uint32_t *data)
	{
		char buf[128];
		snprintf(buf, sizeof(buf), "%" PRIu32, le32toh(*data));
		
		return std::string(buf);
	}, "unsigned 32-bit (little endian)");
}

static REHex::DocumentCtrl::Region *u32be_factory(REHex::SharedDocumentPointer &doc, off_t offset, off_t length)
{
	return new NumericDataTypeRegion<uint32_t>(doc, offset, length, [](const uint32_t *data)
	{
		char buf[128];
		snprintf(buf, sizeof(buf), "%" PRIu32, be32toh(*data));
		
		return std::string(buf);
	}, "unsigned 32-bit (big endian)");
}

static REHex::DocumentCtrl::Region *s32le_factory(REHex::SharedDocumentPointer &doc, off_t offset, off_t length)
{
	return new NumericDataTypeRegion<int32_t>(doc, offset, length, [](const int32_t *data)
	{
		char buf[128];
		snprintf(buf, sizeof(buf), "%" PRId32, le32toh(*data));
		
		return std::string(buf);
	}, "signed 32-bit (little endian)");
}

static REHex::DocumentCtrl::Region *s32be_factory(REHex::SharedDocumentPointer &doc, off_t offset, off_t length)
{
	return new NumericDataTypeRegion<int32_t>(doc, offset, length, [](const int32_t *data)
	{
		char buf[128];
		snprintf(buf, sizeof(buf), "%" PRIu32, be32toh(*data));
		
		return std::string(buf);
	}, "signed 32-bit (big endian)");
}

REHex::DataTypeRegistration u32le_dtr("u32le", "unsigned 32-bit (little endian)", &u32le_factory, sizeof(uint32_t), sizeof(uint32_t));
REHex::DataTypeRegistration u32be_dtr("u32be", "unsigned 32-bit (big endian)",    &u32be_factory, sizeof(uint32_t), sizeof(uint32_t));
REHex::DataTypeRegistration s32le_dtr("s32le", "signed 32-bit (little endian)",   &s32le_factory, sizeof(int32_t), sizeof(int32_t));
REHex::DataTypeRegistration s32be_dtr("s32be", "signed 32-bit (big endian)",      &s32be_factory, sizeof(int32_t), sizeof(int32_t));

static REHex::DocumentCtrl::Region *u64le_factory(REHex::SharedDocumentPointer &doc, off_t offset, off_t length)
{
	return new NumericDataTypeRegion<uint64_t>(doc, offset, length, [](const uint64_t *data)
	{
		char buf[128];
		snprintf(buf, sizeof(buf), "%" PRIu64, le64toh(*data));
		
		return std::string(buf);
	}, "unsigned 64-bit (little endian)");
}

static REHex::DocumentCtrl::Region *u64be_factory(REHex::SharedDocumentPointer &doc, off_t offset, off_t length)
{
	return new NumericDataTypeRegion<uint64_t>(doc, offset, length, [](const uint64_t *data)
	{
		char buf[128];
		snprintf(buf, sizeof(buf), "%" PRIu64, be64toh(*data));
		
		return std::string(buf);
	}, "unsigned 64-bit (big endian)");
}

static REHex::DocumentCtrl::Region *s64le_factory(REHex::SharedDocumentPointer &doc, off_t offset, off_t length)
{
	return new NumericDataTypeRegion<int64_t>(doc, offset, length, [](const int64_t *data)
	{
		char buf[128];
		snprintf(buf, sizeof(buf), "%" PRId64, le64toh(*data));
		
		return std::string(buf);
	}, "signed 64-bit (little endian)");
}

static REHex::DocumentCtrl::Region *s64be_factory(REHex::SharedDocumentPointer &doc, off_t offset, off_t length)
{
	return new NumericDataTypeRegion<int64_t>(doc, offset, length, [](const int64_t *data)
	{
		char buf[128];
		snprintf(buf, sizeof(buf), "%" PRIu64, be64toh(*data));
		
		return std::string(buf);
	}, "signed 64-bit (big endian)");
}

REHex::DataTypeRegistration u64le_dtr("u64le", "unsigned 64-bit (little endian)", &u64le_factory, sizeof(uint64_t), sizeof(uint64_t));
REHex::DataTypeRegistration u64be_dtr("u64be", "unsigned 64-bit (big endian)",    &u64be_factory, sizeof(uint64_t), sizeof(uint64_t));
REHex::DataTypeRegistration s64le_dtr("s64le", "signed 64-bit (little endian)",   &s64le_factory, sizeof(int64_t), sizeof(int64_t));
REHex::DataTypeRegistration s64be_dtr("s64be", "signed 64-bit (big endian)",      &s64be_factory, sizeof(int64_t), sizeof(int64_t));
