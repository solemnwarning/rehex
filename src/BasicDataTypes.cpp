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

#include <functional>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "DataType.hpp"
#include "document.hpp"
#include "DocumentCtrl.hpp"
#include "SharedDocumentPointer.hpp"

template<typename T> class NumericDataTypeRegion: public REHex::DocumentCtrl::Region
{
	private:
		REHex::SharedDocumentPointer doc;
		off_t d_offset, d_length;
		
		std::function<std::string(const T*)> to_string;
		
	public:
		NumericDataTypeRegion(REHex::SharedDocumentPointer &doc, off_t offset, off_t length, const std::function<std::string(const T*)> &to_string):
			doc(doc),
			d_offset(offset),
			d_length(length),
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
			
			std::string data_string = to_string((const T*)(data.data()));
			dc.DrawText(data_string, x, y);
		}
};

static REHex::DocumentCtrl::Region *u16le_factory(REHex::SharedDocumentPointer &doc, off_t offset, off_t length)
{
	return new NumericDataTypeRegion<uint16_t>(doc, offset, length, [](const uint16_t *data)
	{
		char buf[128];
		snprintf(buf, sizeof(buf), "%" PRIu16 " <uint16>", le16toh(*data));
		
		return std::string(buf);
	});
}

static REHex::DocumentCtrl::Region *u16be_factory(REHex::SharedDocumentPointer &doc, off_t offset, off_t length)
{
	return new NumericDataTypeRegion<uint16_t>(doc, offset, length, [](const uint16_t *data)
	{
		char buf[128];
		snprintf(buf, sizeof(buf), "%" PRIu16 " <uint16>", be16toh(*data));
		
		return std::string(buf);
	});
}

static REHex::DocumentCtrl::Region *s16le_factory(REHex::SharedDocumentPointer &doc, off_t offset, off_t length)
{
	return new NumericDataTypeRegion<int16_t>(doc, offset, length, [](const int16_t *data)
	{
		char buf[128];
		snprintf(buf, sizeof(buf), "%" PRId16 " <int16>", le16toh(*data));
		
		return std::string(buf);
	});
}

static REHex::DocumentCtrl::Region *s16be_factory(REHex::SharedDocumentPointer &doc, off_t offset, off_t length)
{
	return new NumericDataTypeRegion<int16_t>(doc, offset, length, [](const int16_t *data)
	{
		char buf[128];
		snprintf(buf, sizeof(buf), "%" PRIu16 " <int16>", be16toh(*data));
		
		return std::string(buf);
	});
}

REHex::DataTypeRegistration u16le_dtr("u16le", "unsigned 16-bit (little endian)", &u16le_factory, sizeof(uint16_t), sizeof(uint16_t));
REHex::DataTypeRegistration u16be_dtr("u16be", "unsigned 16-bit (big endian)",    &u16be_factory, sizeof(uint16_t), sizeof(uint16_t));
REHex::DataTypeRegistration s16le_dtr("s16le", "signed 16-bit (little endian)",   &s16le_factory, sizeof(int16_t), sizeof(int16_t));
REHex::DataTypeRegistration s16be_dtr("s16be", "signed 16-bit (big endian)",      &s16be_factory, sizeof(int16_t), sizeof(int16_t));
