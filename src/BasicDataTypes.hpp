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

#ifndef REHEX_BASICDATATYPES_HPP
#define REHEX_BASICDATATYPES_HPP

#include <assert.h>
#include <exception>
#include <inttypes.h>
#include <stdint.h>
#include <wx/utils.h>

#include "DataType.hpp"
#include "document.hpp"
#include "DocumentCtrl.hpp"
#include "SharedDocumentPointer.hpp"

namespace REHex
{
	template<typename T> class NumericDataTypeRegion: public DocumentCtrl::GenericDataRegion
	{
		protected:
			SharedDocumentPointer doc;
			
		private:
			std::string type_label;
			
			bool input_active;
			std::string input_buf;
			size_t input_pos;
			
			void activate()
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
			
			void commit()
			{
				if(!write_string_value(input_buf))
				{
					wxBell();
				}
				
				input_pos = 0;
				input_buf.clear();
				input_active = false;
			}
			
		protected:
			NumericDataTypeRegion(SharedDocumentPointer &doc, off_t offset, off_t length, const std::string &type_label):
				GenericDataRegion(offset, length),
				doc(doc),
				type_label(type_label),
				input_active(false),
				input_pos(0)
			{
				assert(length == sizeof(T));
			}
			
			virtual std::string to_string(const T *data) const = 0;
			virtual bool write_string_value(const std::string &value) = 0;
			
			virtual int calc_width(DocumentCtrl &doc_ctrl) override
			{
				/* TODO */
				return 50;
			}
			
			virtual void calc_height(DocumentCtrl &doc_ctrl, wxDC &dc) override
			{
				y_lines = indent_final + 1;
			}
			
			virtual void draw(DocumentCtrl &doc_ctrl, wxDC &dc, int x, int64_t y) override
			{
				off_t cursor_pos = doc_ctrl.get_cursor_position();
				
				if(input_active && cursor_pos != d_offset)
				{
					/* Filthy hack - using the draw() function to detect the cursor
					 * moving off and comitting the in-progress edit.
					*/
					
					commit();
				}
				
				draw_container(doc_ctrl, dc, x, y);
				
				int indent_width = doc_ctrl.indent_width(indent_depth);
				x += indent_width;
				
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
				
				if(doc_ctrl.get_show_offsets())
				{
					/* Draw the offsets to the left */
					
					std::string offset_str = format_offset(d_offset, doc_ctrl.get_offset_display_base(), doc->buffer_length());
					
					normal_text();
					dc.DrawText(offset_str, x, y);
					
					x += doc_ctrl.get_offset_column_width();
					
					int offset_vl_x = x - (doc_ctrl.hf_char_width() / 2);
					
					wxPen norm_fg_1px((*active_palette)[Palette::PAL_NORMAL_TEXT_FG], 1);
					
					dc.SetPen(norm_fg_1px);
					dc.DrawLine(offset_vl_x, y, offset_vl_x, y + doc_ctrl.hf_char_height());
				}
				
				bool data_err = false;
				std::vector<unsigned char> data;
				std::string data_string;
				
				try {
					data = doc->read_data(d_offset, d_length);
					assert(data.size() == sizeof(T));
					
					data_string = to_string((const T*)(data.data()));
				}
				catch(const std::exception &e)
				{
					fprintf(stderr, "Exception in REHex::NumericDataTypeRegion::draw: %s\n", e.what());
					
					data_err = true;
					data.insert(data.end(), d_length, '?');
					data_string = "????";
				}
				
				off_t selection_off, selection_length;
				std::tie(selection_off, selection_length) = doc_ctrl.get_selection();
				
				off_t selection_end = selection_off + selection_length;
				off_t d_end = d_offset + d_length;
				
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
				else if(selection_length > 0
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
						
						const char *nibble_to_hex = data_err
							? "????????????????"
							: "0123456789ABCDEF";
						
						const char hex_str[] = {
							nibble_to_hex[ (data[i] & 0xF0) >> 4 ],
							nibble_to_hex[ data[i] & 0x0F ],
							'\0'
						};
						
						if(selection_off <= (d_offset + (off_t)(i)) && selection_end > (d_offset + (off_t)(i)))
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
				else if(cursor_pos == d_offset && doc_ctrl.get_cursor_visible())
				{
					/* Invert colour for cursor position/blink. */
					
					normal_text();
					dc.DrawText("[", x, y);
					
					inverted_text();
					dc.DrawText(data_string, (x + doc_ctrl.hf_char_width()), y);
					
					normal_text();
					dc.DrawText("]", (x + doc_ctrl.hf_string_width(data_string.length() + 1)), y);
				}
				else if(selection_length > 0 && (selection_off == d_offset && selection_length == d_length))
				{
					/* Selection matches our range exactly. Render value using selected
					* text colours.
					*/
					
					normal_text();
					dc.DrawText("[", x, y);
					
					selected_text();
					dc.DrawText(data_string, (x + doc_ctrl.hf_char_width()), y);
					
					normal_text();
					dc.DrawText("]", (x + doc_ctrl.hf_string_width(data_string.length() + 1)), y);
				}
				else{
					/* No data in our range is selected. Render normally. */
					
					normal_text();
					dc.DrawText("[" + data_string + "]", x, y);
				}
				
				x += doc_ctrl.hf_string_width(22);
				
				std::string type_string = std::string("<") + type_label + ">";
				
				normal_text();
				dc.DrawText(type_string, x, y);
			}
			
			virtual std::pair<off_t, ScreenArea> offset_at_xy(DocumentCtrl &doc, int mouse_x_px, int64_t mouse_y_lines) override
			{
				return std::make_pair<off_t, ScreenArea>(-1, SA_NONE);
			}
			
			virtual std::pair<off_t, ScreenArea> offset_near_xy(DocumentCtrl &doc, int mouse_x_px, int64_t mouse_y_lines, ScreenArea type_hint) override
			{
				return std::make_pair(d_offset, SA_SPECIAL);
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
			
			virtual bool OnChar(DocumentCtrl *doc_ctrl, wxKeyEvent &event) override
			{
				int key = event.GetKeyCode();
				
				if(key >= '0' && key <= '9')
				{
					activate();
					
					input_buf.insert(input_pos, 1, key);
					++input_pos;
					
					doc_ctrl->Refresh();
					
					return true;
				}
				else if(key == '-')
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
				
				return false;
			}
	};
	
	#define DECLARE_NDTR_CLASS(NAME, T) \
		class NAME: public NumericDataTypeRegion<T> \
		{ \
			public: \
				NAME(SharedDocumentPointer &doc, off_t offset, off_t length); \
				\
			protected: \
				virtual std::string to_string(const T *data) const override; \
				virtual bool write_string_value(const std::string &value) override; \
		};
	
	DECLARE_NDTR_CLASS(U16LEDataRegion, uint16_t)
	DECLARE_NDTR_CLASS(U16BEDataRegion, uint16_t)
	DECLARE_NDTR_CLASS(S16LEDataRegion, int16_t)
	DECLARE_NDTR_CLASS(S16BEDataRegion, int16_t)
	
	DECLARE_NDTR_CLASS(U32LEDataRegion, uint32_t)
	DECLARE_NDTR_CLASS(U32BEDataRegion, uint32_t)
	DECLARE_NDTR_CLASS(S32LEDataRegion, int32_t)
	DECLARE_NDTR_CLASS(S32BEDataRegion, int32_t)
	
	DECLARE_NDTR_CLASS(U64LEDataRegion, uint64_t)
	DECLARE_NDTR_CLASS(U64BEDataRegion, uint64_t)
	DECLARE_NDTR_CLASS(S64LEDataRegion, int64_t)
	DECLARE_NDTR_CLASS(S64BEDataRegion, int64_t)
}

#endif /* !REHEX_BASICDATATYPES_HPP */
