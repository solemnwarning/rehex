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

#ifndef REHEX_BASICDATATYPES_HPP
#define REHEX_BASICDATATYPES_HPP

#include <assert.h>
#include <exception>
#include <inttypes.h>
#include <stdint.h>
#include <wx/clipbrd.h>
#include <wx/dataobj.h>
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
			
			static const int MAX_INPUT_LEN = 20;               /* Wide enough for any decimal 64-bit value. */
			static const int TYPE_X_CHAR = MAX_INPUT_LEN + 2;  /**< X position to display type relative to left edge of data, in characters. */
			static const int TYPE_MAX_LEN = 5;                 /**< Maximum length of type_label. */
			
			int offset_text_x;  /**< Virtual X coord of left edge of offsets, in pixels. */
			int data_text_x;    /**< Virtual X coord of left edge of data, in pixels. */
			
			off_t input_off;        /**< Is the user typing a new value for this range in?
			                         *   Offset of value relative to d_offset when value is being
			                         *   modified, negative otherwise.
			                        */
			std::string input_buf;  /**< Input text buffer, empty when input_active is false. */
			size_t input_pos;       /**< Insert cursor position in input_buf, zero when input_active is false. */
			
			void activate(DocumentCtrl *doc_ctrl)
			{
				if(input_off >= 0)
				{
					/* Already active. */
					return;
				}
				
				assert(input_buf.empty());
				assert(input_pos == 0);
				
				off_t relative_pos = (doc_ctrl->get_cursor_position() - d_offset).byte();
				relative_pos = relative_pos - (relative_pos % sizeof(T));
				
				assert(relative_pos >= 0);
				assert(relative_pos <= (d_length.byte() - (off_t)(sizeof(T))));
				
				input_off = relative_pos;
			}
			
			void commit()
			{
				if(!write_string_value(input_buf, (d_offset + BitOffset(input_off))))
				{
					wxBell();
				}
				
				input_pos = 0;
				input_buf.clear();
				input_off = -1;
			}
			
		protected:
			NumericDataTypeRegion(SharedDocumentPointer &doc, BitOffset offset, BitOffset length, BitOffset virt_offset, const std::string &type_label):
				GenericDataRegion(offset, length, virt_offset, virt_offset),
				doc(doc),
				type_label(type_label),
				offset_text_x(-1),
				data_text_x(-1),
				input_off(-1),
				input_pos(0)
			{
				assert(length.byte_aligned() && (length.byte() % sizeof(T)) == 0);
			}
			
			virtual std::string to_string(const T *data) const = 0;
			virtual bool write_string_value(const std::string &value, BitOffset file_offset) = 0;
			
			virtual int calc_width(DocumentCtrl &doc_ctrl) override
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
			
			virtual void calc_height(DocumentCtrl &doc_ctrl) override
			{
				y_lines = indent_final + (d_length.byte() / sizeof(T));
			}
			
			virtual void draw(DocumentCtrl &doc_ctrl, wxDC &dc, int x, int64_t y) override
			{
				BitOffset cursor_pos = doc_ctrl.get_cursor_position();
				
				if(input_off >= 0)
				{
					/* Filthy hack - using the draw() function to detect the cursor
					 * moving off and comitting the in-progress edit.
					*/
					
					BitOffset io_base = d_offset + BitOffset(input_off, 0);
					BitOffset io_end = io_base + BitOffset(sizeof(T), 0);
					
					if(cursor_pos < io_base || cursor_pos >= io_end)
					{
						commit();
					}
				}
				
				/* If we are scrolled part-way into a data region, don't render data above the client area
	 			 * as it would get expensive very quickly with large files.
				*/
				int64_t skip_lines = (y < 0 ? (-y / doc_ctrl.hf_char_height()) : 0);
				off_t skip_bytes  = skip_lines * sizeof(T);
				
				y += doc_ctrl.hf_char_height() * skip_lines;
				
				/* The maximum amount of data that can be drawn on the screen before we're past the bottom
				 * of the client area. Drawing more than this would be pointless and very expensive in the
				 * case of large files.
				*/
				int max_lines = ((doc_ctrl.GetClientSize().GetHeight() - y) / doc_ctrl.hf_char_height()) + 1;
				off_t max_bytes = max_lines * sizeof(T);
				
				BitOffset data_pos = d_offset + BitOffset(skip_bytes, 0);
				BitOffset virt_pos = virt_offset + BitOffset(skip_bytes, 0);
				
				BitOffset data_end = std::min(
					(d_offset + d_length),
					(data_pos + BitOffset(max_bytes, 0)));
				
				std::vector<unsigned char> data;
				try {
					data = doc->read_data(data_pos, (data_end - data_pos).byte());
				}
				catch(const std::exception &e)
				{
					fprintf(stderr, "Exception in REHex::NumericDataTypeRegion::draw: %s\n", e.what());
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
				
				BitOffset total_selection_first, total_selection_last;
				std::tie(total_selection_first, total_selection_last) = doc_ctrl.get_selection_raw();
				
				BitOffset region_selection_offset, region_selection_length;
				std::tie(region_selection_offset, region_selection_length) = doc_ctrl.get_selection_in_region(this);
				BitOffset region_selection_end = region_selection_offset + region_selection_length;
				
				for(size_t buf_pos = 0; data_pos < data_end;)
				{
					if(doc_ctrl.get_show_offsets())
					{
						/* Draw the offsets to the left */
						
						std::string offset_str = format_offset(virt_pos, doc_ctrl.get_offset_display_base(), doc_ctrl.get_end_virt_offset());
						
						normal_text();
						dc.DrawText(offset_str, (x + offset_text_x), y);
						
						int offset_vl_x = x + data_text_x - (doc_ctrl.hf_char_width() / 2);
						
						wxPen norm_fg_1px((*active_palette)[Palette::PAL_NORMAL_TEXT_FG], 1);
						
						dc.SetPen(norm_fg_1px);
						dc.DrawLine(offset_vl_x, y, offset_vl_x, y + doc_ctrl.hf_char_height());
					}
					
					int data_x = x + data_text_x;
					
					std::string data_string = ((buf_pos + sizeof(T)) <= data.size())
						? to_string((const T*)(data.data() + buf_pos))
						: "????";
					
					if(input_off >= 0
						&& data_pos >= (d_offset + BitOffset(input_off, 0))
						&& data_pos < (d_offset + BitOffset((input_off + sizeof(T)), 0)))
					{
						normal_text();
						dc.DrawText("[" + input_buf + "]", data_x, y);
						
						if(doc_ctrl.get_cursor_visible())
						{
							int cursor_x = data_x + doc_ctrl.hf_string_width(1 + input_pos);
							dc.DrawLine(cursor_x, y, cursor_x, y + doc_ctrl.hf_char_height());
						}
					}
					else if(region_selection_length > BitOffset::ZERO
						&& ((region_selection_offset > data_pos && region_selection_offset < (data_pos + BitOffset(sizeof(T), 0)))
							|| (region_selection_end > data_pos && region_selection_end < (data_pos + BitOffset(sizeof(T), 0)))))
					{
						/* Selection encompasses *some* of our bytes and/or stretches
						* beyond either end. Render the underlying hex bytes.
						*/
						
						unsigned int bytes_per_group = doc_ctrl.get_bytes_per_group();
						unsigned int col = 0;
						
						for(size_t i = 0; i < sizeof(T); ++i)
						{
							if(i > 0 && (i % bytes_per_group) == 0)
							{
								++col;
							}
							
							const char *nibble_to_hex = ((buf_pos + i) >= data.size())
								? "????????????????"
								: "0123456789ABCDEF";
							
							const char hex_str[] = {
								nibble_to_hex[ (data[buf_pos + i] & 0xF0) >> 4 ],
								nibble_to_hex[ data[buf_pos + i] & 0x0F ],
								'\0'
							};
							
							if(region_selection_offset <= (data_pos + (off_t)(i)) && region_selection_end > (data_pos + (off_t)(i)))
							{
								selected_text();
							}
							else{
								normal_text();
							}
							
							dc.DrawText(hex_str, data_x + doc_ctrl.hf_string_width(col), y);
							col += 2;
						}
					}
					else if(cursor_pos >= data_pos && cursor_pos < (data_pos + BitOffset(sizeof(T), 0)) && doc_ctrl.get_cursor_visible())
					{
						/* Invert colour for cursor position/blink. */
						
						normal_text();
						dc.DrawText("[", data_x, y);
						
						inverted_text();
						dc.DrawText(data_string, (data_x + doc_ctrl.hf_char_width()), y);
						
						normal_text();
						dc.DrawText("]", (data_x + doc_ctrl.hf_string_width(data_string.length() + 1)), y);
					}
					else if(region_selection_length > BitOffset::ZERO
						&& region_selection_offset <= data_pos && region_selection_end >= (data_pos + BitOffset(sizeof(T), 0)))
					{
						/* Selection encompasses our range fully. Render value using selected
						* text colours.
						*/
						
						normal_text();
						dc.DrawText("[", data_x, y);
						
						selected_text();
						dc.DrawText(data_string, (data_x + doc_ctrl.hf_char_width()), y);
						
						normal_text();
						dc.DrawText("]", (data_x + doc_ctrl.hf_string_width(data_string.length() + 1)), y);
					}
					else{
						/* No data in our range is selected. Render normally. */
						
						normal_text();
						dc.DrawText("[" + data_string + "]", data_x, y);
					}
					
					int type_x = data_x + doc_ctrl.hf_string_width(TYPE_X_CHAR);
					
					std::string type_string = std::string("<") + type_label + ">";
					
					normal_text();
					dc.DrawText(type_string, type_x, y);
					
					data_pos += BitOffset(sizeof(T), 0);
					virt_pos += BitOffset(sizeof(T), 0);
					buf_pos  += sizeof(T);
					
					y += doc_ctrl.hf_char_height();
				}
			}
			
			virtual std::pair<BitOffset, ScreenArea> offset_at_xy(DocumentCtrl &doc_ctrl, int mouse_x_px, int64_t mouse_y_lines) override
			{
				BitOffset line_offset = d_offset + BitOffset((mouse_y_lines * sizeof(T)), 0);
				BitOffset line_end = line_offset + BitOffset(sizeof(T), 0);
				
				BitOffset total_selection_first, total_selection_last;
				std::tie(total_selection_first, total_selection_last) = doc_ctrl.get_selection_raw();
				
				BitOffset region_selection_offset, region_selection_length;
				std::tie(region_selection_offset, region_selection_length) = doc_ctrl.get_selection_in_region(this);
				BitOffset region_selection_end = region_selection_offset + region_selection_length;
				
				if(region_selection_length > BitOffset::ZERO
					&& ((region_selection_offset > line_offset && region_selection_offset < line_end)
						|| (region_selection_end > line_offset && region_selection_end < line_end)))
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
						BitOffset clicked_offset            = line_offset + BitOffset::BYTES(line_offset_bytes);
						
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
					
					std::vector<unsigned char> data;
					
					try {
						data = doc->read_data(line_offset, sizeof(T));
						assert(data.size() == sizeof(T));
					}
					catch(const std::exception &e)
					{
						fprintf(stderr, "Exception in REHex::NumericDataTypeRegion::offset_at_xy: %s\n", e.what());
						return std::make_pair<off_t, ScreenArea>(-1, SA_NONE);
					}
					
					std::string data_string = to_string((const T*)(data.data()));
					
					mouse_x_px -= data_text_x + doc_ctrl.hf_char_width() /* [ character */;
					unsigned int char_offset = doc_ctrl.hf_char_at_x(mouse_x_px);
					
					if(mouse_x_px >= 0 && char_offset < data_string.length())
					{
						/* Within screen area of data_string. */
						return std::make_pair(line_offset, SA_SPECIAL);
					}
					else{
						return std::make_pair(BitOffset::INVALID, SA_NONE);
					}
				}
			}
			
			virtual std::pair<BitOffset, ScreenArea> offset_near_xy(DocumentCtrl &doc_ctrl, int mouse_x_px, int64_t mouse_y_lines, ScreenArea type_hint) override
			{
				BitOffset line_offset = d_offset + BitOffset((mouse_y_lines * sizeof(T)), 0);
				return std::make_pair(line_offset, SA_SPECIAL);
			}
			
			virtual BitOffset cursor_left_from(BitOffset pos, ScreenArea active_type) override
			{
				assert(pos >= d_offset);
				assert(pos <= (d_offset + d_length));
				
				off_t relative_pos = (pos - d_offset).byte();
				relative_pos = relative_pos - (relative_pos % sizeof(T));
				
				off_t goto_pos = relative_pos - sizeof(T);
				
				if(goto_pos < 0)
				{
					return CURSOR_PREV_REGION;
				}
				else{
					return d_offset + BitOffset(goto_pos);
				}
			}
			
			virtual BitOffset cursor_right_from(BitOffset pos, ScreenArea active_type) override
			{
				assert(pos >= d_offset);
				assert(pos <= (d_offset + d_length));
				
				off_t relative_pos = (pos - d_offset).byte();
				relative_pos = relative_pos - (relative_pos % sizeof(T));
				
				off_t goto_pos = relative_pos + sizeof(T);
				
				if(goto_pos >= d_length.byte())
				{
					return CURSOR_NEXT_REGION;
				}
				else{
					return d_offset + BitOffset(goto_pos);
				}
			}
			
			virtual BitOffset cursor_up_from(BitOffset pos, ScreenArea active_type) override
			{
				return cursor_left_from(pos, active_type);
			}
			
			virtual BitOffset cursor_down_from(BitOffset pos, ScreenArea active_type) override
			{
				return cursor_right_from(pos, active_type);
			}
			
			virtual BitOffset cursor_home_from(BitOffset pos, ScreenArea active_type) override
			{
				assert(pos >= d_offset);
				assert(pos <= (d_offset + d_length));
				
				return d_offset;
			}
			
			virtual BitOffset cursor_end_from(BitOffset pos, ScreenArea active_type) override
			{
				assert(pos >= d_offset);
				assert(pos <= (d_offset + d_length));
				
				return d_offset;
			}
			
			virtual int cursor_column(BitOffset pos) override
			{
				assert(pos >= d_offset);
				assert(pos <= (d_offset + d_length));
				
				return 0;
			}
			
			virtual BitOffset first_row_nearest_column(int column) override
			{
				return d_offset;
			}
			
			virtual BitOffset last_row_nearest_column(int column) override
			{
				return d_offset + d_length - BitOffset(sizeof(T), 0);
			}
			
			virtual BitOffset nth_row_nearest_column(int64_t row, int column) override
			{
				return d_offset + (sizeof(T) * row);
			}
			
			DocumentCtrl::Rect calc_offset_bounds(BitOffset offset, DocumentCtrl *doc_ctrl) override
			{
				assert(offset >= d_offset);
				assert(offset <= (d_offset + d_length));
				
				off_t rel_offset = (offset - d_offset).byte();
				int64_t line_num = rel_offset / sizeof(T);
				
				BitOffset line_offset = d_offset + BitOffset((line_num * sizeof(T)), 0);
				BitOffset line_end = line_offset + BitOffset(sizeof(T), 0);
				
				BitOffset total_selection_first, total_selection_last;
				std::tie(total_selection_first, total_selection_last) = doc_ctrl->get_selection_raw();
				
				BitOffset region_selection_offset, region_selection_length;
				std::tie(region_selection_offset, region_selection_length) = doc_ctrl->get_selection_in_region(this);
				BitOffset region_selection_end = region_selection_offset + region_selection_length;
				
				if(region_selection_length > BitOffset::ZERO
					&& ((region_selection_offset > line_offset && region_selection_offset < line_end)
						|| (region_selection_end > line_offset && region_selection_end < line_end)))
				{
					/* Our data is partially selected. We are displaying hex bytes. */
					
					off_t offset_within_line = rel_offset % sizeof(T);
					
					unsigned int bytes_per_group = doc_ctrl->get_bytes_per_group();
					int line_x = data_text_x + doc_ctrl->hf_string_width((offset_within_line * 2) + (offset_within_line / bytes_per_group));
					
					return DocumentCtrl::Rect(
						line_x,                        /* x */
						(y_offset * line_num),         /* y */
						doc_ctrl->hf_string_width(2),  /* w */
						1);                            /* h */
				}
				else{
					/* We are displaying normally (i.e. the value in square brackets) */
					
					std::vector<unsigned char> data;
					
					return DocumentCtrl::Rect(
						data_text_x,                                   /* x */
						(y_offset + line_num),                         /* y */
						doc_ctrl->hf_string_width(MAX_INPUT_LEN + 2),  /* w */
						1);                                            /* h */
				}
			}
			
			virtual ScreenArea screen_areas_at_offset(BitOffset offset, DocumentCtrl *doc_ctrl) override
			{
				assert(offset >= d_offset);
				assert(offset <= (d_offset + d_length));
				
				return SA_HEX; /* We currently don't make use of the SA_SPECIAL
				                * screen area for our numeric values and
				                * selectively render them in the hex area instead.
				               */
			}
			
			virtual bool OnChar(DocumentCtrl *doc_ctrl, wxKeyEvent &event) override
			{
				int key = event.GetKeyCode();
				
				if((key >= '0' && key <= '9')
					|| (key >= 'a' && key <= 'z')
					|| (key >= 'A' && key <= 'Z')
					|| key == '.')
				{
					activate(doc_ctrl);
					
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
						activate(doc_ctrl);
						
						input_buf.insert(input_pos, 1, key);
						++input_pos;
						
						doc_ctrl->Refresh();
					}
					
					return true;
				}
				else if(key == WXK_DELETE)
				{
					activate(doc_ctrl);
					
					if(input_pos < input_buf.length())
					{
						input_buf.erase(input_pos, 1);
					}
					
					doc_ctrl->Refresh();
					
					return true;
				}
				else if(key == WXK_BACK) /* Backspace */
				{
					activate(doc_ctrl);
					
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
					
					std::vector<unsigned char> data;
					
					try {
						data = doc->read_data(d_offset, d_length.byte()); /* BITFIXUP */
						assert(data.size() == sizeof(T));
					}
					catch(const std::exception &e)
					{
						fprintf(stderr, "Exception in REHex::NumericDataTypeRegion::OnChar: %s\n", e.what());
						return true;
					}
					
					activate(doc_ctrl);
					
					input_buf = to_string((const T*)(data.data()));
					input_pos = input_buf.length();
					
					doc_ctrl->Refresh();
					
					return true;
				}
				else if(key == WXK_ESCAPE)
				{
					input_pos = 0;
					input_buf.clear();
					input_off = -1;
					
					doc_ctrl->Refresh();
					
					return true;
				}
				else if(key == WXK_RETURN)
				{
					if(input_off >= 0)
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
					if(input_off >= 0)
					{
						input_pos = 0;
						doc_ctrl->Refresh();
					}
					
					return true;
				}
				else if(key == WXK_END)
				{
					if(input_off >= 0)
					{
						input_pos = input_buf.length();
						doc_ctrl->Refresh();
					}
					
					return true;
				}
				
				return false;
			}
			
			virtual wxDataObject *OnCopy(DocumentCtrl &doc_ctrl) override
			{
				BitOffset selection_first, selection_last;
				std::tie(selection_first, selection_last) = doc_ctrl.get_selection_raw();
				
				assert(selection_first >= d_offset);
				assert(selection_last < (d_offset + d_length));
				
				if(selection_first == d_offset && selection_last == (d_offset + d_length - BitOffset::BITS(1))) /* BITFIXUP */
				{
					/* Selection matches our data range. Copy stringified
					 * numeric value to clipboard.
					*/
					
					std::vector<unsigned char> data;
					
					try {
						data = doc->read_data(d_offset, d_length.byte()); /* BITFIXUP */
						assert(data.size() == sizeof(T));
					}
					catch(const std::exception &e)
					{
						fprintf(stderr, "Exception in REHex::NumericDataTypeRegion::OnCopy: %s\n", e.what());
						return NULL;
					}
					
					std::string data_string = to_string((const T*)(data.data()));
					
					return new wxTextDataObject(data_string);
				}
				
				/* Fall back to default handling - copy selected bytes. */
				return NULL;
			}
			
			virtual bool OnPaste(DocumentCtrl *doc_ctrl) override
			{
				BitOffset selection_first, selection_last;
				std::tie(selection_first, selection_last) = doc_ctrl->get_selection_raw();
				
				if(doc_ctrl->has_selection() && (selection_first != d_offset || selection_last != (d_offset + d_length - BitOffset::BYTES(1)))) /* BITFIXUP */
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
					
					activate(doc_ctrl);
					
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
	};
	
	#define DECLARE_NDTR_CLASS(NAME, T) \
		class NAME: public NumericDataTypeRegion<T> \
		{ \
			public: \
				NAME(SharedDocumentPointer &doc, REHex::BitOffset offset, REHex::BitOffset length, REHex::BitOffset virt_offset); \
				\
			protected: \
				virtual std::string to_string(const T *data) const override; \
				virtual bool write_string_value(const std::string &value, BitOffset file_offset) override; \
		};
	
	DECLARE_NDTR_CLASS(U8DataRegion, uint8_t)
	DECLARE_NDTR_CLASS(S8DataRegion, int8_t)
	
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
	
	DECLARE_NDTR_CLASS(F32LEDataRegion, float);
	DECLARE_NDTR_CLASS(F32BEDataRegion, float);
	DECLARE_NDTR_CLASS(F64LEDataRegion, double);
	DECLARE_NDTR_CLASS(F64BEDataRegion, double);
}

#endif /* !REHEX_BASICDATATYPES_HPP */
