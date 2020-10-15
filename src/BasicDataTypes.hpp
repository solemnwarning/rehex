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
			
			bool input_active;      /**< Is the user typing a new value for this range in? */
			std::string input_buf;  /**< Input text buffer, empty when input_active is false. */
			size_t input_pos;       /**< Insert cursor position in input_buf, zero when input_active is false. */
			
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
			
			bool partial_selection(off_t selection_off, off_t selection_length)
			{
				off_t selection_end = selection_off + selection_length;
				off_t d_end = d_offset + d_length;
				
				return selection_length > 0
					&& (selection_off != d_offset || selection_length != d_length)
					&& selection_off < d_end && d_offset < selection_end;
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
			
			virtual void calc_height(DocumentCtrl &doc_ctrl, wxDC &dc) override
			{
				y_lines = indent_final + 1;
			}
			
			virtual void draw(DocumentCtrl &doc_ctrl, wxDC &dc, int x, int64_t y) override
			{
				off_t cursor_pos = doc_ctrl.get_cursor_position();
				
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
					
					std::string offset_str = format_offset(d_offset, doc_ctrl.get_offset_display_base(), doc->buffer_length());
					
					normal_text();
					dc.DrawText(offset_str, x, y);
					
					x += (data_text_x - offset_text_x);
					
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
				else if(partial_selection(selection_off, selection_length))
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
				else if(cursor_pos >= d_offset && cursor_pos < (d_offset + d_length) && doc_ctrl.get_cursor_visible())
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
				
				x += doc_ctrl.hf_string_width(TYPE_X_CHAR);
				
				std::string type_string = std::string("<") + type_label + ">";
				
				normal_text();
				dc.DrawText(type_string, x, y);
			}
			
			virtual std::pair<off_t, ScreenArea> offset_at_xy(DocumentCtrl &doc_ctrl, int mouse_x_px, int64_t mouse_y_lines) override
			{
				off_t selection_off, selection_length;
				std::tie(selection_off, selection_length) = doc_ctrl.get_selection();
				
				if(partial_selection(selection_off, selection_length))
				{
					/* Our data is partially selected. We are displaying hex bytes. */
					
					if(mouse_x_px < data_text_x)
					{
						/* Click was left of data area. */
						return std::make_pair<off_t, ScreenArea>(-1, SA_NONE);
					}
					
					mouse_x_px -= data_text_x;
					
					unsigned int bytes_per_group = doc_ctrl.get_bytes_per_group();
					
					unsigned int char_offset = doc_ctrl.hf_char_at_x(mouse_x_px);
					if(((char_offset + 1) % ((bytes_per_group * 2) + 1)) == 0)
					{
						/* Click was over a space between byte groups. */
						return std::make_pair<off_t, ScreenArea>(-1, SA_NONE);
					}
					else{
						unsigned int char_offset_sub_spaces = char_offset - (char_offset / ((bytes_per_group * 2) + 1));
						unsigned int line_offset_bytes      = char_offset_sub_spaces / 2;
						off_t clicked_offset                = d_offset + line_offset_bytes;
						
						if(clicked_offset < (d_offset + d_length))
						{
							/* Clicked on a byte */
							return std::make_pair(clicked_offset, SA_HEX);
						}
						else{
							/* Clicked past the end of the line */
							return std::make_pair<off_t, ScreenArea>(-1, SA_NONE);
						}
					}
				}
				else{
					/* We are displaying normally (i.e. the value in square brackets) */
					
					std::vector<unsigned char> data;
					
					try {
						data = doc->read_data(d_offset, d_length);
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
						return std::make_pair(d_offset, SA_SPECIAL);
					}
					else{
						return std::make_pair<off_t, ScreenArea>(-1, SA_NONE);
					}
				}
			}
			
			virtual std::pair<off_t, ScreenArea> offset_near_xy(DocumentCtrl &doc_ctrl, int mouse_x_px, int64_t mouse_y_lines, ScreenArea type_hint) override
			{
				mouse_x_px -= data_text_x + doc_ctrl.hf_char_width() /* [ character */;
				mouse_x_px = std::max(mouse_x_px, 0);
				
				off_t mouse_x_bytes = std::min(
					(d_offset + (mouse_x_px / doc_ctrl.hf_string_width(2))),
					(d_offset + d_length - 1));
				
				return std::make_pair(mouse_x_bytes, SA_SPECIAL);
			}
			
			virtual off_t cursor_left_from(off_t pos) override
			{
				assert(pos >= d_offset);
				assert(pos <= (d_offset + d_length));
				
				return CURSOR_PREV_REGION;
			}
			
			virtual off_t cursor_right_from(off_t pos) override
			{
				assert(pos >= d_offset);
				assert(pos <= (d_offset + d_length));
				
				return CURSOR_NEXT_REGION;
			}
			
			virtual off_t cursor_up_from(off_t pos) override
			{
				assert(pos >= d_offset);
				assert(pos <= (d_offset + d_length));
				
				return CURSOR_PREV_REGION;
			}
			
			virtual off_t cursor_down_from(off_t pos) override
			{
				assert(pos >= d_offset);
				assert(pos <= (d_offset + d_length));
				
				return CURSOR_NEXT_REGION;
			}
			
			virtual off_t cursor_home_from(off_t pos) override
			{
				assert(pos >= d_offset);
				assert(pos <= (d_offset + d_length));
				
				return d_offset;
			}
			
			virtual off_t cursor_end_from(off_t pos) override
			{
				assert(pos >= d_offset);
				assert(pos <= (d_offset + d_length));
				
				return d_offset;
			}
			
			virtual int cursor_column(off_t pos) override
			{
				assert(pos >= d_offset);
				assert(pos <= (d_offset + d_length));
				
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
			
			virtual off_t nth_row_nearest_column(int64_t row, int column) override
			{
				return d_offset;
			}
			
			DocumentCtrl::Rect calc_offset_bounds(off_t offset, DocumentCtrl *doc_ctrl) override
			{
				assert(offset >= d_offset);
				assert(offset <= (d_offset + d_length));
				
				off_t selection_off, selection_length;
				std::tie(selection_off, selection_length) = doc_ctrl->get_selection();
				
				if(partial_selection(selection_off, selection_length))
				{
					/* Our data is partially selected. We are displaying hex bytes. */
					
					off_t rel_offset = offset - d_offset;
					
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
			
			virtual bool OnChar(DocumentCtrl *doc_ctrl, wxKeyEvent &event) override
			{
				int key = event.GetKeyCode();
				
				if((key >= '0' && key <= '9')
					|| (key >= 'a' && key <= 'z')
					|| (key >= 'A' && key <= 'Z'))
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
					
					std::vector<unsigned char> data;
					
					try {
						data = doc->read_data(d_offset, d_length);
						assert(data.size() == sizeof(T));
					}
					catch(const std::exception &e)
					{
						fprintf(stderr, "Exception in REHex::NumericDataTypeRegion::OnChar: %s\n", e.what());
						return true;
					}
					
					activate();
					
					input_buf = to_string((const T*)(data.data()));
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
			
			virtual wxDataObject *OnCopy(DocumentCtrl &doc_ctrl) override
			{
				off_t selection_off, selection_length;
				std::tie(selection_off, selection_length) = doc_ctrl.get_selection();
				
				assert(selection_off >= d_offset);
				assert((selection_off + selection_length) <= (d_offset + d_length));
				
				if(selection_off == d_offset && selection_length == d_length)
				{
					/* Selection matches our data range. Copy stringified
					 * numeric value to clipboard.
					*/
					
					std::vector<unsigned char> data;
					
					try {
						data = doc->read_data(d_offset, d_length);
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
			
			virtual bool OnPaste(DocumentCtrl *doc_ctrl)
			{
				off_t selection_off, selection_length;
				std::tie(selection_off, selection_length) = doc_ctrl->get_selection();
				
				if(selection_length > 0 && (selection_off != d_offset || selection_length != d_length))
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
