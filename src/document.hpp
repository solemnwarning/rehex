/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_DOCUMENT_HPP
#define REHEX_DOCUMENT_HPP

#include <list>
#include <stdint.h>
#include <wx/wx.h>

#include "buffer.hpp"

namespace REHex {
	class Document: public wxControl {
		public:
			Document(wxWindow *parent, wxWindowID id, REHex::Buffer *buffer);
			
			void OnPaint(wxPaintEvent &event);
			void OnSize(wxSizeEvent &event);
			void OnScroll(wxScrollWinEvent &event);
			void OnChar(wxKeyEvent &event);
			void OnLeftDown(wxMouseEvent &event);
			
		private:
			struct LineRange {
				uint64_t start; /* First line in range */
				uint64_t lines; /* Number of lines in range */
				
				enum {
					LR_DATA,
					LR_COMMENT,
				} type;
				
				union {
					struct {
						size_t offset;
						size_t length;
					} data;
					
					struct {
						
					} comment;
				};
			};
			
			Buffer *buffer;
			
			std::list<LineRange> lineranges;
			
			wxFont *hex_font;
			
			unsigned int line_bytes_cfg{0};
			unsigned int line_bytes_calc;
			unsigned int group_bytes{4};
			
			unsigned int scroll_xoff{0};
			uint64_t     scroll_yoff{0};
			
			size_t cpos_off{0};
			bool editing_byte{false};
			
			DECLARE_EVENT_TABLE()
			
			void _build_line_ranges(unsigned int cols);
			
			static std::list<std::string> _format_text(const std::string &text, unsigned int cols, unsigned int from_line = 0, unsigned int max_lines = -1);
	};
}

#endif /* !REHEX_DOCUMENT_HPP */
