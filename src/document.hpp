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
			struct Region
			{
				uint64_t y_offset; /* First on-screen line in region */
				uint64_t y_lines;  /* Number of on-screen lines in region */
				
				virtual ~Region();
				
				/* Draw this region on the screen.
				 * 
				 * doc - The parent Document object
				 * dc  - The wxDC to draw in
				 * x,y - The top-left co-ordinates of this Region in the DC (MAY BE NEGATIVE)
				 *
				 * The implementation MAY skip rendering outside of the client area
				 * of the DC to improve performance.
				*/
				virtual void draw(REHex::Document &doc, wxDC &dc, int x, int y) = 0;
				
				struct Data;
				struct Comment;
			};
			
		public:
			friend Region::Data;
			struct Region::Data: public REHex::Document::Region
			{
				size_t d_offset;
				size_t d_length;
				
				Data(REHex::Document &doc, uint64_t y_offset, size_t d_offset, size_t d_length);
				
				virtual void draw(REHex::Document &doc, wxDC &dc, int x, int y);
			};
			
			friend Region::Comment;
			struct Region::Comment: public REHex::Document::Region
			{
				Comment(REHex::Document &doc, wxDC &dc, uint64_t y_offset);
				
				virtual void draw(REHex::Document &doc, wxDC &dc, int x, int y);
			};
			
		private:
			Buffer *buffer;
			
			std::list<Region*> regions;
			
			wxFont *hex_font;
			
			unsigned int line_bytes_cfg{0};
			unsigned int line_bytes_calc;
			unsigned int group_bytes{4};
			
			unsigned int scroll_xoff{0};
			uint64_t     scroll_yoff{0};
			
			size_t cpos_off{0};
			bool editing_byte{false};
			
			DECLARE_EVENT_TABLE()
			
			void _build_line_ranges(wxDC &dc);
			
			static std::list<std::string> _format_text(const std::string &text, unsigned int cols, unsigned int from_line = 0, unsigned int max_lines = -1);
	};
}

#endif /* !REHEX_DOCUMENT_HPP */
