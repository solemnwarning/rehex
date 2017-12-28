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
			
		#ifndef UNIT_TEST
		private:
		#endif
			struct Region
			{
				uint64_t y_offset; /* First on-screen line in region */
				uint64_t y_lines;  /* Number of on-screen lines in region */
				
				virtual ~Region();
				
				virtual void update_lines(REHex::Document &doc, wxDC &dc) = 0;
				
				/* Draw this region on the screen.
				 * 
				 * doc - The parent Document object
				 * dc  - The wxDC to draw in
				 * x,y - The top-left co-ordinates of this Region in the DC (MAY BE NEGATIVE)
				 *
				 * The implementation MAY skip rendering outside of the client area
				 * of the DC to improve performance.
				*/
				virtual void draw(REHex::Document &doc, wxDC &dc, int x, int64_t y) = 0;
				
				struct Data;
				struct Comment;
			};
			
		public:
			friend Region::Data;
			struct Region::Data: public REHex::Document::Region
			{
				size_t d_offset;
				size_t d_length;
				
				Data(size_t d_offset, size_t d_length);
				
				virtual void update_lines(REHex::Document &doc, wxDC &dc);
				virtual void draw(REHex::Document &doc, wxDC &dc, int x, int64_t y);
			};
			
			friend Region::Comment;
			struct Region::Comment: public REHex::Document::Region
			{
				size_t d_offset;
				std::string text;
				
				Comment(size_t d_offset, const std::string &text);
				
				virtual void update_lines(REHex::Document &doc, wxDC &dc);
				virtual void draw(REHex::Document &doc, wxDC &dc, int x, int64_t y);
			};
			
		#ifndef UNIT_TEST
		private:
		#endif
			Buffer *buffer;
			
			std::list<Region*> regions;
			size_t data_regions_count;
			
			wxFont *hex_font;
			
			unsigned int line_bytes_cfg{0};
			unsigned int line_bytes_calc;
			unsigned int group_bytes{4};
			
			unsigned int scroll_xoff{0};
			uint64_t     scroll_yoff{0};
			
			size_t cpos_off{0};
			bool editing_byte{false};
			bool insert_mode{false};
			
			void _init_regions();
			void _recalc_regions(wxDC &dc);
			
			void _overwrite_data(wxDC &dc, size_t offset, const unsigned char *data, size_t length);
			void _insert_data(wxDC &dc, size_t offset, const unsigned char *data, size_t length);
			void _erase_data(wxDC &dc, size_t offset, size_t length);
			
			std::string _get_comment_text(size_t offset);
			void _set_comment_text(wxDC &dc, size_t offset, const std::string &text);
			void _delete_comment(wxDC &dc, size_t offset);
			
			static std::list<std::string> _format_text(const std::string &text, unsigned int cols, unsigned int from_line = 0, unsigned int max_lines = -1);
			
			/* Stays at the bottom because it changes the protection... */
			DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_DOCUMENT_HPP */
