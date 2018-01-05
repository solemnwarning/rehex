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
			Document(wxWindow *parent);
			Document(wxWindow *parent, const std::string &filename);
			~Document();
			
			void save();
			void save(const std::string &filename);
			
			std::string get_title();
			
			unsigned int get_bytes_per_line();
			void set_bytes_per_line(unsigned int bytes_per_line);
			
			unsigned int get_bytes_per_group();
			void set_bytes_per_group(unsigned int bytes_per_group);
			
			bool get_show_offsets();
			void set_show_offsets(bool show_offsets);
			
			bool get_show_ascii();
			void set_show_ascii(bool show_ascii);
			
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
			
			friend Region::Data;
			friend Region::Comment;
			
			Buffer *buffer;
			std::string title;
			
			std::list<Region*> regions;
			size_t data_regions_count;
			
			/* Fixed-width font used for drawing hex data. */
			wxFont *hex_font;
			
			/* Size of a character in hex_font. */
			unsigned char hf_width;
			unsigned char hf_height;
			
			/* Size of the client area in pixels. */
			unsigned int client_width;
			unsigned int client_height;
			
			/* Height of client area in lines. */
			unsigned int visible_lines;
			
			/* Width of the scrollable area. */
			unsigned int virtual_width;
			
			/* Display options */
			unsigned int bytes_per_line;
			unsigned int bytes_per_group;
			
			/* bytes_per_line, after adjusting for auto option. */
			unsigned int bytes_per_line_calc;
			
			bool offset_column{true};
			unsigned int offset_column_width;
			
			bool ascii_view{true};
			
			unsigned int scroll_xoff{0};
			uint64_t     scroll_yoff{0};
			
			off_t cpos_off{0};
			bool editing_byte{false};
			bool insert_mode{false};
			
			void _ctor_pre();
			void _ctor_post();
			
			void _init_regions();
			void _recalc_regions(wxDC &dc);
			
			void _overwrite_data(wxDC &dc, off_t offset, const unsigned char *data, off_t length);
			void _insert_data(wxDC &dc, off_t offset, const unsigned char *data, off_t length);
			void _erase_data(wxDC &dc, off_t offset, off_t length);
			
			std::string _get_comment_text(off_t offset);
			void _set_comment_text(wxDC &dc, off_t offset, const std::string &text);
			void _delete_comment(wxDC &dc, off_t offset);
			
			REHex::Document::Region::Data *_data_region_by_offset(off_t offset);
			
			void _make_line_visible(uint64_t line);
			void _make_x_visible(unsigned int x_px, unsigned int width_px);
			
			void _make_byte_visible(off_t offset);
			
			static std::list<std::string> _format_text(const std::string &text, unsigned int cols, unsigned int from_line = 0, unsigned int max_lines = -1);
			
			/* Stays at the bottom because it changes the protection... */
			DECLARE_EVENT_TABLE()
	};
	
	struct Document::Region::Data: public REHex::Document::Region
	{
		off_t d_offset;
		off_t d_length;
		
		Data(off_t d_offset, off_t d_length);
		
		virtual void update_lines(REHex::Document &doc, wxDC &dc);
		virtual void draw(REHex::Document &doc, wxDC &dc, int x, int64_t y);
	};
	
	struct Document::Region::Comment: public REHex::Document::Region
	{
		off_t c_offset;
		std::string c_text;
		
		Comment(off_t c_offset, const std::string &c_text);
		
		virtual void update_lines(REHex::Document &doc, wxDC &dc);
		virtual void draw(REHex::Document &doc, wxDC &dc, int x, int64_t y);
	};
}

#endif /* !REHEX_DOCUMENT_HPP */
