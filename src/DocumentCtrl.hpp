/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2020 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_DOCUMENTCTRL_HPP
#define REHEX_DOCUMENTCTRL_HPP

#include <functional>
#include <jansson.h>
#include <list>
#include <memory>
#include <stdint.h>
#include <utility>
#include <wx/dataobj.h>
#include <wx/wx.h>

#include "buffer.hpp"
#include "document.hpp"
#include "NestedOffsetLengthMap.hpp"
#include "Palette.hpp"
#include "util.hpp"

namespace REHex {
	class DocumentCtrl: public wxControl {
		public:
			struct Highlight
			{
				bool enable;
				
				Palette::ColourIndex fg_colour_idx;
				Palette::ColourIndex bg_colour_idx;
				bool strong;
			};
			
			class Region
			{
				public:
				
				int64_t y_offset; /* First on-screen line in region */
				int64_t y_lines;  /* Number of on-screen lines in region */
				
				int indent_depth;  /* Indentation depth */
				int indent_final;  /* Number of inner indentation levels we are the final region in */
				
				Region();
				
				virtual ~Region();
				
				virtual void update_lines(REHex::DocumentCtrl &doc, wxDC &dc) = 0;
				
				/* Draw this region on the screen.
				 * 
				 * doc - The parent Document object
				 * dc  - The wxDC to draw in
				 * x,y - The top-left co-ordinates of this Region in the DC (MAY BE NEGATIVE)
				 *
				 * The implementation MAY skip rendering outside of the client area
				 * of the DC to improve performance.
				*/
				virtual void draw(REHex::DocumentCtrl &doc, wxDC &dc, int x, int64_t y) = 0;
				
				virtual wxCursor cursor_for_point(REHex::DocumentCtrl &doc, int x, int64_t y_lines, int y_px);
				
				void draw_container(REHex::DocumentCtrl &doc, wxDC &dc, int x, int64_t y);
				
				friend DocumentCtrl;
			};
			
			class DataRegion: public Region
			{
				public:
				
				off_t d_offset;
				off_t d_length;
				
				int offset_text_x;  /* Virtual X coord of left edge of offsets. */
				int hex_text_x;     /* Virtual X coord of left edge of hex data. */
				int ascii_text_x;   /* Virtual X coord of left edge of ASCII data. */
				
				unsigned int bytes_per_line_actual;  /* Number of bytes being displayed per line. */
				
				NestedOffsetLengthMap<Highlight> highlights;
				
				virtual void update_lines(REHex::DocumentCtrl &doc, wxDC &dc) override;
				virtual void draw(REHex::DocumentCtrl &doc, wxDC &dc, int x, int64_t y) override;
				virtual wxCursor cursor_for_point(REHex::DocumentCtrl &doc, int x, int64_t y_lines, int y_px) override;
				
				off_t offset_at_xy_hex  (REHex::DocumentCtrl &doc, int mouse_x_px, uint64_t mouse_y_lines);
				off_t offset_at_xy_ascii(REHex::DocumentCtrl &doc, int mouse_x_px, uint64_t mouse_y_lines);
				
				off_t offset_near_xy_hex  (REHex::DocumentCtrl &doc, int mouse_x_px, uint64_t mouse_y_lines);
				off_t offset_near_xy_ascii(REHex::DocumentCtrl &doc, int mouse_x_px, uint64_t mouse_y_lines);
				
				virtual Highlight highlight_at_off(off_t off) const
				{
					// TODO
					Highlight h;
					h.enable = false;
					
					return h;
				}
				
				DataRegion(off_t d_offset, off_t d_length, int i_depth = 0);
				
				friend DocumentCtrl;
			};
			
			class CommentRegion: public Region
			{
				public:
				
				off_t c_offset, c_length;
				const wxString &c_text;
				
				Region *final_descendant;
				
				virtual void update_lines(REHex::DocumentCtrl &doc, wxDC &dc) override;
				virtual void draw(REHex::DocumentCtrl &doc, wxDC &dc, int x, int64_t y) override;
				virtual wxCursor cursor_for_point(REHex::DocumentCtrl &doc, int x, int64_t y_lines, int y_px) override;
				
				CommentRegion(off_t c_offset, off_t c_length, const wxString &c_text, int i_depth);
				
				friend DocumentCtrl;
			};
			
			enum InlineCommentMode {
				ICM_HIDDEN       = 0,
				ICM_FULL         = 1,
				ICM_SHORT        = 2,
				ICM_FULL_INDENT  = 3,
				ICM_SHORT_INDENT = 4,
				ICM_MAX          = 4,
			};
			
			DocumentCtrl(wxWindow *parent, REHex::Document *doc);
			~DocumentCtrl();
			
			unsigned int get_bytes_per_line();
			void set_bytes_per_line(unsigned int bytes_per_line);
			
			unsigned int get_bytes_per_group();
			void set_bytes_per_group(unsigned int bytes_per_group);
			
			bool get_show_offsets();
			void set_show_offsets(bool show_offsets);
			
			OffsetBase get_offset_display_base() const;
			void set_offset_display_base(OffsetBase offset_display_base);
			
			bool get_show_ascii();
			void set_show_ascii(bool show_ascii);
			
			off_t get_cursor_position() const;
			void set_cursor_position(off_t off);
			bool get_insert_mode();
			void set_insert_mode(bool enabled);
			
			void set_selection(off_t off, off_t length);
			void clear_selection();
			std::pair<off_t, off_t> get_selection();
			
			const std::list<Region*> &get_regions() const;
			
			void append_region(Region *region);
			void insert_region(Region *region, std::list<Region*>::const_iterator before_this);
			void erase_region(std::list<Region*>::const_iterator i);
			void replace_region(Region *region, std::list<Region*>::const_iterator replace_this);
			
			void OnPaint(wxPaintEvent &event);
			void OnSize(wxSizeEvent &event);
			void OnScroll(wxScrollWinEvent &event);
			void OnWheel(wxMouseEvent &event);
			void OnChar(wxKeyEvent &event);
			void OnLeftDown(wxMouseEvent &event);
			void OnLeftUp(wxMouseEvent &event);
			void OnRightDown(wxMouseEvent &event);
			void OnMotion(wxMouseEvent &event);
			void OnSelectTick(wxTimerEvent &event);
			void OnMotionTick(int mouse_x, int mouse_y);
			void OnRedrawCursor(wxTimerEvent &event);
			void OnClearHighlight(wxCommandEvent &event);
			
		#ifndef UNIT_TEST
		private:
		#endif
			enum CursorState {
				CSTATE_HEX,
				CSTATE_HEX_MID,
				CSTATE_ASCII,
				
				/* Only valid as parameter to _set_cursor_position(), will go
				 * CSTATE_HEX if in CSTATE_HEX_MID, else will use current state.
				*/
				CSTATE_GOTO,
			};
			
			friend DataRegion;
			friend CommentRegion;
			
			REHex::Document *doc;
			
			std::list<Region*> regions;
			
			/* Fixed-width font used for drawing hex data. */
			wxFont *hex_font;
			
			/* Size of a character in hex_font. */
			unsigned char hf_height;
			
			/* Size of the client area in pixels. */
			int client_width;
			int client_height;
			
			/* Height of client area in lines. */
			unsigned int visible_lines;
			
			/* Width of the scrollable area. */
			int virtual_width;
			
			/* Display options */
			unsigned int bytes_per_line;
			unsigned int bytes_per_group;
			
			bool offset_column{true};
			int offset_column_width;
			OffsetBase offset_display_base;
			
			bool show_ascii;
			
			InlineCommentMode inline_comment_mode;
			
			bool highlight_selection_match;
			
			int     scroll_xoff;
			int64_t scroll_yoff;
			int64_t scroll_yoff_max;
			int64_t scroll_ydiv;
			
			int wheel_vert_accum;
			int wheel_horiz_accum;
			
			off_t cpos_off{0};
			bool insert_mode{false};
			
			off_t selection_off;
			off_t selection_length;
			
			bool cursor_visible;
			wxTimer redraw_cursor_timer;
			
			static const int MOUSE_SELECT_INTERVAL = 100;
			
			bool mouse_down_in_hex, mouse_down_in_ascii;
			off_t mouse_down_at_offset;
			int mouse_down_at_x;
			wxTimer mouse_select_timer;
			off_t mouse_shift_initial;
			
			enum CursorState cursor_state;
			
			void _reinit_regions();
			void _recalc_regions(wxDC &dc);
			
			void _set_cursor_position(off_t position, enum CursorState cursor_state);
			
			REHex::DocumentCtrl::DataRegion *_data_region_by_offset(off_t offset);
			
			void _make_line_visible(int64_t line);
			void _make_x_visible(int x_px, int width_px);
			
			void _make_byte_visible(off_t offset);
			
			void _handle_width_change();
			void _handle_height_change();
			void _update_vscroll();
			void _update_vscroll_pos();
			
			static std::list<wxString> _format_text(const wxString &text, unsigned int cols, unsigned int from_line = 0, unsigned int max_lines = -1);
			int _indent_width(int depth);
			
			static const int PRECOMP_HF_STRING_WIDTH_TO = 512;
			unsigned int hf_string_width_precomp[PRECOMP_HF_STRING_WIDTH_TO];
			
			int hf_char_width();
			int hf_string_width(int length);
			int hf_char_at_x(int x_px);
			
			/* Stays at the bottom because it changes the protection... */
			DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_DOCUMENTCTRL_HPP */
