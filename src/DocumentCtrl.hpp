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
#include "SharedDocumentPointer.hpp"
#include "util.hpp"

namespace REHex {
	class DocumentCtrl: public wxControl {
		public:
			class Region
			{
				protected:
					int64_t y_offset; /* First on-screen line in region */
					int64_t y_lines;  /* Number of on-screen lines in region */
					
					off_t indent_offset;
					off_t indent_length;
					
					int indent_depth;  /* Indentation depth */
					int indent_final;  /* Number of inner indentation levels we are the final region in */
					
				public:
					Region();
					virtual ~Region();
					
				protected:
					virtual int calc_width(REHex::DocumentCtrl &doc);
					virtual void calc_height(REHex::DocumentCtrl &doc, wxDC &dc) = 0;
					
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
					struct Highlight
					{
						public:
							const bool enable;
							
							const Palette::ColourIndex fg_colour_idx;
							const Palette::ColourIndex bg_colour_idx;
							const bool strong;
							
							Highlight(Palette::ColourIndex fg_colour_idx, Palette::ColourIndex bg_colour_idx, bool strong):
								enable(true),
								fg_colour_idx(fg_colour_idx),
								bg_colour_idx(bg_colour_idx),
								strong(strong) {}
						
						protected:
							Highlight():
								enable(false),
								fg_colour_idx(Palette::PAL_INVALID),
								bg_colour_idx(Palette::PAL_INVALID),
								strong(false) {}
					};
					
					struct NoHighlight: Highlight
					{
						NoHighlight(): Highlight() {}
					};
					
				protected:
					off_t d_offset;
					off_t d_length;
					
					int offset_text_x;  /* Virtual X coord of left edge of offsets. */
					int hex_text_x;     /* Virtual X coord of left edge of hex data. */
					int ascii_text_x;   /* Virtual X coord of left edge of ASCII data. */
					
					unsigned int bytes_per_line_actual;  /* Number of bytes being displayed per line. */
					
				public:
					DataRegion(off_t d_offset, off_t d_length);
					
					int calc_width_for_bytes(DocumentCtrl &doc_ctrl, unsigned int line_bytes) const;
					
				protected:
					virtual int calc_width(REHex::DocumentCtrl &doc) override;
					virtual void calc_height(REHex::DocumentCtrl &doc, wxDC &dc) override;
					virtual void draw(REHex::DocumentCtrl &doc, wxDC &dc, int x, int64_t y) override;
					virtual wxCursor cursor_for_point(REHex::DocumentCtrl &doc, int x, int64_t y_lines, int y_px) override;
					
					off_t offset_at_xy_hex  (REHex::DocumentCtrl &doc, int mouse_x_px, uint64_t mouse_y_lines);
					off_t offset_at_xy_ascii(REHex::DocumentCtrl &doc, int mouse_x_px, uint64_t mouse_y_lines);
					
					off_t offset_near_xy_hex  (REHex::DocumentCtrl &doc, int mouse_x_px, uint64_t mouse_y_lines);
					off_t offset_near_xy_ascii(REHex::DocumentCtrl &doc, int mouse_x_px, uint64_t mouse_y_lines);
					
					virtual Highlight highlight_at_off(off_t off) const;
					
				friend DocumentCtrl;
			};
			
			class DataRegionDocHighlight: public DataRegion
			{
				private:
					Document &doc;
					
				public:
					DataRegionDocHighlight(off_t d_offset, off_t d_length, Document &doc);
					
				protected:
					virtual Highlight highlight_at_off(off_t off) const override;
			};
			
			class CommentRegion: public Region
			{
				public:
				
				off_t c_offset, c_length;
				const wxString &c_text;
				
				bool truncate;
				
				virtual void calc_height(REHex::DocumentCtrl &doc, wxDC &dc) override;
				virtual void draw(REHex::DocumentCtrl &doc, wxDC &dc, int x, int64_t y) override;
				virtual wxCursor cursor_for_point(REHex::DocumentCtrl &doc, int x, int64_t y_lines, int y_px) override;
				
				CommentRegion(off_t c_offset, off_t c_length, const wxString &c_text, bool nest_children, bool truncate);
				
				friend DocumentCtrl;
			};
			
			DocumentCtrl(wxWindow *parent, SharedDocumentPointer &doc);
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
			
			bool get_highlight_selection_match();
			void set_highlight_selection_match(bool highlight_selection_match);
			
			off_t get_cursor_position() const;
			Document::CursorState get_cursor_state() const;
			
			void set_cursor_position(off_t position, Document::CursorState cursor_state = Document::CSTATE_GOTO);
			
			bool get_insert_mode();
			void set_insert_mode(bool enabled);
			
			void linked_scroll_insert_self_after(DocumentCtrl *p);
			void linked_scroll_remove_self();
			
			void set_selection(off_t off, off_t length);
			void clear_selection();
			std::pair<off_t, off_t> get_selection();
			
			const std::list<Region*> &get_regions() const;
			void replace_all_regions(std::list<Region*> &new_regions);
			
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
			friend DataRegion;
			friend CommentRegion;
			
			SharedDocumentPointer doc;
			
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
			
			bool highlight_selection_match;
			
			int     scroll_xoff;
			int64_t scroll_yoff;
			int64_t scroll_yoff_max;
			int64_t scroll_ydiv;
			
			DocumentCtrl *linked_scroll_prev;
			DocumentCtrl *linked_scroll_next;
			
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
			
			Document::CursorState cursor_state;
			
			void _set_cursor_position(off_t position, Document::CursorState cursor_state);
			
			DataRegion *_data_region_by_offset(off_t offset);
			DataRegion *_prev_data_region(DataRegion *dr);
			DataRegion *_next_data_region(DataRegion *dr);
			
			void _make_line_visible(int64_t line);
			void _make_x_visible(int x_px, int width_px);
			
			void _make_byte_visible(off_t offset);
			
			void _handle_width_change();
			void _handle_height_change();
			void _update_vscroll();
			void _update_vscroll_pos(bool update_linked_scroll_others = true);
			
			void linked_scroll_visit_others(const std::function<void(DocumentCtrl*)> &func);
			
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
