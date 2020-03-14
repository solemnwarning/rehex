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

#ifndef REHEX_DOCUMENT_HPP
#define REHEX_DOCUMENT_HPP

#include <functional>
#include <jansson.h>
#include <list>
#include <memory>
#include <stdint.h>
#include <utility>
#include <wx/dataobj.h>
#include <wx/wx.h>

#include "buffer.hpp"
#include "NestedOffsetLengthMap.hpp"

namespace REHex {
	wxDECLARE_EVENT(EV_CURSOR_MOVED,      wxCommandEvent);
	wxDECLARE_EVENT(EV_INSERT_TOGGLED,    wxCommandEvent);
	wxDECLARE_EVENT(EV_SELECTION_CHANGED, wxCommandEvent);
	wxDECLARE_EVENT(EV_COMMENT_MODIFIED,  wxCommandEvent);
	wxDECLARE_EVENT(EV_DATA_MODIFIED,     wxCommandEvent);
	wxDECLARE_EVENT(EV_UNDO_UPDATE,       wxCommandEvent);
	wxDECLARE_EVENT(EV_BECAME_CLEAN,      wxCommandEvent);
	wxDECLARE_EVENT(EV_BECAME_DIRTY,      wxCommandEvent);
	
	class Document: public wxControl {
		public:
			struct Comment
			{
				/* We use a shared_ptr here so that unmodified comment text isn't
				 * duplicated throughout undo_stack and redo_stack. This might be
				 * made obsolete in the future if we apply a similar technique to
				 * the comments/highlights copies as a whole.
				 *
				 * wxString is used rather than std::string as it is unicode-aware
				 * and will keep everything in order in memory and on-screen.
				*/
				
				std::shared_ptr<const wxString> text;
				
				Comment(const wxString &text);
				
				bool operator==(const Comment &rhs) const
				{
					return *text == *(rhs.text);
				}
				
				wxString menu_preview() const;
			};
			
			enum InlineCommentMode {
				ICM_HIDDEN       = 0,
				ICM_FULL         = 1,
				ICM_SHORT        = 2,
				ICM_FULL_INDENT  = 3,
				ICM_SHORT_INDENT = 4,
				ICM_MAX          = 4,
			};
			
			Document(wxWindow *parent);
			Document(wxWindow *parent, const std::string &filename);
			~Document();
			
			void save();
			void save(const std::string &filename);
			
			std::string get_title();
			std::string get_filename();
			bool is_dirty();
			
			unsigned int get_bytes_per_line();
			void set_bytes_per_line(unsigned int bytes_per_line);
			
			unsigned int get_bytes_per_group();
			void set_bytes_per_group(unsigned int bytes_per_group);
			
			bool get_show_offsets();
			void set_show_offsets(bool show_offsets);
			
			bool get_show_ascii();
			void set_show_ascii(bool show_ascii);
			
			InlineCommentMode get_inline_comment_mode();
			void set_inline_comment_mode(InlineCommentMode mode);
			
			bool get_highlight_selection_match();
			void set_highlight_selection_match(bool highlight_selection_match);
			
			off_t get_cursor_position() const;
			void set_cursor_position(off_t off);
			bool get_insert_mode();
			void set_insert_mode(bool enabled);
			
			void set_selection(off_t off, off_t length);
			void clear_selection();
			std::pair<off_t, off_t> get_selection();
			
			std::vector<unsigned char> read_data(off_t offset, off_t max_length) const;
			void overwrite_data(off_t offset, const void *data, off_t length);
			void insert_data(off_t offset, const unsigned char *data, off_t length);
			void erase_data(off_t offset, off_t length);
			off_t buffer_length();
			
			const NestedOffsetLengthMap<Comment> &get_comments() const;
			bool set_comment(off_t offset, off_t length, const Comment &comment);
			bool erase_comment(off_t offset, off_t length);
			void edit_comment_popup(off_t offset, off_t length);
			
			void handle_paste(const std::string &clipboard_text);
			std::string handle_copy(bool cut);
			size_t copy_upper_limit();
			
			void handle_paste(const NestedOffsetLengthMap<Document::Comment> &clipboard_comments);
			
			void undo();
			const char *undo_desc();
			void redo();
			const char *redo_desc();
			
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
			
			struct Region
			{
				int64_t y_offset; /* First on-screen line in region */
				int64_t y_lines;  /* Number of on-screen lines in region */
				
				int indent_depth;  /* Indentation depth */
				int indent_final;  /* Number of inner indentation levels we are the final region in */
				
				Region();
				
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
				
				virtual wxCursor cursor_for_point(REHex::Document &doc, int x, int64_t y_lines, int y_px);
				
				void draw_container(REHex::Document &doc, wxDC &dc, int x, int64_t y);
				
				struct Data;
				struct Comment;
			};
			
			struct TrackedChange
			{
				const char *desc;
				
				std::function< void() > undo;
				std::function< void() > redo;
				
				off_t       old_cpos_off;
				CursorState old_cursor_state;
				NestedOffsetLengthMap<Comment> old_comments;
				NestedOffsetLengthMap<int> old_highlights;
			};
			
			friend Region::Data;
			friend Region::Comment;
			
			Buffer *buffer;
			std::string filename;
			
			bool dirty;
			void set_dirty(bool dirty);
			
			NestedOffsetLengthMap<Comment> comments;
			NestedOffsetLengthMap<int> highlights;
			
			std::string title;
			
			std::list<Region*> regions;
			size_t data_regions_count;
			
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
			
			static const int UNDO_MAX = 64;
			std::list<REHex::Document::TrackedChange> undo_stack;
			std::list<REHex::Document::TrackedChange> redo_stack;
			
			void _ctor_pre(wxWindow *parent);
			void _ctor_post();
			
			void _reinit_regions();
			void _recalc_regions(wxDC &dc);
			
			void _set_cursor_position(off_t position, enum CursorState cursor_state);
			
			void _UNTRACKED_overwrite_data(wxDC &dc, off_t offset, const unsigned char *data, off_t length);
			void _UNTRACKED_insert_data(wxDC &dc, off_t offset, const unsigned char *data, off_t length);
			void _UNTRACKED_erase_data(wxDC &dc, off_t offset, off_t length);
			
			void _tracked_overwrite_data(const char *change_desc, off_t offset, const unsigned char *data, off_t length, off_t new_cursor_pos, CursorState new_cursor_state);
			void _tracked_insert_data(const char *change_desc, off_t offset, const unsigned char *data, off_t length, off_t new_cursor_pos, CursorState new_cursor_state);
			void _tracked_erase_data(const char *change_desc, off_t offset, off_t length);
			void _tracked_replace_data(const char *change_desc, off_t offset, off_t old_data_length, const unsigned char *new_data, off_t new_data_length, off_t new_cursor_pos, CursorState new_cursor_state);
			void _tracked_change(const char *desc, std::function< void() > do_func, std::function< void() > undo_func);
			
			void _set_comment_text(wxDC &dc, off_t offset, off_t length, const wxString &text);
			void _delete_comment(wxDC &dc, off_t offset, off_t length);
			
			json_t *_dump_metadata();
			void _save_metadata(const std::string &filename);
			
			static NestedOffsetLengthMap<Comment> _load_comments(const json_t *meta, off_t buffer_length);
			static NestedOffsetLengthMap<int> _load_highlights(const json_t *meta, off_t buffer_length);
			void _load_metadata(const std::string &filename);
			
			REHex::Document::Region::Data *_data_region_by_offset(off_t offset);
			
			void _make_line_visible(int64_t line);
			void _make_x_visible(int x_px, int width_px);
			
			void _make_byte_visible(off_t offset);
			
			void _handle_width_change();
			void _handle_height_change();
			void _update_vscroll();
			void _update_vscroll_pos();
			
			static std::list<wxString> _format_text(const wxString &text, unsigned int cols, unsigned int from_line = 0, unsigned int max_lines = -1);
			int _indent_width(int depth);
			
			void _raise_moved();
			void _raise_comment_modified();
			void _raise_data_modified();
			void _raise_undo_update();
			void _raise_dirty();
			void _raise_clean();
			
			static const int PRECOMP_HF_STRING_WIDTH_TO = 512;
			unsigned int hf_string_width_precomp[PRECOMP_HF_STRING_WIDTH_TO];
			
			int hf_char_width();
			int hf_string_width(int length);
			int hf_char_at_x(int x_px);
			
			/* Stays at the bottom because it changes the protection... */
			DECLARE_EVENT_TABLE()
	};
	
	struct Document::Region::Data: public REHex::Document::Region
	{
		off_t d_offset;
		off_t d_length;
		
		int offset_text_x;  /* Virtual X coord of left edge of offsets. */
		int hex_text_x;     /* Virtual X coord of left edge of hex data. */
		int ascii_text_x;   /* Virtual X coord of left edge of ASCII data. */
		
		unsigned int bytes_per_line_actual;  /* Number of bytes being displayed per line. */
		
		Data(off_t d_offset, off_t d_length, int i_depth = 0);
		
		virtual void update_lines(REHex::Document &doc, wxDC &dc) override;
		virtual void draw(REHex::Document &doc, wxDC &dc, int x, int64_t y) override;
		virtual wxCursor cursor_for_point(REHex::Document &doc, int x, int64_t y_lines, int y_px) override;
		
		off_t offset_at_xy_hex  (REHex::Document &doc, int mouse_x_px, uint64_t mouse_y_lines);
		off_t offset_at_xy_ascii(REHex::Document &doc, int mouse_x_px, uint64_t mouse_y_lines);
		
		off_t offset_near_xy_hex  (REHex::Document &doc, int mouse_x_px, uint64_t mouse_y_lines);
		off_t offset_near_xy_ascii(REHex::Document &doc, int mouse_x_px, uint64_t mouse_y_lines);
	};
	
	struct Document::Region::Comment: public REHex::Document::Region
	{
		off_t c_offset, c_length;
		const wxString &c_text;
		
		REHex::Document::Region *final_descendant;
		
		Comment(off_t c_offset, off_t c_length, const wxString &c_text, int i_depth);
		
		/* Kludge for unit tests which really need to be redesigned... */
		Comment(off_t c_offset, const wxString &c_text):
			Comment(c_offset, 0, c_text, 0) {}
		
		virtual void update_lines(REHex::Document &doc, wxDC &dc) override;
		virtual void draw(REHex::Document &doc, wxDC &dc, int x, int64_t y) override;
		virtual wxCursor cursor_for_point(REHex::Document &doc, int x, int64_t y_lines, int y_px) override;
	};
	
	class CommentsDataObject: public wxCustomDataObject
	{
		private:
			struct Header
			{
				off_t file_offset;
				off_t file_length;
				
				size_t text_length;
			};
			
		public:
			static const wxDataFormat format;
			
			CommentsDataObject();
			CommentsDataObject(const std::list<NestedOffsetLengthMap<REHex::Document::Comment>::const_iterator> &comments, off_t base = 0);
			
			NestedOffsetLengthMap<Document::Comment> get_comments() const;
			void set_comments(const std::list<NestedOffsetLengthMap<REHex::Document::Comment>::const_iterator> &comments, off_t base = 0);
	};
}

#endif /* !REHEX_DOCUMENT_HPP */
