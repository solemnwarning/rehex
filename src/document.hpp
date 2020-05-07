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
#include "util.hpp"

namespace REHex {
	wxDECLARE_EVENT(EV_INSERT_TOGGLED,      wxCommandEvent);
	wxDECLARE_EVENT(EV_SELECTION_CHANGED,   wxCommandEvent);
	wxDECLARE_EVENT(EV_COMMENT_MODIFIED,    wxCommandEvent);
	wxDECLARE_EVENT(EV_UNDO_UPDATE,         wxCommandEvent);
	wxDECLARE_EVENT(EV_BECAME_CLEAN,        wxCommandEvent);
	wxDECLARE_EVENT(EV_BECAME_DIRTY,        wxCommandEvent);
	wxDECLARE_EVENT(EV_BASE_CHANGED,        wxCommandEvent);
	wxDECLARE_EVENT(EV_HIGHLIGHTS_CHANGED,  wxCommandEvent);
	
	class Document: public wxEvtHandler {
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
			
			enum CursorState {
				CSTATE_HEX,
				CSTATE_HEX_MID,
				CSTATE_ASCII,
				
				/* Only valid as parameter to _set_cursor_position(), will go
				 * CSTATE_HEX if in CSTATE_HEX_MID, else will use current state.
				*/
				CSTATE_GOTO,
				
				/* Only valid as parameter to data manipulation methods to use
				 * current value of cursor_state.
				*/
				CSTATE_CURRENT,
			};
			
			Document();
			Document(const std::string &filename);
			~Document();
			
			void save();
			void save(const std::string &filename);
			
			std::string get_title();
			std::string get_filename();
			bool is_dirty();
			
			off_t get_cursor_position() const;
			CursorState get_cursor_state() const;
			void set_cursor_position(off_t off, CursorState cursor_state = CSTATE_GOTO);
			
			const NestedOffsetLengthMap<Comment> &get_comments() const;
			bool set_comment(off_t offset, off_t length, const Comment &comment);
			bool erase_comment(off_t offset, off_t length);
			
			const NestedOffsetLengthMap<int> &get_highlights() const;
			bool set_highlight(off_t off, off_t length, int highlight_colour_idx);
			bool erase_highlight(off_t off, off_t length);
			
			void handle_paste(wxWindow *modal_dialog_parent, const NestedOffsetLengthMap<Document::Comment> &clipboard_comments);
			
			void undo();
			const char *undo_desc();
			void redo();
			const char *redo_desc();
			
		#ifndef UNIT_TEST
		private:
		#endif
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
			
			Buffer *buffer;
			std::string filename;
			
			bool dirty;
			void set_dirty(bool dirty);
			
			NestedOffsetLengthMap<Comment> comments;
			NestedOffsetLengthMap<int> highlights;
			
			std::string title;
			
			off_t cpos_off{0};
			bool insert_mode{false};
			
			enum CursorState cursor_state;
			
			static const int UNDO_MAX = 64;
			std::list<REHex::Document::TrackedChange> undo_stack;
			std::list<REHex::Document::TrackedChange> redo_stack;
			
			void _set_cursor_position(off_t position, enum CursorState cursor_state);
			
			void _UNTRACKED_overwrite_data(off_t offset, const unsigned char *data, off_t length);
			void _UNTRACKED_insert_data(off_t offset, const unsigned char *data, off_t length);
			void _UNTRACKED_erase_data(off_t offset, off_t length);
			
			void _tracked_overwrite_data(const char *change_desc, off_t offset, const unsigned char *data, off_t length, off_t new_cursor_pos, CursorState new_cursor_state);
			void _tracked_insert_data(const char *change_desc, off_t offset, const unsigned char *data, off_t length, off_t new_cursor_pos, CursorState new_cursor_state);
			void _tracked_erase_data(const char *change_desc, off_t offset, off_t length, off_t new_cursor_pos, CursorState new_cursor_state);
			void _tracked_replace_data(const char *change_desc, off_t offset, off_t old_data_length, const unsigned char *new_data, off_t new_data_length, off_t new_cursor_pos, CursorState new_cursor_state);
			void _tracked_change(const char *desc, std::function< void() > do_func, std::function< void() > undo_func);
			
			json_t *_dump_metadata();
			void _save_metadata(const std::string &filename);
			
			static NestedOffsetLengthMap<Comment> _load_comments(const json_t *meta, off_t buffer_length);
			static NestedOffsetLengthMap<int> _load_highlights(const json_t *meta, off_t buffer_length);
			void _load_metadata(const std::string &filename);
			
			void _raise_comment_modified();
			void _raise_undo_update();
			void _raise_dirty();
			void _raise_clean();
			void _raise_highlights_changed();
			
		public:
			std::vector<unsigned char> read_data(off_t offset, off_t max_length) const;
			off_t buffer_length();
			
			void overwrite_data(off_t offset, const void *data, off_t length,                                            off_t new_cursor_pos = -1, CursorState new_cursor_state = CSTATE_CURRENT, const char *change_desc = "change data");
			void insert_data(off_t offset, const unsigned char *data, off_t length,                                      off_t new_cursor_pos = -1, CursorState new_cursor_state = CSTATE_CURRENT, const char *change_desc = "change data");
			void erase_data(off_t offset, off_t length,                                                                  off_t new_cursor_pos = -1, CursorState new_cursor_state = CSTATE_CURRENT, const char *change_desc = "change data");
			void replace_data(off_t offset, off_t old_data_length, const unsigned char *new_data, off_t new_data_length, off_t new_cursor_pos = -1, CursorState new_cursor_state = CSTATE_CURRENT, const char *change_desc = "change data");
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
