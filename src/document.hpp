/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "BitOffset.hpp"
#include "buffer.hpp"
#include "ByteRangeMap.hpp"
#include "ByteRangeSet.hpp"
#include "ByteRangeTree.hpp"
#include "CharacterEncoder.hpp"
#include "HighlightColourMap.hpp"
#include "MacFileName.hpp"
#include "util.hpp"

namespace REHex {
	wxDECLARE_EVENT(EV_INSERT_TOGGLED,      wxCommandEvent);
	wxDECLARE_EVENT(EV_SELECTION_CHANGED,   wxCommandEvent);
	wxDECLARE_EVENT(EV_COMMENT_MODIFIED,    wxCommandEvent);
	wxDECLARE_EVENT(EV_UNDO_UPDATE,         wxCommandEvent);
	wxDECLARE_EVENT(EV_BECAME_CLEAN,        wxCommandEvent);
	wxDECLARE_EVENT(EV_BECAME_DIRTY,        wxCommandEvent);
	wxDECLARE_EVENT(EV_DISP_SETTING_CHANGED,wxCommandEvent);
	wxDECLARE_EVENT(EV_HIGHLIGHTS_CHANGED,  wxCommandEvent);
	wxDECLARE_EVENT(EV_TYPES_CHANGED,       wxCommandEvent);
	wxDECLARE_EVENT(EV_MAPPINGS_CHANGED,    wxCommandEvent);
	
	wxDECLARE_EVENT(EVENT_RECURSION_FIXUP, wxCommandEvent);
	
	/**
	 * @brief Data and metadata of an open file.
	 *
	 * This class holds a Buffer of data in the file, metadata (comments, highlights, etc) and
	 * manages access and operations on them.
	*/
	class Document: public wxEvtHandler {
		public:
			/**
			 * @brief A comment in a Document.
			*/
			struct Comment
			{
				/**
				 * @brief The comment text.
				 *
				 * We use a shared_ptr here so that unmodified comment text isn't
				 * duplicated throughout undo_stack and redo_stack. This might be
				 * made obsolete in the future if we apply a similar technique to
				 * the comments/highlights copies as a whole.
				 *
				 * wxString is used rather than std::string as it is unicode-aware
				 * and will keep everything in order in memory and on-screen.
				*/
				std::shared_ptr<const wxString> text;
				
				/**
				 * @brief Create a new comment.
				 *
				 * @param text Comment text.
				*/
				Comment(const wxString &text);
				
				bool operator==(const Comment &rhs) const
				{
					return *text == *(rhs.text);
				}
				
				/**
				 * @brief Get a short preview of the comment, suitable for use as a wxMenuItem label.
				*/
				wxString menu_preview() const;
			};
			
			enum CursorState {
				CSTATE_HEX = 0,
				CSTATE_ASCII = 2,
				CSTATE_SPECIAL,
				
				/* Only valid as parameter to _set_cursor_position(), will use current state. */
				CSTATE_GOTO,
				
				/* Only valid as parameter to data manipulation methods to use
				 * current value of cursor_state.
				*/
				CSTATE_CURRENT,
			};
			
			struct TypeInfo
			{
				std::string name;
				json_t *options;
				
				TypeInfo();
				TypeInfo(const std::string &name, const json_t *options = NULL);
				
				TypeInfo(const TypeInfo &typeinfo);
				TypeInfo &operator=(const TypeInfo &rhs);
				
				TypeInfo(TypeInfo &&typeinfo) = delete;
				TypeInfo &operator=(TypeInfo &&rhs) = delete;
				
				~TypeInfo();
				
				bool operator==(const TypeInfo &rhs) const;
				bool operator!=(const TypeInfo &rhs) const;
				bool operator<(const TypeInfo &rhs) const;
			};
			
			/**
			 * @brief Create a Document for a new file.
			*/
			Document();
			
			/**
			 * @brief Create a Document for an existing file on disk.
			*/
			Document(const std::string &filename);
			
			#ifdef __APPLE__
			/**
			 * @brief Create a Document for an existing file on disk.
			*/
			Document(MacFileName &&filename);
			#endif
			
			~Document();
			
			/**
			 * @brief Reload the document, discarding any changes made.
			*/
			void reload();
			
			/**
			 * @brief Save any changes to the file and its metadata.
			*/
			void save();
			
			/**
			 * @brief Save the file to a new path.
			*/
			void save(const std::string &filename);
			
			/**
			 * @brief Get the user-visible title of the document.
			 *
			 * This will usually be the name of the file, or a locale-appropriate
			 * label like "Untitled" for new files.
			*/
			std::string get_title();
			
			/**
			 * @brief Set the user-visible title of the document.
			*/
			void set_title(const std::string &title);
			
			/**
			 * @brief Get the filename of the document, or an empty string if there is no backing file.
			*/
			std::string get_filename();
			
			/**
			 * @brief Check if the document has any pending changes to be saved.
			*/
			bool is_dirty();
			
			/**
			 * @brief Check if the given byte in the backing file has been modified since the last save.
			*/
			bool is_byte_dirty(BitOffset offset) const;
			
			/**
			 * @brief Check if the BUFFER has any pending changes to be saved.
			*/
			bool is_buffer_dirty() const;
			
			BitOffset get_cursor_position() const;
			CursorState get_cursor_state() const;
			void set_cursor_position(BitOffset off, CursorState cursor_state = CSTATE_GOTO);
			
			/**
			 * @brief Get the comments in the file.
			*/
			const BitRangeTree<Comment> &get_comments() const;
			
			/**
			 * @brief Set a comment in the file.
			 *
			 * @param offset   Offset of byte range.
			 * @param length   Length of byte range.
			 * @param comment  Comment to set.
			 *
			 * Returns true on success, false if off and/or length is beyond the
			 * current size of the file, or the range is straddling the end of another
			 * existing comment.
			 *
			 * Comments can have a length of zero, in which case they are displayed at
			 * the given offset, but do not encompass a range of bytes.
			*/
			bool set_comment(BitOffset offset, BitOffset length, const Comment &comment);
			
			/**
			 * @brief Erase a comment in the file.
			 *
			 * @param offset  Offset of comment to erase.
			 * @param length  Length of comment to erase.
			 *
			 * Returns true on success, false if the comment was not found.
			*/
			bool erase_comment(BitOffset offset, BitOffset length);
			
			/**
			 * @brief Erase a comment and any children in the file.
			 *
			 * @param offset  Offset of comment to erase.
			 * @param length  Length of comment to erase.
			 *
			 * Returns true on success, false if the comment was not found.
			*/
			bool erase_comment_recursive(BitOffset offset, BitOffset length);
			
			/**
			 * @brief Get the highlight colours configured in this document.
			*/
			const HighlightColourMap &get_highlight_colours() const;
			
			/**
			 * @brief Set the highlight colours configured in this document.
			*/
			void set_highlight_colours(const HighlightColourMap &highlight_colours);
			
			/**
			 * @brief Find or add the described highlight colour.
			 *
			 * @param label             Descriptive label for the highlight colour.
			 * @param primary_colour    Primary colour (wxNullColour for default).
			 * @param secondary_colour  Secondary colour (wxNullColour for default).
			 *
			 * @return ID of existing/created highlight colour, -1 if no slots available.
			*/
			int allocate_highlight_colour(const wxString &label, const wxColour &primary_colour = wxNullColour, const wxColour &secondary_colour = wxNullColour);
			
			/**
			 * @brief Get the highlighted byte ranges in the file.
			*/
			const BitRangeMap<int> &get_highlights() const;
			
			/**
			 * @brief Set a highlight on a range of bytes in the file.
			 *
			 * @param off                   Offset of byte range.
			 * @param length                Length of byte range.
			 * @param highlight_colour_idx  Highlight colour index (0 .. HighlightColourMap::MAX_NUM - 1).
			 *
			 * Returns true on success, false if off and/or length is beyond the
			 * current size of the file, or the range is straddling the end of another
			 * existing highlight.
			*/
			bool set_highlight(BitOffset off, BitOffset length, int highlight_colour_idx);
			
			/**
			 * @brief Remove a highlight from the file.
			 *
			 * @param off     Offset of byte range.
			 * @param length  Length of byte range.
			 *
			 * The off and length parameters must exactly match the highlight to be
			 * removed. This constraint will be removed in the future and it will be
			 * possible to remove a portion of a highlight.
			 *
			 * Returns true on success, false if the highlight wasn't found.
			*/
			bool erase_highlight(BitOffset off, BitOffset length);
			
			/**
			 * @brief Get the mapping of byte ranges to data types in the file.
			*/
			const BitRangeMap<TypeInfo> &get_data_types() const;
			
			/**
			 * @brief Set a data type mapping in the file.
			 *
			 * @param offset Offset of data.
			 * @param length Length of data, in bytes.
			 * @param type   Type of data.
			 *
			 * Sets the type of a range of bytes in the file, the type should be an
			 * empty string for untyped data, or a type known to the DataTypeRegistry.
			 *
			 * Returns true on success, false if the offset and/or length is beyond the
			 * current size of the file.
			*/
			bool set_data_type(BitOffset offset, BitOffset length, const std::string &type, const json_t *options = NULL);
			
			const CharacterEncoder *get_text_encoder(BitOffset offset) const;
			
			bool set_virt_mapping(off_t real_offset, off_t virt_offset, off_t length);
			void clear_virt_mapping_r(off_t real_offset, off_t length);
			void clear_virt_mapping_v(off_t virt_offset, off_t length);
			
			const ByteRangeMap<off_t> &get_real_to_virt_segs() const;
			const ByteRangeMap<off_t> &get_virt_to_real_segs() const;
			
			off_t real_to_virt_offset(off_t real_offset) const;
			off_t virt_to_real_offset(off_t virt_offset) const;
			
			void handle_paste(wxWindow *modal_dialog_parent, const BitRangeTree<Document::Comment> &clipboard_comments);
			
			/**
			 * @brief Undo the last change to the document.
			*/
			void undo();
			
			/**
			 * @brief Get a description of the last change to the document.
			*/
			const char *undo_desc();
			
			/**
			 * @brief Replay a change undone with the undo() method.
			*/
			void redo();
			
			/**
			 * @brief Get a description of the next change to be replayed.
			*/
			const char *redo_desc();
			
			/**
			 * @brief Clear the undo/redo history and mark the document as clean.
			*/
			void reset_to_clean();
			
			/**
			 * @brief Write the metadata (comments, highlights, etc) to a file.
			*/
			void save_metadata(const std::string &filename) const;
			
			/**
			 * @brief Replace the document's metadata from a file.
			*/
			void load_metadata(const std::string &filename);
			
			json_t *serialise_metadata(bool even_if_empty) const;
			void load_metadata(const json_t *metadata);
			
			static std::string find_metadata(const std::string &filename);
			
		#ifndef UNIT_TEST
		private:
		#endif
			struct TransOpFunc
			{
				const std::function<TransOpFunc()> func;
				
				TransOpFunc(const std::function<TransOpFunc()> &func);
				TransOpFunc(const TransOpFunc &src);
				TransOpFunc(TransOpFunc &&src);
				
				TransOpFunc operator()() const;
			};
			
			struct Transaction
			{
				const std::string desc;
				
				bool complete;
				
				std::list<TransOpFunc> ops;
				
				BitOffset old_cpos_off;
				CursorState old_cursor_state;
				BitRangeTree<Comment> old_comments;
				HighlightColourMap old_highlight_colours;
				BitRangeMap<int> old_highlights;
				BitRangeMap<TypeInfo> old_types;
				
				ByteRangeMap<off_t> old_real_to_virt_segs;
				ByteRangeMap<off_t> old_virt_to_real_segs;
				
				Transaction(const std::string &desc, Document *doc):
					desc(desc),
					complete(false),
					
					old_cpos_off(doc->get_cursor_position()),
					old_cursor_state(doc->get_cursor_state()),
					old_comments(doc->get_comments()),
					old_highlight_colours(doc->get_highlight_colours()),
					old_highlights(doc->get_highlights()),
					old_types(doc->get_data_types()),
					old_real_to_virt_segs(doc->get_real_to_virt_segs()),
					old_virt_to_real_segs(doc->get_virt_to_real_segs()) {}
			};
			
			void transact_step(const TransOpFunc &op, const std::string &desc);
			
			Buffer *buffer;
			std::string filename;
			bool write_protect;
			
			void _forward_buffer_events();
			
			unsigned int current_seq;
			unsigned int buffer_seq;
			ByteRangeMap<unsigned int> data_seq;
			unsigned int saved_seq;
			
			BitRangeTree<Comment> comments;
			HighlightColourMap highlight_colour_map;
			BitRangeMap<int> highlights;
			BitRangeMap<TypeInfo> types;
			
			ByteRangeMap<off_t> real_to_virt_segs;
			ByteRangeMap<off_t> virt_to_real_segs;
			
			std::string title;
			
			BitOffset cpos_off;
			
			enum CursorState cursor_state;
			
			static const int UNDO_MAX = 64;
			std::list<Transaction> undo_stack;
			std::list<Transaction> redo_stack;
			
			void _set_cursor_position(BitOffset position, enum CursorState cursor_state);
			
			void _UNTRACKED_overwrite_data(BitOffset offset, const unsigned char *data, off_t length, const ByteRangeMap<unsigned int> &data_seq_slice);
			void _UNTRACKED_overwrite_bits(BitOffset offset, const std::vector<bool> &data, const ByteRangeMap<unsigned int> &data_seq_slice);
			
			void _UNTRACKED_insert_data(off_t offset, const unsigned char *data, off_t length, const ByteRangeMap<unsigned int> &data_seq_slice);
			void _update_mappings_data_inserted(off_t offset, off_t length);
			
			void _UNTRACKED_erase_data(off_t offset, off_t length);
			bool _virt_to_real_segs_data_erased(off_t offset, off_t length);
			
			TransOpFunc _op_overwrite_undo(BitOffset offset, std::shared_ptr< std::vector<unsigned char> > old_data, BitOffset new_cursor_pos, CursorState new_cursor_state);
			TransOpFunc _op_overwrite_redo(BitOffset offset, std::shared_ptr< std::vector<unsigned char> > new_data, BitOffset new_cursor_pos, CursorState new_cursor_state);
			
			TransOpFunc _op_overwrite_bits_undo(BitOffset offset, std::shared_ptr< std::vector<bool> > old_data, BitOffset new_cursor_pos, CursorState new_cursor_state);
			TransOpFunc _op_overwrite_bits_redo(BitOffset offset, std::shared_ptr< std::vector<bool> > new_data, BitOffset new_cursor_pos, CursorState new_cursor_state);
			
			TransOpFunc _op_insert_undo(off_t offset, off_t length, BitOffset new_cursor_pos, CursorState new_cursor_state);
			TransOpFunc _op_insert_redo(off_t offset, std::shared_ptr< std::vector<unsigned char> > data, BitOffset new_cursor_pos, CursorState new_cursor_state, const ByteRangeMap<unsigned int> &redo_data_seq_slice);
			
			TransOpFunc _op_erase_undo(off_t offset, std::shared_ptr< std::vector<unsigned char> > old_data, BitOffset new_cursor_pos, CursorState new_cursor_state, const ByteRangeMap<unsigned int> &undo_data_seq_slice);
			TransOpFunc _op_erase_redo(off_t offset, off_t length, BitOffset new_cursor_pos, CursorState new_cursor_state);
			
			TransOpFunc _op_replace_undo(off_t offset, std::shared_ptr< std::vector<unsigned char> > old_data, off_t new_data_length, BitOffset new_cursor_pos, CursorState new_cursor_state, const ByteRangeMap<unsigned int> &undo_data_seq_slice);
			TransOpFunc _op_replace_redo(off_t offset, off_t old_data_length, std::shared_ptr< std::vector<unsigned char> > new_data, BitOffset new_cursor_pos, CursorState new_cursor_state);
			
			void _tracked_change(const char *desc, const std::function< void() > &do_func, const std::function< void() > &undo_func);
			TransOpFunc _op_tracked_change(const std::function< void() > &func, const std::function< void() > &next_func);
			
			void save_metadata_for(const std::string &filename);
			
			static BitRangeTree<Comment> _load_comments(const json_t *meta, off_t buffer_length);
			static BitRangeMap<int> _load_highlights(const json_t *meta, off_t buffer_length, const HighlightColourMap &highlight_colour_map);
			static BitRangeMap<TypeInfo> _load_types(const json_t *meta, off_t buffer_length);
			static std::pair< ByteRangeMap<off_t>, ByteRangeMap<off_t> > _load_virt_mappings(const json_t *meta, off_t buffer_length);
			void _load_metadata(const std::string &filename);
			
			class CommandEventBuffer
			{
				public:
					CommandEventBuffer(wxEvtHandler *handler, wxEventType type);
					~CommandEventBuffer();
					
					void raise();
					
				private:
					wxEvtHandler *handler;
					wxEventType type;
					
					bool frozen, pending;
					
					void OnBulkUpdatesFrozen(wxCommandEvent &event);
					void OnBulkUpdatesThawed(wxCommandEvent &event);
			};
			
			CommandEventBuffer comment_modified_buffer;
			void _raise_comment_modified();
			
			void _raise_undo_update();
			void _raise_dirty();
			void _raise_clean();
			
			CommandEventBuffer highlights_changed_buffer;
			void _raise_highlights_changed();
			
			CommandEventBuffer types_changed_buffer;
			void _raise_types_changed();
			
			CommandEventBuffer mappings_changed_buffer;
			void _raise_mappings_changed();
			
			void OnColourPaletteChanged(wxCommandEvent &event);
			
		public:
			/**
			 * @brief Read some data from the file.
			 * @see Buffer::read_data()
			*/
			std::vector<unsigned char> read_data(BitOffset offset, off_t max_length) const;
			
			/**
			 * @brief Read some data from the file.
			 * @see Buffer::read_bits()
			*/
			std::vector<bool> read_bits(BitOffset offset, size_t max_length) const;
			
			/**
			 * @brief Return the current length of the file in bytes.
			*/
			off_t buffer_length() const;
			
			/**
			 * @brief Returns true if the backing file has been deleted.
			*/
			bool file_deleted() const;
			
			/**
			 * @brief Returns true if the backing file has been modified externally.
			*/
			bool file_modified() const;
			
			/**
			 * @brief Set write protect flag on the file.
			 *
			 * If the write protect flag is set, any attempts to modify the file (buffer) DATA
			 * will be no-ops. Changes to metadata (comments, etc) are still permitted.
			*/
			void set_write_protect(bool write_protect);
			
			/**
			 * @get Get the write protect flag state.
			*/
			bool get_write_protect() const;
			
			/**
			 * @brief Overwrite a range of bytes in the file.
			 *
			 * @param offset            File offset to write data at.
			 * @param data              Pointer to data buffer.
			 * @param length            Length of data to write.
			 * @param new_cursor_pos    New cursor position. Pass a negative value to not change cursor position.
			 * @param new_cursor_state  New cursor state. Pass CSTATE_CURRENT to not change the cursor state.
			 * @param change_desc       Description of change for undo history.
			*/
			void overwrite_data(BitOffset offset, const void *data, off_t length,                                            BitOffset new_cursor_pos = BitOffset::INVALID, CursorState new_cursor_state = CSTATE_CURRENT, const char *change_desc = "change data");
			
			/**
			 * @brief Overwrite a range of bits in the file.
			 *
			 * @param offset            File offset to write data at.
			 * @param data              Pointer to data buffer.
			 * @param new_cursor_pos    New cursor position. Pass a negative value to not change cursor position.
			 * @param new_cursor_state  New cursor state. Pass CSTATE_CURRENT to not change the cursor state.
			 * @param change_desc       Description of change for undo history.
			*/
			void overwrite_bits(BitOffset offset, const std::vector<bool> &data, BitOffset new_cursor_pos = BitOffset::INVALID, CursorState new_cursor_state = CSTATE_CURRENT, const char *change_desc = "change data");
			
			/**
			 * @brief Insert a range of bytes into the file.
			 *
			 * @param offset            File offset to insert data at.
			 * @param data              Pointer to data buffer.
			 * @param length            Length of data to write.
			 * @param new_cursor_pos    New cursor position. Pass a negative value to not change cursor position.
			 * @param new_cursor_state  New cursor state. Pass CSTATE_CURRENT to not change the cursor state.
			 * @param change_desc       Description of change for undo history.
			*/
			void insert_data(off_t offset, const void *data, off_t length,                                      BitOffset new_cursor_pos = BitOffset::INVALID, CursorState new_cursor_state = CSTATE_CURRENT, const char *change_desc = "change data");
			
			/**
			 * @brief Erase a range of bytes in the file.
			 *
			 * @param offset            File offset to erase data from.
			 * @param length            Length of data to erase.
			 * @param new_cursor_pos    New cursor position. Pass a negative value to not change cursor position.
			 * @param new_cursor_state  New cursor state. Pass CSTATE_CURRENT to not change the cursor state.
			 * @param change_desc       Description of change for undo history.
			*/
			void erase_data(off_t offset, off_t length,                                                                  BitOffset new_cursor_pos = BitOffset::INVALID, CursorState new_cursor_state = CSTATE_CURRENT, const char *change_desc = "change data");
			
			/**
			 * @brief Replace a range of bytes in the file.
			 *
			 * @param offset            File offset to replace data at.
			 * @param old_data_length   Length of data to be replaced.
			 * @param new_data          Pointer to data buffer.
			 * @param new_data_length   Length of new data.
			 * @param new_cursor_pos    New cursor position. Pass a negative value to not change cursor position.
			 * @param new_cursor_state  New cursor state. Pass CSTATE_CURRENT to not change the cursor state.
			 * @param change_desc       Description of change for undo history.
			*/
			void replace_data(off_t offset, off_t old_data_length, const void *new_data, off_t new_data_length, BitOffset new_cursor_pos = BitOffset::INVALID, CursorState new_cursor_state = CSTATE_CURRENT, const char *change_desc = "change data");
			
			static const off_t WRITE_TEXT_KEEP_POSITION = -1;  /**< Don't move the cursor after writing. */
			static const off_t WRITE_TEXT_GOTO_NEXT = -2;      /**< Jump to byte following written data. */
			
			static const int WRITE_TEXT_OK = 0;
			static const int WRITE_TEXT_BAD_OFFSET = 1;
			static const int WRITE_TEXT_SKIPPED = 2;
			static const int WRITE_TEXT_TRUNCATED = 4;
			
			int overwrite_text(BitOffset offset, const std::string &utf8_text, BitOffset new_cursor_pos = WRITE_TEXT_GOTO_NEXT, CursorState new_cursor_state = CSTATE_CURRENT, const char *change_desc = "change data");
			int insert_text(off_t offset, const std::string &utf8_text, off_t new_cursor_pos = WRITE_TEXT_GOTO_NEXT, CursorState new_cursor_state = CSTATE_CURRENT, const char *change_desc = "change data");
			int replace_text(off_t offset, off_t old_data_length, const std::string &utf8_text, off_t new_cursor_pos = WRITE_TEXT_GOTO_NEXT, CursorState new_cursor_state = CSTATE_CURRENT, const char *change_desc = "change data");
			
			void transact_begin(const std::string &desc);
			void transact_commit();
			void transact_rollback();
			
			virtual bool ProcessEvent(wxEvent &event) override;
	};
	
	/**
	 * @brief Data object that stores a list of comments.
	 *
	 * This class provides wxDataObject-compatible serialisation of one or more comments so
	 * that they can be copied via the clipboard.
	*/
	class CommentsDataObject: public wxCustomDataObject
	{
		private:
			struct Header
			{
				int64_t file_offset;
				int64_t file_length;
				
				size_t text_length;
			};
			
		public:
			/**
			 * @brief wxDataFormat used for comments in the clipboard.
			*/
			static const wxDataFormat format;
			
			/**
			 * @brief Construct an empty CommentsDataObject.
			*/
			CommentsDataObject();
			
			/**
			 * @brief Construct a CommentsDataObject from a list of comments.
			 *
			 * @param comments  List of iterators to comments to be serialised.
			 * @param base      Base offset to be subtracted from the offset of each comment.
			*/
			CommentsDataObject(const std::list<BitRangeTree<Document::Comment>::const_iterator> &comments, BitOffset base = BitOffset::ZERO);
			
			/**
			 * @brief Deserialise the CommentsDataObject and return the stored comments.
			*/
			BitRangeTree<Document::Comment> get_comments() const;
			
			/**
			 * @brief Replace the serialised list of stored comments.
			 *
			 * @param comments  List of iterators to comments to be serialised.
			 * @param base      Base offset to be subtracted from the offset of each comment.
			*/
			void set_comments(const std::list<BitRangeTree<Document::Comment>::const_iterator> &comments, BitOffset base = BitOffset::ZERO);
	};
	
	/**
	 * @brief RAII-style Document transaction wrapper.
	*/
	class ScopedTransaction
	{
		private:
			Document *doc;
			bool committed;
			
		public:
			/**
			 * @brief Opens a new transaction.
			*/
			ScopedTransaction(Document *doc, const std::string &desc):
				doc(doc),
				committed(false)
			{
				doc->transact_begin(desc);
			}
			
			/**
			 * @brief Rolls back the transaction if not already committed.
			*/
			~ScopedTransaction()
			{
				if(!committed)
				{
					doc->transact_rollback();
				}
			}
			
			/**
			 * @brief Complete the transaction.
			*/
			void commit()
			{
				doc->transact_commit();
				committed = true;
			}
	};
}

#endif /* !REHEX_DOCUMENT_HPP */
