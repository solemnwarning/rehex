/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2021 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <vector>
#include <wx/dataobj.h>
#include <wx/wx.h>

#include "buffer.hpp"
#include "ByteRangeSet.hpp"
#include "document.hpp"
#include "Events.hpp"
#include "NestedOffsetLengthMap.hpp"
#include "Palette.hpp"
#include "SharedDocumentPointer.hpp"
#include "util.hpp"

namespace REHex {
	class DocumentCtrl: public wxControl {
		public:
			/**
			 * @brief An on-screen rectangle in the DocumentCtrl.
			*/
			struct Rect
			{
				int x;      /**< X co-ordinate, in pixels. */
				int64_t y;  /**< Y co-ordinate, in lines. */
				
				int w;      /**< Width, in pixels. */
				int64_t h;  /**< Height, in lines. */
				
				Rect(): x(-1), y(-1), w(-1), h(-1) {}
				Rect(int x, int64_t y, int w, int64_t h): x(x), y(y), w(w), h(h) {}
			};
			
			class Region
			{
				protected:
					int64_t y_offset; /* First on-screen line in region */
					int64_t y_lines;  /* Number of on-screen lines in region */
					
					int indent_depth;  /* Indentation depth */
					int indent_final;  /* Number of inner indentation levels we are the final region in */
					
				public:
					const off_t indent_offset;
					const off_t indent_length;
					
					virtual ~Region();
					
					enum StateFlag
					{
						IDLE       = 0,
						PROCESSING = (1 << 0),
						
						WIDTH_CHANGE  = (1 << 1),
						HEIGHT_CHANGE = (1 << 2),
						REDRAW        = (1 << 3),
					};
					
					virtual unsigned int check();
					
				protected:
					Region(off_t indent_offset, off_t indent_length);
					
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
					void draw_full_height_line(DocumentCtrl *doc_ctrl, wxDC &dc, int x, int64_t y);
					
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
					
					static void draw_hex_line(DocumentCtrl *doc_ctrl, wxDC &dc, int x, int y, const unsigned char *data, size_t data_len, unsigned int pad_bytes, off_t base_off, bool alternate_row, const std::function<Highlight(off_t)> &highlight_at_off);
					static void draw_ascii_line(DocumentCtrl *doc_ctrl, wxDC &dc, int x, int y, const unsigned char *data, size_t data_len, unsigned int pad_bytes, off_t base_off, bool alternate_row, const std::function<Highlight(off_t)> &highlight_at_off);
					
					/**
					 * @brief Calculate offset of byte at X co-ordinate.
					 *
					 * Calculates the offset of the byte at the given X
					 * co-ordinate in a line drawn with draw_hex_line(). Returns
					 * -1 if the co-ordinate is negative or falls between byte
					 * groups.
					*/
					static int offset_at_x_hex(DocumentCtrl *doc_ctrl, int rel_x);
					
					/**
					 * @brief Calculate offset of byte near X co-ordinate.
					 *
					 * Calculates the offset of the byte nearest the given X
					 * co-ordinate in a line drawn with draw_hex_line(). Returns
					 * -1 if the co-ordinate is negative.
					*/
					static int offset_near_x_hex(DocumentCtrl *doc_ctrl, int rel_x);
					
				friend DocumentCtrl;
			};
			
			class GenericDataRegion: public Region
			{
				protected:
					GenericDataRegion(off_t d_offset, off_t d_length, off_t indent_offset);
					
				public:
					const off_t d_offset;
					const off_t d_length;
					
					/**
					 * @brief Represents an on-screen area of the region.
					*/
					enum ScreenArea
					{
						SA_NONE    = 0,  /**< No/Unknown area. */
						SA_HEX     = 1,  /**< The hex (data) view. */
						SA_ASCII   = 2,  /**< The ASCII (text) view. */
						SA_SPECIAL = 4,  /**< Region-specific data area. */
					};
					
					/**
					 * @brief Returns the offset of the byte at the given co-ordinates, negative if there isn't one.
					*/
					virtual std::pair<off_t, ScreenArea> offset_at_xy(DocumentCtrl &doc, int mouse_x_px, int64_t mouse_y_lines) = 0;
					
					/**
					 * @brief Returns the offset of the byte nearest the given co-ordinates and the screen area.
					 *
					 * If type_hint is specified, and supported by the region
					 * type, the nearest character in that area will be
					 * returned rather than in the area under or closest to the
					*/
					virtual std::pair<off_t, ScreenArea> offset_near_xy(DocumentCtrl &doc, int mouse_x_px, int64_t mouse_y_lines, ScreenArea type_hint) = 0;
					
					static const off_t CURSOR_PREV_REGION = -2;
					static const off_t CURSOR_NEXT_REGION = -3;
					
					/**
					 * @brief Returns the offset of the cursor position left of the given offset. May return CURSOR_PREV_REGION.
					*/
					virtual off_t cursor_left_from(off_t pos) = 0;
					
					/**
					 * @brief Returns the offset of the cursor position right of the given offset. May return CURSOR_NEXT_REGION.
					*/
					virtual off_t cursor_right_from(off_t pos) = 0;
					
					/**
					 * @brief Returns the offset of the cursor position up from the given offset. May return CURSOR_PREV_REGION.
					*/
					virtual off_t cursor_up_from(off_t pos) = 0;
					
					/**
					 * @brief Returns the offset of the cursor position down from the given offset. May return CURSOR_NEXT_REGION.
					*/
					virtual off_t cursor_down_from(off_t pos) = 0;
					
					/**
					 * @brief Returns the offset of the cursor position at the start of the line from the given offset.
					*/
					virtual off_t cursor_home_from(off_t pos) = 0;
					
					/**
					 * @brief Returns the offset of the cursor position at the end of the line from the given offset.
					*/
					virtual off_t cursor_end_from(off_t pos) = 0;
					
					/**
					 * @brief Returns the screen column index of the given offset within the region.
					*/
					virtual int cursor_column(off_t pos) = 0;
					
					/**
					 * @brief Returns the offset of the cursor position nearest the given column on the first screen line of the region.
					*/
					virtual off_t first_row_nearest_column(int column) = 0;
					
					/**
					 * @brief Returns the offset of the cursor position nearest the given column on the last screen line of the region.
					*/
					virtual off_t last_row_nearest_column(int column) = 0;
					
					/**
					 * @brief Returns the offset of the cursor position nearest the given column on the given row within the region.
					*/
					virtual off_t nth_row_nearest_column(int64_t row, int column) = 0;
					
					/**
					 * @brief Calculate the on-screen bounding box of a byte in the region.
					*/
					virtual Rect calc_offset_bounds(off_t offset, DocumentCtrl *doc_ctrl) = 0;
					
					/**
					 * @brief Find which screen areas exist for the cursor to occupy at the given offset.
					 * @return SA_XXX constants bitwise OR'd together.
					*/
					virtual ScreenArea screen_areas_at_offset(off_t offset, DocumentCtrl *doc_ctrl) = 0;
					
					/**
					 * @brief Process key presses while the cursor is in this region.
					 * @return true if the event was handled, false otherwise.
					 *
					 * This method is called to process keypresses while the
					 * cursor is in this region.
					 *
					 * If it returns true, no further processing of the event
					 * will be performed, if it returns false, processing will
					 * continue and any default processing of the key press
					 * will be used.
					 *
					 * The method may be called multiple times for the same
					 * event if it returns false, the method MUST be idempotent
					 * when it returns false.
					*/
					virtual bool OnChar(DocumentCtrl *doc_ctrl, wxKeyEvent &event);
					
					/**
					 * @brief Process a clipboard copy operation within this region.
					 * @return wxDataObject pointer, or NULL.
					 *
					 * This method is called to process copy events when the
					 * selection is entirely within a single region.
					 *
					 * Returns a pointer to a wxDataObject object to be placed
					 * into the clipboard, or NULL if the region has no special
					 * clipboard handling, in which case the default copy
					 * behaviour will take over.
					 *
					 * The caller is responsible for ensuring any returned
					 * wxDataObject is deleted.
					*/
					virtual wxDataObject *OnCopy(DocumentCtrl &doc_ctrl);
					
					/**
					 * @brief Process a clipboard paste operation within this region.
					 * @return true if the event was handled, false otherwise.
					 *
					 * This method is called when the user attempts to paste and
					 * one or both of the following is true:
					 *
					 * a) A range of bytes exclusively within this region are selected.
					 *
					 * b) The cursor is within this region.
					 *
					 * The clipboard will already be locked by the caller when
					 * this method is called.
					 *
					 * If this method returns false, default paste handling
					 * will be invoked.
					*/
					virtual bool OnPaste(DocumentCtrl *doc_ctrl);
			};
			
			class DataRegion: public GenericDataRegion
			{
				protected:
					off_t virt_offset;
					
					int offset_text_x;  /* Virtual X coord of left edge of offsets. */
					int hex_text_x;     /* Virtual X coord of left edge of hex data. */
					int ascii_text_x;   /* Virtual X coord of left edge of ASCII data. */
					
					unsigned int bytes_per_line_actual;  /* Number of bytes being displayed per line. */
					unsigned int first_line_pad_bytes;   /* Number of bytes to pad first line with. */
					
				public:
					DataRegion(off_t d_offset, off_t d_length, off_t virt_offset);
					
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
					
					virtual std::pair<off_t, ScreenArea> offset_at_xy(DocumentCtrl &doc, int mouse_x_px, int64_t mouse_y_lines) override;
					virtual std::pair<off_t, ScreenArea> offset_near_xy(DocumentCtrl &doc, int mouse_x_px, int64_t mouse_y_lines, ScreenArea type_hint) override;
					
					virtual off_t cursor_left_from(off_t pos) override;
					virtual off_t cursor_right_from(off_t pos) override;
					virtual off_t cursor_up_from(off_t pos) override;
					virtual off_t cursor_down_from(off_t pos) override;
					virtual off_t cursor_home_from(off_t pos) override;
					virtual off_t cursor_end_from(off_t pos) override;
					
					virtual int cursor_column(off_t pos) override;
					virtual off_t first_row_nearest_column(int column) override;
					virtual off_t last_row_nearest_column(int column) override;
					virtual off_t nth_row_nearest_column(int64_t row, int column) override;
					
					virtual Rect calc_offset_bounds(off_t offset, DocumentCtrl *doc_ctrl) override;
					virtual ScreenArea screen_areas_at_offset(off_t offset, DocumentCtrl *doc_ctrl) override;
					
					virtual Highlight highlight_at_off(off_t off) const;
					
				friend DocumentCtrl;
			};
			
			class DataRegionDocHighlight: public DataRegion
			{
				private:
					Document &doc;
					
				public:
					DataRegionDocHighlight(off_t d_offset, off_t d_length, off_t virt_offset, Document &doc);
					
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
				
				CommentRegion(off_t c_offset, off_t c_length, const wxString &c_text, bool truncate, off_t indent_offset, off_t indent_length);
				
				friend DocumentCtrl;
			};
			
			DocumentCtrl(wxWindow *parent, SharedDocumentPointer &doc);
			~DocumentCtrl();
			
			static const int BYTES_PER_LINE_FIT_BYTES  = 0;
			static const int BYTES_PER_LINE_FIT_GROUPS = -1;
			static const int BYTES_PER_LINE_MIN        = 1;
			static const int BYTES_PER_LINE_MAX        = 128;
			
			int get_bytes_per_line();
			void set_bytes_per_line(int bytes_per_line);
			
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
			
			bool hex_view_active() const;
			bool ascii_view_active() const;
			bool special_view_active() const;
			
			void set_cursor_position(off_t position, Document::CursorState cursor_state = Document::CSTATE_GOTO);
			
			bool get_insert_mode();
			void set_insert_mode(bool enabled);
			
			void linked_scroll_insert_self_after(DocumentCtrl *p);
			void linked_scroll_remove_self();
			
			/**
			 * @brief Set the selection range.
			 *
			 * @param begin Data offset at beginning of selection.
			 * @param end Data offset at end of selection (inclusive).
			*/
			bool set_selection_raw(off_t begin, off_t end);
			
			/**
			 * @brief Clear the selection (if any).
			*/
			void clear_selection();
			
			/**
			 * @brief Returns true if there is a selection.
			*/
			bool has_selection();
			
			/**
			 * @brief Returns the "raw" selection as a begin and end offset.
			 *
			 * NOTE: Unlike most "end" pointers, the end offset returned from this
			 * method is the last byte in the selection, not one past it.
			*/
			std::pair<off_t, off_t> get_selection_raw();
			
			/**
			 * @brief Returns the subset of the current selection scoped to a region.
			 *
			 * The return value from this method is the offset (file relative) and the
			 * length of the current selection, scoped to the given region.
			 *
			 * If there is no selection, or the selection doesn't include any bytes
			 * from the given region, the returned length will be <= 0.
			*/
			std::pair<off_t, off_t> get_selection_in_region(GenericDataRegion *region);
			
			/**
			 * @brief Returns the set of all bytes currently selected.
			 *
			 * NOTE: This method may be expensive to call, as it potentially has to
			 * iterate through all (data) regions in the file.
			*/
			OrderedByteRangeSet get_selection_ranges();
			
			/**
			 * @brief Returns the offset and length of the selection, if linear.
			 *
			 * If there is no selection, or the selection isn't linear and contiguous, the length
			 * will be zero.
			*/
			std::pair<off_t, off_t> get_selection_linear();
			
			const std::vector<Region*> &get_regions() const;
			const std::vector<GenericDataRegion*> &get_data_regions() const;
			void replace_all_regions(std::vector<Region*> &new_regions);
			bool region_OnChar(wxKeyEvent &event);
			GenericDataRegion *data_region_by_offset(off_t offset);
			std::vector<Region*>::iterator region_by_y_offset(int64_t y_offset);
			
			/**
			 * @brief Compare two offsets in the address space defined by the regions.
			 *
			 * Returns zero if the two offsets are equal, a negative integer if a is
			 * less than b and a positive integer if a is greater than b.
			 *
			 * Throws an exception of type std::invalid_argument if either of the
			 * offsets are invalid.
			*/
			int region_offset_cmp(off_t a, off_t b);
			
			/**
			 * @brief Increment an offset in the address space defined by the regions.
			 *
			 * @param base Base offset to start at.
			 * @param add Number of bytes to increment base by.
			 *
			 * @return New offset, negative if invalid.
			*/
			off_t region_offset_add(off_t base, off_t add);
			
			/**
			 * @brief Decrement an offset in the address space defined by the regions.
			 *
			 * @param base Base offset to start at.
			 * @param add Number of bytes to decrement base by.
			 *
			 * @return New offset, negative if invalid.
			*/
			off_t region_offset_sub(off_t base, off_t sub);
			
			/**
			 * @brief Check if a range of offsets is linear and contiguous.
			*/
			bool region_range_linear(off_t begin_offset, off_t end_offset_incl);
			
			wxFont &get_font();
			
			/**
			 * @brief Returns the current vertical scroll position, in lines.
			*/
			int64_t get_scroll_yoff() const;
			
			/**
			 * @brief Set the vertical scroll position, in lines.
			*/
			void set_scroll_yoff(int64_t scroll_yoff);
			
			void OnPaint(wxPaintEvent &event);
			void OnErase(wxEraseEvent& event);
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
			void OnIdle(wxIdleEvent &event);
			void OnFontSizeAdjustmentChanged(FontSizeAdjustmentEvent &event);
			
		#ifndef UNIT_TEST
		private:
		#endif
			friend DataRegion;
			friend CommentRegion;
			
			SharedDocumentPointer doc;
			
			std::vector<Region*> regions;                  /**< List of regions to be displayed. */
			std::vector<GenericDataRegion*> data_regions;  /**< Subset of regions which are a GenericDataRegion. */
			std::vector<Region*> processing_regions;       /**< Subset of regions which are doing background processing. */
			
			/** List of iterators into data_regions, sorted by d_offset. */
			std::vector< std::vector<GenericDataRegion*>::iterator > data_regions_sorted;
			
			/* Fixed-width font used for drawing hex data. */
			wxFont hex_font;
			
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
			int bytes_per_line;
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
			
			off_t selection_begin;
			off_t selection_end;
			
			bool cursor_visible;
			wxTimer redraw_cursor_timer;
			
			static const int MOUSE_SELECT_INTERVAL = 100;
			
			GenericDataRegion::ScreenArea mouse_down_area;
			off_t mouse_down_at_offset;
			int mouse_down_at_x;
			wxTimer mouse_select_timer;
			off_t mouse_shift_initial;
			
			Document::CursorState cursor_state;
			
			void _set_cursor_position(off_t position, Document::CursorState cursor_state);
			
			std::vector<GenericDataRegion*>::iterator _data_region_by_offset(off_t offset);
			
			std::list<Region*>::iterator _region_by_y_offset(int64_t y_offset);
			
			void _make_line_visible(int64_t line);
			void _make_x_visible(int x_px, int width_px);
			
			void _make_byte_visible(off_t offset);
			
			void _handle_width_change();
			void _handle_height_change();
			void _update_vscroll();
			void _update_vscroll_pos(bool update_linked_scroll_others = true);
			
			/**
			 * @brief Fuzzy description of the DocumentCtrl scroll position.
			 *
			 * This struct describes the DocumentCtrl scroll position, in terms of its
			 * contents so it can be restored (as close as possible) when the window
			 * size changes or regions are added/removed/grow/shrink/etc.
			*/
			struct FuzzyScrollPosition
			{
				bool data_offset_valid;   /**< True if data_offset and data_offset_line are valid. */
				off_t data_offset;        /**< File offset used as reference point. */
				int64_t data_offset_line; /**< Visible (on-screen) line where data_offset is. */
				
				bool region_idx_valid;    /**< True if region_idx and region_idx_line are valid. */
				size_t region_idx;        /**< Index of region whose first line is our reference point. */
				int64_t region_idx_line;  /**< Visible (on-screen) line where region begins (may be negative). */
				
				FuzzyScrollPosition():
					data_offset_valid(false),
					region_idx_valid(false) {}
			};
			
			/**
			 * @brief Set scroll_yoff, clamped to valid range.
			*/
			void set_scroll_yoff_clamped(int64_t scroll_yoff);
			
			/**
			 * @brief Fetch the current scroll position.
			*/
			FuzzyScrollPosition get_scroll_position_fuzzy();
			
			/**
			 * @brief Jump to a fuzzy scroll position.
			*/
			void set_scroll_position_fuzzy(const FuzzyScrollPosition &fsp);
			
			FuzzyScrollPosition saved_scroll_position;
			
			/**
			 * @brief Save the current scroll position.
			*/
			void save_scroll_position();
			
			/**
			 * @brief Restore the last saved scroll position.
			*/
			void restore_scroll_position();
			
			void linked_scroll_visit_others(const std::function<void(DocumentCtrl*)> &func);
			
			static const int PRECOMP_HF_STRING_WIDTH_TO = 512;
			unsigned int hf_string_width_precomp[PRECOMP_HF_STRING_WIDTH_TO];
			
		public:
			static std::list<wxString> format_text(const wxString &text, unsigned int cols, unsigned int from_line = 0, unsigned int max_lines = -1);
			int indent_width(int depth);
			int get_offset_column_width();
			bool get_cursor_visible();
			
			int hf_char_width();
			int hf_char_height();
			int hf_string_width(int length);
			int hf_char_at_x(int x_px);
			
			/* Stays at the bottom because it changes the protection... */
			DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_DOCUMENTCTRL_HPP */
