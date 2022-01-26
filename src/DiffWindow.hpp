/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2022 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_DIFFWINDOW_HPP
#define REHEX_DIFFWINDOW_HPP

#include <list>
#include <string>
#include <wx/aui/auibook.h>
#include <wx/frame.h>
#include <wx/gauge.h>
#include <wx/panel.h>
#include <wx/progdlg.h>
#include <wx/splitter.h>
#include <wx/statusbr.h>
#include <wx/timer.h>

#include "ByteRangeSet.hpp"
#include "document.hpp"
#include "DocumentCtrl.hpp"
#include "Events.hpp"
#include "SafeWindowPointer.hpp"
#include "SharedDocumentPointer.hpp"

// #define DIFFWINDOW_PROFILING

namespace REHex {
	class DiffWindow: public wxFrame
	{
		public:
			class Range
			{
				private:
					SharedDocumentPointer doc;
					SafeWindowPointer<DocumentCtrl> main_doc_ctrl;
					
					off_t offset;
					off_t length;
					
					wxSplitterWindow *splitter;
					wxAuiNotebook *notebook;
					DocumentCtrl *doc_ctrl;
					wxPanel      *help_panel;
					
				public:
					Range(SharedDocumentPointer &doc, DocumentCtrl *main_doc_ctrl, off_t offset, off_t length):
						doc(doc),
						main_doc_ctrl(main_doc_ctrl),
						
						offset(offset),
						length(length),
						
						splitter(NULL),
						notebook(NULL),
						doc_ctrl(NULL),
						help_panel(NULL) {}
					
					off_t get_offset() const { return offset; }
					off_t get_length() const { return length; }
					
					/* Not a gaping encapsulation hole in the name of testing. */
					DocumentCtrl *_im_a_test_give_me_doc_ctrl() { return doc_ctrl; }
					
				friend DiffWindow;
			};
			
			DiffWindow(wxWindow *parent);
			virtual ~DiffWindow();
			
			const std::list<Range> &get_ranges() const;
			std::list<Range>::iterator add_range(const Range &range);
			
			void set_folding(bool enable_folding);
			
			static DiffWindow *instance;
			
		private:
			class DiffDataRegion: public DocumentCtrl::DataRegion
			{
				private:
					DiffWindow *diff_window;
					Range *range;
					
				public:
					DiffDataRegion(off_t d_offset, off_t d_length, DiffWindow *diff_window, Range *range);
					
				protected:
					virtual int calc_width(REHex::DocumentCtrl &doc) override;
					virtual Highlight highlight_at_off(off_t off) const override;
			};
			
			class MessageRegion: public DocumentCtrl::Region
			{
				private:
					Document *document;
					
					off_t data_offset;
					std::string message;
					
				public:
					MessageRegion(Document *document, off_t data_offset, const std::string &message);
					
				protected:
					virtual int calc_width(REHex::DocumentCtrl &doc_ctrl) override;
					virtual void calc_height(DocumentCtrl &doc_ctrl, wxDC &dc) override;
					virtual void draw(DocumentCtrl &doc_ctrl, wxDC &dc, int x, int64_t y) override;
			};
			
			class InvisibleDataRegion: public DocumentCtrl::DataRegion
			{
				public:
					InvisibleDataRegion(off_t d_offset, off_t d_length);
					
				protected:
					virtual void draw(REHex::DocumentCtrl &doc_ctrl, wxDC &dc, int x, int64_t y) override;
			};
			
			wxToolBarToolBase *show_offsets_button;
			wxToolBarToolBase *show_ascii_button;
			wxToolBarToolBase *fold_button;
			
			wxStatusBar *statbar;
			wxGauge *sb_gauge;
			
			std::list<Range> ranges;
			bool enable_folding;
			
			static const size_t MAX_COMPARE_DATA = 16384; /**< Maximum amount of data to process in a single idle event. */
			
			bool recalc_bytes_per_line_pending;
			
			ByteRangeSet offsets_pending;    /**< Bytes which need to be processed (relative to Range base). */
			ByteRangeSet offsets_different;  /**< Bytes which have been processed and have differences (relative to Range base). */
			wxTimer update_regions_timer;
			
			off_t relative_cursor_pos;  /**< Current cursor position (relative to Range base). */
			off_t longest_range;        /**< Length of the longest Range. */
			
			bool searching_backwards;
			bool searching_forwards;
			wxProgressDialog *search_modal;
			bool search_modal_updating;
			
			#ifdef DIFFWINDOW_PROFILING
			unsigned idle_ticks;
			double idle_secs;
			off_t idle_bytes;
			unsigned odsr_calls;
			#endif
			
			std::list<Range>::iterator remove_range(std::list<Range>::iterator range, bool called_from_page_closed_handler);
			
			void doc_update(Range *range);
			std::string range_title(Range *range);
			void resize_splitters();
			void recalc_bytes_per_line();
			void set_relative_cursor_pos(off_t relative_cursor_pos);
			off_t process_now(off_t rel_offset, off_t length);
			void update_longest_range();
			void goto_prev_difference();
			void goto_next_difference();
			
			void OnSize(wxSizeEvent &event);
			void OnIdle(wxIdleEvent &event);
			void OnCharHook(wxKeyEvent &event);
			void OnDocumentTitleChange(DocumentTitleEvent &event);
			void OnDocumentDataErase(OffsetLengthEvent &event);
			void OnDocumentDataInsert(OffsetLengthEvent &event);
			void OnDocumentDataOverwrite(OffsetLengthEvent &event);
			void OnDocumentDisplaySettingsChange(wxCommandEvent &event);
			void OnNotebookClosed(wxAuiNotebookEvent &event);
			void OnCursorUpdate(CursorUpdateEvent &event);
			void OnDataRightClick(wxCommandEvent &event);
			void OnToggleOffsets(wxCommandEvent &event);
			void OnToggleASCII(wxCommandEvent &event);
			void OnToggleFold(wxCommandEvent &event);
			void OnPrevDifference(wxCommandEvent &event);
			void OnNextDifference(wxCommandEvent &event);
			void OnUpdateRegionsTimer(wxTimerEvent &event);
			
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_DIFFWINDOW_HPP */
