/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <wx/panel.h>
#include <wx/splitter.h>

#include "document.hpp"
#include "DocumentCtrl.hpp"
#include "Events.hpp"
#include "SafeWindowPointer.hpp"
#include "SharedDocumentPointer.hpp"

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
			
		private:
			class DiffDataRegion: public DocumentCtrl::DataRegion
			{
				private:
					DiffWindow *diff_window;
					Range *range;
					
				public:
					DiffDataRegion(off_t d_offset, off_t d_length, DiffWindow *diff_window, Range *range);
					
				protected:
					virtual Highlight highlight_at_off(off_t off) const override;
			};
			
			wxToolBarToolBase *show_offsets_button;
			wxToolBarToolBase *show_ascii_button;
			
			std::list<Range> ranges;
			
			static DiffWindow *instance;
			
			std::list<Range>::iterator remove_range(std::list<Range>::iterator range, bool called_from_page_closed_handler);
			
			void doc_update(Range *range);
			std::string range_title(Range *range);
			void resize_splitters();
			
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
			
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_DIFFWINDOW_HPP */
