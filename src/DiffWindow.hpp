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
#include <wx/aui/auibook.h>
#include <wx/frame.h>
#include <wx/splitter.h>
#include <wx/stattext.h>

#include "document.hpp"
#include "DocumentCtrl.hpp"
#include "Events.hpp"

namespace REHex {
	class DiffWindow: public wxFrame
	{
		public:
			class Range
			{
				private:
					Document *doc;
					
					off_t offset;
					off_t length;
					
					wxSplitterWindow *splitter;
					wxAuiNotebook *notebook;
					DocumentCtrl *doc_ctrl;
					wxStaticText *foo;
					
				public:
					Range(Document *doc, off_t offset, off_t length):
						doc(doc), offset(offset), length(length),
						splitter(NULL), doc_ctrl(NULL) {}
					
				friend DiffWindow;
			};
			
			DiffWindow();
			virtual ~DiffWindow();
			
			const std::list<Range> &get_ranges() const;
			void add_range(const Range &range);
			
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
			
			std::list<Range> ranges;
			
			static DiffWindow *instance;
			
			std::list<Range>::iterator remove_range(std::list<Range>::iterator range);
			
			void doc_update(Range *range);
			void resize_splitters();
			
			void OnDocumentDestroy(wxWindowDestroyEvent &event);
			void OnNotebookClosed(wxAuiNotebookEvent &event);
			
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_DIFFWINDOW_HPP */
