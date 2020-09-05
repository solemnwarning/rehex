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

#ifndef REHEX_STRINGPANEL_HPP
#define REHEX_STRINGPANEL_HPP

#include <atomic>
#include <condition_variable>
#include <list>
#include <mutex>
#include <stddef.h>
#include <thread>
#include <wx/listctrl.h>
#include <wx/panel.h>
#include <wx/timer.h>
#include <wx/wx.h>

#include "ByteRangeSet.hpp"
#include "document.hpp"
#include "Events.hpp"
#include "SafeWindowPointer.hpp"
#include "SharedDocumentPointer.hpp"
#include "ToolPanel.hpp"

namespace REHex {
	class StringPanel: public ToolPanel
	{
		public:
			StringPanel(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			~StringPanel();
			
			virtual std::string name() const override;
// 			virtual std::string label() const override;
// 			virtual Shape shape() const override;
			
			virtual void save_state(wxConfig *config) const override;
			virtual void load_state(wxConfig *config) override;
			virtual void update() override;
			
			virtual wxSize DoGetBestClientSize() const override;
			
		private:
			class StringPanelListCtrl: public wxListCtrl
			{
				public:
					StringPanelListCtrl(StringPanel *parent);
					
				protected:
					virtual wxString OnGetItemText(long item, long column) const override;
					
				private:
					StringPanel *instance;
			};
			
			SharedDocumentPointer document;
			SafeWindowPointer<DocumentCtrl> document_ctrl;
			
			StringPanelListCtrl *list_ctrl;
			
			std::mutex dirty_lock;
			ByteRangeSet dirty;
			
			std::mutex strings_lock;
			ByteRangeSet strings;
			bool update_needed;
			
			ssize_t last_item_idx;
			std::set<ByteRangeSet::Range>::const_iterator last_item_iter;
			
			std::list<std::thread> threads;  /* List of threads created and not yet reaped. */
			std::atomic<bool> threads_exit;  /* Threads should exit. */
			
			std::mutex pause_lock;              /* Mutex protecting access to this block of members: */
			std::atomic<bool> threads_pause;    /* Running threads should enter paused state. */
			unsigned int spawned_threads;       /* Number of threads created. */
			unsigned int running_threads;       /* Number of threads not paused. */
			std::condition_variable paused_cv;  /* Notifies pause_threads() that a thread has paused. */
			std::condition_variable resume_cv;  /* Notifies paused threads that they should resume. */
			
			void thread_main();
			void start_threads();
			void stop_threads();
			void pause_threads();
			void resume_threads();
			
			std::set<ByteRangeSet::Range>::const_iterator get_nth_string(ssize_t n);
			
			void OnDataModifying(OffsetLengthEvent &event);
			void OnDataModifyAborted(OffsetLengthEvent &event);
			void OnDataErase(OffsetLengthEvent &event);
			void OnDataInsert(OffsetLengthEvent &event);
			void OnDataOverwrite(OffsetLengthEvent &event);
			
		friend StringPanelListCtrl;
	};
}

#endif /* !REHEX_STRINGPANEL_HPP */
