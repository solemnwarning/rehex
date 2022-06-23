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

#ifndef REHEX_STRINGPANEL_HPP
#define REHEX_STRINGPANEL_HPP

#include <atomic>
#include <condition_variable>
#include <list>
#include <mutex>
#include <stddef.h>
#include <thread>
#include <wx/animate.h>
#include <wx/bmpbuttn.h>
#include <wx/checkbox.h>
#include <wx/choice.h>
#include <wx/listctrl.h>
#include <wx/panel.h>
#include <wx/spinctrl.h>
#include <wx/stattext.h>
#include <wx/timer.h>
#include <wx/wx.h>

#include "ByteRangeSet.hpp"
#include "CharacterEncoder.hpp"
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
			
			ByteRangeSet get_strings();
			off_t get_clean_bytes();
			size_t get_num_threads();
			void set_encoding(const std::string &encoding_key);
			void set_min_string_length(int min_string_length);
			
		private:
			class StringPanelListCtrl: public wxListCtrl
			{
				public:
					StringPanelListCtrl(StringPanel *parent);
					
				protected:
					virtual wxString OnGetItemText(long item, long column) const override;
			};
			
			SharedDocumentPointer document;
			SafeWindowPointer<DocumentCtrl> document_ctrl;
			
			StringPanelListCtrl *list_ctrl;
			wxStaticText *status_text;
			
			wxChoice *encoding_choice;
			const CharacterEncoding *selected_encoding;
			
			wxSpinCtrl *min_string_length_ctrl;
			int min_string_length;
			
			wxCheckBox *ignore_cjk_check;
			bool ignore_cjk;
			
			wxBitmapButton *reset_button;
			wxBitmapButton *continue_button;
			wxAnimationCtrl *spinner;
			
			std::mutex strings_lock;
			ByteRangeSet strings;
			bool update_needed;
			
			std::list<std::thread> threads;  /* List of threads created and not yet reaped. */
			std::atomic<bool> threads_exit;  /* Threads should exit. */
			wxTimer timer;
			
			std::mutex pause_lock;              /* Mutex protecting access to this block of members: */
			std::atomic<bool> threads_pause;    /* Running threads should enter paused state. */
			unsigned int spawned_threads;       /* Number of threads created. */
			unsigned int running_threads;       /* Number of threads not paused. */
			std::condition_variable paused_cv;  /* Notifies pause_threads() that a thread has paused. */
			std::condition_variable resume_cv;  /* Notifies paused threads that they should resume. */
			ByteRangeSet dirty;                 /* Ranges which are dirty, but not yet ready to be processed. */
			ByteRangeSet pending;               /* Ranges waiting to be processed. */
			ByteRangeSet working;               /* Ranges currently being processed. */
			off_t search_base;
			
			void mark_dirty(off_t offset, off_t length);
			void mark_dirty_pad(off_t offset, off_t length);
			void mark_work_done(off_t offset, off_t length);
			off_t sum_dirty_bytes();
			off_t sum_clean_bytes();
			
			void thread_main();
			void thread_flush(ByteRangeSet *set_ranges, ByteRangeSet *clear_ranges, bool force);
			void start_threads();
			void stop_threads();
			void pause_threads();
			void resume_threads();
			
			void OnDataModifying(OffsetLengthEvent &event);
			void OnDataModifyAborted(OffsetLengthEvent &event);
			void OnDataErase(OffsetLengthEvent &event);
			void OnDataInsert(OffsetLengthEvent &event);
			void OnDataOverwrite(OffsetLengthEvent &event);
			void OnItemActivate(wxListEvent &event);
			void OnTimerTick(wxTimerEvent &event);
			void OnEncodingChanged(wxCommandEvent &event);
			void OnReset(wxCommandEvent &event);
			void OnContinue(wxCommandEvent &event);
			void OnMinStringLength(wxSpinEvent &event);
			void OnCJKToggle(wxCommandEvent &event);
			
		DECLARE_EVENT_TABLE()
		
		friend StringPanelListCtrl;
	};
}

#endif /* !REHEX_STRINGPANEL_HPP */
