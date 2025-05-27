/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <queue>
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
#include "RangeProcessor.hpp"
#include "SafeWindowPointer.hpp"
#include "SharedDocumentPointer.hpp"
#include "ToolPanel.hpp"

namespace REHex {
	class StringPanel: public ToolPanel
	{
		private:
			class StringPanelListCtrl: public wxListCtrl
			{
				public:
					StringPanelListCtrl(StringPanel *parent);
					
				public:
					virtual wxString OnGetItemText(long item, long column) const override;
			};
			
			/**
			 * @brief Batch of strings detected/cleared by worker threads.
			 *
			 * Each call to work_func() takes ownership of a Batch structure and adds
			 * any ranges to be set/cleared in the strings table to avoid all worker
			 * threads bottlenecking on serialised access to the shared table.
			 *
			 * Batched changes are periodically flushed to the main strings table while
			 * scanning and at the end of a search, or before any data is inserted or
			 * erased to ensure that there are no mid-air collisions in the queue.
			*/
			struct Batch
			{
				ByteRangeSet ranges_to_set;
				ByteRangeSet ranges_to_clear;
				
				int ttl; /**< Remaining number of times this batch can be locked
				          *   before it must be flushed even if under threshold.
				         */
			};
			
		public:
			StringPanel(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			~StringPanel();
			
			virtual std::string name() const override;
			virtual std::string label() const override;
			virtual Shape shape() const override;
			
			virtual void save_state(wxConfig *config) const override;
			virtual void load_state(wxConfig *config) override;
			virtual void update() override;
			
			virtual wxSize DoGetBestClientSize() const override;
			
			ByteRangeSet get_strings();
			off_t get_clean_bytes();
			void set_encoding(const std::string &encoding_key);
			void set_min_string_length(int min_string_length);
			
			void select_all();
			void select_by_file_offset(off_t offset);
			
			wxString copy_get_string(wxString (*get_item_func)(StringPanelListCtrl*, int));
			void do_copy(wxString (*get_item_func)(StringPanelListCtrl*, int));
			
			static wxString get_item_string(StringPanelListCtrl *list_ctrl, int item_idx);
			static wxString get_item_offset_and_string(StringPanelListCtrl *list_ctrl, int item_idx);
			
			bool search_pending() const;
			
		private:
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
			
			RangeProcessor processor;
			wxTimer timer;
			
			bool m_search_pending; /**< Ready to scan file whenever tool is visible. */
			bool m_search_running; /**< Search is running in the background. */
			
			off_t search_base;
			
			void mark_dirty_pad(off_t offset, off_t length);
			off_t sum_dirty_bytes();
			off_t sum_clean_bytes();
			
			void start_search();
			void suspend_search();
			void stop_search();
			
			void restart_search();
			
			void work_func(off_t window_base, off_t window_length);
			
			std::mutex m_batch_mutex;        /**< Mutex for m_batch_queue. */
			std::queue<Batch> m_batch_queue; /**< Queue of unlocked Batch objects. */
			
			/**
			 * @brief Lock a Batch from the queue or allocate a new one.
			*/
			Batch next_batch();
			
			/**
			 * @brief Return a Batch to the queue.
			*/
			void release_batch(Batch &&batch);
			
			/**
			 * @brief Flush changes from a Batch to the strings table.
			 *
			 * @param batch  Batch object.
			 * @param force  Force flush even if below required number of changes.
			*/
			void flush_batch(Batch *batch, bool force);
			
			/**
			 * @brief Flush changes from all Batch objects in the queue.
			*/
			void flush_all_batches();
			
			void do_export(wxString (*get_item_func)(StringPanelListCtrl*, int));
			
			void OnDataModifying(OffsetLengthEvent &event);
			void OnDataModifyAborted(OffsetLengthEvent &event);
			void OnDataErase(OffsetLengthEvent &event);
			void OnDataInsert(OffsetLengthEvent &event);
			void OnDataOverwrite(OffsetLengthEvent &event);
			void OnItemActivate(wxListEvent &event);
			void OnItemRightClick(wxListEvent &event);
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
