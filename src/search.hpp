/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_SEARCH_HPP
#define REHEX_SEARCH_HPP

#include <atomic>
#include <mutex>
#include <set>
#include <string>
#include <sys/types.h>
#include <thread>
#include <vector>
#include <wx/checkbox.h>
#include <wx/choice.h>
#include <wx/combobox.h>
#include <wx/progdlg.h>
#include <wx/radiobut.h>
#include <wx/textctrl.h>
#include <wx/timer.h>

#include "CharacterEncoder.hpp"
#include "document.hpp"
#include "NumericTextCtrl.hpp"
#include "SharedDocumentPointer.hpp"

namespace REHex {
	class Search: public wxDialog {
		public:
			enum class SearchDirection { FORWARDS = 1, BACKWARDS = -1 };
			
			class Text;
			class ByteSequence;
			class Value;
			
			static const size_t DEFAULT_WINDOW_SIZE = 2134016; /* 2MiB */
			
		protected:
			SharedDocumentPointer doc;
			
			off_t range_begin, range_end;
			off_t align_to, align_from;
			
			wxCheckBox *range_cb;
			wxTextCtrl *range_begin_tc, *range_end_tc;
			
			wxCheckBox *align_cb;
			wxTextCtrl *align_tc;
			
			wxCheckBox *ralign_cb;
			wxTextCtrl *ralign_tc;
			
			std::mutex lock;
			std::list<std::thread> threads;
			std::atomic<off_t> next_window_start;
			std::atomic<off_t> match_found_at;
			std::atomic<bool> running;
			
			/* Start and end (inclusive) of current search. */
			off_t search_base;
			off_t search_end;
			
			SearchDirection search_direction;
			
			wxWindow *m_saved_focus;
			long m_saved_focus_from, m_saved_focus_to;
			
			void save_focus(wxWindow *control);
			void restore_focus();
			
			wxProgressDialog *progress;
			wxTimer timer;
			
			bool auto_close;
			bool auto_wrap;
			wxWindow *modal_parent;
			
		protected:
			Search(wxWindow *parent, SharedDocumentPointer &doc, const char *title);
			
			void setup_window();
			virtual void setup_window_controls(wxWindow *parent, wxSizer *sizer) = 0;
			virtual bool read_window_controls() = 0;
			
			virtual bool wrap_query(const char *message);
			virtual void not_found_notification();
			
		public:
			void limit_range(off_t range_begin, off_t range_end, OffsetBase fmt_base = OffsetBase::OFFSET_BASE_DEC);
			void require_alignment(off_t alignment, off_t relative_to_offset = 0);
			
			void set_auto_close(bool auto_close);
			void set_auto_wrap(bool auto_wrap);
			void set_modal_parent(wxWindow *modal_parent);
			
			off_t find_next(off_t from_offset, size_t window_size = DEFAULT_WINDOW_SIZE);
			void begin_search(off_t range_begin, off_t range_end, SearchDirection direction, size_t window_size = DEFAULT_WINDOW_SIZE);
			void end_search();
			
			virtual bool test(const void *data, size_t data_size) = 0;
			virtual size_t test_max_window() = 0;
			
			void OnCheckBox(wxCommandEvent &event);
			void OnFindNext(wxCommandEvent &event);
			void OnFindPrev(wxCommandEvent &event);
			void OnTextEnter(wxCommandEvent &event);
			void OnCancel(wxCommandEvent &event);
			void OnTimer(wxTimerEvent &event);
			void OnClose(wxCloseEvent &event);
			
		private:
			void enable_controls();
			bool read_base_window_controls();
			void thread_main(size_t window_size, size_t compare_size);
			
		/* Stays at the bottom because it changes the protection... */
		DECLARE_EVENT_TABLE()
	};
	
	class Search::Text: public Search
	{
		private:
			std::string search_for;
			bool case_sensitive;
			const CharacterEncoding *encoding;
			bool cmp_fast_path;
			
			std::string initial_encoding; /* Only used during initialisation. */
			
			wxComboBox *search_for_tc;
			wxCheckBox *case_sensitive_cb;
			wxChoice *encoding_choice;

			static wxArrayString search_history;
			static std::set<Search::Text*> instances;
			
		public:
			Text(wxWindow *parent, SharedDocumentPointer &doc, const wxString &search_for = "", bool case_sensitive = true, const std::string &encoding = "ASCII");
			virtual ~Text();
			
			virtual bool test(const void *data, size_t data_size);
			virtual size_t test_max_window();
			
			bool set_search_string(const wxString &search_for);
			
		protected:
			virtual void setup_window_controls(wxWindow *parent, wxSizer *sizer);
			virtual bool read_window_controls();
	};
	
	class Search::ByteSequence: public Search
	{
		private:
			std::vector<unsigned char> search_for;
			
			wxTextCtrl *search_for_tc;
			
		public:
			ByteSequence(wxWindow *parent, SharedDocumentPointer &doc, const std::vector<unsigned char> &search_for = std::vector<unsigned char>());
			virtual ~ByteSequence();
			
			virtual bool test(const void *data, size_t data_size);
			virtual size_t test_max_window();
			
		protected:
			virtual void setup_window_controls(wxWindow *parent, wxSizer *sizer);
			virtual bool read_window_controls();
	};
	
	class Search::Value: public Search
	{
		private:
			std::list< std::vector<unsigned char> > search_for;
			
			NumericTextCtrl *search_for_tc, *epsilon_tc;
			wxCheckBox *i8_cb, *i16_cb,*i32_cb, *i64_cb, *f32_cb, *f64_cb;
			wxRadioButton *e_little, *e_big, *e_either;
			
			bool be_enabled, le_enabled;
			bool f32_enabled, f64_enabled;
			float f32_value, f32_epsilon;
			double f64_value, f64_epsilon;
		
		public:
			Value(wxWindow *parent, SharedDocumentPointer &doc);
			virtual ~Value();
			
			static const unsigned FMT_LE  = (1 << 0);
			static const unsigned FMT_BE  = (1 << 1);
			static const unsigned FMT_I8  = (1 << 2);
			static const unsigned FMT_I16 = (1 << 3);
			static const unsigned FMT_I32 = (1 << 4);
			static const unsigned FMT_I64 = (1 << 5);
			static const unsigned FMT_F32 = (1 << 6);
			static const unsigned FMT_F64 = (1 << 7);
			
			void configure(const std::string &value, unsigned formats, const std::string &epsilon = "0");
			
			virtual bool test(const void *data, size_t data_size);
			virtual size_t test_max_window();
			
		protected:
			virtual void setup_window_controls(wxWindow *parent, wxSizer *sizer);
			virtual bool read_window_controls();
			
		private:
			void OnText(wxCommandEvent &event);
	};
}

#endif /* !REHEX_SEARCH_HPP */
