/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <string>
#include <sys/types.h>
#include <thread>
#include <wx/checkbox.h>
#include <wx/textctrl.h>

#include "document.hpp"
#include "NumericTextCtrl.hpp"

namespace REHex {
	class Search: public wxDialog {
		public:
			class Text;
			class ByteSequence;
			class Value;
			
			static const size_t DEFAULT_WINDOW_SIZE = 2134016; /* 2MiB */
			
		protected:
			REHex::Document &doc;
			
			off_t range_begin, range_end;
			off_t align_to, align_from;
			
		private:
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
			
		protected:
			Search(wxWindow *parent, REHex::Document &doc, const char *title);
			
			virtual bool test(const unsigned char *data, size_t data_size) = 0;
			virtual size_t test_max_window() = 0;
			
			void setup_window();
			virtual void setup_window_controls(wxWindow *parent, wxSizer *sizer) = 0;
			virtual bool read_window_controls() = 0;
			
		public:
			void limit_range(off_t range_begin, off_t range_end);
			void require_alignment(off_t alignment, off_t relative_to_offset = 0);
			
			off_t find_next(off_t from_offset, size_t window_size = DEFAULT_WINDOW_SIZE);
			void begin_search(off_t from_offset, size_t window_size = DEFAULT_WINDOW_SIZE);
			void end_search();
			
			void OnCheckBox(wxCommandEvent &event);
			void OnFindNext(wxCommandEvent &event);
			
		private:
			void enable_controls();
			bool read_base_window_controls();
			void thread_main(size_t window_size, size_t compare_size, off_t end);
			
		/* Stays at the bottom because it changes the protection... */
		DECLARE_EVENT_TABLE()
	};
	
	class Search::Text: public Search
	{
		private:
			std::string search_for;
			bool case_sensitive;
			
			wxTextCtrl *search_for_tc;
			wxCheckBox *case_sensitive_cb;
			
		public:
			Text(wxWindow *parent, REHex::Document &doc, const std::string &search_for = "", bool case_sensitive = true);
			
		protected:
			virtual bool test(const unsigned char *data, size_t data_size);
			virtual size_t test_max_window();
			
			virtual void setup_window_controls(wxWindow *parent, wxSizer *sizer);
			virtual bool read_window_controls();
	};
	
	class Search::ByteSequence: public Search
	{
		private:
			std::vector<unsigned char> search_for;
			
			wxTextCtrl *search_for_tc;
			
		public:
			ByteSequence(wxWindow *parent, REHex::Document &doc, const std::vector<unsigned char> &search_for = std::vector<unsigned char>());
			
		protected:
			virtual bool test(const unsigned char *data, size_t data_size);
			virtual size_t test_max_window();
			
			virtual void setup_window_controls(wxWindow *parent, wxSizer *sizer);
			virtual bool read_window_controls();
	};
	
	class Search::Value: public Search
	{
		private:
			std::list< std::vector<unsigned char> > search_for;
			
			NumericTextCtrl *search_for_tc;
			wxCheckBox *t_u8_cb, *t_s8_cb;
			wxCheckBox *t_u16be_cb, *t_u16le_cb, *t_s16be_cb, *t_s16le_cb;
			wxCheckBox *t_u32be_cb, *t_u32le_cb, *t_s32be_cb, *t_s32le_cb;
			wxCheckBox *t_u64be_cb, *t_u64le_cb, *t_s64be_cb, *t_s64le_cb;
		
		public:
			Value(wxWindow *parent, REHex::Document &doc);
			
		protected:
			virtual bool test(const unsigned char *data, size_t data_size);
			virtual size_t test_max_window();
			
			virtual void setup_window_controls(wxWindow *parent, wxSizer *sizer);
			virtual bool read_window_controls();
			
		private:
			void OnText(wxCommandEvent &event);
	};
}

#endif /* !REHEX_SEARCH_HPP */
