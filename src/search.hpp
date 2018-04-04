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

#include <string>
#include <sys/types.h>
#include <wx/checkbox.h>
#include <wx/textctrl.h>

#include "document.hpp"

namespace REHex {
	class Search: public wxDialog {
		public:
			class Text;
			class ByteSequence;
			class Value;
			
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
			
		protected:
			Search(wxWindow *parent, REHex::Document &doc);
			
			virtual bool test(off_t offset, off_t max_length) = 0;
			
			void setup_window();
			virtual void setup_window_controls(wxWindow *parent, wxSizer *sizer) = 0;
			virtual bool read_window_controls() = 0;
			
		public:
			void limit_range(off_t range_begin, off_t range_end);
			void require_alignment(off_t alignment, off_t relative_to_offset = 0);
			
			virtual off_t find_next(off_t from_offset);
			
			void OnCheckBox(wxCommandEvent &event);
			void OnFindNext(wxCommandEvent &event);
			
		private:
			void enable_controls();
			bool read_base_window_controls();
			
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
			virtual bool test(off_t offset, off_t max_length);
			
			virtual void setup_window_controls(wxWindow *parent, wxSizer *sizer);
			virtual bool read_window_controls();
	};
	
	class Search::ByteSequence: public Search
	{
		
	};
	
	class Search::Value: public Search
	{
		
	};
}

#endif /* !REHEX_SEARCH_HPP */
