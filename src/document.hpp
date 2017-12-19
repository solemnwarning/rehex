/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_DOCUMENT_HPP
#define REHEX_DOCUMENT_HPP

#include <stdint.h>
#include <wx/wx.h>

#include "buffer.hpp"

namespace REHex {
	class Document: public wxControl {
		public:
			Document(wxWindow *parent, wxWindowID id, const wxPoint &pos, const wxSize &size, REHex::Buffer *buffer);
			
			void OnPaint(wxPaintEvent &event);
			void OnSize(wxSizeEvent &event);
			void OnScroll(wxScrollWinEvent &event);
			void OnChar(wxKeyEvent &event);
			
		private:
			Buffer *buffer;
			
			wxFont *hex_font;
			
			unsigned int line_bytes_cfg{16};
			unsigned int line_bytes_calc;
			unsigned int group_bytes{4};
			
			unsigned int scroll_xoff{0};
			uint64_t     scroll_yoff{0};
			
			size_t cpos_off{0};
			bool cpos_high{true};
			
			DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_DOCUMENT_HPP */
