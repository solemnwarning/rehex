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

#ifndef REHEX_CODECTRL_HPP
#define REHEX_CODECTRL_HPP

#include <string>
#include <list>
#include <wx/control.h>
#include <wx/wx.h>

namespace REHex {
	class CodeCtrl: public wxControl {
		public:
			CodeCtrl(wxWindow *parent, wxWindowID id = wxID_ANY);
			
			void append_line(off_t offset, const std::string &text, bool active = false);
			void clear();
			
			void center_line(int line);
			
		private:
			struct Line {
				off_t offset;
				std::string text;
				bool active;
				
				Line(off_t offset, const std::string &text, bool active):
					offset(offset), text(text), active(active) {}
			};
			
			wxFont *font;
			int font_width;
			int font_height;
			
			std::list<Line> lines;
			int max_line_width;
			
			int scroll_xoff, scroll_xoff_max;
			int scroll_yoff, scroll_yoff_max;
			int wheel_vert_accum;
			int wheel_horiz_accum;
			
			void update_scrollbars();
			
			void OnPaint(wxPaintEvent &event);
			void OnSize(wxSizeEvent &event);
			void OnScroll(wxScrollWinEvent &event);
			void OnWheel(wxMouseEvent &event);
			
			/* Stays at the bottom because it changes the protection... */
			DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_CODECTRL_HPP */
