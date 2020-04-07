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
#include <utility>
#include <vector>
#include <wx/control.h>
#include <wx/wx.h>

#include "util.hpp"

namespace REHex {
	class CodeCtrl: public wxControl {
		public:
			CodeCtrl(wxWindow *parent, wxWindowID id = wxID_ANY);
			
			void append_line(off_t offset, const std::string &text, bool active = false);
			void clear();
			
			void center_line(int line);
			
			void set_offset_display(OffsetBase offset_display_base, off_t offset_display_upper_bound);
			
		private:
			static const int MOUSE_SELECT_INTERVAL = 100;
			
			struct Line {
				off_t offset;
				std::string text;
				bool active;
				
				Line(off_t offset, const std::string &text, bool active):
					offset(offset), text(text), active(active) {}
			};
			
			typedef std::pair<int, int> CodeCharRef;
			
			wxFont *font;
			int font_width;
			int font_height;
			int code_xoff;
			
			std::vector<Line> lines;
			int max_line_width;
			
			OffsetBase offset_display_base;
			off_t offset_display_upper_bound;
			
			int scroll_xoff, scroll_xoff_max;
			int scroll_yoff, scroll_yoff_max;
			int wheel_vert_accum;
			int wheel_horiz_accum;
			
			bool mouse_selecting;
			wxTimer mouse_selecting_timer;
			CodeCharRef mouse_selecting_from;
			CodeCharRef mouse_selecting_to;
			
			/* If text has been selected, selection_end will be greater than selection_end.
			 *
			 * selection_begin points to first character in selection.
			 * selection_end points one past the last character on the final line.
			*/
			CodeCharRef selection_begin;
			CodeCharRef selection_end;
			
			void update_scrollbars();
			CodeCharRef char_near_abs_xy(int abs_x, int abs_y);
			CodeCharRef char_near_rel_xy(int rel_x, int rel_y);
			void copy_selection();
			void select_all();
			
			void OnPaint(wxPaintEvent &event);
			void OnSize(wxSizeEvent &event);
			void OnScroll(wxScrollWinEvent &event);
			void OnWheel(wxMouseEvent &event);
			void OnChar(wxKeyEvent &event);
			void OnLeftDown(wxMouseEvent &event);
			void OnLeftUp(wxMouseEvent &event);
			void OnRightDown(wxMouseEvent &event);
			void OnCopy(wxCommandEvent &event);
			void OnSelectAll(wxCommandEvent &event);
			void OnMotion(wxMouseEvent &event);
			void OnSelectTick(wxTimerEvent &event);
			void OnMotionTick(int mouse_x, int mouse_y);
			
			/* Stays at the bottom because it changes the protection... */
			DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_CODECTRL_HPP */
