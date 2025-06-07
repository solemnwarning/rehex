/* Reverse Engineer's Hex Editor
 * Copyright (C) 2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_POPUPTIPWINDOW_HPP
#define REHEX_POPUPTIPWINDOW_HPP

#include <wx/popupwin.h>

namespace REHex
{
	/**
	 * @brief Tooltip window.
	*/
	class PopupTipWindow: public wxPopupWindow
	{
		public:
			/**
			 * @brief Create tooltip window.
			 *
			 * This constructor creates a tooltip window positioned relative to the
			 * cursor position expressed in screen co-ordinates.
			*/
			PopupTipWindow(wxWindow *parent, const wxString &text, const wxPoint &cursor_screen_pos);
			
			/**
			 * @brief Create tooltip window.
			 *
			 * This constructor creates a tooltip window positioned relative to the
			 * cursor position expressed in window client co-ordinates.
			*/
			PopupTipWindow(wxWindow *parent, const wxString &text, wxWindow *cursor_window, const wxPoint &cursor_window_pos);
			
			/**
			 * @brief Replace tooltip text.
			*/
			void set_text(const wxString &text);
			
			/**
			 * @brief Move tooltip to track cursor position in screen co-ordinates.
			*/
			void move_to_cursor_screen_position(const wxPoint &cursor_screen_pos);
			
			/**
			 * @brief Move tooltip to track cursor position in window co-ordinates.
			*/
			void move_to_cursor_window_position(wxWindow *cursor_window, const wxPoint &cursor_window_pos);
			
		private:
			wxString text;
			
			void OnPaint(wxPaintEvent &event);
			
		wxDECLARE_EVENT_TABLE();
	};
}

#endif /* !REHEX_POPUPTIPWINDOW_HPP */
