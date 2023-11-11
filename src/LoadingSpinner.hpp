/* Reverse Engineer's Hex Editor
 * Copyright (C) 2023 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_LOADINGSPINNER_HPP
#define REHEX_LOADINGSPINNER_HPP

#include <wx/control.h>
#include <wx/timer.h>

namespace REHex
{
	/**
	 * @brief Control for drawing a loading "spinner"
	 *
	 * Draws an animated spinner to indicate something is happening.
	 *
	 * The control will proportionally scale to arbitrary sizes.
	 *
	 * The background and foreground colour can be controlled using the
	 * wxWindow::SetBackgroundColour() and wxWindow::SetForegroundColour() methods.
	*/
	class LoadingSpinner: public wxControl
	{
		public:
			LoadingSpinner(wxWindow *parent, wxWindowID id = wxID_ANY, const wxPoint &pos = wxDefaultPosition, const wxSize &size = wxDefaultSize, long style = wxBORDER_NONE);
			
		private:
			void OnPaint(wxPaintEvent &event);
			void OnRepaintTimer(wxTimerEvent &event);
			
			wxTimer repaint_timer;
			
		/* Keep at end. */
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_LOADINGSPINNER_HPP */
