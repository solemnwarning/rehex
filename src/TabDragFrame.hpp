/* Reverse Engineer's Hex Editor
 * Copyright (C) 2022 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_TABDRAGFRAME_HPP
#define REHEX_TABDRAGFRAME_HPP

#include <wx/frame.h>

#include "mainwindow.hpp"
#include "Tab.hpp"

/* When we detatch the only tab in a MainWindow, we destroy that MainWindow, and destroying a
 * wxFrame while holding down the mouse button seems to upset mouse capture on both Windows and
 * macOS:
 *
 * On Windows, the capture supposedly succeeds (even win32 tells us we own it), but we only get
 * mouse events when the cursor is over the window.
 *
 * On macOS, the capture supposedly succeeds, but it doesn't take effect until the button is
 * released (which we don't get the event for).
 *
 * I've tried lots of hacky work-arounds, from moving the CaptureMouse() call into wxEVT_IDLE, to
 * deferring it even more with a timer to hooking the wxEVT_DESTROY of the MainWindow that is being
 * disposed of, it seems to straight-up be a no-go on those platforms right now... so we poll the
 * mouse position/state on a timer like cavemen and hope for the best. This will probably interact
 * badly in situations where we *should* lose the capture (e.g. task switching).
*/
#if defined(WIN32) || defined(__APPLE__)
#define REHEX_TABDRAGFRAME_FAKE_CAPTURE
#endif

namespace REHex
{
	class TabDragFrame: public wxFrame
	{
		public:
			TabDragFrame(Tab *tab, wxSize original_window_size);
			~TabDragFrame();
			
			static TabDragFrame *get_instance();
			
		private:
			static TabDragFrame *instance;
			
			Tab *tab;
			wxSize original_window_size;
			bool dragging;
			
			void drop();
			
#ifdef REHEX_TABDRAGFRAME_FAKE_CAPTURE
			wxTimer mouse_poll_timer;
			void OnMousePoll(wxTimerEvent &event);
#else
			void OnMotion(wxMouseEvent &event);
			void OnCaptureLost(wxMouseCaptureLostEvent &event);
			void OnLeftUp(wxMouseEvent &event);
#endif
		
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_TABDRAGFRAME_HPP */
