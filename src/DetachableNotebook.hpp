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

#ifndef REHEX_DETATCHABLENOTEBOOK_HPP
#define REHEX_DETATCHABLENOTEBOOK_HPP

#include <wx/aui/auibook.h>
#include <wx/frame.h>
#include <wx/timer.h>

//#define REHEX_TABDRAGFRAME_FAKE_CAPTURE

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
	class DetachedPageEvent: public wxEvent
	{
		public:
			wxWindow *page;
			
			DetachedPageEvent(wxWindow *source, wxEventType event);
			
			virtual wxEvent *Clone() const override;
	};
	
	typedef void (wxEvtHandler::*DetachedPageEventFunction)(DetachedPageEvent&);
	
	wxDECLARE_EVENT(EVT_PAGE_DETACHED, DetachedPageEvent);
	wxDECLARE_EVENT(EVT_PAGE_DROPPED, DetachedPageEvent);
	
	/**
	 * @brief wxAuiNotebook-derived control that allows detatching tabs by dragging.
	 *
	 * This control is a wxAuiNotebook with an unhealthy amount of shimming and monkey patching
	 * to enable dragging tabs between windows and even dragging them away to form new ones.
	 *
	 * When dragging a tab around within the wxAuiNotebook tab area, the base class handles
	 * everything. When we detect the user trying to drag the tab outside of the control, we
	 * create a new wxFrame to hold the page, move the page wxWindow into it and trick the
	 * control into not doing anything else, while we handle moving the new wxFrame around with
	 * the mouse until the user either re-inserts it back into a DetachableNotebook, or lets
	 * go of the button to create a new window containing the page.
	 *
	 * This class introduces the following extra events on top of wxAuiNotebook:
	 *
	 * EVT_PAGE_DETACHED
	 *
	 * Raised when a tab is detatched from the DetachableNotebook control, but still being
	 * dragged. After this point the page is no longer directly owned by the DetachableNotebook
	 * and no further events will come directly from it. The DetachableNotebook *MAY* be
	 * destroyed by the owner after this point.
	 *
	 * EVT_PAGE_DROPPED
	 *
	 * Raised when a tab that has been detatched is "dropped" somewhere other than the tab bar
	 * of a suitable DetachableNotebook control. This event *MUST* be handled and should deal
	 * with relocating the page into a new/existing window.
	 *
	 * This event is not (necessarily) raised from the DetachableNotebook control. A pointer to
	 * a different wxEvtHandler to dispatch the event through may be provided to the
	 * DetachableNotebook constructor to allow destroying the DetachableNotebook when a tab has
	 * been detatched from it.
	*/
	class DetachableNotebook: public wxAuiNotebook
	{
		public:
			/**
			 * @brief Construct a new DetachableNotebook.
			 *
			 * @param parent See wxAuiNotebook.
			 * @param id See wxAuiNotebook.
			 * @param page_drop_group If not NULL, is an opaque pointer identifying a
			 *                        group of DetachableNotebook controls which allow
			 *                        tabs to be moved between them.
			 * @param detached_page_handler If not NULL, is a wxEvtHandler to dispatch
			 *                              events from detatched pages.
			 * @param pos See wxAuiNotebook.
			 * @param size See wxAuiNotebook.
			 * @param style See wxAuiNotebook.
			*/
			DetachableNotebook(wxWindow *parent, wxWindowID id = wxID_ANY, const void *page_drop_group = NULL, wxEvtHandler *detached_page_handler = NULL, const wxPoint &pos = wxDefaultPosition, const wxSize &size = wxDefaultSize, long style = wxAUI_NB_DEFAULT_STYLE);
			virtual ~DetachableNotebook();
			
		private:
			const void *page_drop_group;
			wxEvtHandler *detached_page_handler;
			wxWindow *deferred_drag_page;
			
			void restart_drag(wxWindow *page);
			
			void OnTabDragMotion(wxAuiNotebookEvent &event);
			void OnIdle(wxIdleEvent &event);
			
			/**
			 * @brief Owner of a detatched DetachableNotebook page.
			 *
			 * Owns the wxWindow of a detatched DetachableNotebook page and handles
			 * re-inserting it back into a DetachableNotebook or transferring it to a
			 * new owner.
			*/
			class DragFrame: public wxFrame
			{
				public:
					DragFrame(wxWindow *page, const wxString &page_caption, const wxBitmap &page_bitmap, const void *page_drop_group, wxEvtHandler *detached_page_handler);
					~DragFrame();
					
					const void *page_drop_group;
					wxEvtHandler *detached_page_handler;
					
					static DragFrame *get_instance();
					
				private:
					static DragFrame *instance;
					
					wxAuiNotebook *notebook;
					wxWindow *page;
					wxString page_caption;
					wxBitmap page_bitmap;
					wxSize original_tab_size;
					bool dragging;
					
					void drag(const wxPoint &mouse_pos);
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
			
			friend DragFrame;
	};
	
	#define EVT_DETACHABLENOTEBOOK_PAGE_DETACHED(winid, func) \
		wx__DECLARE_EVT1(REHex::EVT_PAGE_DETACHED, winid, wxEVENT_HANDLER_CAST(DetachedPageEventFunction, func))
}

#endif /* !REHEX_DETATCHABLENOTEBOOK_HPP*/
