/* Reverse Engineer's Hex Editor
 * Copyright (C) 2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_PROXYDROPTARGET_HPP
#define REHEX_PROXYDROPTARGET_HPP

#include <wx/dnd.h>
#include <wx/event.h>

namespace REHex
{
	class DropEvent;

	wxDECLARE_EVENT(DROP_ENTER, DropEvent);
	wxDECLARE_EVENT(DROP_LEAVE, DropEvent);
	wxDECLARE_EVENT(DROP_MOTION, DropEvent);
	wxDECLARE_EVENT(DROP_DROP, DropEvent);
	wxDECLARE_EVENT(DROP_DATA, DropEvent);
	
	/**
	 * @brief wxDropTarget implementation which raises events in a target wxEvtHandler
	 *
	 * @param handler  wxEvtHandler to receive events.
	 * @param data     Initial wxDataObject to receive data.
	 *
	 * This class proxies wxDropTarget to a wxWindow or other wxEvtHandler to be processed there.
	 *
	 * The following events will be raised:
	 *
	 * DROP_ENTER   - Pointer entered drop target.
	 * DROP_LEAVE   - Pointer left drop target.
	 * DROP_MOTION  - Pointer moved within drop target.
	 * DROP_DROP    - Mouse button was released over drop target.
	 * DROP_DATA    - Raised after DROP_DROP accepts the data.
	*/
	class ProxyDropTarget: public wxDropTarget
	{
		private:
			wxEvtHandler *m_handler;

		public:
			ProxyDropTarget(wxEvtHandler *handler, wxDataObject *data = NULL);

			virtual wxDragResult OnData(wxCoord x, wxCoord y, wxDragResult defResult) override;
			virtual wxDragResult OnDragOver(wxCoord x, wxCoord y, wxDragResult defResult) override;
			virtual bool OnDrop(wxCoord x, wxCoord y) override;
			virtual wxDragResult OnEnter(wxCoord x, wxCoord y, wxDragResult defResult) override;
			virtual void OnLeave() override;
	};

	/**
	 * @brief Event object raised by ProxyDropTarget
	*/
	class DropEvent: public wxEvent
	{
		private:
			wxCoord m_x, m_y;

			wxDragResult m_default_result;
			wxDragResult m_result;

			bool m_accept;

		public:
			DropEvent(wxEventType eventType, wxCoord x, wxCoord y, wxDragResult defResult);
			virtual ~DropEvent() override = default;

			virtual wxEvent *Clone() const override;

			/**
			 * @brief Returns the mouse position within the drop target.
			 *
			 * Valid for DROP_ENTER, DROP_MOTION, DROP_DROP and DROP_DATA events.
			*/
			wxCoord GetX() const;
			
			/**
			 * @brief Returns the mouse position within the drop target.
			 *
			 * Valid for DROP_ENTER, DROP_MOTION, DROP_DROP and DROP_DATA events.
			*/
			wxCoord GetY() const;

			/**
			 * @brief Returns the requested drag type (move/copy/etc).
			 *
			 * Valid for DROP_ENTER, DROP_MOTION and DROP_DATA events.
			*/
			wxDragResult GetDefaultResult() const;
			
			/**
			 * @brief Set the drag event type.
			 *
			 * Valid for DROP_ENTER, DROP_MOTION and DROP_DATA events. Defaults to the value
			 * returned by GetDefaultResult().
			*/
			void SetResult(wxDragResult result);

			/**
			 * @brief Accept the data in a DROP_DROP event.
			 *
			 * The default behaviour is to accept data if AcceptData() or RejectData() is not
			 * called within the DROP_DROP event.
			*/
			void AcceptData(bool accept = true);
			
			/**
			 * @brief Reject the data in a DROP_DROP event.
			 * * The default behaviour is to accept data if AcceptData() or RejectData() is not
			 * called within the DROP_DROP event.
			*/
			void RejectData();

		friend ProxyDropTarget;
	};
}

#endif /* !REHEX_PROXYDROPTARGET_HPP */
