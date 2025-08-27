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

#include "platform.hpp"

#include <assert.h>

#include "ProxyDropTarget.hpp"

wxDEFINE_EVENT(REHex::DROP_ENTER, REHex::DropEvent);
wxDEFINE_EVENT(REHex::DROP_LEAVE, REHex::DropEvent);
wxDEFINE_EVENT(REHex::DROP_MOTION, REHex::DropEvent);
wxDEFINE_EVENT(REHex::DROP_DROP, REHex::DropEvent);
wxDEFINE_EVENT(REHex::DROP_DATA, REHex::DropEvent);

REHex::ProxyDropTarget::ProxyDropTarget(wxEvtHandler *handler, wxDataObject *data):
	wxDropTarget(data),
    m_handler(handler) {}

wxDragResult REHex::ProxyDropTarget::OnData(wxCoord x, wxCoord y, wxDragResult defResult)
{
	DropEvent event(DROP_DATA, x, y, defResult);
	m_handler->ProcessEvent(event);

	return event.m_result;
}

wxDragResult REHex::ProxyDropTarget::OnDragOver(wxCoord x, wxCoord y, wxDragResult defResult)
{
	DropEvent event(DROP_MOTION, x, y, defResult);
	m_handler->ProcessEvent(event);

	return event.m_result;
}

bool REHex::ProxyDropTarget::OnDrop(wxCoord x, wxCoord y)
{
	DropEvent event(DROP_DROP, x, y, wxDragNone);
	m_handler->ProcessEvent(event);

	return event.m_accept;
}

wxDragResult REHex::ProxyDropTarget::OnEnter(wxCoord x, wxCoord y, wxDragResult defResult)
{
	DropEvent event(DROP_ENTER, x, y, defResult);
	m_handler->ProcessEvent(event);

	return event.m_result;
}

void REHex::ProxyDropTarget::OnLeave()
{
    DropEvent event(DROP_LEAVE, -1, -1, wxDragNone);
	m_handler->ProcessEvent(event);
}

REHex::DropEvent::DropEvent(wxEventType eventType, wxCoord x, wxCoord y, wxDragResult defResult):
	wxEvent(0, eventType),
	m_x(x),
	m_y(y),
	m_default_result(defResult),
	m_result(defResult),
	m_accept(true) {}

wxEvent *REHex::DropEvent::Clone() const
{
	return new DropEvent(*this);
}

wxCoord REHex::DropEvent::GetX() const
{
	assert(GetEventType() == DROP_ENTER || GetEventType() == DROP_MOTION || GetEventType() == DROP_DROP || GetEventType() == DROP_DATA);
	return m_x;
}

wxCoord REHex::DropEvent::GetY() const
{
	assert(GetEventType() == DROP_ENTER || GetEventType() == DROP_MOTION || GetEventType() == DROP_DROP || GetEventType() == DROP_DATA);
	return m_y;
}

wxDragResult REHex::DropEvent::GetDefaultResult() const
{
	assert(GetEventType() == DROP_ENTER || GetEventType() == DROP_MOTION || GetEventType() == DROP_DATA);
	return m_default_result;
}

void REHex::DropEvent::SetResult(wxDragResult result)
{
	assert(GetEventType() == DROP_ENTER || GetEventType() == DROP_MOTION || GetEventType() == DROP_DATA);
	m_result = result;
}

void REHex::DropEvent::AcceptData(bool accept)
{
	assert(GetEventType() == DROP_DROP);
	m_accept = accept;
}

void REHex::DropEvent::RejectData()
{
	assert(GetEventType() == DROP_DROP);
	m_accept = false;
}

REHex::ScopedProxyDropTarget::ScopedProxyDropTarget(wxWindow *window, wxEvtHandler *handler, wxDataObject *data)
{
	Add(window, handler, data);
}

REHex::ScopedProxyDropTarget::~ScopedProxyDropTarget()
{
	for(auto it = m_windows.begin(); it != m_windows.end(); ++it)
	{
		if(*it)
		{
			(*it)->SetDropTarget(NULL);
		}
	}
}

REHex::ProxyDropTarget *REHex::ScopedProxyDropTarget::Add(wxWindow *window, wxEvtHandler *handler, wxDataObject *data)
{
	/* wxWidgets will destroy any existing drop target, so we can't restore it afterwards. */
	assert(window->GetDropTarget() == NULL);
	
	ProxyDropTarget *target = new ProxyDropTarget(handler, data);
	
	window->SetDropTarget(target);
	m_windows.emplace_back(window);
	
	return target;
}
