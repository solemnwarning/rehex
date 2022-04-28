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

#include "TabDragFrame.hpp"

REHex::TabDragFrame *REHex::TabDragFrame::instance = NULL;

BEGIN_EVENT_TABLE(REHex::TabDragFrame, wxFrame)
	EVT_MOTION(REHex::TabDragFrame::OnMotion)
	EVT_MOUSE_CAPTURE_LOST(REHex::TabDragFrame::OnCaptureLost)
	EVT_LEFT_UP(REHex::TabDragFrame::OnLeftUp)
END_EVENT_TABLE()

REHex::TabDragFrame::TabDragFrame(Tab *tab, wxSize original_window_size):
	wxFrame(NULL, wxID_ANY, "", wxDefaultPosition, tab->GetSize(), (wxFRAME_NO_TASKBAR | wxSTAY_ON_TOP)),
	tab(tab),
	original_window_size(original_window_size),
	dragging(true)
{
	assert(instance == NULL);
	instance = this;
	
	tab->Reparent(this);
	Show();
	
	CallAfter([&]()
	{
		CaptureMouse();
	});
}

REHex::TabDragFrame::~TabDragFrame()
{
	assert(instance == this);
	instance = NULL;
}

void REHex::TabDragFrame::drop()
{
	wxPoint mouse_pos = wxGetMousePosition();
	
	/* We shift the mouse co-ords up/left so that wxFindWindowAtPoint() can return the window
	 * behind us. This is likely to break in lots of situations and needs to be modified such
	 * that we are transparent to the window finding code.
	*/
	wxWindow* drop_window = wxFindWindowAtPoint(wxPoint(mouse_pos.x - 1, mouse_pos.y - 1));
	
	wxAuiTabCtrl *tab_ctrl = NULL;
	MainWindow *window = NULL;
	
	// make sure we are not over the hint window
	if (!wxDynamicCast(drop_window, wxFrame))
	{
		for(
			wxWindow *w = drop_window;
			w != NULL && (tab_ctrl = dynamic_cast<wxAuiTabCtrl*>(w)) == NULL;
			w = w->GetParent()) {}
		
		// TODO: Check its the right kind of wxAuiNotebook
		
		for(
			wxWindow *w = tab_ctrl;
			w != NULL && (window = dynamic_cast<MainWindow*>(w)) == NULL;
			w = w->GetParent()) {}
	}
	
	if(window == NULL)
	{
		window = new MainWindow(original_window_size);
		window->insert_tab(tab, -1);
		window->SetTransparent(127);
		window->Show();
	}
	else{
		window->insert_tab(tab, -1);
	}
}

void REHex::TabDragFrame::OnMotion(wxMouseEvent &event)
{
	wxPoint mouse_pos = wxGetMousePosition();
	SetPosition(mouse_pos);
}

void REHex::TabDragFrame::OnCaptureLost(wxMouseCaptureLostEvent &event)
{
	if(dragging)
	{
		dragging = false;
		drop();
	}
	
	Destroy();
}

void REHex::TabDragFrame::OnLeftUp(wxMouseEvent &event)
{
	if(dragging)
	{
		dragging = false;
		ReleaseMouse();
		drop();
	}
	
	Destroy();
}
