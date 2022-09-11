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
#ifdef REHEX_TABDRAGFRAME_FAKE_CAPTURE
	EVT_TIMER(wxID_ANY, REHex::TabDragFrame::OnMousePoll)
#else
	EVT_MOTION(REHex::TabDragFrame::OnMotion)
	EVT_MOUSE_CAPTURE_LOST(REHex::TabDragFrame::OnCaptureLost)
	EVT_LEFT_UP(REHex::TabDragFrame::OnLeftUp)
#endif
END_EVENT_TABLE()

REHex::TabDragFrame::TabDragFrame(Tab *tab, wxSize original_window_size):
	wxFrame(NULL, wxID_ANY, "", wxDefaultPosition, tab->GetSize(), (wxFRAME_NO_TASKBAR | wxSTAY_ON_TOP)),
	tab(tab),
	original_window_size(original_window_size),
	dragging(true)
#ifdef REHEX_TABDRAGFRAME_FAKE_CAPTURE
	, mouse_poll_timer(this, wxID_ANY)
#endif
{
	assert(instance == NULL);
	instance = this;
	
	SetTransparent(127);
	
	tab->Reparent(this);
	#ifdef __APPLE__
	tab->Show();
	#endif
	Show();
	
#ifdef REHEX_TABDRAGFRAME_FAKE_CAPTURE
	mouse_poll_timer.Start(50);
#else
	CallAfter([&]()
	{
		CaptureMouse();
	});
#endif
}

REHex::TabDragFrame::~TabDragFrame()
{
	assert(instance == this);
	instance = NULL;
}

static wxAuiTabCtrl *find_wxAuiTabCtrl(wxWindow *w)
{
	auto w_children = w->GetChildren();
	
	for(auto c = w_children.GetFirst(); c; c = c->GetNext())
	{
		wxWindow *cw = (wxWindow*)(c->GetData());
		
		wxAuiTabCtrl *tc = dynamic_cast<wxAuiTabCtrl*>(cw);
		if(tc != NULL)
		{
			return tc;
		}
		
		tc = find_wxAuiTabCtrl(cw);
		if(tc != NULL)
		{
			return tc;
		}
	}
	
	return NULL;
}

void REHex::TabDragFrame::drop()
{
	wxPoint mouse_pos = wxGetMousePosition();
	
	MainWindow *window = NULL;
	
	const std::list<MainWindow*> &all_windows = MainWindow::get_instances();
	for(auto w = all_windows.begin(); w != all_windows.end(); ++w)
	{
		if((*w)->IsIconized())
		{
			continue;
		}
		
		if((*w)->GetScreenRect().Contains(mouse_pos))
		{
			wxAuiTabCtrl *w_tc = find_wxAuiTabCtrl(*w);
			if(w_tc->GetScreenRect().Contains(mouse_pos))
			{
				window = *w;
			}
			
			break;
		}
	}
	
	if(window == NULL)
	{
		window = new MainWindow(original_window_size);
		window->insert_tab(tab, -1);
		window->Show();
	}
	else{
		window->insert_tab(tab, -1);
	}
}

#ifdef REHEX_TABDRAGFRAME_FAKE_CAPTURE
void REHex::TabDragFrame::OnMousePoll(wxTimerEvent &event)
{
	if(dragging)
	{
		wxMouseState mouse_state = wxGetMouseState();
		
		if(mouse_state.LeftIsDown())
		{
			wxPoint mouse_pos = wxGetMousePosition();
			SetPosition(mouse_pos);
		}
		else{
			mouse_poll_timer.Stop();
			
			dragging = false;
			drop();
			
			Destroy();
		}
	}
}
#else
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
#endif
