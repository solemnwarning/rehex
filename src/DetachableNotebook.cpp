/* Reverse Engineer's Hex Editor
 * Copyright (C) 2022-2023 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "DetachableNotebook.hpp"
#include "mainwindow.hpp"

wxDEFINE_EVENT(REHex::EVT_PAGE_DETACHED, REHex::DetachedPageEvent);
wxDEFINE_EVENT(REHex::EVT_PAGE_DROPPED, REHex::DetachedPageEvent);

static wxAuiTabCtrl *find_wxAuiTabCtrl(wxWindow *w);

REHex::DetachableNotebook::DetachableNotebook(wxWindow *parent, wxWindowID id, const void *page_drop_group, wxEvtHandler *detached_page_handler, const wxPoint &pos, const wxSize &size, long style):
	wxAuiNotebook(parent, id, pos, size, style),
	page_drop_group(page_drop_group),
	detached_page_handler(detached_page_handler != NULL ? detached_page_handler : this),
	deferred_drag_page(NULL)
{
	assert((style & wxAUI_NB_TAB_EXTERNAL_MOVE) == 0);
	Bind(wxEVT_AUINOTEBOOK_DRAG_MOTION, &REHex::DetachableNotebook::OnTabDragMotion, this);
	Bind(wxEVT_IDLE, &REHex::DetachableNotebook::OnIdle, this);
}

REHex::DetachableNotebook::~DetachableNotebook() {}

void REHex::DetachableNotebook::restart_drag(wxWindow *page)
{
	deferred_drag_page = NULL;
	
	wxAuiTabCtrl *dst_tc = find_wxAuiTabCtrl(this);
	int page_idx = GetPageIndex(page);
	if(page_idx == wxNOT_FOUND)
	{
		return;
	}
	
	wxRect tab_rect = dst_tc->GetPage(page_idx).rect;
	if(tab_rect.IsEmpty())
	{
		/* Tab rect not yet initialised. */
		deferred_drag_page = page;
		return;
	}
	
	wxPoint mouse_pos = wxGetMousePosition();
	
	{
		wxMouseEvent e1(wxEVT_LEFT_DOWN);
		e1.SetX(tab_rect.x);
		e1.SetY(tab_rect.y);
		e1.SetLeftDown(true);
		
		dst_tc->GetEventHandler()->ProcessEvent(e1);
	}
	
	{
		int drag_x_threshold = wxSystemSettings::GetMetric(wxSYS_DRAG_X);
		
		wxMouseEvent e2(wxEVT_MOTION);
		e2.SetX(tab_rect.x + drag_x_threshold + 1);
		e2.SetY(tab_rect.y);
		e2.SetLeftDown(true);
		
		dst_tc->GetEventHandler()->ProcessEvent(e2);
	}
	
	{
		wxPoint rel_mouse_pos = dst_tc->ScreenToClient(mouse_pos);
		
		wxMouseEvent e3(wxEVT_MOTION);
		e3.SetX(rel_mouse_pos.x);
		e3.SetY(rel_mouse_pos.y);
		e3.SetLeftDown(true);
		
		dst_tc->GetEventHandler()->ProcessEvent(e3);
	}
	
	#ifdef __APPLE__
	fake_broken_mouse_capture(dst_tc);
	#endif
}

void REHex::DetachableNotebook::OnTabDragMotion(wxAuiNotebookEvent &event)
{
	wxAuiTabCtrl* tab_ctrl = dynamic_cast<wxAuiTabCtrl*>(event.GetEventObject());
	assert(tab_ctrl != NULL);
	
	wxPoint screen_pt = wxGetMousePosition();
	
	if(!tab_ctrl->GetScreenRect().Contains(screen_pt))
	{
		if(DragFrame::get_instance() != NULL)
		{
			/* Sometimes (only seen on macOS) we get multiple wxEVT_AUINOTEBOOK_DRAG_MOTION
			 * events, which can cause us to try setting up multiple drag operations at the
			 * same time without this check.
			*/
			return;
		}
		
		/* The wxEVT_MOUSE_CAPTURE_LOST event makes the wxAuiTabCtrl abort its drag
		 * operation, but it leaves some members in an inconsistent state that can make
		 * it crash if the mouse returns while the left button is still down, so we need to
		 * synthesise a wxEVT_LEFT_UP event too.
		 *
		 * We can't *just* do wxEVT_LEFT_UP as that somehow doesn't always release the
		 * capture...
		*/
		
		if(tab_ctrl->HasCapture())
		{
			tab_ctrl->ReleaseMouse();
			
			wxMouseCaptureLostEvent e;
			tab_ctrl->GetEventHandler()->ProcessEvent(e);
		}
		
		{
			wxMouseEvent e(wxEVT_LEFT_UP);
			tab_ctrl->GetEventHandler()->ProcessEvent(e);
		}
		
		wxWindow *page = GetPage(event.GetSelection());
		wxString page_caption = GetPageText(event.GetSelection());
		wxBitmap page_bitmap = GetPageBitmap(event.GetSelection());
		RemovePage(event.GetSelection());
		
		new DragFrame(page, page_caption, page_bitmap, page_drop_group, detached_page_handler);
		
		DetachedPageEvent e(page, EVT_PAGE_DETACHED);
		ProcessEvent(e);
	}
	else if(DragFrame::get_instance() != NULL)
	{
		/* I'm not exactly sure why, but sometimes a tab dragging event comes out of the
		 * wxAuiNotebook while we are setting up the DragFrame, so we suppress the handling
		 * during any external drag.
		*/
	}
	else{
		event.Skip();
	}
}

void REHex::DetachableNotebook::OnIdle(wxIdleEvent &event)
{
	if(deferred_drag_page != NULL)
	{
		restart_drag(deferred_drag_page);
	}
}

REHex::DetachableNotebook::DragFrame *REHex::DetachableNotebook::DragFrame::instance = NULL;

BEGIN_EVENT_TABLE(REHex::DetachableNotebook::DragFrame, wxFrame)
#ifdef REHEX_TABDRAGFRAME_FAKE_CAPTURE
	EVT_TIMER(wxID_ANY, REHex::DetachableNotebook::DragFrame::OnMousePoll)
#else
	EVT_MOTION(REHex::DetachableNotebook::DragFrame::OnMotion)
	EVT_MOUSE_CAPTURE_LOST(REHex::DetachableNotebook::DragFrame::OnCaptureLost)
	EVT_LEFT_UP(REHex::DetachableNotebook::DragFrame::OnLeftUp)
#endif
END_EVENT_TABLE()

REHex::DetachableNotebook::DragFrame::DragFrame(wxWindow *page, const wxString &page_caption, const wxBitmap &page_bitmap, const void *page_drop_group, wxEvtHandler *detached_page_handler):
	wxFrame(NULL, wxID_ANY, "", wxDefaultPosition, page->GetParent()->GetSize(), (wxBORDER_NONE | wxFRAME_NO_TASKBAR | wxSTAY_ON_TOP)),
	page_drop_group(page_drop_group),
	detached_page_handler(detached_page_handler),
	page(page),
	page_caption(page_caption),
	page_bitmap(page_bitmap),
	dragging(true)
#ifdef REHEX_TABDRAGFRAME_FAKE_CAPTURE
	, mouse_poll_timer(this, wxID_ANY)
#endif
{
	assert(instance == NULL);
	instance = this;
	
	SetTransparent(127);
	
	notebook = new wxAuiNotebook(this, wxID_ANY, wxPoint(0,0), GetClientSize());
	
	page->Reparent(notebook);
	notebook->InsertPage(-1, page, page_caption, true, page_bitmap);
	#ifdef __APPLE__
	page->Show();
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

REHex::DetachableNotebook::DragFrame::~DragFrame()
{
	assert(instance == this);
	instance = NULL;
}

REHex::DetachableNotebook::DragFrame *REHex::DetachableNotebook::DragFrame::get_instance()
{
	return instance;
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

void REHex::DetachableNotebook::DragFrame::drag(const wxPoint &mouse_pos)
{
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
	
	if(window != NULL)
	{
		/* The cursor has been moved over the wxAuiTabCtrl of a valid drop target.
		 *
		 * What we do now, is insert the page into the target notebook and synthesize mouse
		 * events to make the wxAuiNotebook initiate its own drag-n-drop handling.
		*/
		
		#ifndef REHEX_TABDRAGFRAME_FAKE_CAPTURE
		ReleaseMouse();
		#endif
		
		notebook->RemovePage(0);
		
		DetachableNotebook *dst_notebook = window->get_notebook();
		
		page->Reparent(dst_notebook);
		dst_notebook->AddPage(page, page_caption);
		
		int page_idx = dst_notebook->GetPageCount() - 1;
		dst_notebook->SetPageBitmap(page_idx, page_bitmap);
		
		dst_notebook->restart_drag(page);
		
		dragging = false;
		Destroy();
	}
	else{
		SetPosition(mouse_pos);
	}
}

void REHex::DetachableNotebook::DragFrame::drop()
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
	
	notebook->RemovePage(0);
	
	if(window == NULL)
	{
		DetachedPageEvent e(page, EVT_PAGE_DROPPED);
		bool e_handled = detached_page_handler->ProcessEvent(e);
		assert(e_handled);
	}
	else{
		window->insert_tab((Tab*)(page), -1);
	}
}

#ifdef REHEX_TABDRAGFRAME_FAKE_CAPTURE
void REHex::DetachableNotebook::DragFrame::OnMousePoll(wxTimerEvent &event)
{
	if(dragging)
	{
		wxMouseState mouse_state = wxGetMouseState();
		
		if(mouse_state.LeftIsDown())
		{
			wxPoint mouse_pos = wxGetMousePosition();
			drag(mouse_pos);
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
void REHex::DetachableNotebook::DragFrame::OnMotion(wxMouseEvent &event)
{
	wxPoint mouse_pos = wxGetMousePosition();
	drag(mouse_pos);
}

void REHex::DetachableNotebook::DragFrame::OnCaptureLost(wxMouseCaptureLostEvent &event)
{
	if(dragging)
	{
		dragging = false;
		drop();
	}
	
	Destroy();
}

void REHex::DetachableNotebook::DragFrame::OnLeftUp(wxMouseEvent &event)
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

REHex::DetachedPageEvent::DetachedPageEvent(wxWindow *page, wxEventType event):
	wxEvent(wxID_NONE, event),
	page(page)
{
	m_propagationLevel = wxEVENT_PROPAGATE_MAX;
}

wxEvent *REHex::DetachedPageEvent::Clone() const
{
	return new DetachedPageEvent(page, GetEventType());
}
