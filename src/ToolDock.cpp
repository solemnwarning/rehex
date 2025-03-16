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

#include <wx/bitmap.h>
#include <wx/statbmp.h>

#include "ToolDock.hpp"

#include "../res/dock_bottom.h"
#include "../res/dock_left.h"
#include "../res/dock_right.h"
#include "../res/dock_top.h"

BEGIN_EVENT_TABLE(REHex::ToolDock, REHex::MultiSplitter)
	EVT_LEFT_UP(REHex::ToolDock::OnLeftUp)
	EVT_MOUSE_CAPTURE_LOST(REHex::ToolDock::OnMouseCaptureLost)
	EVT_MOTION(REHex::ToolDock::OnMotion)
END_EVENT_TABLE()

REHex::ToolDock::ToolDock(wxWindow *parent):
	MultiSplitter(parent),
	m_main_panel(NULL),
	m_drag_pending(false),
	m_drag_active(NULL),
	m_left_dock_site(NULL),
	m_right_dock_site(NULL),
	m_top_dock_site(NULL),
	m_bottom_dock_site(NULL)
{
	m_left_notebook = new ToolNotebook(this, wxID_ANY, wxNB_LEFT);
	m_left_notebook->Bind(wxEVT_LEFT_DOWN, &REHex::ToolDock::OnNotebookLeftDown, this);
	m_left_notebook->Hide();
	
	m_right_notebook = new ToolNotebook(this, wxID_ANY, wxNB_RIGHT);
	m_right_notebook->Bind(wxEVT_LEFT_DOWN, &REHex::ToolDock::OnNotebookLeftDown, this);
	m_right_notebook->Hide();
	
	m_top_notebook = new ToolNotebook(this, wxID_ANY, wxNB_TOP);
	m_top_notebook->Bind(wxEVT_LEFT_DOWN, &REHex::ToolDock::OnNotebookLeftDown, this);
	m_top_notebook->Hide();
	
	m_bottom_notebook = new ToolNotebook(this, wxID_ANY, wxNB_BOTTOM);
	m_bottom_notebook->Bind(wxEVT_LEFT_DOWN, &REHex::ToolDock::OnNotebookLeftDown, this);
	m_bottom_notebook->Hide();
	
	m_dock_shadow = new DockShadow(this, wxRect(0, 0, 0, 0));
}

void REHex::ToolDock::AddMainPanel(wxWindow *main_panel)
{
	assert(m_main_panel == NULL);
	
	AddFirst(main_panel);
	m_main_panel = main_panel;
	
	AddLeftOf(m_left_notebook, m_main_panel);
	SetWindowWeight(m_left_notebook, 0.0f);
	
	AddRightOf(m_right_notebook, m_main_panel);
	SetWindowWeight(m_right_notebook, 0.0f);
	
	AddAbove(m_top_notebook, m_main_panel);
	SetWindowWeight(m_top_notebook, 0.0f);
	
	AddBelow(m_bottom_notebook, m_main_panel);
	SetWindowWeight(m_bottom_notebook, 0.0f);
	
#ifdef __APPLE__
	/* The default sash size on macOS is ONE pixel wide, and there seems to be several weird
	 * bugs(?) around the positioning and client area of wxNotebook on macOS, so to get resizing
	 * working nicely on Mac, we force the sash size to be wider and also capture mouse clicks
	 * within the unused edge/border space of the wxNotebook.
	*/
	
	SetSashSize(10);
	
	SetWindowDragBorder(m_left_notebook, 10);
	SetWindowDragBorder(m_right_notebook, 10);
	SetWindowDragBorder(m_top_notebook, 10);
	SetWindowDragBorder(m_bottom_notebook, 10);
#endif
}

void REHex::ToolDock::DestroyTool(ToolPanel *tool)
{
	ToolNotebook *notebook;
	int page_idx = m_right_notebook->FindPage(tool);
	
	if(page_idx != wxNOT_FOUND)
	{
		notebook = m_right_notebook;
	}
	else{
		page_idx = m_bottom_notebook->FindPage(tool);
		notebook = m_bottom_notebook;
	}
	
	assert(page_idx != wxNOT_FOUND);
	
	notebook->DeletePage(page_idx);
	
	if(notebook->GetPageCount() == 0)
	{
		notebook->Hide();
	}
}

void REHex::ToolDock::CreateTool(const std::string &name, SharedDocumentPointer &document, DocumentCtrl *document_ctrl)
{
	ToolPanel *tool = FindToolByName(name);
	if(tool != NULL)
	{
		/* An instance of this tool already exists. */
		return;
	}
	
	const ToolPanelRegistration *tpr = ToolPanelRegistry::by_name(name);
	if(tpr == NULL)
	{
		/* TODO: Some kind of warning? */
		return;
	}
	
	ToolNotebook *target_notebook = NULL;
	
	if(tpr->shape == ToolPanel::TPS_TALL)
	{
		if(m_right_notebook->GetPageCount() > 0 || m_left_notebook->GetPageCount() == 0)
		{
			target_notebook = m_right_notebook;
		}
		else{
			target_notebook = m_left_notebook;
		}
	}
	else if(tpr->shape == ToolPanel::TPS_WIDE)
	{
		if(m_bottom_notebook->GetPageCount() > 0 || m_top_notebook->GetPageCount() == 0)
		{
			target_notebook = m_bottom_notebook;
		}
		else{
			target_notebook = m_top_notebook;
		}
	}
	
	tool = tpr->factory(target_notebook, document, document_ctrl);
	
	target_notebook->AddPage(tool, tool->label(), true);
	
	if(target_notebook->GetPageCount() == 1)
	{
		ResetNotebookSize(target_notebook);
	}
}

void REHex::ToolDock::DestroyTool(const std::string &name)
{
	ToolPanel *tool = FindToolByName(name);
	if(tool != NULL)
	{
		DestroyTool(tool);
	}
}

bool REHex::ToolDock::ToolExists(const std::string &name) const
{
	return FindToolByName(name) != NULL;
}

void REHex::ToolDock::HideFrames()
{
	for(auto it = m_tool_frames.begin(); it != m_tool_frames.end(); ++it)
	{
		it->second->Hide();
	}
}

void REHex::ToolDock::UnhideFrames()
{
	for(auto it = m_tool_frames.begin(); it != m_tool_frames.end(); ++it)
	{
		it->second->ShowWithoutActivating();
	}
}

void REHex::ToolDock::SaveTools(wxConfig *config) const
{
	{
		wxConfigPathChanger scoped_path(config, "left/");
		SaveToolsFromNotebook(config, m_left_notebook);
	}
	
	{
		wxConfigPathChanger scoped_path(config, "right/");
		SaveToolsFromNotebook(config, m_right_notebook);
	}
	
	{
		wxConfigPathChanger scoped_path(config, "top/");
		SaveToolsFromNotebook(config, m_top_notebook);
	}
	
	{
		wxConfigPathChanger scoped_path(config, "bottom/");
		SaveToolsFromNotebook(config, m_bottom_notebook);
	}
	
	{
		wxConfigPathChanger scoped_path(config, "frames/");
		SaveToolFrames(config);
	}
}

void REHex::ToolDock::SaveToolsFromNotebook(wxConfig *config, ToolNotebook *notebook)
{
	size_t num_pages = notebook->GetPageCount();
	
	if(num_pages > 0)
	{
		wxSize size = notebook->GetSize();
		
		config->Write("width", size.GetWidth());
		config->Write("height", size.GetHeight());
	}
	
	for(size_t i = 0; i < num_pages; ++i)
	{
		char i_path[32];
		snprintf(i_path, sizeof(i_path), "%zu/", i);
		
		wxConfigPathChanger scoped_path(config, i_path);
		
		ToolPanel *tool = (ToolPanel*)(notebook->GetPage(i));
		
		config->Write("name", wxString(tool->name()));
		config->Write("selected", (tool == notebook->GetCurrentPage()));
		tool->save_state(config);
	}
}

void REHex::ToolDock::SaveToolFrames(wxConfig *config) const
{
	size_t i = 0;
	for(auto it = m_tool_frames.begin(); it != m_tool_frames.end(); ++it, ++i)
	{
		char i_path[32];
		snprintf(i_path, sizeof(i_path), "%zu/", i);
		
		wxConfigPathChanger scoped_path(config, i_path);
		
		ToolPanel *tool = it->first;
		ToolFrame *frame = it->second;
		
		config->Write("frame/x", frame->GetPosition().x);
		config->Write("frame/y", frame->GetPosition().y);
		
		config->Write("frame/width", frame->GetSize().GetWidth());
		config->Write("frame/height", frame->GetSize().GetHeight());
		
		config->Write("name", wxString(tool->name()));
		tool->save_state(config);
	}
}

void REHex::ToolDock::LoadTools(wxConfig *config, SharedDocumentPointer &document, DocumentCtrl *document_ctrl)
{
	{
		wxConfigPathChanger scoped_path(config, "left/");
		LoadToolsIntoNotebook(config, m_left_notebook, document, document_ctrl);
	}
	
	{
		wxConfigPathChanger scoped_path(config, "right/");
		LoadToolsIntoNotebook(config, m_right_notebook, document, document_ctrl);
	}
	
	{
		wxConfigPathChanger scoped_path(config, "top/");
		LoadToolsIntoNotebook(config, m_top_notebook, document, document_ctrl);
	}
	
	{
		wxConfigPathChanger scoped_path(config, "bottom/");
		LoadToolsIntoNotebook(config, m_bottom_notebook, document, document_ctrl);
	}
	
	{
		wxConfigPathChanger scoped_path(config, "frames/");
		LoadToolFrames(config, document, document_ctrl);
	}
}

void REHex::ToolDock::LoadToolsIntoNotebook(wxConfig *config, ToolNotebook *notebook, SharedDocumentPointer &document, DocumentCtrl *document_ctrl)
{
	for(size_t i = 0;; ++i)
	{
		char i_path[64];
		snprintf(i_path, sizeof(i_path), "%zu/", i);
		
		if(config->HasGroup(i_path))
		{
			wxConfigPathChanger scoped_path(config, i_path);
			
			std::string name = config->Read    ("name", "").ToStdString();
			bool selected    = config->ReadBool("selected", false);
			
			const ToolPanelRegistration *tpr = ToolPanelRegistry::by_name(name);
			if(tpr != NULL)
			{
				ToolPanel *tool_window = tpr->factory(notebook, document, document_ctrl);
				if(config)
				{
					tool_window->load_state(config);
				}
				
				notebook->AddPage(tool_window, tpr->label, selected);
			}
			else{
				/* TODO: Some kind of warning? */
			}
		}
		else{
			break;
		}
	}
	
	if(notebook->GetPageCount() > 0)
	{
		notebook->Show();
		
		if(notebook == m_top_notebook || notebook == m_bottom_notebook)
		{
			wxSize size(-1, config->ReadLong("height", -1));
			SetWindowSize(notebook, size);
		}
		else{
			wxSize size(config->ReadLong("width", -1), -1);
			SetWindowSize(notebook, size);
		}
	}
}

void REHex::ToolDock::LoadToolFrames(wxConfig *config, SharedDocumentPointer &document, DocumentCtrl *document_ctrl)
{
	for(size_t i = 0;; ++i)
	{
		char i_path[64];
		snprintf(i_path, sizeof(i_path), "%zu/", i);
		
		if(config->HasGroup(i_path))
		{
			wxConfigPathChanger scoped_path(config, i_path);
			
			wxPoint frame_position(
				config->ReadLong("frame/x", wxDefaultPosition.x),
				config->ReadLong("frame/y", wxDefaultPosition.y));
			
			wxSize frame_size(
				config->ReadLong("frame/width", wxDefaultSize.GetWidth()),
				config->ReadLong("frame/height", wxDefaultSize.GetHeight()));
			
			std::string name = config->Read("name", "").ToStdString();
			
			const ToolPanelRegistration *tpr = ToolPanelRegistry::by_name(name);
			if(tpr != NULL)
			{
				ToolFrame *frame = new ToolFrame(this, frame_position, frame_size);
				
				ToolPanel *tool = tpr->factory(frame, document, document_ctrl);
				tool->load_state(config);
				
				frame->AdoptTool(tool, false);
				
				frame->Show();
				
				frame->Bind(wxEVT_CLOSE_WINDOW, &REHex::ToolDock::OnFrameClose, this);
				
				m_tool_frames.emplace(tool, frame);
			}
			else{
				/* TODO: Some kind of warning? */
			}
		}
		else{
			break;
		}
	}
}

void REHex::ToolDock::ResetNotebookSize(ToolNotebook *notebook)
{
	CallAfter([this, notebook]()
	{
		wxSize min_size = notebook->GetEffectiveMinSize();
		wxSize best_size = notebook->GetBestSize();
		
		if(notebook == m_top_notebook || notebook == m_bottom_notebook)
		{
			int height = std::max(min_size.GetHeight(), best_size.GetHeight());
			SetWindowSize(notebook, wxSize(-1, height));
		}
		else{
			int width = std::max(min_size.GetWidth(), best_size.GetWidth());
			SetWindowSize(notebook, wxSize(width, -1));
		}
	});
}

void REHex::ToolDock::SetupDockSites()
{
	if(m_left_dock_site == NULL)
	{
		m_left_dock_site = new DockSite(this, wxBITMAP_PNG_FROM_DATA(dock_left), Anchor::LEFT);
		m_left_dock_site->Show();
	}
	
	if(m_right_dock_site == NULL)
	{
		m_right_dock_site = new DockSite(this, wxBITMAP_PNG_FROM_DATA(dock_right), Anchor::RIGHT);
		m_right_dock_site->Show();
	}
	
	if(m_top_dock_site == NULL)
	{
		m_top_dock_site = new DockSite(this, wxBITMAP_PNG_FROM_DATA(dock_top), Anchor::TOP);
		m_top_dock_site->Show();
	}
	
	if(m_bottom_dock_site == NULL)
	{
		m_bottom_dock_site = new DockSite(this, wxBITMAP_PNG_FROM_DATA(dock_bottom), Anchor::BOTTOM);
		m_bottom_dock_site->Show();
	}
}

void REHex::ToolDock::DestroyDockSites()
{
	if(m_left_dock_site != NULL)
	{
		m_left_dock_site->Destroy();
		m_left_dock_site = NULL;
	}
	
	if(m_right_dock_site != NULL)
	{
		m_right_dock_site->Destroy();
		m_right_dock_site = NULL;
	}
	
	if(m_top_dock_site != NULL)
	{
		m_top_dock_site->Destroy();
		m_top_dock_site = NULL;
	}
	
	if(m_bottom_dock_site != NULL)
	{
		m_bottom_dock_site->Destroy();
		m_bottom_dock_site = NULL;
	}
}

REHex::ToolDock::ToolFrame *REHex::ToolDock::FindFrameByTool(ToolPanel *tool)
{
	auto frame_it = m_tool_frames.find(tool);
	return frame_it != m_tool_frames.end() ? frame_it->second : NULL;
}

REHex::ToolDock::ToolNotebook *REHex::ToolDock::FindNotebookByTool(ToolPanel *tool)
{
	if(m_left_notebook->FindPage(tool) != wxNOT_FOUND)
	{
		return m_left_notebook;
	}
	else if(m_right_notebook->FindPage(tool) != wxNOT_FOUND)
	{
		return m_right_notebook;
	}
	else if(m_top_notebook->FindPage(tool) != wxNOT_FOUND)
	{
		return m_top_notebook;
	}
	else if(m_bottom_notebook->FindPage(tool) != wxNOT_FOUND)
	{
		return m_bottom_notebook;
	}
	else{
		return NULL;
	}
}

REHex::ToolPanel *REHex::ToolDock::FindToolByName(const std::string &name) const
{
	/* Search for any instances of the tool floating in a tool window... */
	
	for(auto frame_it = m_tool_frames.begin(); frame_it != m_tool_frames.end(); ++frame_it)
	{
		if(frame_it->first->name() == name)
		{
			return frame_it->first;
		}
	}
	
	/* Search for any instances of the tool in a notebook... */
	
	auto find_in_notebook = [&](ToolNotebook *notebook)
	{
		size_t num_pages = notebook->GetPageCount();
		
		for(size_t i = 0; i < num_pages; ++i)
		{
			ToolPanel *tool = (ToolPanel*)(notebook->GetPage(i));
			
			if(tool->name() == name)
			{
				return tool;
			}
		}
		
		return (ToolPanel*)(NULL);
	};
	
	ToolPanel *tool = NULL;
	
	if(tool == NULL) { tool = find_in_notebook(m_left_notebook); }
	if(tool == NULL) { tool = find_in_notebook(m_right_notebook); }
	if(tool == NULL) { tool = find_in_notebook(m_top_notebook); }
	if(tool == NULL) { tool = find_in_notebook(m_bottom_notebook); }
	
	return tool;
}

REHex::ToolDock::ToolNotebook *REHex::ToolDock::FindDockNotebook(const wxPoint &point, ToolNotebook *current_notebook)
{
	ToolNotebook *dest_notebook = (ToolNotebook*)(FindChildByPoint(point));
	if(dest_notebook == NULL || dest_notebook != current_notebook)
	{
		wxPoint screen_point = ClientToScreen(point);
		
		if(m_left_dock_site != NULL && m_left_dock_site->GetScreenRect().Contains(screen_point))
		{
			dest_notebook = m_left_notebook;
		}
		else if(m_right_dock_site != NULL && m_right_dock_site->GetScreenRect().Contains(screen_point))
		{
			dest_notebook = m_right_notebook;
		}
		else if(m_top_dock_site != NULL && m_top_dock_site->GetScreenRect().Contains(screen_point))
		{
			dest_notebook = m_top_notebook;
		}
		else if(m_bottom_dock_site != NULL && m_bottom_dock_site->GetScreenRect().Contains(screen_point))
		{
			dest_notebook = m_bottom_notebook;
		}
		else{
			dest_notebook = NULL;
		}
	}
	
	return dest_notebook;
}

void REHex::ToolDock::OnNotebookLeftDown(wxMouseEvent &event)
{
	ToolNotebook *notebook = (ToolNotebook*)(event.GetEventObject());
	assert(notebook == m_left_notebook || notebook == m_right_notebook || notebook == m_top_notebook || notebook == m_bottom_notebook);
	
	long hit_flags;
	int hit_page = notebook->HitTest(event.GetPosition(), &hit_flags);
	
	if(hit_page != wxNOT_FOUND && (hit_flags & (wxBK_HITTEST_ONICON | wxBK_HITTEST_ONLABEL | wxBK_HITTEST_ONITEM)) != 0)
	{
		/* Mouse button pressed over tab. */
		
		/* The default wxEVT_LEFT_DOWN handler on macOS does something weird which prevents future
		 * wxEVT_MOTION events from being received until the button is released again, so on macOS
		 * we don't call Skip() and handle switching the page ourselves.
		*/
		
		#ifdef __APPLE__
		notebook->SetSelection(hit_page);
		#endif
		
		m_drag_pending = true;
		m_left_down_point = event.GetPosition();
		m_left_down_tool = (ToolPanel*)(notebook->GetPage(hit_page));
		
		CaptureMouse();
	}
	
	#ifndef __APPLE__
	event.Skip();
	#endif
}

void REHex::ToolDock::OnLeftUp(wxMouseEvent &event)
{
	if(m_drag_active)
	{
		ToolFrame *frame = FindFrameByTool(m_left_down_tool);
		ToolNotebook *notebook = FindNotebookByTool(m_left_down_tool);
		
		assert(frame == NULL || notebook == NULL);
		
		ToolNotebook *dest_notebook = FindDockNotebook(event.GetPosition(), notebook);
		
		if(dest_notebook != NULL && dest_notebook != notebook)
		{
			if(notebook != NULL)
			{
				notebook->RemovePage(notebook->FindPage(m_left_down_tool));
				
				if(notebook->GetPageCount() == 0)
				{
					notebook->Hide();
				}
			}

			if(frame != NULL)
			{
				frame->GetSizer()->Detach(m_left_down_tool);
			}
			
			m_left_down_tool->Reparent(dest_notebook);
			dest_notebook->AddPage(m_left_down_tool, m_left_down_tool->label(), true);
			
			if(dest_notebook->GetPageCount() == 1)
			{
				ResetNotebookSize(dest_notebook);
			}
			
			if(frame != NULL)
			{
				frame->Destroy();
				m_tool_frames.erase(m_left_down_tool);
			}
		}
	}
	
	if(m_drag_pending || m_drag_active)
	{
		ReleaseMouse();
		
		m_drag_pending = false;
		m_drag_active = false;
		
		DestroyDockSites();
		m_dock_shadow->Hide();
	}
	
	event.Skip();
}

void REHex::ToolDock::OnMouseCaptureLost(wxMouseCaptureLostEvent &event)
{
	if(m_drag_pending || m_drag_active)
	{
		m_drag_pending = false;
		m_drag_active = false;
		
		DestroyDockSites();
		m_dock_shadow->Hide();
	}
	else{
		event.Skip();
	}
}

void REHex::ToolDock::OnMotion(wxMouseEvent &event)
{
	if(m_drag_pending)
	{
		int drag_thresh_w = wxSystemSettings::GetMetric(wxSYS_DRAG_X);
		int drag_thresh_h = wxSystemSettings::GetMetric(wxSYS_DRAG_Y);
		
		int delta_x = abs(event.GetPosition().x - m_left_down_point.x);
		int delta_y = abs(event.GetPosition().y - m_left_down_point.y);
		
		if((drag_thresh_w <= 0 || delta_x >= (drag_thresh_w / 2)) || (drag_thresh_h <= 0 || delta_y >= (drag_thresh_h / 2)))
		{
			m_drag_pending = false;
			m_drag_active = true;
		}
	}
	
	if(m_drag_active)
	{
		ToolFrame *frame = FindFrameByTool(m_left_down_tool);
		ToolNotebook *notebook = FindNotebookByTool(m_left_down_tool);
		
		assert(frame == NULL || notebook == NULL);
		
		ToolNotebook *dest_notebook = FindDockNotebook(event.GetPosition(), notebook);
		
		if(dest_notebook != NULL)
		{
			if(dest_notebook != notebook)
			{
				if(dest_notebook->IsShown())
				{
					m_dock_shadow->Move(dest_notebook->GetScreenRect());
					m_dock_shadow->Show();
				}
				else{
					wxPoint client_base = ClientToScreen(wxPoint(0, 0));
					wxSize client_size = GetClientSize();
					
					wxSize min_size = m_left_down_tool->GetEffectiveMinSize();
					wxSize best_size = m_left_down_tool->GetBestSize();
					
					wxRect rect;
					
					if(dest_notebook == m_top_notebook || dest_notebook == m_bottom_notebook)
					{
						rect.width = client_size.GetWidth();
						rect.height = std::max(min_size.GetHeight(), best_size.GetHeight());
					}
					else{
						rect.width = std::max(min_size.GetWidth(), best_size.GetWidth());
						rect.height = client_size.GetHeight();
					}
					
					if(dest_notebook == m_left_notebook || dest_notebook == m_top_notebook)
					{
						rect.x = client_base.x;
						rect.y = client_base.y;
					}
					else if(dest_notebook == m_right_notebook)
					{
						rect.x = client_base.x + client_size.GetWidth() - rect.width;
						rect.y = client_base.y;
					}
					else if(dest_notebook == m_bottom_notebook)
					{
						rect.x = client_base.x;
						rect.y = client_base.y + client_size.GetHeight() - rect.height;
					}
					
					m_dock_shadow->Move(rect);
					m_dock_shadow->Show();
				}

				/* On Windows, the transparent wxPopupWindow isn't redrawn when the frame moves
				 * around under it and I can't figure out a way to trigger an update that doesn't
				 * result in the popup drawing over itself until its effectively opaque, so we just
				 * hide the frame when the cursor is over a dock site on Windows.
				*/
				#ifdef _WIN32
				assert(frame != NULL);
				frame->Hide();
				#endif
			}
		}
		else{
			if(notebook != NULL)
			{
				notebook->RemovePage(notebook->FindPage(m_left_down_tool));
				
				if(notebook->GetPageCount() == 0)
				{
					notebook->Hide();
				}
			}
			
			wxPoint frame_pos = ClientToScreen(event.GetPosition());
			
			if(frame == NULL)
			{
				frame = new ToolFrame(this, wxDefaultPosition, wxDefaultSize, m_left_down_tool);
				frame->SetPosition(frame_pos);
				
				frame->Bind(wxEVT_CLOSE_WINDOW, &REHex::ToolDock::OnFrameClose, this);
				
				m_tool_frames.emplace(m_left_down_tool, frame);
			}
			
			SetupDockSites();
			m_dock_shadow->Hide();

			frame->Show();
		}
		
		if(frame != NULL)
		{
			wxPoint frame_pos = ClientToScreen(event.GetPosition());
			frame->SetPosition(frame_pos);
		}
	}
	
	event.Skip();
}

void REHex::ToolDock::OnFrameClose(wxCloseEvent &event)
{
	ToolFrame *frame = (ToolFrame*)(event.GetEventObject());
	
	ToolPanel *tool = frame->GetTool();
	if(tool != NULL)
	{
		frame->RemoveTool(tool);
		
		ToolNotebook *dest_notebook = NULL;
		
		switch(tool->shape())
		{
			case ToolPanel::Shape::TPS_WIDE:
				if(m_bottom_notebook->GetPageCount() > 0 || m_top_notebook->GetPageCount() == 0)
				{
					dest_notebook = m_bottom_notebook;
				}
				else{
					dest_notebook = m_top_notebook;
				}
				
				break;
				
			case ToolPanel::Shape::TPS_TALL:
				if(m_right_notebook->GetPageCount() > 0 || m_left_notebook->GetPageCount() == 0)
				{
					dest_notebook = m_right_notebook;
				}
				else{
					dest_notebook = m_left_notebook;
				}
				
				break;
		}
		
		tool->Reparent(dest_notebook);
		dest_notebook->AddPage(tool, tool->label(), true);
		
		if(dest_notebook->GetPageCount() == 1)
		{
			ResetNotebookSize(dest_notebook);
		}
		
		m_tool_frames.erase(tool);
	}
	
	frame->Destroy();
}

BEGIN_EVENT_TABLE(REHex::ToolDock::ToolNotebook, wxNotebook)
	EVT_NOTEBOOK_PAGE_CHANGED(wxID_ANY, REHex::ToolDock::ToolNotebook::OnPageChanged)
END_EVENT_TABLE()

REHex::ToolDock::ToolNotebook::ToolNotebook(wxWindow *parent, wxWindowID id, long style):
	wxNotebook(parent, id, wxDefaultPosition, wxDefaultSize, style) {}

bool REHex::ToolDock::ToolNotebook::AddPage(wxWindow *page, const wxString &text, bool select, int imageId)
{
	bool res = wxNotebook::AddPage(page, text, select, imageId);
	UpdateToolVisibility();
	
	if(GetPageCount() == 1)
	{
		Show();
	}
	
	return res;
}

bool REHex::ToolDock::ToolNotebook::DeletePage(size_t page)
{
	bool res = wxNotebook::DeletePage(page);
	UpdateToolVisibility();
	
	if(GetPageCount() == 0)
	{
		Hide();
	}
	
	return res;
}

bool REHex::ToolDock::ToolNotebook::InsertPage(size_t index, wxWindow *page, const wxString &text, bool select, int imageId)
{
	bool res = wxNotebook::InsertPage(index, page, text, select, imageId);
	UpdateToolVisibility();
	
	if(GetPageCount() == 1)
	{
		Show();
	}
	
	return res;
}

bool REHex::ToolDock::ToolNotebook::RemovePage(size_t page)
{
	bool res = wxNotebook::RemovePage(page);
	UpdateToolVisibility();
	
	if(GetPageCount() == 0)
	{
		Hide();
	}
	
	return res;
}

int REHex::ToolDock::ToolNotebook::ChangeSelection(size_t page)
{
	int old_page = wxNotebook::ChangeSelection(page);
	
	if (old_page != wxNOT_FOUND)
	{
		ToolPanel *old_tool = (ToolPanel*)(GetPage(old_page));
		assert(old_tool != NULL);
		
		old_tool->set_visible(false);
	}
	
	ToolPanel *new_tool = (ToolPanel*)(GetPage(page));
	assert(new_tool != NULL);
	
	if(new_tool != NULL)
	{
		new_tool->set_visible(true);
	}

	return old_page;
}

wxSize REHex::ToolDock::ToolNotebook::GetMinSize() const
{
	wxWindow *current_page = GetCurrentPage();
	if(current_page != NULL)
	{
		/* We compare the current size of the notebook to the current size of the current
		 * page to calculate the additional size required for the notebook control itself.
		 *
		 * This isn't entirely reliable - on some platforms there is a delay between the
		 * notebook resizing and the page content being resized, but I can't come up with
		 * anything more reliable and this is only used for size validation when the user
		 * is dragging the sash, by which point the window size should be updated.
		*/
		
		wxSize current_notebook_size = GetSize();
		wxSize current_page_size = current_page->GetSize();
		
		int notebook_width_overhead = current_notebook_size.GetWidth() - current_page_size.GetWidth();
		int notebook_height_overhead = current_notebook_size.GetHeight() - current_page_size.GetHeight();
		
		wxSize current_page_min_size = current_page->GetMinSize();
		
		return wxSize(
			(current_page_min_size.GetWidth() + notebook_width_overhead),
			(current_page_min_size.GetHeight() + notebook_height_overhead));
	}
	else{
		return wxDefaultSize;
	}
}

void REHex::ToolDock::ToolNotebook::UpdateToolVisibility()
{
	int selected_page = GetSelection();
	size_t num_pages = GetPageCount();
	
	for(size_t i = 0; i < num_pages; ++i)
	{
		ToolPanel *tool = (ToolPanel*)(GetPage(i));
		tool->set_visible((int)(i) == selected_page);
	}
}

void REHex::ToolDock::ToolNotebook::OnPageChanged(wxNotebookEvent& event)
{
	if(event.GetEventObject() == this)
	{
		if (event.GetOldSelection() != wxNOT_FOUND)
		{
			ToolPanel *old_tool = (ToolPanel*)(GetPage(event.GetOldSelection()));
			assert(old_tool != NULL);
			
			old_tool->set_visible(false);
		}
		
		if (event.GetSelection() != wxNOT_FOUND)
		{
			ToolPanel *new_tool = (ToolPanel*)(GetPage(event.GetSelection()));
			assert(new_tool != NULL);
			
			new_tool->set_visible(true);
		}
	}
	
	event.Skip();
}

REHex::ToolDock::ToolFrame::ToolFrame(wxWindow *parent, wxPoint position, wxSize size, ToolPanel *tool):
	wxFrame(parent, wxID_ANY, wxEmptyString, position, size,
		(wxCAPTION | wxCLOSE_BOX | wxRESIZE_BORDER | wxFRAME_TOOL_WINDOW | wxFRAME_FLOAT_ON_PARENT)),
	m_tool(NULL)
{
	m_sizer = new wxBoxSizer(wxHORIZONTAL);
	SetSizer(m_sizer);
	
	if(tool != NULL)
	{
		AdoptTool(tool);
	}
}

void REHex::ToolDock::ToolFrame::AdoptTool(ToolPanel *tool, bool resize)
{
	assert(m_tool == NULL);
	
	m_tool = tool;
	
	if(resize)
	{
		SetClientSize(tool->GetSize());
	}
	
	tool->Reparent(this);
	tool->Show();
	
	SetTitle(tool->label());
	m_sizer->Add(tool, 1, wxEXPAND);
}

void REHex::ToolDock::ToolFrame::RemoveTool(ToolPanel *tool)
{
	assert(m_tool == tool);
	
	m_tool = NULL;
	
	m_sizer->Detach(tool);
}

REHex::ToolPanel *REHex::ToolDock::ToolFrame::GetTool() const
{
	return m_tool;
}

REHex::ToolDock::DockSite::DockSite(wxWindow *parent, const wxBitmap &image, Anchor anchor):
	wxPopupWindow()
{
	static const int MARGIN = 16;
	
	SetBackgroundStyle(wxBG_STYLE_TRANSPARENT);
	Create(parent);
	
	wxStaticBitmap *sbmp = new wxStaticBitmap(this, wxID_ANY, image);
	
	SetClientSize(sbmp->GetSize());
	
	wxRect parent_rect = parent->GetScreenRect();
	wxSize size = GetSize();
	
	int x, y;
	switch(anchor)
	{
		case Anchor::LEFT:
			x = parent_rect.x + MARGIN;
			y = parent_rect.y + (parent_rect.height / 2) - (size.GetHeight() / 2);
			break;
			
		case Anchor::RIGHT:
			x = parent_rect.x + parent_rect.width - size.GetWidth() - MARGIN;
			y = parent_rect.y + (parent_rect.height / 2) - (size.GetHeight() / 2);
			break;
			
		case Anchor::TOP:
			x = parent_rect.x + (parent_rect.width / 2) - (size.GetWidth() / 2);
			y = parent_rect.y + MARGIN;
			break;
			
		case Anchor::BOTTOM:
			x = parent_rect.x + (parent_rect.width / 2) - (size.GetWidth() / 2);
			y = parent_rect.y + parent_rect.height - size.GetHeight() - MARGIN;
			break;
	}
	
	SetPosition(wxPoint(x, y));
}

BEGIN_EVENT_TABLE(REHex::ToolDock::DockShadow, wxPopupWindow)
	EVT_PAINT(REHex::ToolDock::DockShadow::OnPaint)
END_EVENT_TABLE()

REHex::ToolDock::DockShadow::DockShadow(wxWindow *parent, const wxRect &rect):
	wxPopupWindow()
{
	SetBackgroundStyle(wxBG_STYLE_TRANSPARENT);
	Create(parent);
	
	Move(rect);
}

void REHex::ToolDock::DockShadow::Move(const wxRect &rect)
{
	/* In wxGTK (at least), changing the wxPopupWindow size/position to one which overlaps
	 * with the previous position causes some weird bug where the client/paint area only covers
	 * the intersection between the new/old positions, returning the size/position to the
	 * previous position restores correct behaviour until you try moving it to overlap again.
	 *
	 * So we set the position miles off screen and *then* put it where we need it instead.
	*/
	#ifdef __WXGTK__
	if(GetScreenRect() == rect)
	{
		/* Avoid flickering if the window is already in the correct place. */
		return;
	}
	
	SetPosition(wxPoint(999999, 999999));
	#endif
	
	SetPosition(wxPoint(rect.x, rect.y));
	SetSize(wxSize(rect.width, rect.height));
}

void REHex::ToolDock::DockShadow::OnPaint(wxPaintEvent &event)
{
	wxPaintDC dc(this);
	
	wxGraphicsContext *gc = wxGraphicsContext::Create(dc);
	if(gc)
	{
		wxSize client_size = GetClientSize();
		
		gc->SetBrush(wxBrush(wxColour(0xF6, 0xD3, 0x2D, 100)));
		gc->DrawRectangle(0, 0, client_size.GetWidth(), client_size.GetHeight());
		
		delete gc;
	}
}
