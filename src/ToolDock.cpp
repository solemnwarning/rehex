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

// Enable (experimental) custom styling of ToolNotebook under GTK
// #define REHEX_TOOLNOTEBOOK_CUSTOM_CSS

#include "platform.hpp"

#include <algorithm>
#include <wx/bitmap.h>
#include <wx/statbmp.h>

#if defined(__WXGTK__) && defined(REHEX_TOOLNOTEBOOK_CUSTOM_CSS)
#include <gtk/gtk.h>
#endif

#include "App.hpp"
#include "ToolDock.hpp"

#include "../res/dock_bottom.h"
#include "../res/dock_left.h"
#include "../res/dock_right.h"
#include "../res/dock_top.h"

wxDEFINE_EVENT(REHex::TOOLPANEL_CLOSED, wxCommandEvent);

BEGIN_EVENT_TABLE(REHex::ToolDock, REHex::MultiSplitter)
	EVT_LEFT_UP(REHex::ToolDock::OnLeftUp)
	EVT_MOUSE_CAPTURE_LOST(REHex::ToolDock::OnMouseCaptureLost)
	EVT_MOTION(REHex::ToolDock::OnMotion)
	EVT_NOTEBOOK_PAGE_CHANGED(wxID_ANY, REHex::ToolDock::OnNotebookPageChanged)
	EVT_SIZE(REHex::ToolDock::OnSize)
END_EVENT_TABLE()

REHex::ToolDock::ToolDock(wxWindow *parent):
	MultiSplitter(parent),
	m_main_panel(NULL),
	m_initial_size_done(false),
	m_drag_pending(false),
	m_drag_active(false),
	m_left_dock_site(NULL),
	m_right_dock_site(NULL),
	m_top_dock_site(NULL),
	m_bottom_dock_site(NULL)

#ifdef _WIN32
	, m_shadow_site(NULL)
#endif
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
}

REHex::ToolDock::~ToolDock()
{
	RemoveAllChildren();
	DestroyChildren();
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
	ToolFrame *frame = FindFrameByTool(tool);
	ToolNotebook *notebook = FindNotebookByTool(tool);
	
	assert(frame != NULL || notebook != NULL);
	
	if(frame != NULL)
	{
		frame->RemoveTool(tool);
		tool->Destroy();
		
		if(frame->GetTools().empty())
		{
			frame->Destroy();
		}
	}
	else if(notebook != NULL)
	{
		int page_idx = notebook->FindPage(tool);
		assert(page_idx != wxNOT_FOUND);
		
		notebook->DeletePage(page_idx);
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
	for(auto it = m_frames.begin(); it != m_frames.end(); ++it)
	{
		(*it)->Hide();
	}
}

void REHex::ToolDock::UnhideFrames()
{
	for(auto it = m_frames.begin(); it != m_frames.end(); ++it)
	{
		(*it)->ShowWithoutActivating();
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
	size_t fi = 0;
	for(auto fit = m_frames.begin(); fit != m_frames.end(); ++fit, ++fi)
	{
		char fi_path[32];
		snprintf(fi_path, sizeof(fi_path), "%zu/", fi);
		
		wxConfigPathChanger f_scoped_path(config, fi_path);
		
		ToolFrame *frame = *fit;
		
		config->Write("frame/x", frame->GetPosition().x);
		config->Write("frame/y", frame->GetPosition().y);
		
		config->Write("frame/width", frame->GetSize().GetWidth());
		config->Write("frame/height", frame->GetSize().GetHeight());
		
		std::vector<ToolPanel*> tools = frame->GetTools();
		
		size_t ti = 0;
		for(auto tit = tools.begin(); tit != tools.end(); ++tit, ++ti)
		{
			char ti_path[32];
			snprintf(ti_path, sizeof(ti_path), "%zu/", ti);
			
			wxConfigPathChanger t_scoped_path(config, ti_path);
			
			ToolPanel *tool = *tit;
			
			config->Write("name", wxString(tool->name()));
			tool->save_state(config);
		}
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
	
	CallAfter([this]()
	{
		ApplySizeConstraints();
		m_initial_size_done = true;
	});
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
			int height = config->ReadLong("height", -1);
			
			if(height > 0)
			{
				wxSize size(-1, height);
				SetWindowSize(notebook, size);
			}
			else{
				ResetNotebookSize(notebook);
			}
		}
		else{
			int width = config->ReadLong("width", -1);
			
			if(width > 0)
			{
				wxSize size(width, -1);
				SetWindowSize(notebook, size);
			}
			else{
				ResetNotebookSize(notebook);
			}
		}
	}
}

void REHex::ToolDock::LoadToolFrames(wxConfig *config, SharedDocumentPointer &document, DocumentCtrl *document_ctrl)
{
	for(size_t fi = 0;; ++fi)
	{
		char fi_path[64];
		snprintf(fi_path, sizeof(fi_path), "%zu/", fi);
		
		if(config->HasGroup(fi_path))
		{
			wxConfigPathChanger scoped_path(config, fi_path);
			
			wxPoint frame_position(
				config->ReadLong("frame/x", wxDefaultPosition.x),
				config->ReadLong("frame/y", wxDefaultPosition.y));
			
			wxSize frame_size(
				config->ReadLong("frame/width", wxDefaultSize.GetWidth()),
				config->ReadLong("frame/height", wxDefaultSize.GetHeight()));
			
			ToolFrame *frame = NULL;
			
			for(size_t ti = 0;; ++ti)
			{
				char ti_path[64];
				snprintf(ti_path, sizeof(ti_path), "%zu/", ti);
				
				if(config->HasGroup(ti_path))
				{
					wxConfigPathChanger scoped_path(config, ti_path);
					
					std::string name = config->Read("name", "").ToStdString();
					
					const ToolPanelRegistration *tpr = ToolPanelRegistry::by_name(name);
					if(tpr != NULL)
					{
						if(frame == NULL)
						{
							frame = new ToolFrame(this, &m_frames, frame_position, frame_size);
							frame->GetNotebook()->Bind(wxEVT_LEFT_DOWN, &REHex::ToolDock::OnNotebookLeftDown, this);
						}
						
						ToolPanel *tool = tpr->factory(frame, document, document_ctrl);
						tool->load_state(config);
						
						frame->AdoptTool(tool, false);
						
						frame->Show();
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
	std::vector<wxRect> mask_regions;
	mask_regions.reserve(m_frames.size());
	
	for(auto f_it = m_frames.begin(); f_it != m_frames.end(); ++f_it)
	{
		if(*f_it != m_drag_frame)
		{
			(*f_it)->SetupDockSite(mask_regions);
			mask_regions.push_back((*f_it)->GetScreenRect());
		}
	}
	
	if(m_left_dock_site == NULL)
	{
		m_left_dock_site = new DockSite(this, wxBITMAP_PNG_FROM_DATA(dock_left), Anchor::LEFT, mask_regions);
		m_left_dock_site->Show();
	}
	
	if(m_right_dock_site == NULL)
	{
		m_right_dock_site = new DockSite(this, wxBITMAP_PNG_FROM_DATA(dock_right), Anchor::RIGHT, mask_regions);
		m_right_dock_site->Show();
	}
	
	if(m_top_dock_site == NULL)
	{
		m_top_dock_site = new DockSite(this, wxBITMAP_PNG_FROM_DATA(dock_top), Anchor::TOP, mask_regions);
		m_top_dock_site->Show();
	}
	
	if(m_bottom_dock_site == NULL)
	{
		m_bottom_dock_site = new DockSite(this, wxBITMAP_PNG_FROM_DATA(dock_bottom), Anchor::BOTTOM, mask_regions);
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
	
	for(auto it = m_frames.begin(); it != m_frames.end(); ++it)
	{
		(*it)->DestroyDockSite();
	}
}

void REHex::ToolDock::ShowShadow(ToolNotebook *notebook, const wxRect &rect)
{
#ifdef _WIN32
	if(m_shadow_site != NULL)
	{
		if(m_shadow_site->GetShadowRect() == rect)
		{
			return;
		}

		m_shadow_site->Destroy();
		m_shadow_site = NULL;
	}
#endif

	if(notebook == m_left_notebook)
	{
#ifdef _WIN32
		m_shadow_site = new DockSite(this, wxBITMAP_PNG_FROM_DATA(dock_left), Anchor::LEFT, {}, rect);
		m_shadow_site->Show();
		
#else
		m_left_dock_site->ShowShadow(rect);
		
		m_right_dock_site->HideShadow();
		m_top_dock_site->HideShadow();
		m_bottom_dock_site->HideShadow();
#endif
		
		for(auto it = m_frames.begin(); it != m_frames.end(); ++it)
		{
			(*it)->HideShadow();
		}
		
	}
	else if(notebook == m_right_notebook)
	{
#ifdef _WIN32
		m_shadow_site = new DockSite(this, wxBITMAP_PNG_FROM_DATA(dock_right), Anchor::RIGHT, {}, rect);
		m_shadow_site->Show();

#else
		m_right_dock_site->ShowShadow(rect);
		
		m_left_dock_site->HideShadow();
		m_top_dock_site->HideShadow();
		m_bottom_dock_site->HideShadow();
#endif
		
		for(auto it = m_frames.begin(); it != m_frames.end(); ++it)
		{
			(*it)->HideShadow();
		}
	}
	else if(notebook == m_top_notebook)
	{
#ifdef _WIN32
		m_shadow_site = new DockSite(this, wxBITMAP_PNG_FROM_DATA(dock_top), Anchor::TOP, {}, rect);
		m_shadow_site->Show();

#else
		m_top_dock_site->ShowShadow(rect);
		
		m_left_dock_site->HideShadow();
		m_right_dock_site->HideShadow();
		m_bottom_dock_site->HideShadow();
#endif
		
		for(auto it = m_frames.begin(); it != m_frames.end(); ++it)
		{
			(*it)->HideShadow();
		}
	}
	else if(notebook == m_bottom_notebook)
	{
#ifdef _WIN32
		m_shadow_site = new DockSite(this, wxBITMAP_PNG_FROM_DATA(dock_bottom), Anchor::BOTTOM, {}, rect);
		m_shadow_site->Show();

#else
		m_bottom_dock_site->ShowShadow(rect);
		
		m_left_dock_site->HideShadow();
		m_right_dock_site->HideShadow();
		m_top_dock_site->HideShadow();
#endif
		
		for(auto it = m_frames.begin(); it != m_frames.end(); ++it)
		{
			(*it)->HideShadow();
		}
	}
	else{
#ifndef _WIN32
		m_left_dock_site->HideShadow();
		m_right_dock_site->HideShadow();
		m_top_dock_site->HideShadow();
		m_bottom_dock_site->HideShadow();
#endif
		
		for(auto it = m_frames.begin(); it != m_frames.end(); ++it)
		{
			if((*it)->GetNotebook() == notebook)
			{
				(*it)->ShowShadow();
			}
			else{
				(*it)->HideShadow();
			}
		}
	}
}

void REHex::ToolDock::HideShadow()
{
#ifdef _WIN32
	if(m_shadow_site != NULL)
	{
		m_shadow_site->Destroy();
		m_shadow_site = NULL;
	}

#else
	if(m_left_dock_site != NULL)   { m_left_dock_site  ->HideShadow(); }
	if(m_right_dock_site != NULL)  { m_right_dock_site ->HideShadow(); }
	if(m_top_dock_site != NULL)    { m_top_dock_site   ->HideShadow(); }
	if(m_bottom_dock_site != NULL) { m_bottom_dock_site->HideShadow(); }
#endif
	
	for(auto it = m_frames.begin(); it != m_frames.end(); ++it)
	{
		(*it)->HideShadow();
	}
}

REHex::ToolDock::ToolFrame *REHex::ToolDock::FindFrameByTool(ToolPanel *tool)
{
	for(auto it = m_frames.begin(); it != m_frames.end(); ++it)
	{
		if((*it)->GetNotebook()->FindPage(tool) != wxNOT_FOUND)
		{
			return *it;
		}
	}
	
	return NULL;
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
	
	for(auto frame_it = m_frames.begin(); frame_it != m_frames.end(); ++frame_it)
	{
		std::vector<ToolPanel*> frame_tools = (*frame_it)->GetTools();
		
		for(auto tool_it = frame_tools.begin(); tool_it != frame_tools.end(); ++tool_it)
		{
			if((*tool_it)->name() == name)
			{
				return *tool_it;
			}
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
	wxPoint screen_point = ClientToScreen(point);
	
	if(m_dock_frame != NULL)
	{
		if(m_dock_frame->ScreenPointInDockImage(screen_point))
		{
			return m_dock_frame->GetNotebook();
		}
		else{
			m_dock_frame = NULL;
		}
	}
	else if(m_dock_notebook != NULL)
	{
		assert(m_dock_site != NULL);
		
		if(m_dock_site->PointInImage(screen_point))
		{
			return m_dock_notebook;
		}
		else{
			m_dock_notebook = NULL;
		}
	}
	
	for(auto it = m_frames.begin(); it != m_frames.end(); ++it)
	{
		if((*it)->GetScreenRect().Contains(screen_point) && (*it)->GetNotebook()->FindPage(m_left_down_tool) == wxNOT_FOUND)
		{
			if((*it)->ScreenPointInDockImage(screen_point))
			{
				m_dock_frame = *it;
				return (*it)->GetNotebook();
			}
			else{
				return NULL;
			}
		}
	}
	
	ToolNotebook *dest_notebook = (ToolNotebook*)(FindChildByPoint(point));
	if(dest_notebook == NULL || dest_notebook != current_notebook)
	{
		if(m_left_dock_site != NULL && m_left_dock_site->PointInImage(screen_point))
		{
			m_dock_notebook = m_left_notebook;
			m_dock_site = m_left_dock_site;
			
			dest_notebook = m_left_notebook;
		}
		else if(m_right_dock_site != NULL && m_right_dock_site->PointInImage(screen_point))
		{
			m_dock_notebook = m_right_notebook;
			m_dock_site = m_right_dock_site;
			
			dest_notebook = m_right_notebook;
		}
		else if(m_top_dock_site != NULL && m_top_dock_site->PointInImage(screen_point))
		{
			m_dock_notebook = m_top_notebook;
			m_dock_site = m_top_dock_site;
			
			dest_notebook = m_top_notebook;
		}
		else if(m_bottom_dock_site != NULL && m_bottom_dock_site->PointInImage(screen_point))
		{
			m_dock_notebook = m_bottom_notebook;
			m_dock_site = m_bottom_dock_site;
			
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
	#ifdef REHEX_ENABLE_WAYLAND_HACKS
	if(REHex::App::is_wayland_session())
	{
		/* Skip toolpanel detaching under Wayland :( */
		event.Skip();
		return;
	}
	#endif
	
	ToolNotebook *notebook = (ToolNotebook*)(event.GetEventObject());
	// assert(notebook == m_left_notebook || notebook == m_right_notebook || notebook == m_top_notebook || notebook == m_bottom_notebook);
	
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
		m_left_down_point = ScreenToClient(notebook->ClientToScreen(event.GetPosition()));
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
			if(frame != NULL)
			{
				frame->RemoveTool(m_left_down_tool);
				
				if(frame->GetTools().empty())
				{
					frame->Destroy();
				}
			}
			else if(notebook != NULL)
			{
				notebook->RemovePage(notebook->FindPage(m_left_down_tool));
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
			}
		}
		
		HideShadow();
		DestroyDockSites();
	}
	
	if(m_drag_pending || m_drag_active)
	{
		ReleaseMouse();
		
		m_drag_pending = false;
		m_drag_active = false;
	}
	
	event.Skip();
}

void REHex::ToolDock::OnMouseCaptureLost(wxMouseCaptureLostEvent &event)
{
	if(m_drag_active)
	{
		HideShadow();
		DestroyDockSites();
	}
	
	if(m_drag_pending || m_drag_active)
	{
		m_drag_pending = false;
		m_drag_active = false;
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
			
			m_drag_frame = NULL;
			m_dock_notebook = NULL;
			m_dock_frame = NULL;
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
					ShowShadow(dest_notebook, dest_notebook->GetScreenRect());
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
					
					ShowShadow(dest_notebook, rect);
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
			wxPoint frame_pos = ClientToScreen(event.GetPosition());
			
			if(m_drag_frame == NULL)
			{
				if(frame != NULL)
				{
					if(frame->GetTools().size() == 1U)
					{
						m_drag_frame = frame;
					}
					else{
						frame->RemoveTool(m_left_down_tool);
					}
				}
				else if(notebook != NULL)
				{
					notebook->RemovePage(notebook->FindPage(m_left_down_tool));
				}
				
				if(m_drag_frame == NULL)
				{
					frame = m_drag_frame = new ToolFrame(this, &m_frames, wxDefaultPosition, wxDefaultSize, m_left_down_tool);
					frame->SetPosition(frame_pos);

					frame->GetNotebook()->Bind(wxEVT_LEFT_DOWN, &REHex::ToolDock::OnNotebookLeftDown, this);
				}
			}
			
			SetupDockSites();
			HideShadow();

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

void REHex::ToolDock::OnNotebookPageChanged(wxNotebookEvent &event)
{
	CallAfter([this]()
	{
		ApplySizeConstraints();
	});
}

void REHex::ToolDock::OnSize(wxSizeEvent &event)
{
	if(m_initial_size_done)
	{
		ApplySizeConstraints();
	}
	
	event.Skip(); /* Continue propagation. */
}

BEGIN_EVENT_TABLE(REHex::ToolDock::ToolNotebook, wxNotebook)
	EVT_NOTEBOOK_PAGE_CHANGED(wxID_ANY, REHex::ToolDock::ToolNotebook::OnPageChanged)
END_EVENT_TABLE()

REHex::ToolDock::ToolNotebook::ToolNotebook(wxWindow *parent, wxWindowID id, long style):
	wxNotebook(parent, id, wxDefaultPosition, wxDefaultSize, style)
{
#if defined(__WXGTK__) && defined(REHEX_TOOLNOTEBOOK_CUSTOM_CSS)
	GtkNotebook *gtk_notebook = (GtkNotebook*)(GetHandle());
	
	/* The radius of the border around the "top" edge of each tool tab. */
	#define TAB_BORDER_RADIUS "0.25em"
	
	char stylesheet[256];
	int stylesheet_len;
	
	if((style & wxNB_LEFT) != 0)
	{
		stylesheet_len = snprintf(stylesheet, sizeof(stylesheet),
			"notebook tab {"
			"  padding: 0.5em 0.5em 0.5em 0px;"
			"  border: 1px solid #000000;"
			"  border-radius: " TAB_BORDER_RADIUS " 0px 0px " TAB_BORDER_RADIUS ";"
			"  margin: 0.5em 0px 0px 0.5em;"
			"}"
			"notebook tab:checked {"
			"  background-color: #f6f5f4;"
			"}"
		);
	}
	else if((style & wxNB_RIGHT) != 0)
	{
		stylesheet_len = snprintf(stylesheet, sizeof(stylesheet),
			"notebook tab {"
			"  padding: 0.5em 0.1em 0.5em 0px;"
			"  border: 1px solid #000000;"
			"  border-radius: 0px " TAB_BORDER_RADIUS " " TAB_BORDER_RADIUS " 0px;"
			"  margin: 0.5em 0.5em 0px 0px;"
			"}"
			"notebook tab:checked {"
			"  background-color: #f6f5f4;"
			"}"
		);
	}
	else if((style & wxNB_BOTTOM) != 0)
	{
		stylesheet_len = snprintf(stylesheet, sizeof(stylesheet),
			"notebook tab {"
			"  padding: 0px 0.5em;"
			"  border: 1px solid #000000;"
			"  border-radius: 0px 0px " TAB_BORDER_RADIUS " " TAB_BORDER_RADIUS ";"
			"  margin: 0px 0px 0.5em 0.5em;"
			"}"
			"notebook tab:checked {"
			"  background-color: #f6f5f4;"
			"}"
		);
	}
	else{
		stylesheet_len = snprintf(stylesheet, sizeof(stylesheet),
			"notebook tab {"
			"  padding: 0px 0.5em;"
			"  border: 1px solid #000000;"
			"  border-radius: " TAB_BORDER_RADIUS " " TAB_BORDER_RADIUS " 0px 0px;"
			"  margin: 0.5em 0px 0px 0.5em;"
			"}"
			"notebook tab:checked {"
			"  background-color: #f6f5f4;"
			"}"
		);
	}
	
	assert((stylesheet_len + 1) < (int)(sizeof(stylesheet)));
	
	GtkCssProvider *provider = gtk_css_provider_new();
	gtk_css_provider_load_from_data(provider, stylesheet, -1, NULL);
	
	GtkStyleContext *context = gtk_widget_get_style_context((GtkWidget*)(gtk_notebook));
	gtk_style_context_add_provider(context, GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
#endif
}

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

BEGIN_EVENT_TABLE(REHex::ToolDock::ToolFrame, wxFrame)
	EVT_ACTIVATE(REHex::ToolDock::ToolFrame::OnWindowActivate)
END_EVENT_TABLE()

REHex::ToolDock::ToolFrame::ToolFrame(wxWindow *parent, std::list<ToolFrame*> *frame_order, wxPoint position, wxSize size, ToolPanel *tool):
	wxFrame(parent, wxID_ANY, wxEmptyString, position, size,
		(wxCAPTION | wxCLOSE_BOX | wxRESIZE_BORDER | wxFRAME_TOOL_WINDOW | wxFRAME_FLOAT_ON_PARENT)),
	m_frames(frame_order),
	m_dock_site(NULL)
	
#ifdef _WIN32
	, m_shadow_site(NULL)
#endif
{
	m_sizer = new wxBoxSizer(wxHORIZONTAL);
	
	m_notebook = new ToolNotebook(this, wxID_ANY, wxNB_TOP);
	m_sizer->Add(m_notebook, 1, wxEXPAND);
	
	SetSizerAndFit(m_sizer);
	
	if(tool != NULL)
	{
		AdoptTool(tool);
	}
	
	m_frames->push_front(this);
}

REHex::ToolDock::ToolFrame::~ToolFrame()
{
	/* Raise a TOOLPANEL_CLOSED event for each tool attached to the frame so that the
	 * corresponding MainWindow menu item for the tool can be un-checked.
	*/
	
	while(m_notebook->GetPageCount() > 0)
	{
		std::string name = ((ToolPanel*)(m_notebook->GetPage(0)))->name();
		m_notebook->DeletePage(0);
		
		/* Raise the event as if our parent (the ToolDock) generated it. */
		
		wxCommandEvent tpc_event(TOOLPANEL_CLOSED, GetParent()->GetId());
		tpc_event.SetEventObject(GetParent());
		tpc_event.SetString(name);
		
		GetParent()->ProcessWindowEvent(tpc_event);
	}
	
	auto it = std::find(m_frames->begin(), m_frames->end(), this);
	assert(it != m_frames->end());
	
	m_frames->erase(it);
}

void REHex::ToolDock::ToolFrame::AdoptTool(ToolPanel *tool, bool resize)
{
	if(resize)
	{
		SetClientSize(tool->GetSize());
	}
	
	SetTitle(tool->label());
	
	tool->Reparent(m_notebook);
	
	m_notebook->AddPage(tool, tool->label(), true);
}

void REHex::ToolDock::ToolFrame::RemoveTool(ToolPanel *tool)
{
	m_notebook->RemovePage(m_notebook->FindPage(tool));
}

REHex::ToolDock::ToolNotebook *REHex::ToolDock::ToolFrame::GetNotebook() const
{
	return m_notebook;
}

std::vector<REHex::ToolPanel*> REHex::ToolDock::ToolFrame::GetTools() const
{
	size_t num_pages = m_notebook->GetPageCount();
	
	std::vector<ToolPanel*> tools;
	tools.reserve(num_pages);
	
	for(size_t i = 0; i < num_pages; ++i)
	{
		tools.push_back((ToolPanel*)(m_notebook->GetPage(i)));
	}
	
	return tools;
}

void REHex::ToolDock::ToolFrame::SetupDockSite(const std::vector<wxRect> &mask_regions)
{
	if(m_dock_site == NULL)
	{
		m_dock_site = new DockSite(this, wxBITMAP_PNG_FROM_DATA(dock_top), Anchor::TOP, mask_regions);
		m_dock_site->Show();
	}
}

void REHex::ToolDock::ToolFrame::DestroyDockSite()
{
	if(m_dock_site != NULL)
	{
		m_dock_site->Destroy();
		m_dock_site = NULL;
	}
}

void REHex::ToolDock::ToolFrame::ShowShadow()
{
	wxRect shadow_rect = m_notebook->GetScreenRect();
	
#ifdef _WIN32
	if(m_shadow_site == NULL)
	{
		m_shadow_site = new DockSite(this, wxBITMAP_PNG_FROM_DATA(dock_top), Anchor::TOP, {}, shadow_rect);
		m_shadow_site->Show();
	}
#else
	if(m_dock_site != NULL)
	{
		m_dock_site->ShowShadow(shadow_rect);
	}
#endif
}

void REHex::ToolDock::ToolFrame::HideShadow()
{
#ifdef _WIN32
	if(m_shadow_site != NULL)
	{
		m_shadow_site->Destroy();
		m_shadow_site = NULL;
	}
#else
	if(m_dock_site != NULL)
	{
		m_dock_site->HideShadow();
	}
#endif
}

bool REHex::ToolDock::ToolFrame::ScreenPointInDockImage(const wxPoint &screen_point) const
{
	return m_dock_site != NULL && m_dock_site->PointInImage(screen_point);
}

void REHex::ToolDock::ToolFrame::OnWindowActivate(wxActivateEvent &event)
{
	auto it = std::find(m_frames->begin(), m_frames->end(), this);
	assert(it != m_frames->end());
	
	m_frames->erase(it);
	m_frames->push_front(this);
}

BEGIN_EVENT_TABLE(REHex::ToolDock::DockSite, wxPopupWindow)
	EVT_PAINT(REHex::ToolDock::DockSite::OnPaint)
END_EVENT_TABLE()

REHex::ToolDock::DockSite::DockSite(wxWindow *parent, const wxBitmap &image, Anchor anchor, const std::vector<wxRect> &mask_regions, const wxRect &shadow_rect):
	wxPopupWindow(),
	m_image(image.ConvertToImage()),
	m_image_bitmap(image),
	m_anchor(anchor),
	m_mask_regions(mask_regions),
	m_mask_enabled(shadow_rect.IsEmpty()),
	m_shadow(shadow_rect)
{
	/* We query whether transparency is supported via the parent window because we can't call
	 * it on our own window before constructing the window... but we need to know up-front
	 * whether transparency is supported so we know whether to set the background mode before
	 * constructing the window.
	 *
	 * ...except on Windows, where IsTransparentBackgroundSupported() will always return false, but
	 * transparency works well enough for our purposes on Windows 8 and later.
	*/
#ifdef _WIN32
#	if defined(_MSC_VER)
#	pragma warning( push )
#	pragma warning( disable : 4996 ) /* Suppress error due to GetVersionEx() being deprecated. */
#	endif

	OSVERSIONINFO version = { sizeof(OSVERSIONINFO) };
	if(GetVersionEx(&version) && ((version.dwMajorVersion == 6 && version.dwMinorVersion >= 2) || version.dwMajorVersion > 6))

#	if defined(_MSC_VER)
#	pragma warning( pop )
#	endif
#else
	if(parent->IsTransparentBackgroundSupported())
#endif
	{
		m_transparency = true;
		SetBackgroundStyle(wxBG_STYLE_TRANSPARENT);
	}
	else{
		m_transparency = false;
	}
	
	Create(parent);
	
	Resize();
}

#ifndef _WIN32
void REHex::ToolDock::DockSite::ShowShadow(const wxRect &rect)
{
	m_shadow = rect;
	Resize();
	
	if(m_mask_enabled)
	{
		m_mask_enabled = false;
		Refresh();
	}
}

void REHex::ToolDock::DockSite::HideShadow()
{
	m_shadow = wxRect(-1, -1, -1, -1);
	Resize();
	
	if(!m_mask_enabled)
	{
		m_mask_enabled = true;
		Refresh();
	}
}
#endif

wxRect REHex::ToolDock::DockSite::GetShadowRect() const
{
	return m_shadow;
}

bool REHex::ToolDock::DockSite::PointInImage(const wxPoint &screen_point) const
{
	wxRect screen_rect = GetScreenRect();
	
	int image_relative_x = screen_point.x - screen_rect.x - m_image_x;
	int image_relative_y = screen_point.y - screen_rect.y - m_image_y;
	
	wxSize image_size = m_image.GetSize();
	
	if(image_relative_x >= 0 && image_relative_x < image_size.GetWidth()
		&& image_relative_y >= 0 && image_relative_y < image_size.GetHeight())
	{
		return m_image.GetAlpha(image_relative_x, image_relative_y) > 0;
	}
	else{
		return false;
	}
}

void REHex::ToolDock::DockSite::Resize()
{
	static const int MARGIN = 16;
	
	wxRect parent_rect = GetParent()->GetScreenRect();
	
	wxSize image_size = m_image.GetSize();
	wxRect image_rect(-1, -1, image_size.GetWidth(), image_size.GetHeight());
	
	switch(m_anchor)
	{
		case Anchor::LEFT:
			image_rect.x = parent_rect.x + MARGIN;
			image_rect.y = parent_rect.y + (parent_rect.height / 2) - (image_size.GetHeight() / 2);
			break;
			
		case Anchor::RIGHT:
			image_rect.x = parent_rect.x + parent_rect.width - image_size.GetWidth() - MARGIN;
			image_rect.y = parent_rect.y + (parent_rect.height / 2) - (image_size.GetHeight() / 2);
			break;
			
		case Anchor::TOP:
			image_rect.x = parent_rect.x + (parent_rect.width / 2) - (image_size.GetWidth() / 2);
			image_rect.y = parent_rect.y + MARGIN;
			break;
			
		case Anchor::BOTTOM:
			image_rect.x = parent_rect.x + (parent_rect.width / 2) - (image_size.GetWidth() / 2);
			image_rect.y = parent_rect.y + parent_rect.height - image_size.GetHeight() - MARGIN;
			break;
	}
	
	wxRect total_rect = image_rect;
	
	if(!(m_shadow.IsEmpty()))
	{
		total_rect += m_shadow;
	}
	
	m_image_x = image_rect.x - total_rect.x;
	m_image_y = image_rect.y - total_rect.y;
	
	SetPosition(wxPoint(total_rect.x, total_rect.y));
	SetSize(wxSize(total_rect.width, total_rect.height));
}

void REHex::ToolDock::DockSite::OnPaint(wxPaintEvent &event)
{
	wxPaintDC dc(this);
	
	wxGraphicsContext *gc = wxGraphicsContext::Create(dc);
	if(gc)
	{
		if(m_mask_enabled)
		{
			wxSize size = GetSize();
			wxRegion clip_region(0, 0, size.GetWidth(), size.GetHeight());
			
			for(auto it = m_mask_regions.begin(); it != m_mask_regions.end(); ++it)
			{
				wxPoint local_top_left = ScreenToClient(it->GetTopLeft());
				wxPoint local_bottom_right = ScreenToClient(it->GetBottomRight());
				
				wxRect local_mask(local_top_left, local_bottom_right);
				
				clip_region.Subtract(local_mask);
			}
			
			gc->Clip(clip_region);
		}
		
		if(!(m_shadow.IsEmpty()))
		{
			wxRect screen_rect = GetScreenRect();
			
			gc->SetBrush(wxBrush(wxColour(0xF6, 0xD3, 0x2D, 100)));
			gc->DrawRectangle((m_shadow.x - screen_rect.x), (m_shadow.y - screen_rect.y), m_shadow.width, m_shadow.height);
		}
		
		wxSize image_size = m_image.GetSize();
		
		gc->DrawBitmap(m_image_bitmap, m_image_x, m_image_y, image_size.GetWidth(), image_size.GetHeight());
		
		delete gc;
	}
}
