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
#include <wx/dataobj.h>
#include <wx/dcbuffer.h>
#include <wx/graphics.h>
#include <wx/statbmp.h>

#if defined(__WXGTK__) && defined(REHEX_TOOLNOTEBOOK_CUSTOM_CSS)
#include <gtk/gtk.h>
#endif

#include "App.hpp"
#include "ToolDock.hpp"

#ifdef REHEX_ENABLE_WAYLAND_HACKS
#include "ProxyDropTarget.hpp"
#endif

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
	
#ifdef REHEX_WINDOW_SCREENSHOT_BROKEN
	m_left_dock_site(NULL),
	m_right_dock_site(NULL),
	m_top_dock_site(NULL),
	m_bottom_dock_site(NULL)
#ifdef _WIN32
	, m_shadow_site(NULL)
#endif
#else
	m_imposter(NULL),
	m_saved_left_notebook_width(-1),
	m_saved_right_notebook_width(-1),
	m_saved_top_notebook_height(-1),
	m_saved_bottom_notebook_height(-1)
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

#ifdef REHEX_ENABLE_WAYLAND_HACKS
void REHex::ToolDock::DragDropTool()
{
	SetupDockSites();

	/* We use a private data format for the drag-and-drop operation to avoid other
	 * applications being valid drop targets and skipping the detach operation.
	*/
	wxDataFormat format("rehex/toolpanel-drag-and-drop");

	m_imposter->SetDropTarget(new ProxyDropTarget(m_imposter, new wxCustomDataObject(format)));

	m_imposter->Bind(DROP_MOTION, [&](DropEvent &event)
	{
		ToolNotebook *dest_notebook;

		if(m_imposter->PointerInDropZone(event.GetX(), event.GetY(), wxTOP))
		{
			dest_notebook = m_top_notebook;
		}
		else if(m_imposter->PointerInDropZone(event.GetX(), event.GetY(), wxBOTTOM))
		{
			dest_notebook = m_bottom_notebook;
		}
		else if(m_imposter->PointerInDropZone(event.GetX(), event.GetY(), wxLEFT))
		{
			dest_notebook = m_left_notebook;
		}
		else if(m_imposter->PointerInDropZone(event.GetX(), event.GetY(), wxRIGHT))
		{
			dest_notebook = m_right_notebook;
		}
		else{
			dest_notebook = NULL;
		}

		if(dest_notebook != NULL)
		{
			wxRect shadow_rect = CalculateShadowForNotebook(dest_notebook, m_left_down_tool, false);
			m_imposter->ShowShadow(shadow_rect);
			//event.SetResult(wxDragMove);
		}
		else{
			m_imposter->HideShadow();
			//event.SetResult(wxDragCopy);
		}
	});

	m_imposter->Bind(DROP_DROP, [&](DropEvent &event)
	{
		ToolNotebook *dest_notebook;

		if(m_imposter->PointerInDropZone(event.GetX(), event.GetY(), wxTOP))
		{
			dest_notebook = m_top_notebook;
		}
		else if(m_imposter->PointerInDropZone(event.GetX(), event.GetY(), wxBOTTOM))
		{
			dest_notebook = m_bottom_notebook;
		}
		else if(m_imposter->PointerInDropZone(event.GetX(), event.GetY(), wxLEFT))
		{
			dest_notebook = m_left_notebook;
		}
		else if(m_imposter->PointerInDropZone(event.GetX(), event.GetY(), wxRIGHT))
		{
			dest_notebook = m_right_notebook;
		}
		else{
			event.RejectData();
			return;
		}

		if(dest_notebook != NULL)
		{
			ToolFrame *frame = FindFrameByTool(m_left_down_tool);
			ToolNotebook *notebook = FindNotebookByTool(m_left_down_tool);
			
			assert(frame == NULL || notebook == NULL);
			
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
				
				if(frame != NULL)
				{
					frame->Destroy();
				}
			}
		}
	});

	m_imposter->Bind(DROP_LEAVE, [&](DropEvent &event)
	{
		m_imposter->HideShadow();
	});
	
	for(auto fi = m_frames.begin(); fi != m_frames.end(); ++fi)
	{
		ToolFrame *frame = *fi;

		Imposter *frame_imposter = frame->GetImposter();
		assert(frame_imposter != NULL);

		frame_imposter->SetDropTarget(new ProxyDropTarget(frame_imposter, new wxCustomDataObject(format)));

		frame_imposter->Bind(DROP_MOTION, [frame, frame_imposter](DropEvent &event)
		{
			if(frame_imposter->PointerInDropZone(event.GetX(), event.GetY(), wxTOP))
			{
				frame->ShowShadow();
			}
			else{
				frame->HideShadow();
			}
		});

		frame_imposter->Bind(DROP_DROP, [this, frame, frame_imposter](DropEvent &event)
		{
			if(frame_imposter->PointerInDropZone(event.GetX(), event.GetY(), wxTOP))
			{
				ToolFrame *src_frame = FindFrameByTool(m_left_down_tool);
				ToolNotebook *notebook = FindNotebookByTool(m_left_down_tool);
				
				assert(src_frame == NULL || notebook == NULL);
				
				if(src_frame != frame)
				{
					if(src_frame != NULL)
					{
						src_frame->RemoveTool(m_left_down_tool);
						
						if(src_frame->GetTools().empty())
						{
							src_frame->Destroy();
						}
					}
					else if(notebook != NULL)
					{
						notebook->RemovePage(notebook->FindPage(m_left_down_tool));
					}

					ToolNotebook *dest_notebook = frame->GetNotebook();
					
					m_left_down_tool->Reparent(dest_notebook);
					dest_notebook->AddPage(m_left_down_tool, m_left_down_tool->label(), true);
				}
			}
			else{
				event.RejectData();
			}
		});

		frame_imposter->Bind(DROP_LEAVE, [&](DropEvent &event)
		{
			frame_imposter->HideShadow();
		});
	}

	wxCustomDataObject dobj(format);
	wxDropSource ds(dobj, this);
	wxDragResult drag_result = ds.DoDragDrop(0);

	/* Dropping the tool outside of a drop zone will detach the tool, so we need to create a
	 * new ToolFrame for it. GTK returns wxDragCancel if the user released the mouse button
	 * over somewhere that doesn't accept the data type.
	*/
	
	if(drag_result == wxDragNone || drag_result == wxDragCancel)
	{
		ToolNotebook *notebook = FindNotebookByTool(m_left_down_tool);
		ToolFrame *frame = FindFrameByTool(m_left_down_tool);

		assert(notebook != NULL || frame != NULL);

		if(notebook != NULL)
		{
			notebook->RemovePage(notebook->FindPage(m_left_down_tool));
		}
		else if(frame != NULL)
		{
			frame->RemoveTool(m_left_down_tool);

			if(frame->GetTools().empty())
			{
				frame->Destroy();
			}
		}

		frame = new ToolFrame(this, &m_frames, wxGetMousePosition(), wxDefaultSize, m_left_down_tool);

		frame->GetNotebook()->Bind(wxEVT_LEFT_DOWN, &REHex::ToolDock::OnNotebookLeftDown, this);

		frame->Show();
	}

	DestroyDockSites();
}
#endif

void REHex::ToolDock::SetupDockSites()
{
#ifdef REHEX_WINDOW_SCREENSHOT_BROKEN
	
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
	
#else /* REHEX_WINDOW_SCREENSHOT_BROKEN */
	
	if(m_imposter == NULL)
	{
		wxBitmap s = window_screenshot(this);
		
		m_saved_left_notebook_width    = m_left_notebook  ->IsShown() ? m_left_notebook  ->GetSize().GetWidth()  : -1;
		m_saved_right_notebook_width   = m_right_notebook ->IsShown() ? m_right_notebook ->GetSize().GetWidth()  : -1;
		m_saved_top_notebook_height    = m_top_notebook   ->IsShown() ? m_top_notebook   ->GetSize().GetHeight() : -1;
		m_saved_bottom_notebook_height = m_bottom_notebook->IsShown() ? m_bottom_notebook->GetSize().GetHeight() : -1;
		
		/* Hide our children so the imposter can draw on the screen space instead. */
		m_main_panel->Hide();
		m_left_notebook->Hide();
		m_right_notebook->Hide();
		m_top_notebook->Hide();
		m_bottom_notebook->Hide();
		
		m_imposter = new Imposter(this, s, wxALL, wxPoint(0, 0), s.GetSize());
	}

	for(auto f_it = m_frames.begin(); f_it != m_frames.end(); ++f_it)
	{
		(*f_it)->SetupDockSite();
	}
	
#endif /* !REHEX_WINDOW_SCREENSHOT_BROKEN */
}

void REHex::ToolDock::DestroyDockSites()
{
#ifdef REHEX_WINDOW_SCREENSHOT_BROKEN
	
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
	
#else /* REHEX_WINDOW_SCREENSHOT_BROKEN */
	
	if(m_imposter != NULL)
	{
		m_main_panel->Show();

		auto RestoreNotebook = [&](ToolNotebook *notebook, const wxSize &size)
		{
			if(notebook->GetPageCount() > 0)
			{
				notebook->Show();

				if(size.GetWidth() >= 0 || size.GetHeight() >= 0)
				{
					SetWindowSize(notebook, size);
				}
				else{
					ResetNotebookSize(notebook);
				}
			}
		};

		RestoreNotebook(m_left_notebook, wxSize(m_saved_left_notebook_width, -1));
		RestoreNotebook(m_right_notebook, wxSize(m_saved_right_notebook_width, -1));
		RestoreNotebook(m_top_notebook, wxSize(-1, m_saved_top_notebook_height));
		RestoreNotebook(m_bottom_notebook, wxSize(-1, m_saved_bottom_notebook_height));
		
		m_imposter->Destroy();
		m_imposter = NULL;
		
		m_saved_left_notebook_width = -1;
		m_saved_right_notebook_width = -1;
		m_saved_top_notebook_height = -1;
		m_saved_bottom_notebook_height = -1;
	}
	
#endif /* !REHEX_WINDOW_SCREENSHOT_BROKEN */

	for(auto it = m_frames.begin(); it != m_frames.end(); ++it)
	{
		(*it)->DestroyDockSite();
	}
}

wxRect REHex::ToolDock::CalculateShadowForNotebook(ToolNotebook *notebook, ToolPanel *tool, bool screen)
{
	if(notebook->IsShown())
	{
		return screen
			? notebook->GetScreenRect()
			: notebook->GetRect();
	}
	else{
		wxSize client_size = GetClientSize();
		
		wxSize min_size = m_left_down_tool->GetEffectiveMinSize();
		wxSize best_size = m_left_down_tool->GetBestSize();
		
		wxRect rect;
		
#ifndef REHEX_WINDOW_SCREENSHOT_BROKEN
		if(notebook == m_left_notebook && m_saved_left_notebook_width >= 0)
		{
			rect.x = 0;
			rect.y = 0;
			
			rect.width = m_saved_left_notebook_width;
			rect.height = client_size.GetHeight();
		}
		else if(notebook == m_right_notebook && m_saved_right_notebook_width >= 0)
		{
			rect.x = client_size.GetWidth() - m_saved_right_notebook_width;
			rect.y = 0;
			
			rect.width = m_saved_right_notebook_width;
			rect.height = client_size.GetHeight();
		}
		else if(notebook == m_top_notebook && m_saved_top_notebook_height >= 0)
		{
			rect.x = 0;
			rect.y = 0;
			
			rect.width = client_size.GetWidth();
			rect.height = m_saved_top_notebook_height;
		}
		else if(notebook == m_bottom_notebook && m_saved_bottom_notebook_height >= 0)
		{
			rect.x = 0;
			rect.y = client_size.GetHeight() - m_saved_bottom_notebook_height;
			
			rect.width = client_size.GetWidth();
			rect.height = m_saved_bottom_notebook_height;
		}
		else
#endif /* !REHEX_WINDOW_SCREENSHOT_BROKEN */
		{
			if(notebook == m_top_notebook || notebook == m_bottom_notebook)
			{
				rect.width = client_size.GetWidth();
				rect.height = std::max(min_size.GetHeight(), best_size.GetHeight());
			}
			else{
				rect.width = std::max(min_size.GetWidth(), best_size.GetWidth());
				rect.height = client_size.GetHeight();
			}
			
			if(notebook == m_left_notebook || notebook == m_top_notebook)
			{
				rect.x = 0;
				rect.y = 0;
			}
			else if(notebook == m_right_notebook)
			{
				rect.x = client_size.GetWidth() - rect.width;
				rect.y = 0;
			}
			else if(notebook == m_bottom_notebook)
			{
				rect.x = 0;
				rect.y = client_size.GetHeight() - rect.height;
			}
		}
		
		if(screen)
		{
			wxPoint client_base = ClientToScreen(wxPoint(0, 0));
			
			rect.x += client_base.x;
			rect.y += client_base.y;
		}
		
		return rect;
	}
}

void REHex::ToolDock::ShowShadow(ToolNotebook *notebook, const wxRect &rect)
{
#ifdef REHEX_ENABLE_WAYLAND_HACKS
	/* This path shouldn't be hit under Wayland. */
	assert(!(REHex::App::is_wayland_session()));
#endif
	
#ifdef REHEX_WINDOW_SCREENSHOT_BROKEN
	
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
	
#else /* REHEX_WINDOW_SCREENSHOT_BROKEN */
	
	if(notebook == m_left_notebook || notebook == m_right_notebook || notebook == m_top_notebook || notebook == m_bottom_notebook)
	{
		/* Adjust screen-space co-ordinate to be relative to the Imposter. */
		
		wxPoint base = m_imposter->GetScreenPosition();
		
		wxRect local_rect = rect;
		local_rect.Offset(wxPoint(0, 0) - base);
		
		m_imposter->ShowShadow(local_rect);
		
		for(auto it = m_frames.begin(); it != m_frames.end(); ++it)
		{
			(*it)->HideShadow();
		}
	}
	else{
		m_imposter->HideShadow();
		
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
	
#endif /* !REHEX_WINDOW_SCREENSHOT_BROKEN */
}

void REHex::ToolDock::HideShadow()
{
#ifdef REHEX_ENABLE_WAYLAND_HACKS
	/* This path shouldn't be hit under Wayland. */
	assert(!(REHex::App::is_wayland_session()));
#endif
	
#ifdef REHEX_WINDOW_SCREENSHOT_BROKEN
	
#ifdef _WIN32
	if(m_shadow_site != NULL)
	{
		m_shadow_site->Destroy();
		m_shadow_site = NULL;
	}

#else /* _WIN32 */
	if(m_left_dock_site != NULL)   { m_left_dock_site  ->HideShadow(); }
	if(m_right_dock_site != NULL)  { m_right_dock_site ->HideShadow(); }
	if(m_top_dock_site != NULL)    { m_top_dock_site   ->HideShadow(); }
	if(m_bottom_dock_site != NULL) { m_bottom_dock_site->HideShadow(); }
#endif /* !_WIN32 */
	
#else /* REHEX_WINDOW_SCREENSHOT_BROKEN */
	
	if(m_imposter != NULL)
	{
		m_imposter->HideShadow();
	}
	
#endif /* !REHEX_WINDOW_SCREENSHOT_BROKEN */
	
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
#ifdef REHEX_WINDOW_SCREENSHOT_BROKEN
		assert(m_dock_site != NULL);
		
		if(m_dock_site->PointInImage(screen_point))
		{
			return m_dock_notebook;
		}
#else /* REHEX_WINDOW_SCREENSHOT_BROKEN */
		assert(m_imposter != NULL);
		
		if((m_dock_notebook == m_left_notebook && m_imposter->PointerInDropZone(point.x, point.y, wxLEFT))
			|| (m_dock_notebook == m_right_notebook && m_imposter->PointerInDropZone(point.x, point.y, wxRIGHT))
			|| (m_dock_notebook == m_top_notebook && m_imposter->PointerInDropZone(point.x, point.y, wxTOP))
			|| (m_dock_notebook == m_bottom_notebook && m_imposter->PointerInDropZone(point.x, point.y, wxBOTTOM)))
		{
			return m_dock_notebook;
		}
#endif /* !REHEX_WINDOW_SCREENSHOT_BROKEN */
		
		m_dock_notebook = NULL;
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
	
#ifdef REHEX_WINDOW_SCREENSHOT_BROKEN
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
	
#else /* REHEX_WINDOW_SCREENSHOT_BROKEN */
	
	ToolNotebook *dest_notebook = NULL;
	
	if(m_imposter != NULL)
	{
		wxPoint imposter_point = m_imposter->ScreenToClient(screen_point);
		
		if(m_imposter->PointerInDropZone(imposter_point.x, imposter_point.y, wxLEFT))
		{
			dest_notebook = m_left_notebook;
		}
		else if(m_imposter->PointerInDropZone(imposter_point.x, imposter_point.y, wxRIGHT))
		{
			dest_notebook = m_right_notebook;
		}
		else if(m_imposter->PointerInDropZone(imposter_point.x, imposter_point.y, wxTOP))
		{
			dest_notebook = m_top_notebook;
		}
		else if(m_imposter->PointerInDropZone(imposter_point.x, imposter_point.y, wxBOTTOM))
		{
			dest_notebook = m_bottom_notebook;
		}
	}
	
#endif /* !REHEX_WINDOW_SCREENSHOT_BROKEN */
	
	return dest_notebook;
}

void REHex::ToolDock::OnNotebookLeftDown(wxMouseEvent &event)
{
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

#ifdef REHEX_ENABLE_WAYLAND_HACKS
			if(REHex::App::is_wayland_session())
			{
				/* Wayland has no global co-ordinate space and doesn't allow an application to
				 * receive events when the mouse it outside of one of its windows, even when it has
				 * captured the mouse, so under Wayland we instead implement the tool drag and drop
				 * as an actual drag and drop operation, we don't do this on all platforms as it
				 * offers a slightly worse/less experience (detatched tabs can't follow the mouse).
				*/
			
				m_drag_active = false;
				ReleaseMouse();

				DragDropTool();

				return; // TODO: Should fall through to event.Skip() ?
			}
#endif
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
				wxRect shadow_rect = CalculateShadowForNotebook(dest_notebook, m_left_down_tool, true);
				ShowShadow(dest_notebook, shadow_rect);
				
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
#ifdef REHEX_WINDOW_SCREENSHOT_BROKEN
	m_dock_site(NULL)
	
#ifdef _WIN32
	, m_shadow_site(NULL)
#endif
#else
	m_imposter(NULL)
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

#ifdef REHEX_WINDOW_SCREENSHOT_BROKEN
void REHex::ToolDock::ToolFrame::SetupDockSite(const std::vector<wxRect> &mask_regions)
{
	if(m_dock_site == NULL)
	{
		m_dock_site = new DockSite(this, wxBITMAP_PNG_FROM_DATA(dock_top), Anchor::TOP, mask_regions);
		m_dock_site->Show();
	}
}
#else /* REHEX_WINDOW_SCREENSHOT_BROKEN */
void REHex::ToolDock::ToolFrame::SetupDockSite()
{
	if(m_imposter == NULL)
	{
		wxBitmap s = window_screenshot(this);
		
		m_notebook->Hide();
		m_imposter = new Imposter(this, s, wxTOP, wxPoint(0, 0), GetClientSize());
	}
}
#endif /* !REHEX_WINDOW_SCREENSHOT_BROKEN */

void REHex::ToolDock::ToolFrame::DestroyDockSite()
{
#ifdef REHEX_WINDOW_SCREENSHOT_BROKEN
	
	if(m_dock_site != NULL)
	{
		m_dock_site->Destroy();
		m_dock_site = NULL;
	}
	
#else /* REHEX_WINDOW_SCREENSHOT_BROKEN */
	
	if(m_imposter != NULL)
	{
		m_imposter->Destroy();
		m_imposter = NULL;
		
		m_notebook->Show();
	}
	
#endif /* !REHEX_WINDOW_SCREENSHOT_BROKEN */
}

void REHex::ToolDock::ToolFrame::ShowShadow()
{
#ifdef REHEX_WINDOW_SCREENSHOT_BROKEN
	
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
	
#else /* REHEX_WINDOW_SCREENSHOT_BROKEN */
	
	if(m_imposter != NULL)
	{
		m_imposter->ShowShadow(wxRect(wxPoint(0, 0), m_imposter->GetSize()));
	}
	
#endif /* !REHEX_WINDOW_SCREENSHOT_BROKEN */
}

void REHex::ToolDock::ToolFrame::HideShadow()
{
#ifdef REHEX_WINDOW_SCREENSHOT_BROKEN
	
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
	
#else /* REHEX_WINDOW_SCREENSHOT_BROKEN */
	
	if(m_imposter != NULL)
	{
		m_imposter->HideShadow();
	}
	
#endif /* !REHEX_WINDOW_SCREENSHOT_BROKEN */
}

bool REHex::ToolDock::ToolFrame::ScreenPointInDockImage(const wxPoint &screen_point) const
{
#ifdef REHEX_WINDOW_SCREENSHOT_BROKEN
	return m_dock_site != NULL && m_dock_site->PointInImage(screen_point);
	
#else /* REHEX_WINDOW_SCREENSHOT_BROKEN */
	if(m_imposter != NULL)
	{
		wxPoint local_point = m_imposter->ScreenToClient(screen_point);
		return m_imposter->PointerInDropZone(local_point.x, local_point.y, wxTOP);
	}
	else{
		return false;
	}
	
#endif /* !REHEX_WINDOW_SCREENSHOT_BROKEN */
}

#ifndef REHEX_WINDOW_SCREENSHOT_BROKEN
REHex::ToolDock::Imposter *REHex::ToolDock::ToolFrame::GetImposter()
{
	return m_imposter;
}
#endif

void REHex::ToolDock::ToolFrame::OnWindowActivate(wxActivateEvent &event)
{
	auto it = std::find(m_frames->begin(), m_frames->end(), this);
	assert(it != m_frames->end());
	
	m_frames->erase(it);
	m_frames->push_front(this);
}

#ifdef REHEX_WINDOW_SCREENSHOT_BROKEN

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

#else /* REHEX_WINDOW_SCREENSHOT_BROKEN */

BEGIN_EVENT_TABLE(REHex::ToolDock::Imposter, wxWindow)
	EVT_PAINT(REHex::ToolDock::Imposter::OnPaint)
	EVT_ERASE_BACKGROUND(REHex::ToolDock::Imposter::OnErase)
END_EVENT_TABLE()

REHex::ToolDock::Imposter::Imposter(wxWindow *parent, const wxBitmap &background, enum wxDirection sides, const wxPoint &pos, const wxSize &size):
	wxWindow(parent, wxID_ANY, pos, size),
	m_background(background)
{
	static const int MARGIN = 16;

	if((sides & wxTOP) == wxTOP)
	{
		m_top_bitmap = wxBITMAP_PNG_FROM_DATA(dock_top);

		m_top_rect.x = (size.GetWidth() / 2) - (m_top_bitmap.GetWidth() / 2);
		m_top_rect.y = MARGIN;
		m_top_rect.width = m_top_bitmap.GetWidth();
		m_top_rect.height = m_top_bitmap.GetHeight();
	}

	if((sides & wxBOTTOM) == wxBOTTOM)
	{
		m_bottom_bitmap = wxBITMAP_PNG_FROM_DATA(dock_bottom);

		m_bottom_rect.x = (size.GetWidth() / 2) - (m_bottom_bitmap.GetWidth() / 2);
		m_bottom_rect.y = size.GetHeight() - 1 - MARGIN - m_bottom_bitmap.GetHeight();
		m_bottom_rect.width = m_bottom_bitmap.GetWidth();
		m_bottom_rect.height = m_bottom_bitmap.GetHeight();
	}

	if((sides & wxLEFT) == wxLEFT)
	{
		m_left_bitmap = wxBITMAP_PNG_FROM_DATA(dock_left);

		m_left_rect.x = MARGIN;
		m_left_rect.y = (size.GetHeight() / 2) - (m_left_bitmap.GetHeight() / 2);
		m_left_rect.width = m_left_bitmap.GetWidth();
		m_left_rect.height = m_left_bitmap.GetHeight();
	}

	if((sides & wxRIGHT) == wxRIGHT)
	{
		m_right_bitmap = wxBITMAP_PNG_FROM_DATA(dock_right);

		m_right_rect.x = size.GetWidth() - 1 - MARGIN - m_right_bitmap.GetWidth();
		m_right_rect.y = (size.GetHeight() / 2) - (m_right_bitmap.GetHeight() / 2);
		m_right_rect.width = m_right_bitmap.GetWidth();
		m_right_rect.height = m_right_bitmap.GetHeight();
	}
}

bool REHex::ToolDock::Imposter::PointerInDropZone(wxCoord x, wxCoord y, enum wxDirection edge) const
{
	switch(edge)
	{
		case wxTOP:    return m_top_rect.Contains(x, y);
		case wxBOTTOM: return m_bottom_rect.Contains(x, y);
		case wxLEFT:   return m_left_rect.Contains(x, y);
		case wxRIGHT:  return m_right_rect.Contains(x, y);
		default:       return false;
	}
}

void REHex::ToolDock::Imposter::ShowShadow(const wxRect &rect)
{
	m_shadow_rect = rect;
	Refresh();
}

void REHex::ToolDock::Imposter::HideShadow()
{
	m_shadow_rect = wxRect();
	Refresh();
}

void REHex::ToolDock::Imposter::OnPaint(wxPaintEvent &event)
{
	wxBufferedPaintDC dc(this);

	std::unique_ptr<wxGraphicsContext> gc(wxGraphicsContext::Create(dc));
	if(gc)
	{
		gc->DrawBitmap(m_background, 0, 0, m_background.GetWidth(), m_background.GetHeight());

		gc->SetBrush(wxBrush(wxColour(0xF6, 0xD3, 0x2D, 100)));
		gc->DrawRectangle(m_shadow_rect.x, m_shadow_rect.y, m_shadow_rect.width, m_shadow_rect.height);

		if(m_top_bitmap.IsOk())
		{
			gc->DrawBitmap(m_top_bitmap, m_top_rect.x, m_top_rect.y, m_top_rect.width, m_top_rect.height);
		}

		if(m_bottom_bitmap.IsOk())
		{
			gc->DrawBitmap(m_bottom_bitmap, m_bottom_rect.x, m_bottom_rect.y, m_bottom_rect.width, m_bottom_rect.height);
		}

		if(m_left_bitmap.IsOk())
		{
			gc->DrawBitmap(m_left_bitmap, m_left_rect.x, m_left_rect.y, m_left_rect.width, m_left_rect.height);
		}

		if(m_right_bitmap.IsOk())
		{
			gc->DrawBitmap(m_right_bitmap, m_right_rect.x, m_right_rect.y, m_right_rect.width, m_right_rect.height);
		}
	}
}

void REHex::ToolDock::Imposter::OnErase(wxEraseEvent &event)
{
	/* Left blank to disable background erase */
}

#endif /* !REHEX_WINDOW_SCREENSHOT_BROKEN */
