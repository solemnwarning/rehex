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

#include "ToolPanelDock.hpp"

BEGIN_EVENT_TABLE(REHex::ToolPanelDock, REHex::MultiSplitter)
	EVT_LEFT_UP(REHex::ToolPanelDock::OnLeftUp)
	EVT_MOUSE_CAPTURE_LOST(REHex::ToolPanelDock::OnMouseCaptureLost)
	EVT_MOTION(REHex::ToolPanelDock::OnMotion)
END_EVENT_TABLE()

REHex::ToolPanelDock::ToolPanelDock(wxWindow *parent):
	MultiSplitter(parent),
	m_main_panel(NULL),
	m_drag_pending(false),
	m_drag_active(NULL)
{
	m_left_notebook = new Notebook(this, wxID_ANY, wxNB_LEFT);
	m_left_notebook->Bind(wxEVT_LEFT_DOWN, &REHex::ToolPanelDock::OnNotebookLeftDown, this);
	m_left_notebook->Hide();
	
	m_right_notebook = new Notebook(this, wxID_ANY, wxNB_RIGHT);
	m_right_notebook->Bind(wxEVT_LEFT_DOWN, &REHex::ToolPanelDock::OnNotebookLeftDown, this);
	m_right_notebook->Hide();
	
	m_top_notebook = new Notebook(this, wxID_ANY, wxNB_TOP);
	m_top_notebook->Bind(wxEVT_LEFT_DOWN, &REHex::ToolPanelDock::OnNotebookLeftDown, this);
	m_top_notebook->Hide();
	
	m_bottom_notebook = new Notebook(this, wxID_ANY, wxNB_BOTTOM);
	m_bottom_notebook->Bind(wxEVT_LEFT_DOWN, &REHex::ToolPanelDock::OnNotebookLeftDown, this);
	m_bottom_notebook->Hide();
}

void REHex::ToolPanelDock::AddMainPanel(wxWindow *main_panel)
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
}

void REHex::ToolPanelDock::DestroyTool(ToolPanel *tool)
{
	Notebook *notebook;
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

void REHex::ToolPanelDock::CreateTool(const std::string &name, SharedDocumentPointer &document, DocumentCtrl *document_ctrl)
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
	
	Notebook *target_notebook = NULL;
	
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
	
	target_notebook->AddPage(tool, tool->name(), true);
	
	if(target_notebook->GetPageCount() == 1)
	{
		ResetNotebookSize(target_notebook);
		target_notebook->Show();
	}
}

void REHex::ToolPanelDock::DestroyTool(const std::string &name)
{
	ToolPanel *tool = FindToolByName(name);
	if(tool != NULL)
	{
		DestroyTool(tool);
	}
}

bool REHex::ToolPanelDock::ToolExists(const std::string &name) const
{
	return FindToolByName(name) != NULL;
}

void REHex::ToolPanelDock::SaveTools(wxConfig *config) const
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
}

void REHex::ToolPanelDock::SaveToolsFromNotebook(wxConfig *config, Notebook *notebook)
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

void REHex::ToolPanelDock::LoadTools(wxConfig *config, SharedDocumentPointer &document, DocumentCtrl *document_ctrl)
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
}

void REHex::ToolPanelDock::LoadToolsIntoNotebook(wxConfig *config, Notebook *notebook, SharedDocumentPointer &document, DocumentCtrl *document_ctrl)
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
			
			fprintf(stderr, "name = %s\n", name.c_str());
			
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

void REHex::ToolPanelDock::ResetNotebookSize(Notebook *notebook)
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
}

REHex::ToolPanelDock::ToolFrame *REHex::ToolPanelDock::FindFrameByTool(ToolPanel *tool)
{
	auto frame_it = m_tool_frames.find(tool);
	return frame_it != m_tool_frames.end() ? frame_it->second : NULL;
}

REHex::ToolPanelDock::Notebook *REHex::ToolPanelDock::FindNotebookByTool(ToolPanel *tool)
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

REHex::ToolPanel *REHex::ToolPanelDock::FindToolByName(const std::string &name) const
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
	
	auto find_in_notebook = [&](Notebook *notebook)
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

void REHex::ToolPanelDock::OnNotebookLeftDown(wxMouseEvent &event)
{
	Notebook *notebook = (Notebook*)(event.GetEventObject());
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

void REHex::ToolPanelDock::OnLeftUp(wxMouseEvent &event)
{
	if(m_drag_pending || m_drag_active)
	{
		ReleaseMouse();
		
		m_drag_pending = false;
		m_drag_active = false;
	}
	
	#ifndef __APPLE__
	event.Skip();
	#endif
}

void REHex::ToolPanelDock::OnMouseCaptureLost(wxMouseCaptureLostEvent &event)
{
	if(m_drag_pending || m_drag_active)
	{
		m_drag_pending = false;
		m_drag_active = false;
	}
	else{
		event.Skip();
	}
}

void REHex::ToolPanelDock::OnMotion(wxMouseEvent &event)
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
		Notebook *notebook = FindNotebookByTool(m_left_down_tool);
		
		assert(frame == NULL || notebook == NULL);
		
		Notebook *dest_notebook = (Notebook*)(FindChildByPoint(event.GetPosition()));
		if(dest_notebook == m_main_panel)
		{
			wxRect mp_all = m_main_panel->GetRect();
			
			wxRect mp_left(mp_all.GetLeft(), mp_all.GetTop() + 10, 10, mp_all.GetHeight() - 20);
			wxRect mp_right(mp_all.GetRight() - 10, mp_all.GetTop() + 10, 10, mp_all.GetHeight() - 20);
			wxRect mp_top(mp_all.GetLeft() + 10, mp_all.GetTop(), mp_all.GetWidth() - 20, 10);
			wxRect mp_bottom(mp_all.GetLeft() + 10, mp_all.GetBottom() - 10, mp_all.GetWidth() - 20, 10);
			
			if(m_left_notebook->GetPageCount() == 0 && mp_left.Contains(event.GetPosition()))
			{
				dest_notebook = m_left_notebook;
			}
			else if(m_right_notebook->GetPageCount() == 0 && mp_right.Contains(event.GetPosition()))
			{
				dest_notebook = m_right_notebook;
			}
			else if(m_top_notebook->GetPageCount() == 0 && mp_top.Contains(event.GetPosition()))
			{
				dest_notebook = m_top_notebook;
			}
			else if(m_bottom_notebook->GetPageCount() == 0 && mp_bottom.Contains(event.GetPosition()))
			{
				dest_notebook = m_bottom_notebook;
			}
			else{
				dest_notebook = NULL;
			}
		}
		
		if(dest_notebook != NULL)
		{
			if(dest_notebook != notebook)
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
				dest_notebook->AddPage(m_left_down_tool, m_left_down_tool->name(), true);
				
				if(dest_notebook->GetPageCount() == 1)
				{
					ResetNotebookSize(dest_notebook);
					dest_notebook->Show();
				}
				
				if(frame != NULL)
				{
					frame->Destroy();
					m_tool_frames.erase(m_left_down_tool);
				}
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
			
			if(frame != NULL)
			{
				frame->SetPosition(frame_pos);
			}
			else{
				frame = new ToolFrame(this, m_left_down_tool);
				frame->SetPosition(frame_pos);
				frame->Show();
				
				ToolPanel *tool = m_left_down_tool;
				
				#if 0
				frame->Bind(wxEVT_ICONIZE, [this, frame, tool](wxIconizeEvent &event)
				{
					if(event.IsIconized())
					{
						tool->Reparent(m_right_notebook);
						m_right_notebook->AddPage(tool, tool->name(), true);
						
						m_tool_frames.erase(tool);
						frame->Destroy();
					}
				});
				#endif
				
				frame->Bind(wxEVT_CLOSE_WINDOW, [this, frame, tool](wxCloseEvent &event)
				{
					frame->GetSizer()->Detach(tool);
					tool->Reparent(m_right_notebook);

					m_right_notebook->AddPage(tool, tool->name(), true);

					if(m_right_notebook->GetPageCount() == 1)
					{
						ResetNotebookSize(m_right_notebook);
						m_right_notebook->Show();
					}
					
					m_tool_frames.erase(tool);
					frame->Destroy();
				});
				
				m_tool_frames.emplace(m_left_down_tool, frame);
			}
		}
	}
	
	event.Skip();
}

REHex::ToolPanelDock::Notebook::Notebook(wxWindow *parent, wxWindowID id, long style):
	wxNotebook(parent, id, wxDefaultPosition, wxDefaultSize, style) {}

REHex::ToolPanelDock::ToolFrame::ToolFrame(wxWindow *parent, ToolPanel *tool):
	wxFrame(parent, wxID_ANY, tool->name(), wxDefaultPosition, wxDefaultSize,
		(wxCAPTION | wxCLOSE_BOX | wxRESIZE_BORDER | wxFRAME_TOOL_WINDOW | wxFRAME_FLOAT_ON_PARENT))
{
	SetClientSize(tool->GetSize());

	tool->Reparent(this);
	tool->Show();

	wxBoxSizer *sizer = new wxBoxSizer(wxHORIZONTAL);
	sizer->Add(tool, 1, wxEXPAND);
	SetSizer(sizer);
}
