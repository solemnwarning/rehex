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

#ifndef REHEX_TOOLPANELDOCK_HPP
#define REHEX_TOOLPANELDOCK_HPP

#include <map>
#include <string>
#include <wx/config.h>
#include <wx/event.h>
#include <wx/notebook.h>
#include <wx/sizer.h>

#include "MultiSplitter.hpp"
#include "ToolPanel.hpp"

namespace REHex
{
	/**
	 * @brief Splitter window for tiling and detaching/docking tool panels.
	*/
	class ToolDock: public MultiSplitter
	{
		public:
			ToolDock(wxWindow *parent);
			
			void AddMainPanel(wxWindow *main_panel);
			
			void CreateTool(const std::string &name, SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			void DestroyTool(const std::string &name);
			bool ToolExists(const std::string &name) const;
			
			void SaveTools(wxConfig *config) const;
			void LoadTools(wxConfig *config, SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			
		private:
			/**
			 * @brief wxNotebook specialisation for holding any tools docked to the main window.
			*/
			class ToolNotebook: public wxNotebook
			{
				public:
					ToolNotebook(wxWindow *parent, wxWindowID id, long style = 0);
					
					virtual bool AddPage(wxWindow *page, const wxString &text, bool select = false, int imageId = NO_IMAGE) override;
					virtual bool DeletePage(size_t page) override;
					virtual bool InsertPage(size_t index, wxWindow *page, const wxString &text, bool select = false, int imageId = NO_IMAGE) override;
					virtual bool RemovePage(size_t page) override;
					virtual int ChangeSelection(size_t page) override;
					
					virtual wxSize GetMinSize() const override;
					
				private:
					/**
					 * @brief Update the visible flag of each tool in this notebook.
					 *
					 * This is called internally after adding/removing any pages from the notebook
					 * because wxEVT_NOTEBOOK_PAGE_CHANGED events aren't generated consistently
					 * between platforms and versions of wxWidgets when the selected tab is changed
					 * due to adding/removing a page.
					*/
					void UpdateToolVisibility();
					
					void OnPageChanged(wxNotebookEvent &event);
					
				DECLARE_EVENT_TABLE()
			};
			
			/**
			 * @brief wxFrame specialisation for holding a detached/floating tool.
			*/
			class ToolFrame: public wxFrame
			{
				public:
					ToolFrame(wxWindow *parent, ToolPanel *tool = NULL);
					
					void AdoptTool(ToolPanel *tool);
					
					/**
					 * @brief Remove the owned tool.
					 *
					 * This method must be called to detach the tool from the
					 * floating frame before it can be re-inserted elsewhere in
					 * the window heierarchy.
					*/
					void RemoveTool(ToolPanel *tool);
					
					ToolPanel *GetTool() const;
					
				private:
					wxBoxSizer *m_sizer;
					ToolPanel *m_tool;
			};
			
			wxWindow *m_main_panel;
			
			ToolNotebook *m_left_notebook;
			ToolNotebook *m_right_notebook;
			ToolNotebook *m_top_notebook;
			ToolNotebook *m_bottom_notebook;
			
			std::map<ToolPanel*, ToolFrame*> m_tool_frames;
			
			bool m_drag_pending;
			wxPoint m_left_down_point;
			ToolPanel *m_left_down_tool;
			bool m_drag_active;
			
			ToolFrame *FindFrameByTool(ToolPanel *tool);
			ToolNotebook *FindNotebookByTool(ToolPanel *tool);
			ToolPanel *FindToolByName(const std::string &name) const;
			
			void DestroyTool(ToolPanel *tool);
			
			static void SaveToolsFromNotebook(wxConfig *config, ToolNotebook *notebook);
			void LoadToolsIntoNotebook(wxConfig *config, ToolNotebook *notebook, SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			
			/**
			 * @brief Reset the size of a notebook to its default size.
			 *
			 * Resets the width/height (as applicable) of a Notebook in the splitter to
			 * its minimum/best size (whichever is larger).
			*/
			void ResetNotebookSize(ToolNotebook *notebook);
			
			void OnNotebookLeftDown(wxMouseEvent &event);
			void OnLeftUp(wxMouseEvent &event);
			void OnMouseCaptureLost(wxMouseCaptureLostEvent &event);
			void OnMotion(wxMouseEvent &event);
			void OnFrameClose(wxCloseEvent &event);
			
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_TOOLPANELDOCK_HPP */
