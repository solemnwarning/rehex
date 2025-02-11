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

#include "MultiSplitter.hpp"
#include "ToolPanel.hpp"

namespace REHex
{
	/**
	 * @brief Splitter window for tiling and detaching/docking tool panels.
	*/
	class ToolPanelDock: public MultiSplitter
	{
		public:
			ToolPanelDock(wxWindow *parent);
			
			void AddMainPanel(wxWindow *main_panel);
			
			void CreateTool(const std::string &name, SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			void DestroyTool(const std::string &name);
			bool ToolExists(const std::string &name) const;
			
			void SaveTools(wxConfig *config) const;
			void LoadTools(wxConfig *config, SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			
		private:
			class Notebook: public wxNotebook
			{
				public:
					Notebook(wxWindow *parent, wxWindowID id, long style = 0);
			};
			
			class ToolFrame: public wxFrame
			{
				public:
					ToolFrame(wxWindow *parent, ToolPanel *tool);
			};
			
			wxWindow *m_main_panel;
			
			Notebook *m_left_notebook;
			Notebook *m_right_notebook;
			Notebook *m_top_notebook;
			Notebook *m_bottom_notebook;
			
			std::map<ToolPanel*, ToolFrame*> m_tool_frames;
			
			bool m_drag_pending;
			wxPoint m_left_down_point;
			ToolPanel *m_left_down_tool;
			bool m_drag_active;
			
			ToolFrame *FindFrameByTool(ToolPanel *tool);
			Notebook *FindNotebookByTool(ToolPanel *tool);
			ToolPanel *FindToolByName(const std::string &name) const;
			
			void DestroyTool(ToolPanel *tool);
			
			static void SaveToolsFromNotebook(wxConfig *config, Notebook *notebook);
			void LoadToolsIntoNotebook(wxConfig *config, Notebook *notebook, SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			
			/**
			 * @brief Reset the size of a notebook to its default size.
			 *
			 * Resets the width/height (as applicable) of a Notebook in the splitter to
			 * its minimum/best size (whichever is larger).
			*/
			void ResetNotebookSize(Notebook *notebook);
			
			void OnNotebookLeftDown(wxMouseEvent &event);
			void OnLeftUp(wxMouseEvent &event);
			void OnMouseCaptureLost(wxMouseCaptureLostEvent &event);
			void OnMotion(wxMouseEvent &event);
			
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_TOOLPANELDOCK_HPP */
