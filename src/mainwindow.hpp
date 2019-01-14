/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2019 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_MAINWINDOW_HPP
#define REHEX_MAINWINDOW_HPP

#include <wx/aui/auibook.h>
#include <wx/dnd.h>
#include <wx/splitter.h>
#include <wx/wx.h>

#include "decodepanel.hpp"
#include "disassemble.hpp"
#include "document.hpp"

namespace REHex {
	class MainWindow: public wxFrame
	{
		public:
			MainWindow();
			virtual ~MainWindow();
			
			void open_file(const std::string &filename);
			
			void OnWindowClose(wxCloseEvent& event);
			
			void OnNew(wxCommandEvent &event);
			void OnOpen(wxCommandEvent &event);
			void OnRecentOpen(wxCommandEvent &event);
			void OnSave(wxCommandEvent &event);
			void OnSaveAs(wxCommandEvent &event);
			void OnClose(wxCommandEvent &event);
			void OnExit(wxCommandEvent &event);
			
			void OnSearchText(wxCommandEvent &event);
			void OnSearchBSeq(wxCommandEvent &event);
			void OnSearchValue(wxCommandEvent &event);
			void OnGotoOffset(wxCommandEvent &event);
			void OnCut(wxCommandEvent &event);
			void OnCopy(wxCommandEvent &event);
			void OnPaste(wxCommandEvent &event);
			void OnUndo(wxCommandEvent &event);
			void OnRedo(wxCommandEvent &event);
			void OnOverwriteMode(wxCommandEvent &event);
			
			void OnSetBytesPerLine(wxCommandEvent &event);
			void OnSetBytesPerGroup(wxCommandEvent &event);
			void OnShowOffsets(wxCommandEvent &event);
			void OnShowASCII(wxCommandEvent &event);
			void OnShowDecodes(wxCommandEvent &event);
			
			void OnAbout(wxCommandEvent &event);
			
			void OnDocumentChange(wxAuiNotebookEvent &event);
			void OnDocumentClose(wxAuiNotebookEvent &event);
			void OnDocumentClosed(wxAuiNotebookEvent &event);
			
			void OnCursorMove(wxCommandEvent &event);
			void OnSelectionChange(wxCommandEvent &event);
			void OnInsertToggle(wxCommandEvent &event);
			
		private:
			class Tab: public wxPanel
			{
				public:
					Tab(wxWindow *parent);
					Tab(wxWindow *parent, const std::string &filename);
					
					wxSplitterWindow   *v_splitter;
					wxSplitterWindow   *h_splitter;
					wxNotebook         *v_tools;
					REHex::DecodePanel *dp;
					REHex::Disassemble *disasm;
					REHex::Document    *doc;
					wxNotebook         *h_tools;
					
					void OnSize(wxSizeEvent &size);
					void OnCursorMove(wxCommandEvent &event);
					void OnValueChange(wxCommandEvent &event);
					void OnValueFocus(wxCommandEvent &event);
					void OnHToolChange(wxBookCtrlEvent &event);
					void OnVToolChange(wxBookCtrlEvent &event);
					void OnHSplitterSashPosChanging(wxSplitterEvent &event);
					void OnVSplitterSashPosChanging(wxSplitterEvent &event);
					
					void vtools_adjust();
					void htools_adjust();
					
				private:
					enum {
						ID_HTOOLS = 1,
						ID_VTOOLS,
						ID_HSPLITTER,
						ID_VSPLITTER,
					};
					
					int hsplit_clamp_sash(int sash_position);
					int vsplit_clamp_sash(int sash_position);
					
					DECLARE_EVENT_TABLE()
			};
			
			class DropTarget: public wxFileDropTarget
			{
				private:
					MainWindow *window;
					
				public:
					DropTarget(MainWindow *window);
					virtual ~DropTarget();
					
					virtual bool OnDropFiles(wxCoord x, wxCoord y, const wxArrayString &filenames) override;
			};
			
			wxMenu *recent_files_menu;
			wxMenu *edit_menu;
			wxMenu *doc_menu;
			wxAuiNotebook *notebook;
			
			void _update_status_offset(REHex::Document *doc);
			void _update_status_selection(REHex::Document *doc);
			void _update_status_mode(REHex::Document *doc);
			
			void _clipboard_copy(bool cut);
			
			DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_MAINWINDOW_HPP */
