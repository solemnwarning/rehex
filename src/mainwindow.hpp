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

#include <map>
#include <set>
#include <vector>
#include <wx/aui/auibook.h>
#include <wx/dnd.h>
#include <wx/splitter.h>
#include <wx/wx.h>

#include "document.hpp"
#include "ToolPanel.hpp"

namespace REHex {
	class MainWindow: public wxFrame
	{
		public:
			MainWindow();
			virtual ~MainWindow();
			
			void new_file();
			void open_file(const std::string &filename);
			
			void OnWindowClose(wxCloseEvent& event);
			
			void OnNew(wxCommandEvent &event);
			void OnOpen(wxCommandEvent &event);
			void OnRecentOpen(wxCommandEvent &event);
			void OnSave(wxCommandEvent &event);
			void OnSaveAs(wxCommandEvent &event);
			void OnClose(wxCommandEvent &event);
			void OnCloseAll(wxCommandEvent &event);
			void OnCloseOthers(wxCommandEvent &event);
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
			void OnSelectAll(wxCommandEvent &event);
			void OnSelectRange(wxCommandEvent &event);
			void OnOverwriteMode(wxCommandEvent &event);
			
			void OnSetBytesPerLine(wxCommandEvent &event);
			void OnSetBytesPerGroup(wxCommandEvent &event);
			void OnShowOffsets(wxCommandEvent &event);
			void OnShowASCII(wxCommandEvent &event);
			void OnInlineCommentsMode(wxCommandEvent &event);
			void OnHighlightSelectionMatch(wxCommandEvent &event);
			void OnShowToolPanel(wxCommandEvent &event, const REHex::ToolPanelRegistration *tpr);
			void OnPalette(wxCommandEvent &event);
			void OnSaveView(wxCommandEvent &event);
			
			void OnGithub(wxCommandEvent &event);
			void OnDonate(wxCommandEvent &event);
			void OnAbout(wxCommandEvent &event);
			
			void OnDocumentChange(wxAuiNotebookEvent &event);
			void OnDocumentClose(wxAuiNotebookEvent &event);
			void OnDocumentClosed(wxAuiNotebookEvent &event);
			void OnDocumentMenu(wxAuiNotebookEvent &event);
			
			void OnCursorMove(wxCommandEvent &event);
			void OnSelectionChange(wxCommandEvent &event);
			void OnInsertToggle(wxCommandEvent &event);
			void OnUndoUpdate(wxCommandEvent &event);
			void OnBecameDirty(wxCommandEvent &event);
			void OnBecameClean(wxCommandEvent &event);
			
		private:
			class Tab: public wxPanel
			{
				public:
					Tab(wxWindow *parent);
					Tab(wxWindow *parent, const std::string &filename);
					
					virtual ~Tab();
					
					REHex::Document    *doc;
					wxSplitterWindow   *v_splitter;
					wxSplitterWindow   *h_splitter;
					wxNotebook         *v_tools;
					wxNotebook         *h_tools;
					
					std::map<std::string, ToolPanel*> tools;
					std::set<wxDialog*> search_dialogs;
					
					bool tool_active(const std::string &name);
					void tool_create(const std::string &name, bool switch_to, wxConfig *config = NULL, bool adjust = true);
					void tool_destroy(const std::string &name);
					
					void search_dialog_register(wxDialog *search_dialog);
					
					void save_view(wxConfig *config);
					
					void OnSize(wxSizeEvent &size);
					void OnHToolChange(wxBookCtrlEvent &event);
					void OnVToolChange(wxBookCtrlEvent &event);
					void OnHSplitterSashPosChanging(wxSplitterEvent &event);
					void OnVSplitterSashPosChanging(wxSplitterEvent &event);
					void OnSearchDialogDestroy(wxWindowDestroyEvent &event);
					
					void vtools_adjust();
					void htools_adjust();
					void vtools_adjust_on_idle();
					void vtools_adjust_now_idle(wxIdleEvent &event);
					void htools_adjust_on_idle();
					void htools_adjust_now_idle(wxIdleEvent &event);
					
				private:
					enum {
						ID_HTOOLS = 1,
						ID_VTOOLS,
						ID_HSPLITTER,
						ID_VSPLITTER,
					};
					
					int hsplit_clamp_sash(int sash_position);
					int vsplit_clamp_sash(int sash_position);
					
					void init_default_doc_view();
					void init_default_tools();
					
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
			
			wxMenu *file_menu;
			wxMenu *recent_files_menu;
			wxMenu *edit_menu;
			wxMenu *view_menu;
			
			wxAuiNotebook *notebook;
			wxBitmap notebook_dirty_bitmap;
			
			wxMenu *tool_panels_menu;
			std::map<std::string, int> tool_panel_name_to_tpm_id;
			
			wxMenu *inline_comments_menu;
			
			Tab *active_tab();
			Document *active_document();
			
			void _update_status_offset(REHex::Document *doc);
			void _update_status_selection(REHex::Document *doc);
			void _update_status_mode(REHex::Document *doc);
			void _update_undo(REHex::Document *doc);
			void _update_dirty(REHex::Document *doc);
			
			void _clipboard_copy(bool cut);
			
			bool unsaved_confirm();
			bool unsaved_confirm(const std::vector<wxString> &files);
			
			void close_tab(Tab *tab);
			void close_all_tabs();
			void close_other_tabs(Tab *tab);
			
			DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_MAINWINDOW_HPP */
