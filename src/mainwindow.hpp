/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2023 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <list>
#include <map>
#include <vector>
#include <wx/aui/auibook.h>
#include <wx/dnd.h>
#include <wx/wx.h>

#include "DetachableNotebook.hpp"
#include "Events.hpp"
#include "Tab.hpp"
#include "ToolPanel.hpp"

namespace REHex {
	/**
	 * @brief The main application window.
	*/
	class MainWindow: public wxFrame
	{
		public:
			MainWindow(const wxSize& size);
			virtual ~MainWindow();
			
			/**
			 * @brief Create a new tab with an empty file.
			*/
			void new_file();
			
			/**
			 * @brief Create a new tab with a file loaded from disk.
			*/
			Tab *open_file(const std::string &filename);
			
			Tab *import_hex_file(const std::string &filename);
			
			wxMenuBar *get_menu_bar() const;
			wxMenu *get_file_menu() const;
			wxMenu *get_edit_menu() const;
			wxMenu *get_view_menu() const;
			wxMenu *get_tools_menu() const;
			wxMenu *get_help_menu() const;
			
			/**
			 * @brief Gets the currently visible Tab.
			*/
			Tab *active_tab();
			
			/**
			 * @brief Gets the Document in the currently visible Tab.
			*/
			Document *active_document();
			
			/**
			 * @brief Switch the active Tab.
			*/
			void switch_tab(DocumentCtrl *doc_ctrl);
			
			void insert_tab(Tab *tab, int position);
			DetachableNotebook *get_notebook();
			
			void OnWindowClose(wxCloseEvent& event);
			void OnWindowActivate(wxActivateEvent &event);
			void OnCharHook(wxKeyEvent &event);
			
			void OnNew(wxCommandEvent &event);
			void OnOpen(wxCommandEvent &event);
			void OnRecentOpen(wxCommandEvent &event);
			void OnSave(wxCommandEvent &event);
			void OnSaveAs(wxCommandEvent &event);
			void OnReload(wxCommandEvent &event);
			void OnAutoReload(wxCommandEvent &event);
			void OnImportHex(wxCommandEvent &event);
			void OnExportHex(wxCommandEvent &event);
			void OnClose(wxCommandEvent &event);
			void OnCloseAll(wxCommandEvent &event);
			void OnCloseOthers(wxCommandEvent &event);
			void OnExit(wxCommandEvent &event);
			
			void OnCursorPrev(wxCommandEvent &event);
			void OnCursorNext(wxCommandEvent &event);
			
			void OnSearchText(wxCommandEvent &event);
			void OnSearchBSeq(wxCommandEvent &event);
			void OnSearchValue(wxCommandEvent &event);
			void OnCompareFile(wxCommandEvent &event);
			void OnGotoOffset(wxCommandEvent &event);
			void OnCut(wxCommandEvent &event);
			void OnCopy(wxCommandEvent &event);
			void OnPaste(wxCommandEvent &event);
			void OnUndo(wxCommandEvent &event);
			void OnRedo(wxCommandEvent &event);
			void OnSelectAll(wxCommandEvent &event);
			void OnSelectRange(wxCommandEvent &event);
			void OnFillRange(wxCommandEvent &event);
			void OnOverwriteMode(wxCommandEvent &event);
			void OnWriteProtect(wxCommandEvent &event);
			
			void OnSetBytesPerLine(wxCommandEvent &event);
			void OnSetBytesPerGroup(wxCommandEvent &event);
			void OnShowOffsets(wxCommandEvent &event);
			void OnShowASCII(wxCommandEvent &event);
			void OnInlineCommentsMode(wxCommandEvent &event);
			void OnAsmSyntax(wxCommandEvent &event);
			void OnDocumentDisplayMode(wxCommandEvent &event);
			void OnHighlightSelectionMatch(wxCommandEvent &event);
			void OnShowToolPanel(wxCommandEvent &event, const REHex::ToolPanelRegistration *tpr);
			void OnPalette(wxCommandEvent &event);
			void OnFSAIncrease(wxCommandEvent &event);
			void OnFSADecrease(wxCommandEvent &event);
			void OnHexOffsets(wxCommandEvent &event);
			void OnDecOffsets(wxCommandEvent &event);
			void OnSaveView(wxCommandEvent &event);
			
			void OnGithub(wxCommandEvent &event);
			void OnDonate(wxCommandEvent &event);
			void OnHelp(wxCommandEvent &event);
			void OnAbout(wxCommandEvent &event);
			
			void OnDocumentChange(wxAuiNotebookEvent &event);
			void OnDocumentClose(wxAuiNotebookEvent &event);
			void OnDocumentClosed(wxAuiNotebookEvent &event);
			void OnDocumentMenu(wxAuiNotebookEvent &event);
			void OnDocumentMiddleMouse(wxAuiNotebookEvent& event);
			void OnDocumentDetached(DetachedPageEvent &event);
			
			void OnCursorUpdate(CursorUpdateEvent &event);
			void OnSelectionChange(wxCommandEvent &event);
			void OnInsertToggle(wxCommandEvent &event);
			void OnUndoUpdate(wxCommandEvent &event);
			void OnBecameDirty(wxCommandEvent &event);
			void OnBecameClean(wxCommandEvent &event);
			void OnFileDeleted(wxCommandEvent &event);
			void OnFileModified(wxCommandEvent &event);
			void OnTitleChanged(DocumentTitleEvent &event);
			
			/**
			 * @brief MainWindow setup phases, in order of execution.
			*/
			enum class SetupPhase
			{
				FILE_MENU_PRE,     /**< About to create file menu - use for adding menus left of it. */
				FILE_MENU_TOP,     /**< About to populate file menu - use for adding items to the top. */
				FILE_MENU_BOTTOM,  /**< Finished populating file menu - use for adding items to the bottom. */
				FILE_MENU_POST,    /**< Added file menu - use for adding menus right of it. */
				
				EDIT_MENU_PRE,     /**< About to create edit menu - use for adding menus left of it. */
				EDIT_MENU_TOP,     /**< About to populate edit menu - use for adding items to the top. */
				EDIT_MENU_BOTTOM,  /**< Finished populating edit menu - use for adding items to the bottom. */
				EDIT_MENU_POST,    /**< Added edit menu - use for adding menus right of it. */
				
				VIEW_MENU_PRE,     /**< About to create view menu - use for adding menus left of it. */
				VIEW_MENU_TOP,     /**< About to populate view menu - use for adding items to the top. */
				VIEW_MENU_BOTTOM,  /**< Finished populating view menu - use for adding items to the bottom. */
				VIEW_MENU_POST,    /**< Added view menu - use for adding menus right of it. */
				
				TOOLS_MENU_PRE,     /**< About to create tools menu - use for adding menus left of it. */
				TOOLS_MENU_TOP,     /**< About to populate tools menu - use for adding items to the top. */
				TOOLS_MENU_BOTTOM,  /**< Finished populating tools menu - use for adding items to the bottom. */
				TOOLS_MENU_POST,    /**< Added tools menu - use for adding menus right of it. */
				
				HELP_MENU_PRE,     /**< About to create help menu - use for adding menus left of it. */
				HELP_MENU_TOP,     /**< About to populate help menu - use for adding items to the top. */
				HELP_MENU_BOTTOM,  /**< Finished populating help menu - use for adding items to the bottom. */
				HELP_MENU_POST,    /**< Added help menu - use for adding menus right of it. */
				
				DONE,              /**< MainWindow constructor is about to return. */
			};
			
			typedef std::function<void(MainWindow*)> SetupHookFunction;
			
			/**
			 * @brief Register a hook function to be called during a setup phase.
			 *
			 * @param phase  Setup phase to call the hook during.
			 * @param func   Pointer to a std::function to invoke.
			 *
			 * You should probably use SetupHookRegistration rather than calling this
			 * function directly.
			 *
			 * NOTE: The std::function pointed to by func MUST remain valid until
			 * unregister_setup_hook() is used - it will be used to call the function
			 * and identifies the unique binding until is is unregistered.
			*/
			static void register_setup_hook(SetupPhase phase, const SetupHookFunction *func);
			
			/**
			 * @brief Unregister a setup hook.
			*/
			static void unregister_setup_hook(SetupPhase phase, const SetupHookFunction *func);
			
			/**
			 * @brief Get a list of all MainWindow instances.
			 *
			 * Returns a reference to the internal instances list. Elements are ordered
			 * from most recently activated (e.g. top of Z order) to least.
			*/
			static const std::list<MainWindow*> &get_instances();
			
			/**
			 * @brief Performs RAII-style MainWindow setup hook registration.
			*/
			class SetupHookRegistration
			{
				public:
					SetupPhase phase;        /**< @brief MainWindow setup phase to call function during. */
					SetupHookFunction func;  /**< @brief Hook function to be called. */
					
					/**
					 * @brief Register the setup hook.
					 *
					 * @param phase  MainWindow setup phase to call function during.
					 * @param func   Hook function to be called.
					*/
					SetupHookRegistration(SetupPhase phase, const SetupHookFunction &func);
					
					/**
					 * @brief Unregister the setup hook.
					*/
					~SetupHookRegistration();
					
					SetupHookRegistration(const SetupHookRegistration &src) = delete;
					SetupHookRegistration &operator=(const SetupHookRegistration &rhs) = delete;
			};
			
		private:
			class DropTarget: public wxFileDropTarget
			{
				private:
					MainWindow *window;
					
				public:
					DropTarget(MainWindow *window);
					virtual ~DropTarget();
					
					virtual bool OnDropFiles(wxCoord x, wxCoord y, const wxArrayString &filenames) override;
			};
			
			wxMenuBar *menu_bar;
			wxMenu *file_menu;
			wxMenu *recent_files_menu;
			wxMenu *edit_menu;
			wxMenu *view_menu;
			wxMenu *tools_menu;
			wxMenu *help_menu;
			
			DetachableNotebook *notebook;
			wxBitmap notebook_dirty_bitmap;
			wxBitmap notebook_bad_bitmap;
			
			wxMenu *tool_panels_menu;
			std::map<std::string, int> tool_panel_name_to_tpm_id;
			
			wxMenu *inline_comments_menu;
			wxMenu *asm_syntax_menu;
			
			void _update_status_offset(Tab *tab);
			void _update_status_selection(REHex::DocumentCtrl *doc_ctrl);
			void _update_status_mode(REHex::DocumentCtrl *doc_ctrl);
			void _update_undo(REHex::Document *doc);
			void _update_dirty(REHex::Document *doc);
			void _update_cpos_buttons(DocumentCtrl *doc_ctrl);
			
			bool confirm_close_tabs(const std::vector<Tab*> &tabs);
			
			void close_tab(Tab *tab);
			void close_all_tabs();
			void close_other_tabs(Tab *tab);
			
			static std::multimap<SetupPhase, const SetupHookFunction*> *setup_hooks;
			void call_setup_hooks(SetupPhase phase);
			
			static std::list<MainWindow*> instances;
			std::list<MainWindow*>::iterator instances_iter;
			
			DECLARE_EVENT_TABLE()
	};
	
	/**
	 * @brief Event raised by MainWindow when a document is created or opened.
	*/
	class TabCreatedEvent: public wxEvent
	{
		public:
			Tab *tab; /**< @brief The new tab. */
			
			TabCreatedEvent(MainWindow *source, Tab *tab);
			
			virtual wxEvent *Clone() const override;
	};
	
	wxDECLARE_EVENT(TAB_CREATED, TabCreatedEvent);
}

#endif /* !REHEX_MAINWINDOW_HPP */
