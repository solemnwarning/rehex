/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_TAB_HPP
#define REHEX_TAB_HPP

#include <map>
#include <set>
#include <string>
#include <vector>
#include <wx/dialog.h>
#include <wx/notebook.h>
#include <wx/panel.h>
#include <wx/wx.h>

#include "BitOffset.hpp"
#include "DataMapScrollbar.hpp"
#include "DiffWindow.hpp"
#include "document.hpp"
#include "DocumentCtrl.hpp"
#include "Events.hpp"
#include "GotoOffsetDialog.hpp"
#include "SafeWindowPointer.hpp"
#include "SettingsDialog.hpp"
#include "SharedDocumentPointer.hpp"
#include "ToolDock.hpp"

namespace REHex
{
	enum InlineCommentMode {
		ICM_HIDDEN       = 0,
		ICM_FULL         = 1,
		ICM_SHORT        = 2,
		ICM_FULL_INDENT  = 3,
		ICM_SHORT_INDENT = 4,
		ICM_MAX          = 4,
	};
	
	enum DocumentDisplayMode {
		DDM_NORMAL = 0,
		DDM_VIRTUAL = 1,
		
		DDM_MAX = 2,
	};
	
	wxDECLARE_EVENT(LAST_GOTO_OFFSET_CHANGED, wxCommandEvent);
	
	class Tab: public wxPanel
	{
		public:
			Tab(wxWindow *parent);
			Tab(wxWindow *parent, SharedDocumentPointer &document);
			
			virtual ~Tab();
			
			SharedDocumentPointer doc;
			DocumentCtrl *doc_ctrl;
			
			bool tool_active(const std::string &name);
			void tool_create(const std::string &name, bool switch_to, wxConfig *config = NULL);
			void tool_destroy(const std::string &name);
			
			void search_dialog_register(wxDialog *search_dialog);
			
			void hide_child_windows();
			void unhide_child_windows();
			
			void set_parent_window_active(bool parent_window_active);
			
			void save_view(wxConfig *config);
			
			void handle_copy(bool cut);
			void paste_text(const std::string &text);
			void compare_whole_file();
			void compare_selection();
			
			InlineCommentMode get_inline_comment_mode() const;
			void set_inline_comment_mode(InlineCommentMode inline_comment_mode);
			
			DocumentDisplayMode get_document_display_mode() const;
			void set_document_display_mode(DocumentDisplayMode document_display_mode);
			
			bool get_auto_reload() const;
			void set_auto_reload(bool auto_reload);
			
			void show_goto_offset_dialog();
			
			std::pair<BitOffset, bool> get_last_goto_offset() const;
			void set_last_goto_offset(BitOffset last_goto_offset, bool is_relative);
			
			enum class DataMapScrollbarType
			{
				NONE,
				ENTROPY,
			};
			
			DataMapScrollbarType get_dsm_type() const;
			void set_dsm_type(DataMapScrollbarType dsm_type);
			
			/* Public for use by unit tests. */
			static std::vector<DocumentCtrl::Region*> compute_regions(SharedDocumentPointer doc, BitOffset real_offset_base, BitOffset virt_offset_base, BitOffset length, InlineCommentMode inline_comment_mode);
			
		private:
			InlineCommentMode inline_comment_mode;
			DocumentDisplayMode document_display_mode;
			
			ToolDock *tool_dock;
			
			std::set<wxDialog*> search_dialogs;
			
			SafeWindowPointer<SettingsDialog> doc_properties;
			SafeWindowPointer<GotoOffsetDialog> goto_offset_dialog;
			BitOffset last_goto_offset;
			bool last_goto_offset_relative;
			
			wxPanel *doc_ctrl_panel;
			wxSizer *data_map_scrollbar_sizer;
			DataMapScrollbarType data_map_scrollbar_type;
			DataMapScrollbar *data_map_scrollbar;
			
			void OnSearchDialogDestroy(wxWindowDestroyEvent &event);
			
			void OnDocumentCtrlChar(wxKeyEvent &key);
			
			void OnCommentLeftClick(BitRangeEvent &event);
			void OnCommentRightClick(BitRangeEvent &event);
			void OnDataRightClick(wxCommandEvent &event);
			
			void OnDocumentDataErase(OffsetLengthEvent &event);
			void OnDocumentDataInsert(OffsetLengthEvent &event);
			void OnDocumentDataOverwrite(OffsetLengthEvent &event);
			
			void OnDocumentCursorUpdate(CursorUpdateEvent &event);
			void OnDocumentCtrlCursorUpdate(CursorUpdateEvent &event);
			void OnDocumentCommentModified(wxCommandEvent &event);
			void OnDocumenHighlightsChanged(wxCommandEvent &event);
			void OnDocumentDataTypesChanged(wxCommandEvent &event);
			void OnDocumentMappingsChanged(wxCommandEvent &event);
			
			void OnDocumentFileDeleted(wxCommandEvent &event);
			void OnDocumentFileModified(wxCommandEvent &event);
			
			void OnBulkUpdatesFrozen(wxCommandEvent &event);
			void OnBulkUpdatesThawed(wxCommandEvent &event);
			
			template<typename T> void OnEventToForward(T &event)
			{
				event.Skip();
				
				T event_copy(event);
				ProcessWindowEvent(event_copy);
			}
			
			bool repopulate_regions_frozen;
			bool repopulate_regions_pending;
			
			void repopulate_regions();
			void repopulate_regions_freeze();
			void repopulate_regions_thaw();
			
			int hsplit_clamp_sash(int sash_position);
			int vsplit_clamp_sash(int sash_position);
			
			void init_default_doc_view();
			void init_default_tools();
			
			void compare_range(off_t offset, off_t length);
			
			bool child_windows_hidden;
			bool parent_window_active;
			
			bool file_deleted_dialog_pending;
			void file_deleted_dialog();
			
			bool file_modified_dialog_pending;
			void file_modified_dialog();
			
			bool auto_reload;
			
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_TAB_HPP */
