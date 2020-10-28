/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2020 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <wx/splitter.h>
#include <wx/wx.h>

#include "DiffWindow.hpp"
#include "document.hpp"
#include "DocumentCtrl.hpp"
#include "Events.hpp"
#include "SharedDocumentPointer.hpp"
#include "ToolPanel.hpp"

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
	
	class Tab: public wxPanel
	{
		public:
			Tab(wxWindow *parent);
			Tab(wxWindow *parent, const std::string &filename);
			
			virtual ~Tab();
			
			SharedDocumentPointer doc;
			DocumentCtrl *doc_ctrl;
			
			bool tool_active(const std::string &name);
			void tool_create(const std::string &name, bool switch_to, wxConfig *config = NULL, bool adjust = true);
			void tool_destroy(const std::string &name);
			
			void search_dialog_register(wxDialog *search_dialog);
			
			void hide_child_windows();
			void unhide_child_windows();
			
			void save_view(wxConfig *config);
			
			void handle_copy(bool cut);
			void paste_text(const std::string &text);
			
			InlineCommentMode get_inline_comment_mode() const;
			void set_inline_comment_mode(InlineCommentMode inline_comment_mode);
			
			/* Public for use by unit tests. */
			static std::vector<DocumentCtrl::Region*> compute_regions(SharedDocumentPointer doc, InlineCommentMode inline_comment_mode);
			
		private:
			InlineCommentMode inline_comment_mode;
			
			wxSplitterWindow   *v_splitter;
			wxSplitterWindow   *h_splitter;
			wxNotebook         *v_tools;
			wxNotebook         *h_tools;
			
			std::map<std::string, ToolPanel*> tools;
			std::set<wxDialog*> search_dialogs;
			
			void OnSize(wxSizeEvent &size);
			
			void OnHToolChange(wxBookCtrlEvent &event);
			void OnVToolChange(wxBookCtrlEvent &event);
			void OnHSplitterSashPosChanging(wxSplitterEvent &event);
			void OnVSplitterSashPosChanging(wxSplitterEvent &event);
			void OnSearchDialogDestroy(wxWindowDestroyEvent &event);
			
			void OnDocumentCtrlChar(wxKeyEvent &key);
			
			void OnCommentLeftClick(OffsetLengthEvent &event);
			void OnCommentRightClick(OffsetLengthEvent &event);
			void OnDataRightClick(wxCommandEvent &event);
			
			void OnDocumentDataErase(OffsetLengthEvent &event);
			void OnDocumentDataInsert(OffsetLengthEvent &event);
			void OnDocumentDataOverwrite(OffsetLengthEvent &event);
			
			void OnDocumentCursorUpdate(CursorUpdateEvent &event);
			void OnDocumentCtrlCursorUpdate(CursorUpdateEvent &event);
			void OnDocumentCommentModified(wxCommandEvent &event);
			void OnDocumenHighlightsChanged(wxCommandEvent &event);
			void OnDocumentDataTypesChanged(wxCommandEvent &event);
			
			template<typename T> void OnEventToForward(T &event)
			{
				event.Skip();
				
				T event_copy(event);
				ProcessWindowEvent(event_copy);
			}
			
			void vtools_adjust();
			void htools_adjust();
			void vtools_adjust_on_idle();
			void vtools_adjust_now_idle(wxIdleEvent &event);
			void htools_adjust_on_idle();
			void htools_adjust_now_idle(wxIdleEvent &event);
			void xtools_fix_visibility(wxNotebook *notebook);
			
			void repopulate_regions();
			
			int hsplit_clamp_sash(int sash_position);
			int vsplit_clamp_sash(int sash_position);
			
			void init_default_doc_view();
			void init_default_tools();
			
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_TAB_HPP */
