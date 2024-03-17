/* Reverse Engineer's Hex Editor
 * Copyright (C) 2019-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_COMMENTTREE_HPP
#define REHEX_COMMENTTREE_HPP

#include <set>
#include <string>
#include <wx/dataview.h>
#include <wx/panel.h>
#include <wx/textctrl.h>
#include <wx/timer.h>

#include "CodeCtrl.hpp"
#include "document.hpp"
#include "LoadingSpinner.hpp"
#include "SafeWindowPointer.hpp"
#include "SharedDocumentPointer.hpp"
#include "ToolPanel.hpp"

/* wxDataViewModel has two ways of being notified of updates - individually (e.g. calling
 * wxDataViewModel::ItemAdded()), or batched (e.g. calling wxDataViewModel::ItemsAdded()).
 *
 * In theory, the batched approach should be as fast as doing the updates or faster on platforms
 * whose native treeview-ish control support batch updates.
 *
 * In my testing, this is not the case.
 *
 * macOS is painfully slow at doing lots of individual updates and fast at doing batched updates.
 * Windows is fast at doing lots of individual updates and slightly slower if you batch them.
 * GTK is somewhat slow at doing lots of individual updates, and even slower if they are batched.
 *
 * So we only batch wxDataViewModel updates on macOS.
*/
#ifdef __APPLE__
#define COMMENTTREEMODEL_BATCH_MODEL_UPDATES
#define COMMENTREEEMODEL_MAX_BATCHED_UPDATES 128
#endif

namespace REHex {
	class CommentTreeModel: public wxDataViewModel
	{
		public:
			CommentTreeModel(SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			
			bool refresh_comments();
			int get_max_comment_depth() const;
			static const BitRangeTreeKey *dv_item_to_key(const wxDataViewItem &item);
			
			void set_filter_text(const wxString &filter_text);
			wxString get_filter_text() const;
			
			virtual int Compare(const wxDataViewItem &item1, const wxDataViewItem &item2, unsigned int column, bool ascending) const override;
			virtual unsigned int GetChildren(const wxDataViewItem &item, wxDataViewItemArray &children) const override;
			virtual unsigned int GetColumnCount() const override;
			virtual wxString GetColumnType(unsigned int col) const override;
			virtual wxDataViewItem GetParent(const wxDataViewItem &item) const override;
			virtual void GetValue(wxVariant &variant, const wxDataViewItem &item, unsigned int col) const override;
			virtual bool IsContainer(const wxDataViewItem &item) const override;
			virtual bool SetValue(const wxVariant &variant, const wxDataViewItem &item, unsigned int col) override;
			virtual bool HasContainerColumns(const wxDataViewItem &item) const override;
			
		private:
			SharedDocumentPointer document;
			SafeWindowPointer<DocumentCtrl> document_ctrl;
			
			struct CommentData;
			typedef std::pair<const BitRangeTreeKey, CommentData> values_elem_t;
			
			struct ChildElemCompare
			{
				bool operator()(const values_elem_t *a, const values_elem_t *b) const
				{
					return a->first < b->first;
				}
			};
			
			struct CommentData
			{
				values_elem_t *parent;
				std::set<values_elem_t*, ChildElemCompare> children;
				bool is_container;
				
				std::shared_ptr<const wxString> text;
				
				CommentData(values_elem_t *parent, const std::shared_ptr<const wxString> &text): parent(parent), is_container(false), text(text) {}
			};
			
			std::map<BitRangeTreeKey, CommentData> values;
			std::set<values_elem_t*, ChildElemCompare> root;
			
			int max_comment_depth;
			int pending_max_comment_depth;
			
			wxString filter_text;
			
			std::map<BitRangeTreeKey, CommentData>::iterator erase_value(std::map<BitRangeTreeKey, CommentData>::iterator value_i);
			void re_add_item(values_elem_t *value, bool as_container);
			
			#ifdef COMMENTTREEMODEL_BATCH_MODEL_UPDATES
			wxDataViewItemArray accumulated_items_to_add;
			wxDataViewItemArray accumulated_items_to_delete;
			wxDataViewItemArray accumulated_items_to_change;
			wxDataViewItem accumulated_items_parent;
			#endif
			
			void batched_item_added(const wxDataViewItem &parent, const wxDataViewItem &item);
			void batched_item_deleted(const wxDataViewItem &parent, const wxDataViewItem &item);
			void batched_item_changed(const wxDataViewItem &item);
			void batched_item_flush();
			
			bool comment_or_child_matches_filter(const BitRangeTree<Document::Comment>::Node *comment);
	};
	
	class CommentTree: public ToolPanel
	{
		public:
			CommentTree(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			virtual ~CommentTree();
			
			virtual std::string name() const override;
// 			virtual std::string label() const override;
// 			virtual Shape shape() const override;
			
			virtual void save_state(wxConfig *config) const override;
			virtual void load_state(wxConfig *config) override;
			virtual void update() override;
			
			virtual wxSize DoGetBestClientSize() const override;
			
		private:
			/* Maximum time to wait for an idle event when updating the comments. */
			static const int MAX_IDLE_WAIT_MS = 50;
			
			SharedDocumentPointer document;
			SafeWindowPointer<DocumentCtrl> document_ctrl;
			
			wxTextCtrl *filter_textctrl;
			
			wxDataViewCtrl *dvc;
			wxDataViewColumn *offset_col, *text_col;
			CommentTreeModel *model;
			
			LoadingSpinner *spinner;
			
			int historic_max_comment_depth;
			bool refresh_running;
			wxTimer refresh_timer;
			
			void refresh_comments();
			void reposition_spinner();
			
			void OnCommentModified(wxCommandEvent &event);
			
			void OnContextMenu(wxDataViewEvent &event);
			void OnActivated(wxDataViewEvent &event);
			void OnIdle(wxIdleEvent &event);
			void OnRefreshTimer(wxTimerEvent &event);
			void OnSize(wxSizeEvent &event);
			void OnFilterTextChange(wxCommandEvent &event);
			
		/* Keep at end. */
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_COMMENTTREE_HPP */
