/* Reverse Engineer's Hex Editor
 * Copyright (C) 2019 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <wx/dataview.h>
#include <wx/panel.h>

#include "CodeCtrl.hpp"
#include "document.hpp"
#include "SafeWindowPointer.hpp"
#include "SharedDocumentPointer.hpp"
#include "ToolPanel.hpp"

namespace REHex {
	class CommentTreeModel: public wxDataViewModel
	{
		public:
			CommentTreeModel(REHex::Document *document);
			
			void refresh_comments();
			static const NestedOffsetLengthMapKey *dv_item_to_key(const wxDataViewItem &item);
			
			virtual int Compare(const wxDataViewItem &item1, const wxDataViewItem &item2, unsigned int column, bool ascending) const override;
			virtual unsigned int GetChildren(const wxDataViewItem &item, wxDataViewItemArray &children) const override;
			virtual unsigned int GetColumnCount() const override;
			virtual wxString GetColumnType(unsigned int col) const override;
			virtual wxDataViewItem GetParent(const wxDataViewItem &item) const override;
			virtual void GetValue(wxVariant &variant, const wxDataViewItem &item, unsigned int col) const override;
			virtual bool IsContainer(const wxDataViewItem &item) const override;
			virtual bool SetValue(const wxVariant &variant, const wxDataViewItem &item, unsigned int col) override;
			
		private:
			REHex::Document *document;
			
			struct CommentData;
			typedef std::pair<const NestedOffsetLengthMapKey, CommentData> values_elem_t;
			
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
				
				std::shared_ptr<const wxString> text;
				
				CommentData(values_elem_t *parent, const std::shared_ptr<const wxString> &text): parent(parent), text(text) {}
			};
			
			std::map<NestedOffsetLengthMapKey, CommentData> values;
			std::set<values_elem_t*, ChildElemCompare> root;
			
			std::map<NestedOffsetLengthMapKey, CommentData>::iterator erase_value(std::map<NestedOffsetLengthMapKey, CommentData>::iterator value_i);
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
			SharedDocumentPointer document;
			SafeWindowPointer<DocumentCtrl> document_ctrl;
			
			wxDataViewCtrl *dvc;
			wxDataViewColumn *dvc_col;
			CommentTreeModel *model;
			
			void refresh_comments();
			
			void OnCommentModified(wxCommandEvent &event);
			
			void OnContextMenu(wxDataViewEvent &event);
			void OnActivated(wxDataViewEvent &event);
			
		/* Keep at end. */
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_COMMENTTREE_HPP */
