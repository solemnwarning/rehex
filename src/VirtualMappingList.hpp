/* Reverse Engineer's Hex Editor
 * Copyright (C) 2021 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_VIRTUALMAPPINGLIST_HPP
#define REHEX_VIRTUALMAPPINGLIST_HPP

#include <set>
#include <wx/dataview.h>
#include <wx/panel.h>

#include "document.hpp"
#include "SafeWindowPointer.hpp"
#include "SharedDocumentPointer.hpp"
#include "ToolPanel.hpp"

namespace REHex {
	class VirtualMappingListModel: public wxDataViewModel
	{
		public:
			enum {
				COLUMN_REAL_BASE = 0,
				COLUMN_VIRT_BASE,
				COLUMN_SEGMENT_LENGTH,
				
				_COLUMN_COUNT,
			};
			
			struct Value
			{
				off_t real_base;
				off_t virt_base;
				off_t segment_length;
				
				Value(off_t real_base, off_t virt_base, off_t segment_length):
					real_base(real_base), virt_base(virt_base), segment_length(segment_length) {}
				
				bool operator<(const Value &rhs) const
				{
					return real_base < rhs.real_base;
				}
			};
			
			void refresh_mappings(Document *document);
			static const Value *dv_item_to_value(const wxDataViewItem &item);
			
			virtual int Compare(const wxDataViewItem &item1, const wxDataViewItem &item2, unsigned int column, bool ascending) const override;
			virtual unsigned int GetChildren(const wxDataViewItem &item, wxDataViewItemArray &children) const override;
			virtual unsigned int GetColumnCount() const override;
			virtual wxString GetColumnType(unsigned int col) const override;
			virtual wxDataViewItem GetParent(const wxDataViewItem &item) const override;
			virtual void GetValue(wxVariant &variant, const wxDataViewItem &item, unsigned int col) const override;
			virtual bool IsContainer(const wxDataViewItem &item) const override;
			virtual bool SetValue(const wxVariant &variant, const wxDataViewItem &item, unsigned int col) override;
			
		private:
			std::set<Value> values;
	};
	
	class VirtualMappingList: public ToolPanel
	{
		public:
			VirtualMappingList(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			virtual ~VirtualMappingList();
			
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
			wxDataViewColumn *dvc_file_base_col;
			wxDataViewColumn *dvc_virt_base_col;
			wxDataViewColumn *dvc_segment_length_col;
			
			VirtualMappingListModel *model;
			
			void set_column_width(wxDataViewColumn *column, const char *sample_value);
			void refresh_mappings();
			
			void OnMappingsChanged(wxCommandEvent &event);
			
			void OnContextMenu(wxDataViewEvent &event);
			void OnActivated(wxDataViewEvent &event);
			
		/* Keep at end. */
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_VIRTUALMAPPINGLIST_HPP */
