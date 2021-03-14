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

#include "platform.hpp"

#include <stack>
#include <utility>
#include <wx/clipbrd.h>

#include "VirtualMappingDialog.hpp"
#include "VirtualMappingList.hpp"
#include "util.hpp"

static REHex::ToolPanel *VirtualMappingList_factory(wxWindow *parent, REHex::SharedDocumentPointer &document, REHex::DocumentCtrl *document_ctrl)
{
	return new REHex::VirtualMappingList(parent, document, document_ctrl);
}

static REHex::ToolPanelRegistration tpr("VirtualMappingList", "Virtual sections", REHex::ToolPanel::TPS_TALL, &VirtualMappingList_factory);

enum {
	ID_EDIT_MAPPING = 1,
	ID_DELETE_MAPPING,
	ID_GOTO,
	ID_SELECT,
};

BEGIN_EVENT_TABLE(REHex::VirtualMappingList, wxPanel)
	EVT_DATAVIEW_ITEM_CONTEXT_MENU(wxID_ANY, REHex::VirtualMappingList::OnContextMenu)
	EVT_DATAVIEW_ITEM_ACTIVATED(wxID_ANY, REHex::VirtualMappingList::OnActivated)
END_EVENT_TABLE()

REHex::VirtualMappingList::VirtualMappingList(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl):
	ToolPanel(parent),
	document(document),
	document_ctrl(document_ctrl)
{
	model = new VirtualMappingListModel();
	
	dvc = new wxDataViewCtrl(this, wxID_ANY, wxDefaultPosition, wxDefaultSize);
	
	dvc_file_base_col = dvc->AppendTextColumn("File offset", VirtualMappingListModel::COLUMN_REAL_BASE);
	dvc_file_base_col->SetSortable(true);
	set_column_width(dvc_file_base_col, "0x00000000");
	
	dvc_virt_base_col = dvc->AppendTextColumn("Virtual address", VirtualMappingListModel::COLUMN_VIRT_BASE);
	dvc_virt_base_col->SetSortable(true);
	set_column_width(dvc_virt_base_col, "0x00000000");
	
	dvc_segment_length_col = dvc->AppendTextColumn("Length", VirtualMappingListModel::COLUMN_SEGMENT_LENGTH);
	dvc_segment_length_col->SetSortable(true);
	set_column_width(dvc_segment_length_col, "0x00000000");
	
	dvc->AssociateModel(model);
	
	/* NOTE: This has to come after AssociateModel, or it will segfault. */
	dvc_file_base_col->SetSortOrder(true);
	
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);
	sizer->Add(dvc, 1, wxEXPAND);
	SetSizerAndFit(sizer);
	
	this->document.auto_cleanup_bind(EV_MAPPINGS_CHANGED, &REHex::VirtualMappingList::OnMappingsChanged, this);
	
	wxSize min_size = GetMinClientSize();
	min_size.SetWidth(
		dvc_file_base_col->GetMinWidth()
		+ dvc_virt_base_col->GetMinWidth()
		+ dvc_segment_length_col->GetMinWidth());
	
	SetMinClientSize(min_size);
	
	refresh_mappings();
}

REHex::VirtualMappingList::~VirtualMappingList()
{
	model->DecRef();
}

std::string REHex::VirtualMappingList::name() const
{
	return "VirtualMappingList";
}

void REHex::VirtualMappingList::save_state(wxConfig *config) const
{
	/* No state to save. */
}

void REHex::VirtualMappingList::load_state(wxConfig *config)
{
	/* No state to load. */
}

void REHex::VirtualMappingList::update()
{
	/* Nothing to update */
}

wxSize REHex::VirtualMappingList::DoGetBestClientSize() const
{
	int width = dvc_file_base_col->GetWidth()
		+ dvc_virt_base_col->GetWidth()
		+ dvc_segment_length_col->GetWidth();
	
	return wxSize(width, -1);
}

void REHex::VirtualMappingList::set_column_width(wxDataViewColumn *column, const char *sample_value)
{
	/* We could just set the widths of each column to wxCOL_WIDTH_AUTOSIZE and let wxWidgets take
	 * care of this for us... except it doesn't work properly on GTK. The Internet says the only
	 * "reliable" way is to size the columns yourself...
	*/
	
	wxSize title_size = dvc->GetTextExtent(column->GetTitle());
	wxSize sample_size = dvc->GetTextExtent(sample_value);
	
	int col_width = std::max(title_size.GetWidth(), sample_size.GetWidth());
	
	/* Multipliers pulled out of my ass... they seem about right on my laptop at least. */
	
	column->SetMinWidth(col_width * 1.25);
	column->SetWidth(col_width * 1.5);
}

void REHex::VirtualMappingList::refresh_mappings()
{
	model->refresh_mappings(document);
	dvc->Refresh();
}

void REHex::VirtualMappingList::OnMappingsChanged(wxCommandEvent &event)
{
	refresh_mappings();
	event.Skip();
}

void REHex::VirtualMappingList::OnContextMenu(wxDataViewEvent &event)
{
	const VirtualMappingListModel::Value *v = VirtualMappingListModel::dv_item_to_value(event.GetItem());
	if(v == NULL)
	{
		/* Click wasn't over an item. */
		return;
	}
	
	wxMenu menu;
	
	menu.Append(ID_GOTO, "&Jump to offset");
	menu.Append(ID_SELECT, "&Select bytes");
	
	menu.AppendSeparator();
	
	menu.Append(ID_EDIT_MAPPING,   "&Edit mapping");
	menu.Append(ID_DELETE_MAPPING, "&Delete mapping");
	
	menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
	{
		switch(event.GetId())
		{
			case ID_GOTO:
				document->set_cursor_position(v->real_base);
				
				CallAfter([this]()
				{
					document_ctrl->SetFocus();
					document_ctrl->Refresh(); /* TODO: Refresh in DocumentCtrl when it gains focus. */
				});
				
				break;
				
			case ID_SELECT:
				document->set_cursor_position(v->real_base);
				document_ctrl->set_selection(v->real_base, v->segment_length);
				
				CallAfter([this]()
				{
					document_ctrl->SetFocus();
					document_ctrl->Refresh(); /* TODO: Refresh in DocumentCtrl when it gains focus. */
				});
				
				break;
				
			case ID_EDIT_MAPPING:
			{
				VirtualMappingDialog d(this, document, v->real_base, v->segment_length);
				d.ShowModal();
				break;
			}
				
			case ID_DELETE_MAPPING:
				document->clear_virt_mapping_r(v->real_base, v->segment_length);
				break;
			
			default:
				break;
		}
	});
	
	PopupMenu(&menu);
}

void REHex::VirtualMappingList::OnActivated(wxDataViewEvent &event)
{
	const VirtualMappingListModel::Value *v = VirtualMappingListModel::dv_item_to_value(event.GetItem());
	
	document->set_cursor_position(v->real_base);
	
	CallAfter([this]()
	{
		document_ctrl->SetFocus();
		document_ctrl->Refresh(); /* TODO: Refresh in DocumentCtrl when it gains focus. */
	});
}

void REHex::VirtualMappingListModel::refresh_mappings(Document *document)
{
	const ByteRangeMap<off_t> &real_to_virt_segs = document->get_real_to_virt_segs();
	
	/* Erase any comments which no longer exist, or are children of such. */
	
	for(auto i = values.begin(); i != values.end();)
	{
		auto j = real_to_virt_segs.get_range(i->real_base);
		
		if(j == real_to_virt_segs.end() || j->first.offset != i->real_base || j->first.length != i->segment_length || j->second != i->virt_base)
		{
			const Value *v = &(*i);
			
			i = values.erase(i);
			ItemDeleted(wxDataViewItem(NULL), wxDataViewItem((void*)(v)));
		}
		else{
			++i;
		}
	}
	
	for(auto i = real_to_virt_segs.begin(); i != real_to_virt_segs.end(); ++i)
	{
		std::set<Value>::iterator item_iter;
		bool new_item;
		
		std::tie(item_iter, new_item) = values.emplace(i->first.offset, i->second, i->first.length);
		
		if(new_item)
		{
			ItemAdded(wxDataViewItem(NULL), wxDataViewItem((void*)(&(*item_iter))));
		}
	}
}

const REHex::VirtualMappingListModel::Value *REHex::VirtualMappingListModel::dv_item_to_value(const wxDataViewItem &item)
{
	return (const Value*)(item.GetID());
}

int REHex::VirtualMappingListModel::Compare(const wxDataViewItem &item1, const wxDataViewItem &item2, unsigned int column, bool ascending) const
{
	const Value *v1 = (const Value*)(item1.GetID());
	const Value *v2 = (const Value*)(item2.GetID());
	
	off_t w1, w2;
	switch(column)
	{
		case COLUMN_REAL_BASE:
			w1 = v1->real_base;
			w2 = v2->real_base;
			break;
			
		case COLUMN_VIRT_BASE:
			w1 = v1->virt_base;
			w2 = v2->virt_base;
			break;
			
		case COLUMN_SEGMENT_LENGTH:
			w1 = v1->segment_length;
			w2 = v2->segment_length;
			break;
			
		default:
			abort();
	}
	
	int result;
	if(w1 < w2)
	{
		result = -1;
	}
	else if(w1 == w2)
	{
		result = 0;
	}
	else /* if(w1 > w2) */
	{
		result = 1;
	}
	
	if(!ascending)
	{
		result *= -1;
	}
	
	return result;
}

unsigned int REHex::VirtualMappingListModel::GetChildren(const wxDataViewItem &item, wxDataViewItemArray &children) const
{
	if(item.GetID() == NULL)
	{
		children.Alloc(values.size());
		
		for(auto i = values.begin(); i != values.end(); ++i)
		{
			const Value *v = &(*i);
			children.Add(wxDataViewItem((void*)(v)));
		}
		
		return values.size();
	}
	else{
		return 0;
	}
}

unsigned int REHex::VirtualMappingListModel::GetColumnCount() const
{
	return _COLUMN_COUNT;
}

wxString REHex::VirtualMappingListModel::GetColumnType(unsigned int col) const
{
	assert(col < _COLUMN_COUNT);
	return "string";
}

wxDataViewItem REHex::VirtualMappingListModel::GetParent(const wxDataViewItem &item) const
{
	return wxDataViewItem(NULL);
}

void REHex::VirtualMappingListModel::GetValue(wxVariant &variant, const wxDataViewItem &item, unsigned int col) const
{
	const Value *v = (const Value*)(item.GetID());
	char buf[64];
	
	switch(col)
	{
		case COLUMN_REAL_BASE:
			snprintf(buf, sizeof(buf), "0x%08llX", (unsigned long long)(v->real_base));
			break;
			
		case COLUMN_VIRT_BASE:
			snprintf(buf, sizeof(buf), "0x%08llX", (unsigned long long)(v->virt_base));
			break;
			
		case COLUMN_SEGMENT_LENGTH:
			snprintf(buf, sizeof(buf), "0x%08llX", (unsigned long long)(v->segment_length));
			break;
			
		default:
			abort();
	}
	
	variant = buf;
}

bool REHex::VirtualMappingListModel::IsContainer(const wxDataViewItem &item) const
{
	return false;
}

bool REHex::VirtualMappingListModel::SetValue(const wxVariant &variant, const wxDataViewItem &item, unsigned int col)
{
	/* Base implementation is pure virtual, but I don't think we need this... */
	abort();
}
