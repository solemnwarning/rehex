/* Reverse Engineer's Hex Editor
 * Copyright (C) 2019-2021 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "CommentTree.hpp"
#include "EditCommentDialog.hpp"
#include "util.hpp"

static REHex::ToolPanel *CommentTree_factory(wxWindow *parent, REHex::SharedDocumentPointer &document, REHex::DocumentCtrl *document_ctrl)
{
	return new REHex::CommentTree(parent, document, document_ctrl);
}

static REHex::ToolPanelRegistration tpr("CommentTree", "Comments", REHex::ToolPanel::TPS_TALL, &CommentTree_factory);

enum {
	ID_EDIT_COMMENT = 1,
	ID_COPY_COMMENT,
	ID_GOTO,
	ID_SELECT,
};

BEGIN_EVENT_TABLE(REHex::CommentTree, wxPanel)
	EVT_DATAVIEW_ITEM_CONTEXT_MENU(wxID_ANY, REHex::CommentTree::OnContextMenu)
	EVT_DATAVIEW_ITEM_ACTIVATED(wxID_ANY, REHex::CommentTree::OnActivated)
END_EVENT_TABLE()

REHex::CommentTree::CommentTree(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl):
	ToolPanel(parent),
	document(document),
	document_ctrl(document_ctrl)
{
	model = new CommentTreeModel(this->document); /* Reference /class/ document pointer! */
	
	dvc = new wxDataViewCtrl(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxDV_NO_HEADER);
	
	dvc_col = dvc->AppendTextColumn("Comment", 0);
	dvc_col->SetSortable(true);
	
	dvc->AssociateModel(model);
	
	/* NOTE: This has to come after AssociateModel, or it will segfault. */
	dvc_col->SetSortOrder(true);
	
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);
	sizer->Add(dvc, 1, wxEXPAND);
	SetSizerAndFit(sizer);
	
	this->document.auto_cleanup_bind(EV_COMMENT_MODIFIED, &REHex::CommentTree::OnCommentModified, this);
	
	refresh_comments();
}

REHex::CommentTree::~CommentTree()
{
	model->DecRef();
}

std::string REHex::CommentTree::name() const
{
	return "CommentTree";
}

void REHex::CommentTree::save_state(wxConfig *config) const
{
	/* No state to save. */
}

void REHex::CommentTree::load_state(wxConfig *config)
{
	/* No state to load. */
}

void REHex::CommentTree::update()
{
	/* Nothing to update */
}

wxSize REHex::CommentTree::DoGetBestClientSize() const
{
	/* TODO: Calculate a reasonable best size. */
	return wxSize(200, -1);
}

void REHex::CommentTree::refresh_comments()
{
	model->refresh_comments();
	dvc_col->SetWidth(wxCOL_WIDTH_AUTOSIZE); /* Refreshes column width */
	dvc->Refresh();
}

void REHex::CommentTree::OnCommentModified(wxCommandEvent &event)
{
	refresh_comments();
	event.Skip();
}

void REHex::CommentTree::OnContextMenu(wxDataViewEvent &event)
{
	assert(document != NULL);
	
	const NestedOffsetLengthMapKey *key = CommentTreeModel::dv_item_to_key(event.GetItem());
	if(key == NULL)
	{
		/* Click wasn't over an item. */
		return;
	}
	
	wxMenu menu;
	
	menu.Append(ID_GOTO, "&Jump to offset");
	
	menu.Append(ID_SELECT, "&Select bytes");
	menu.Enable(ID_SELECT, (key->length > 0));
	
	menu.AppendSeparator();
	
	menu.Append(ID_EDIT_COMMENT,  "&Edit comment");
	menu.Append(ID_COPY_COMMENT,  "&Copy comment(s)");
	
	menu.Bind(wxEVT_MENU, [this, key](wxCommandEvent &event)
	{
		switch(event.GetId())
		{
			case ID_GOTO:
				document->set_cursor_position(key->offset);
				
				CallAfter([this]()
				{
					document_ctrl->SetFocus();
					document_ctrl->Refresh(); /* TODO: Refresh in DocumentCtrl when it gains focus. */
				});
				
				break;
				
			case ID_SELECT:
				document->set_cursor_position(key->offset);
				document_ctrl->set_selection_raw(key->offset, (key->offset + key->length - 1));
				
				CallAfter([this]()
				{
					document_ctrl->SetFocus();
					document_ctrl->Refresh(); /* TODO: Refresh in DocumentCtrl when it gains focus. */
				});
				
				break;
				
			case ID_EDIT_COMMENT:
				EditCommentDialog::run_modal(this, document, key->offset, key->length);
				break;
				
			case ID_COPY_COMMENT:
			{
				ClipboardGuard cg;
				if(cg)
				{
					auto all_comments      = document->get_comments();
					auto selected_comments = NestedOffsetLengthMap_get_recursive(all_comments, *key);
					
					CommentsDataObject *d = new CommentsDataObject(selected_comments, key->offset);
					
					wxTheClipboard->SetData(d);
				}
				
				break;
			}
			
			default:
				break;
		}
	});
	
	PopupMenu(&menu);
}

void REHex::CommentTree::OnActivated(wxDataViewEvent &event)
{
	assert(document != NULL);
	
	const NestedOffsetLengthMapKey *key = CommentTreeModel::dv_item_to_key(event.GetItem());
	assert(key != NULL);
	
	document->set_cursor_position(key->offset);
	
	CallAfter([this]()
	{
		document_ctrl->SetFocus();
		document_ctrl->Refresh(); /* TODO: Refresh in DocumentCtrl when it gains focus. */
	});
}

REHex::CommentTreeModel::CommentTreeModel(REHex::Document *document):
	document(document) {}

void REHex::CommentTreeModel::refresh_comments()
{
	if(document == NULL)
	{
		return;
	}
	
	const REHex::NestedOffsetLengthMap<REHex::Document::Comment> &comments = document->get_comments();
	
	/* Erase any comments which no longer exist, or are children of such. */
	
	for(auto i = values.begin(); i != values.end();)
	{
		values_elem_t *value = &(*i);
		
		if(comments.find(value->first) == comments.end())
		{
			i = erase_value(i);
		}
		else{
			++i;
		}
	}
	
	/* Add any comments which we don't already have registered. */
	
	/* Stack of comments the point we are processing is nested within. */
	std::stack<values_elem_t*> parents;
	
	for(auto offset_base = comments.begin(); offset_base != comments.end();)
	{
		/* Pop any comments off parents which we have gone past the end of. */
		while(!parents.empty() && (parents.top()->first.offset + parents.top()->first.length) <= offset_base->first.offset)
		{
			parents.pop();
		}
		
		/* We process any comments at the same offset from largest to smallest, ensuring
		 * smaller comments are parented to the next-larger one at the same offset.
		 *
		 * This could be optimised by changing the order of keys in the comments map, but
		 * that'll probably break something...
		*/
		
		auto next_offset = offset_base;
		while(next_offset != comments.end() && next_offset->first.offset == offset_base->first.offset)
		{
			++next_offset;
		}
		
		auto c = next_offset;
		do {
			--c;
			
			values_elem_t *parent = parents.empty() ? NULL : parents.top();
			
			auto x = values.emplace(std::make_pair(c->first, CommentData(parent, c->second.text)));
			values_elem_t *value = &(*(x.first));
			
			if(value->second.parent != parent)
			{
				/* Remove the item so we can re-add it if a new parent has been
				 * created around it.
				*/
				
				assert(!x.second);
				
				erase_value(x.first);
				
				x = values.emplace(std::make_pair(c->first, CommentData(parent, c->second.text)));
				value = &(*(x.first));
				
				assert(x.second);
			}
			
			parents.push(value);
			
			if(x.second)
			{
				/* Add the item if it wasn't already in the values map. */
				
				if(parent == NULL)
				{
					root.insert(value);
				}
				else{
					parent->second.children.insert(value);
				}
				
				ItemAdded(wxDataViewItem(parent), wxDataViewItem((void*)(value)));
			}
			else if(value->second.text.get() != c->second.text.get())
			{
				/* Text has changed. */
				
				value->second.text = c->second.text;
				ItemChanged(wxDataViewItem((void*)(value)));
			}
		} while(c != offset_base);
		
		offset_base = next_offset;
	}
}

const REHex::NestedOffsetLengthMapKey *REHex::CommentTreeModel::dv_item_to_key(const wxDataViewItem &item)
{
	return (const NestedOffsetLengthMapKey*)(item.GetID());
}

std::map<REHex::NestedOffsetLengthMapKey, REHex::CommentTreeModel::CommentData>::iterator REHex::CommentTreeModel::erase_value(std::map<REHex::NestedOffsetLengthMapKey, REHex::CommentTreeModel::CommentData>::iterator value_i)
{
	values_elem_t *value  = &(*value_i);
	values_elem_t *parent = value->second.parent;
	
	for(std::set<values_elem_t*, ChildElemCompare>::iterator c; (c = value->second.children.begin()) != value->second.children.end();)
	{
		values_elem_t *child = *c;
		erase_value(values.find(child->first));
	}
	
	if(parent == NULL)
	{
		root.erase(value);
	}
	else{
		parent->second.children.erase(value);
	}
	
	auto next_value_i = values.erase(value_i);
	
	ItemDeleted(wxDataViewItem(parent), wxDataViewItem(value));
	
	return next_value_i;
}

int REHex::CommentTreeModel::Compare(const wxDataViewItem &item1, const wxDataViewItem &item2, unsigned int column, bool ascending) const
{
	assert(column == 0);
	
	const NestedOffsetLengthMapKey *key1 = (const NestedOffsetLengthMapKey*)(item1.GetID());
	const NestedOffsetLengthMapKey *key2 = (const NestedOffsetLengthMapKey*)(item2.GetID());
	
	int result;
	if(key1->offset < key2->offset)
	{
		result = -1;
	}
	else if(key1->offset == key2->offset)
	{
		if(key1->length < key2->length)
		{
			result = -1;
		}
		else if(key1->length == key2->length)
		{
			result = 0;
		}
		else /* if(key1->length > key2->length) */
		{
			result = 1;
		}
	}
	else /* if(key1->offset > key2->offset) */
	{
		result = 1;
	}
	
	if(!ascending)
	{
		result *= -1;
	}
	
	return result;
}

unsigned int REHex::CommentTreeModel::GetChildren(const wxDataViewItem &item, wxDataViewItemArray &children) const
{
	values_elem_t *value = (values_elem_t*)(item.GetID());
	auto v_children = (value != NULL ? &(value->second.children) : &root);
	
	children.Alloc(v_children->size());
	
	for(auto v = v_children->begin(); v != v_children->end(); ++v)
	{
		values_elem_t *v_data = *v;
		children.Add(wxDataViewItem((void*)(v_data)));
	}
	
	return v_children->size();
}

unsigned int REHex::CommentTreeModel::GetColumnCount() const
{
	return 1;
}

wxString REHex::CommentTreeModel::GetColumnType(unsigned int col) const
{
	assert(col == 0);
	return "string";
}

wxDataViewItem REHex::CommentTreeModel::GetParent(const wxDataViewItem &item) const
{
	values_elem_t *value = (values_elem_t*)(item.GetID());
	return wxDataViewItem(value->second.parent);
}

void REHex::CommentTreeModel::GetValue(wxVariant &variant, const wxDataViewItem &item, unsigned int col) const
{
	assert(col == 0);
	
	if(document == NULL)
	{
		variant = "BUG: Document destroyed";
		return;
	}
	
	const NestedOffsetLengthMapKey *key = (const NestedOffsetLengthMapKey*)(item.GetID());
	const REHex::NestedOffsetLengthMap<REHex::Document::Comment> &comments = document->get_comments();
	
	auto c = comments.find(*key);
	if(c != comments.end())
	{
		/* Only include up to the first line break in the comment text.
		 * Note that wxString::find_first_of() returns the string length
		 * if it doesn't find a match.
		*/
		size_t line_len = c->second.text->find_first_of("\r\n");
		variant = c->second.text->substr(0, line_len);
	}
	else{
		variant = "BUG: Unknown key in REHex::CommentTreeModel::GetValue";
	}
}

bool REHex::CommentTreeModel::IsContainer(const wxDataViewItem &item) const
{
	return true;
}

bool REHex::CommentTreeModel::SetValue(const wxVariant &variant, const wxDataViewItem &item, unsigned int col)
{
	/* Base implementation is pure virtual, but I don't think we need this... */
	abort();
}
