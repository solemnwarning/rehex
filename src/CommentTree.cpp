/* Reverse Engineer's Hex Editor
 * Copyright (C) 2019-2022 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifdef __WXGTK__
#include <gtk/gtk.h>
#endif

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

#define MODEL_OFFSET_COLUMN 0
#define MODEL_TEXT_COLUMN 1

BEGIN_EVENT_TABLE(REHex::CommentTree, wxPanel)
	EVT_DATAVIEW_ITEM_CONTEXT_MENU(wxID_ANY, REHex::CommentTree::OnContextMenu)
	EVT_DATAVIEW_ITEM_ACTIVATED(wxID_ANY, REHex::CommentTree::OnActivated)
END_EVENT_TABLE()

REHex::CommentTree::CommentTree(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl):
	ToolPanel(parent),
	document(document),
	document_ctrl(document_ctrl),
	historic_max_comment_depth(0)
{
	model = new CommentTreeModel(this->document, document_ctrl); /* Reference /class/ document pointer! */
	
	dvc = new wxDataViewCtrl(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, 0);
	
	offset_col = dvc->AppendTextColumn("Offset", MODEL_OFFSET_COLUMN);
	offset_col->SetSortable(true);
	
	text_col = dvc->AppendTextColumn("Comment", MODEL_TEXT_COLUMN);
	text_col->SetSortable(false);
	
	dvc->AssociateModel(model);
	
	/* NOTE: This has to come after AssociateModel, or it will segfault. */
	offset_col->SetSortOrder(true);
	
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
	
	#ifdef __WXGTK__
	/* wxGTK doesn't account for the expander arrow when using wxCOL_WIDTH_AUTOSIZE, so we need
	 * to calculate the width ourselves...
	 *
	 * We only resize the column when a new comment is added at a deeper level than any
	 * previously existed at so as to not override if the user manually resizes the column.
	*/
	
	int max_comment_depth = model->get_max_comment_depth();
	if(max_comment_depth > historic_max_comment_depth)
	{
		historic_max_comment_depth = max_comment_depth;
		
		/* Get the width of the expander arrow in pixels. */
		
		GtkWidget *tree = dvc->GtkGetTreeView();
		
		int expander_size;
		gtk_widget_style_get(tree, "expander-size", &expander_size, NULL);
		// +1 to match GtkTreeView behavior
		expander_size++;
		
		/* Get the width of the ADDITIONAL per-level indentation in pixels. */
		
		int extra_indent = dvc->GetIndent();
		
		/* Calculate the worst-case width for the actual offset text. */
		
		std::string offset_text = format_offset(0, document_ctrl->get_offset_display_base(), document->buffer_length());
		
		/* Change any alpha characters to 'X' - probably the widest in the font? */
		for(auto it = offset_text.begin();
			(it = std::find_if(it, offset_text.end(), [](char c) { return isalnum(c); })) != offset_text.end();
			++it)
		{
			*it = 'X';
		}
		
		wxSize offset_size = dvc->GetTextExtent(offset_text);
		
		offset_col->SetWidth(offset_size.GetWidth() + ((max_comment_depth + 1) * expander_size) + (max_comment_depth * extra_indent));
	}
	
	#else
	offset_col->SetWidth(wxCOL_WIDTH_AUTOSIZE); /* Refreshes column width */
	#endif
	
	text_col->SetWidth(wxCOL_WIDTH_AUTOSIZE); /* Refreshes column width */
	
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

REHex::CommentTreeModel::CommentTreeModel(SharedDocumentPointer &document, DocumentCtrl *document_ctrl):
	document(document),
	document_ctrl(document_ctrl),
	max_comment_depth(-1) {}

void REHex::CommentTreeModel::refresh_comments()
{
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
	
	max_comment_depth = -1;
	
	/* Stack of comments the point we are processing is nested within. */
	std::stack<values_elem_t*> parents;
	
	for(auto offset_base = comments.begin(); offset_base != comments.end();)
	{
		/* Pop any comments off parents which we have gone past the end of. */
		while(!parents.empty() && (parents.top()->first.offset + parents.top()->first.length) <= offset_base->first.offset)
		{
			parents.pop();
		}
		
		if((int)(parents.size()) > max_comment_depth)
		{
			max_comment_depth = parents.size();
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
					if(!parent->second.is_container)
					{
						/* Parent just became a container. Have to re-add it. */
						re_add_item(parent, true);
					}
					
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

int REHex::CommentTreeModel::get_max_comment_depth() const
{
	return max_comment_depth;
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
	
	bool parent_became_empty = false;
	if(parent == NULL)
	{
		root.erase(value);
	}
	else{
		parent->second.children.erase(value);
		parent_became_empty = parent->second.children.empty();
	}
	
	auto next_value_i = values.erase(value_i);
	
	ItemDeleted(wxDataViewItem(parent), wxDataViewItem(value));
	
	if(parent_became_empty)
	{
		/* Parent ceased to be a container. Have to re-add it. */
		re_add_item(parent, false);
	}
	
	return next_value_i;
}

void REHex::CommentTreeModel::re_add_item(values_elem_t *value, bool as_container)
{
	values_elem_t *parent = value->second.parent;
	
	/* Removing the last child of a container, even momentarily, will collapse that container
	 * in the wxDataViewCtrl, so we insert a placeholder alongside the element we are removing
	 * to stop the parent from collapsing and then remove it when we are done.
	 *
	 * Some code in this class expects all wxDataViewItem pointers to be elements within the
	 * values map, but none of it should be hit within the ItemDeleted()/ItemAdded() calls...
	*/
	
	std::shared_ptr<const wxString> placeholder_text(new wxString(""));
	values_elem_t placeholder(NestedOffsetLengthMapKey(-1, 0), CommentData(parent, placeholder_text));
	bool added_placeholder = false;
	
	if(parent != NULL && parent->second.children.size() == 1U)
	{
		parent->second.children.insert(&placeholder);
		ItemAdded(wxDataViewItem(parent), wxDataViewItem(&placeholder));
		added_placeholder = true;
	}
	
	if(parent != NULL)
	{
		parent->second.children.erase(value);
	}
	else{
		root.erase(value);
	}
	
	ItemDeleted(wxDataViewItem(parent), wxDataViewItem(value));
	
	value->second.is_container = as_container;
	
	if(parent != NULL)
	{
		parent->second.children.insert(value);
	}
	else{
		root.insert(value);
	}
	
	ItemAdded(wxDataViewItem(parent), wxDataViewItem(value));
	
	if(added_placeholder)
	{
		parent->second.children.erase(&placeholder);
		ItemDeleted(wxDataViewItem(parent), wxDataViewItem(&placeholder));
	}
}

int REHex::CommentTreeModel::Compare(const wxDataViewItem &item1, const wxDataViewItem &item2, unsigned int column, bool ascending) const
{
	assert(column == MODEL_OFFSET_COLUMN);
	
	assert(item1.IsOk());
	assert(item2.IsOk());
	
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
	return 2;
}

wxString REHex::CommentTreeModel::GetColumnType(unsigned int col) const
{
	assert(col == MODEL_OFFSET_COLUMN || col == MODEL_TEXT_COLUMN);
	return "string";
}

wxDataViewItem REHex::CommentTreeModel::GetParent(const wxDataViewItem &item) const
{
	if(!item.IsOk())
	{
		return wxDataViewItem(NULL);
	}
	
	values_elem_t *value = (values_elem_t*)(item.GetID());
	return wxDataViewItem(value->second.parent);
}

void REHex::CommentTreeModel::GetValue(wxVariant &variant, const wxDataViewItem &item, unsigned int col) const
{
	assert(col == MODEL_OFFSET_COLUMN || col == MODEL_TEXT_COLUMN);
	
	if(!item.IsOk())
	{
		return;
	}
	
	values_elem_t *value = (values_elem_t*)(item.GetID());
	
	if(col == MODEL_TEXT_COLUMN)
	{
		/* Only include up to the first line break in the comment text.
		 * Note that wxString::find_first_of() returns the string length
		 * if it doesn't find a match.
		*/
		
		size_t line_len = value->second.text->find_first_of("\r\n");
		variant = value->second.text->substr(0, line_len);
	}
	else /* if(col == MODEL_OFFSET_COLUMN) */
	{
		variant = format_offset(value->first.offset, document_ctrl->get_offset_display_base(), document->buffer_length());
	}
}

bool REHex::CommentTreeModel::IsContainer(const wxDataViewItem &item) const
{
	if(!item.IsOk())
	{
		/* The root node is always a container. */
		return true;
	}
	
	values_elem_t *value = (values_elem_t*)(item.GetID());
	return value->second.is_container;
}

bool REHex::CommentTreeModel::SetValue(const wxVariant &variant, const wxDataViewItem &item, unsigned int col)
{
	/* Base implementation is pure virtual, but I don't think we need this... */
	abort();
}

bool REHex::CommentTreeModel::HasContainerColumns(const wxDataViewItem &item) const
{
	return true;
}
