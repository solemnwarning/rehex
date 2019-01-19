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

#include "CommentTree.hpp"

REHex::CommentTree::CommentTree(wxWindow *parent, REHex::Document &document):
	wxPanel(parent, wxID_ANY),
	document(document),
	events_bound(false)
{
	model = new CommentTreeModel(document);
	
	dvc = new wxDataViewCtrl(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxDV_NO_HEADER);
	dvc->AppendTextColumn("Comment", 0);
	dvc->AssociateModel(model);
	
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);
	sizer->Add(dvc, 1, wxEXPAND);
	SetSizerAndFit(sizer);
	
	document.Bind(wxEVT_DESTROY, &REHex::CommentTree::OnDocumentDestroy, this);
	document.Bind(EV_COMMENT_MODIFIED, &REHex::CommentTree::OnCommentModified, this);
	
	events_bound = true;
	
	refresh_comments();
}

REHex::CommentTree::~CommentTree()
{
	unbind_events();
	model->DecRef();
}

wxSize REHex::CommentTree::DoGetBestClientSize() const
{
	/* TODO: Calculate a reasonable best size. */
	return wxSize(200, -1);
}

void REHex::CommentTree::unbind_events()
{
	if(events_bound)
	{
		document.Unbind(EV_COMMENT_MODIFIED, &REHex::CommentTree::OnCommentModified, this);
		document.Unbind(wxEVT_DESTROY, &REHex::CommentTree::OnDocumentDestroy, this);
		
		events_bound = false;
	}
}

void REHex::CommentTree::refresh_comments()
{
	model->refresh_comments();
}

void REHex::CommentTree::OnDocumentDestroy(wxWindowDestroyEvent &event)
{
	unbind_events();
	event.Skip();
}

void REHex::CommentTree::OnCommentModified(wxCommandEvent &event)
{
	refresh_comments();
	event.Skip();
}

REHex::CommentTreeModel::CommentTreeModel(REHex::Document &document):
	document(document) {}

void REHex::CommentTreeModel::refresh_comments()
{
	const REHex::NestedOffsetLengthMap<REHex::Document::Comment> &comments = document.get_comments();
	
	/* TODO: Handle nested comments. */
	/* TODO: Intelligently add/remove elements rather than repopulating. */
	
	values.clear();
	Cleared();
	
	for(auto c = comments.begin(); c != comments.end(); ++c)
	{
		auto x = values.insert(c->first);
		const NestedOffsetLengthMapKey *key = &(*(x.first));
		
		ItemAdded(wxDataViewItem(NULL), wxDataViewItem((void*)(key)));
	}
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
		else if(key1->length > key2->length)
		{
			result = 1;
		}
	}
	else if(key1->offset > key2->offset)
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
	/* TODO: Handle nested comments. */
	
	const NestedOffsetLengthMapKey *key = (const NestedOffsetLengthMapKey*)(item.GetID());
	if(key == NULL)
	{
		children.Alloc(values.size());
		
		for(auto v = values.begin(); v != values.end(); ++v)
		{
			const NestedOffsetLengthMapKey *vk = &(*v);
			children.Add(wxDataViewItem((void*)(vk)));
		}
		
		return values.size();
	}
	else{
		return 0;
	}
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
	/* TODO: Handle nested comments. */
	return wxDataViewItem(NULL);
}

void REHex::CommentTreeModel::GetValue(wxVariant &variant, const wxDataViewItem &item, unsigned int col) const
{
	assert(col == 0);
	
	const NestedOffsetLengthMapKey *key = (const NestedOffsetLengthMapKey*)(item.GetID());
	const REHex::NestedOffsetLengthMap<REHex::Document::Comment> &comments = document.get_comments();
	
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
