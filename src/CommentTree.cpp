/* Reverse Engineer's Hex Editor
 * Copyright (C) 2019-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <functional>
#include <stack>
#include <utility>
#include <wx/artprov.h>
#include <wx/clipbrd.h>
#include <wx/statbmp.h>

#ifdef __WXGTK__
#include <gtk/gtk.h>
#endif

#include "CommentTree.hpp"
#include "EditCommentDialog.hpp"
#include "profile.hpp"
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
	ID_GOTO_END,
	ID_SELECT,
	ID_FILTER_TEXT,
	ID_REFRESH_TIMER,
};

#define MODEL_OFFSET_COLUMN 0
#define MODEL_TEXT_COLUMN 1

BEGIN_EVENT_TABLE(REHex::CommentTree, wxPanel)
	EVT_DATAVIEW_ITEM_CONTEXT_MENU(wxID_ANY, REHex::CommentTree::OnContextMenu)
	EVT_DATAVIEW_ITEM_ACTIVATED(wxID_ANY, REHex::CommentTree::OnActivated)
	EVT_TIMER(ID_REFRESH_TIMER, REHex::CommentTree::OnRefreshTimer)
	
	EVT_TEXT(ID_FILTER_TEXT, REHex::CommentTree::OnFilterTextChange)
END_EVENT_TABLE()

REHex::CommentTree::CommentTree(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl):
	ToolPanel(parent),
	document(document),
	document_ctrl(document_ctrl),
	historic_max_comment_depth(0),
	refresh_running(false),
	refresh_timer(this, ID_REFRESH_TIMER)
{
	model = new CommentTreeModel(this->document, document_ctrl); /* Reference /class/ document pointer! */
	
	wxBoxSizer *filter_sizer = new wxBoxSizer(wxHORIZONTAL);
	
	filter_textctrl = new wxTextCtrl(this, ID_FILTER_TEXT);
	filter_textctrl->SetHint("Search text");
	
	int filter_height = filter_textctrl->GetSize().GetHeight();
	
	wxBitmap find_bitmap = wxArtProvider::GetBitmap(wxART_FIND, wxART_FRAME_ICON, wxSize(filter_height, filter_height));
	wxStaticBitmap *filter_sbmp = new wxStaticBitmap(this, wxID_ANY, find_bitmap);
	
	filter_sizer->Add(filter_sbmp, 0);
	filter_sizer->Add(filter_textctrl, 1);
	
	dvc = new wxDataViewCtrl(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, 0);
	
	offset_col = dvc->AppendTextColumn("Offset", MODEL_OFFSET_COLUMN);
	offset_col->SetSortable(true);
	
	text_col = dvc->AppendTextColumn("Comment", MODEL_TEXT_COLUMN);
	text_col->SetSortable(false);
	
	dvc->AssociateModel(model);
	
	/* NOTE: This has to come after AssociateModel, or it will segfault. */
	offset_col->SetSortOrder(true);
	
	spinner = new LoadingSpinner(this, wxID_ANY, wxPoint(0, 0), wxSize(32, 32), wxBORDER_SIMPLE);
	
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);
	sizer->Add(filter_sizer, 0, wxEXPAND);
	sizer->Add(dvc, 1, wxEXPAND);
	SetSizerAndFit(sizer);
	
	dvc->Bind(wxEVT_SIZE, [&](wxSizeEvent &event)
	{
		reposition_spinner();
		event.Skip();
	});
	
	reposition_spinner();
	
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

std::string REHex::CommentTree::label() const
{
	return "Comments";
}

REHex::ToolPanel::Shape REHex::CommentTree::shape() const
{
	return ToolPanel::TPS_TALL;
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
	if(!refresh_running)
	{
		refresh_running = true;
		spinner->Show();
		
		Bind(wxEVT_IDLE, &REHex::CommentTree::OnIdle, this);
	}
	
	bool changed = model->refresh_comments();
	if(!changed)
	{
		#ifdef __APPLE__
		offset_col->SetWidth(wxCOL_WIDTH_AUTOSIZE); /* Refreshes column width */
		text_col->SetWidth(wxCOL_WIDTH_AUTOSIZE); /* Refreshes column width */
		#endif
		
		refresh_timer.Stop();
		Unbind(wxEVT_IDLE, &REHex::CommentTree::OnIdle, this);
		
		refresh_running = false;
		spinner->Hide();
		return;
	}
	
	/* Schedule a timer to do another update step in case the system is too busy for us to be
	 * given any idle time slots.
	*/
	refresh_timer.Start(MAX_IDLE_WAIT_MS, wxTIMER_ONE_SHOT);
	
	#if defined(__WXGTK__)
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
	
	text_col->SetWidth(wxCOL_WIDTH_AUTOSIZE); /* Refreshes column width */
	
	#elif defined(__APPLE__)
	/* wxDataViewColumn::SetWidth() is somewhat expensive on macOS and makes the columns
	 * twitch around, so we only update the column widths when the maximum depth increases, or
	 * when a refresh finishes (see above).
	*/
	
	int max_comment_depth = model->get_max_comment_depth();
	if(max_comment_depth > historic_max_comment_depth)
	{
		historic_max_comment_depth = max_comment_depth;
		
		offset_col->SetWidth(wxCOL_WIDTH_AUTOSIZE); /* Refreshes column width */
		text_col->SetWidth(wxCOL_WIDTH_AUTOSIZE); /* Refreshes column width */
	}
	
	#else
	offset_col->SetWidth(wxCOL_WIDTH_AUTOSIZE); /* Refreshes column width */
	text_col->SetWidth(wxCOL_WIDTH_AUTOSIZE); /* Refreshes column width */
	#endif
	
	dvc->Refresh();
}

void REHex::CommentTree::reposition_spinner()
{
	wxSize dvc_size = dvc->GetSize();
	wxPoint dvc_pos = dvc->GetPosition();
	
	wxSize spinner_size = spinner->GetSize();
	
	spinner->SetPosition(wxPoint(
		(dvc_pos.x + dvc_size.GetWidth() - spinner_size.GetWidth()),
		(dvc_pos.y + dvc_size.GetHeight() - spinner_size.GetHeight())));
}

void REHex::CommentTree::OnCommentModified(wxCommandEvent &event)
{
	refresh_comments();
	event.Skip();
}

void REHex::CommentTree::OnContextMenu(wxDataViewEvent &event)
{
	assert(document != NULL);
	
	const BitRangeTreeKey *key = CommentTreeModel::dv_item_to_key(event.GetItem());
	if(key == NULL)
	{
		/* Click wasn't over an item. */
		return;
	}
	
	wxMenu menu;
	
	menu.Append(ID_GOTO, "&Jump to start");
	
	menu.Append(ID_GOTO_END, "Jump &to end");
	menu.Enable(ID_GOTO_END, (key->length > BitOffset::ZERO));
	
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
				
			case ID_GOTO_END:
			{
				DocumentCtrl::GenericDataRegion *end_dr = document_ctrl->data_region_by_offset(key->offset + key->length - BitOffset(0, 1));
				if(end_dr != NULL)
				{
					document->set_cursor_position(end_dr->last_row_nearest_column(INT_MAX));
				}
				
				break;
			}
				
			case ID_SELECT:
				document->set_cursor_position(key->offset);
				document_ctrl->set_selection_raw(key->offset, (key->offset + key->length - BitOffset(0, 1)));
				
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
					const BitRangeTree<Document::Comment> &comments = document->get_comments();
					const BitRangeTree<Document::Comment>::Node *root_comment = comments.find_node(*key);
					
					std::list< BitRangeTree<Document::Comment>::const_iterator > selected_comments;
					
					std::function<void(const BitRangeTree<Document::Comment>::Node*)> add_comment;
					add_comment = [&](const BitRangeTree<Document::Comment>::Node *comment)
					{
						selected_comments.push_back(comments.find(comment->key));
						
						for(comment = comment->get_first_child(); comment != NULL; comment = comment->get_next())
						{
							add_comment(comment);
						}
					};
					
					add_comment(root_comment);
					
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
	
	const BitRangeTreeKey *key = CommentTreeModel::dv_item_to_key(event.GetItem());
	assert(key != NULL);
	
	document->set_cursor_position(key->offset);
	
	CallAfter([this]()
	{
		document_ctrl->SetFocus();
		document_ctrl->Refresh(); /* TODO: Refresh in DocumentCtrl when it gains focus. */
	});
}

void REHex::CommentTree::OnIdle(wxIdleEvent &event)
{
	if(refresh_running)
	{
		refresh_comments();
		
		if(refresh_running)
		{
			event.RequestMore();
		}
	}
}

void REHex::CommentTree::OnRefreshTimer(wxTimerEvent &event)
{
	if(refresh_running)
	{
		refresh_comments();
	}
}

void REHex::CommentTree::OnFilterTextChange(wxCommandEvent &event)
{
	model->set_filter_text(filter_textctrl->GetValue());
	refresh_comments();
}

REHex::CommentTreeModel::CommentTreeModel(SharedDocumentPointer &document, DocumentCtrl *document_ctrl):
	document(document),
	document_ctrl(document_ctrl),
	max_comment_depth(-1),
	pending_max_comment_depth(-1) {}

#define MAX_CHANGES 100

bool REHex::CommentTreeModel::refresh_comments()
{
	PROFILE_BLOCK("REHex::CommentTreeModel::refresh_comments");
	
	const BitRangeTree<Document::Comment> &comments = document->get_comments();
	unsigned num_changed = 0;
	
	/* Erase any comments which no longer exist, or are children of such. */
	
	for(auto i = values.begin(); num_changed < MAX_CHANGES && i != values.end();)
	{
		values_elem_t *value = &(*i);
		
		auto comment = comments.find_node(value->first);
		if(comment == NULL || !comment_or_child_matches_filter(comment))
		{
			i = erase_value(i);
			++num_changed;
		}
		else{
			++i;
		}
	}
	
	/* Add any comments which we don't already have registered. */
	
	std::function<void(const BitRangeTree<Document::Comment>::Node*, values_elem_t*, int)> add_comment;
	add_comment = [&](const BitRangeTree<Document::Comment>::Node *comment, values_elem_t *parent, int depth)
	{
		if(depth > pending_max_comment_depth)
		{
			pending_max_comment_depth = depth;
		}
		
		if(!comment_or_child_matches_filter(comment))
		{
			return;
		}
		
		auto x = values.emplace(std::make_pair(comment->key, CommentData(parent, comment->value.text)));
		values_elem_t *value = &(*(x.first));
		
		if(value->second.parent != parent)
		{
			/* Remove the item so we can re-add it if a new parent has been
			 * created around it.
			*/
			
			assert(!x.second);
			
			erase_value(x.first);
			
			x = values.emplace(std::make_pair(comment->key, CommentData(parent, comment->value.text)));
			value = &(*(x.first));
			
			assert(x.second);
		}
		
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
			
			batched_item_added(wxDataViewItem(parent), wxDataViewItem((void*)(value)));
			++num_changed;
		}
		else if(value->second.text.get() != comment->value.text.get())
		{
			/* Text has changed. */
			
			value->second.text = comment->value.text;
			batched_item_changed(wxDataViewItem((void*)(value)));
			
			++num_changed;
		}
		
		for(auto child = comment->get_first_child(); child != NULL && num_changed < MAX_CHANGES; child = child->get_next())
		{
			add_comment(child, value, depth + 1);
		}
	};
	
	for(auto comment = comments.first_root_node(); comment != NULL && num_changed < MAX_CHANGES; comment = comment->get_next())
	{
		add_comment(comment, NULL, 0);
	}
	
	if(num_changed < MAX_CHANGES)
	{
		max_comment_depth = pending_max_comment_depth;
		pending_max_comment_depth = -1;
	}
	
	batched_item_flush();
	
	return num_changed > 0;
}

bool REHex::CommentTreeModel::comment_or_child_matches_filter(const BitRangeTree<Document::Comment>::Node *comment)
{
	if(filter_text.empty())
	{
		return true;
	}
	
	if(comment->value.text.get()->Find(filter_text) != wxNOT_FOUND)
	{
		return true;
	}
	
	for(auto child = comment->get_first_child(); child != NULL; child = child->get_next())
	{
		if(comment_or_child_matches_filter(child))
		{
			return true;
		}
	}
	
	return false;
}

int REHex::CommentTreeModel::get_max_comment_depth() const
{
	return max_comment_depth;
}

const REHex::BitRangeTreeKey *REHex::CommentTreeModel::dv_item_to_key(const wxDataViewItem &item)
{
	return (const BitRangeTreeKey*)(item.GetID());
}

void REHex::CommentTreeModel::set_filter_text(const wxString &filter_text)
{
	this->filter_text = filter_text;
}

wxString REHex::CommentTreeModel::get_filter_text() const
{
	return filter_text;
}

std::map<REHex::BitRangeTreeKey, REHex::CommentTreeModel::CommentData>::iterator REHex::CommentTreeModel::erase_value(std::map<REHex::BitRangeTreeKey, REHex::CommentTreeModel::CommentData>::iterator value_i)
{
	values_elem_t *value  = &(*value_i);
	values_elem_t *parent = value->second.parent;
	
	for(std::set<values_elem_t*, ChildElemCompare>::iterator c; (c = value->second.children.begin()) != value->second.children.end();)
	{
		values_elem_t *child = *c;
		erase_value(values.find(child->first));
	}
	
	#ifdef COMMENTTREEMODEL_BATCH_MODEL_UPDATES
	if(!accumulated_items_to_add.IsEmpty() || !accumulated_items_to_change.IsEmpty())
	{
		batched_item_flush();
	}
	#endif
	
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
	
	batched_item_deleted(wxDataViewItem(parent), wxDataViewItem(value));
	
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
	values_elem_t placeholder(BitRangeTreeKey(BitOffset(-1, 0), BitOffset(0, 0)), CommentData(parent, placeholder_text));
	bool added_placeholder = false;
	
	if(parent != NULL && parent->second.children.size() == 1U)
	{
		parent->second.children.insert(&placeholder);
		batched_item_added(wxDataViewItem(parent), wxDataViewItem(&placeholder));
		added_placeholder = true;
	}
	
	#ifdef COMMENTTREEMODEL_BATCH_MODEL_UPDATES
	if(!accumulated_items_to_add.IsEmpty() || !accumulated_items_to_change.IsEmpty())
	{
		batched_item_flush();
	}
	#endif
	
	if(parent != NULL)
	{
		parent->second.children.erase(value);
	}
	else{
		root.erase(value);
	}
	
	batched_item_deleted(wxDataViewItem(parent), wxDataViewItem(value));
	
	value->second.is_container = as_container;
	
	if(parent != NULL)
	{
		parent->second.children.insert(value);
	}
	else{
		root.insert(value);
	}
	
	batched_item_added(wxDataViewItem(parent), wxDataViewItem(value));
	
	if(added_placeholder)
	{
		parent->second.children.erase(&placeholder);
		batched_item_deleted(wxDataViewItem(parent), wxDataViewItem(&placeholder));
	}
}

void REHex::CommentTreeModel::batched_item_added(const wxDataViewItem &parent, const wxDataViewItem &item)
{
	#ifdef COMMENTTREEMODEL_BATCH_MODEL_UPDATES
	if(accumulated_items_to_add.GetCount() >= COMMENTREEEMODEL_MAX_BATCHED_UPDATES
		|| !accumulated_items_to_delete.IsEmpty()
		|| !accumulated_items_to_change.IsEmpty()
		|| accumulated_items_parent != parent)
	{
		batched_item_flush();
	}
	
	accumulated_items_parent = parent;
	accumulated_items_to_add.Add(item);
	
	#else
	ItemAdded(parent, item);
	
	#endif
}

void REHex::CommentTreeModel::batched_item_deleted(const wxDataViewItem &parent, const wxDataViewItem &item)
{
	#ifdef COMMENTTREEMODEL_BATCH_MODEL_UPDATES
	if(accumulated_items_to_delete.GetCount() >= COMMENTREEEMODEL_MAX_BATCHED_UPDATES
		|| !accumulated_items_to_add.IsEmpty()
		|| !accumulated_items_to_change.IsEmpty()
		|| accumulated_items_parent != parent)
	{
		batched_item_flush();
	}
	
	accumulated_items_parent = parent;
	accumulated_items_to_delete.Add(item);
	
	#else
	ItemDeleted(parent, item);
	
	#endif
}

void REHex::CommentTreeModel::batched_item_changed(const wxDataViewItem &item)
{
	#ifdef COMMENTTREEMODEL_BATCH_MODEL_UPDATES
	if(accumulated_items_to_change.GetCount() >= COMMENTREEEMODEL_MAX_BATCHED_UPDATES
		|| !accumulated_items_to_add.IsEmpty()
		|| !accumulated_items_to_delete.IsEmpty())
	{
		batched_item_flush();
	}
	
	accumulated_items_to_change.Add(item);
	
	#else
	ItemChanged(item);
	
	#endif
}

void REHex::CommentTreeModel::batched_item_flush()
{
	#ifdef COMMENTTREEMODEL_BATCH_MODEL_UPDATES
	
	if(!accumulated_items_to_add.IsEmpty())
	{
		assert(accumulated_items_to_delete.IsEmpty());
		assert(accumulated_items_to_change.IsEmpty());
		
		ItemsAdded(accumulated_items_parent, accumulated_items_to_add);
		accumulated_items_to_add.Empty();
	}
	else if(!accumulated_items_to_delete.IsEmpty())
	{
		assert(accumulated_items_to_add.IsEmpty());
		assert(accumulated_items_to_change.IsEmpty());
		
		ItemsDeleted(accumulated_items_parent, accumulated_items_to_delete);
		accumulated_items_to_delete.Empty();
	}
	else if(!accumulated_items_to_change.IsEmpty())
	{
		assert(accumulated_items_to_add.IsEmpty());
		assert(accumulated_items_to_delete.IsEmpty());
		
		ItemsChanged(accumulated_items_to_change);
		accumulated_items_to_change.Empty();
	}
	
	#endif
}

int REHex::CommentTreeModel::Compare(const wxDataViewItem &item1, const wxDataViewItem &item2, unsigned int column, bool ascending) const
{
	assert(column == MODEL_OFFSET_COLUMN);
	
	assert(item1.IsOk());
	assert(item2.IsOk());
	
	const BitRangeTreeKey *key1 = (const BitRangeTreeKey*)(item1.GetID());
	const BitRangeTreeKey *key2 = (const BitRangeTreeKey*)(item2.GetID());
	
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
