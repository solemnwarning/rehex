/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <algorithm>
#include <set>

#include "DiffWindow.hpp"
#include "Palette.hpp"

#include "../res/icon16.h"
#include "../res/icon32.h"
#include "../res/icon48.h"
#include "../res/icon64.h"

BEGIN_EVENT_TABLE(REHex::DiffWindow, wxFrame)
	EVT_AUINOTEBOOK_PAGE_CLOSED(wxID_ANY, REHex::DiffWindow::OnNotebookClosed)
END_EVENT_TABLE()

REHex::DiffWindow::DiffWindow(wxWindow *parent):
	wxFrame(parent, wxID_ANY, "Show differences - Reverse Engineers' Hex Editor", wxDefaultPosition, wxSize(740, 540))
{
	/* TODO: Construct a single wxIconBundle instance somewhere. */
	
	wxIconBundle icons;
	
	{
		wxBitmap b16 = wxBITMAP_PNG_FROM_DATA(icon16);
		wxIcon i16;
		i16.CopyFromBitmap(b16);
		icons.AddIcon(i16);
		
		wxBitmap b32 = wxBITMAP_PNG_FROM_DATA(icon32);
		wxIcon i32;
		i32.CopyFromBitmap(b32);
		icons.AddIcon(i32);
		
		wxBitmap b48 = wxBITMAP_PNG_FROM_DATA(icon48);
		wxIcon i48;
		i48.CopyFromBitmap(b48);
		icons.AddIcon(i48);
		
		wxBitmap b64 = wxBITMAP_PNG_FROM_DATA(icon64);
		wxIcon i64;
		i64.CopyFromBitmap(b64);
		icons.AddIcon(i64);
	}
	
	SetIcons(icons);
}

REHex::DiffWindow::~DiffWindow()
{
	/* Disconnect any remaining external Document event bindings. */
	
	std::set<Document*> unique_docs;
	
	for(auto r = ranges.begin(); r != ranges.end(); ++r)
	{
		unique_docs.insert(r->doc);
	}
	
	for(auto d = unique_docs.begin(); d != unique_docs.end(); ++d)
	{
		(*d)->Unbind(wxEVT_DESTROY, &REHex::DiffWindow::OnDocumentDestroy, this);
	}
}

const std::list<REHex::DiffWindow::Range> &REHex::DiffWindow::get_ranges() const
{
	return ranges;
}

void REHex::DiffWindow::add_range(const Range &range)
{
	auto new_range = ranges.insert(ranges.end(), range);
	
	if(ranges.size() == 1)
	{
		new_range->splitter = new wxSplitterWindow(
			this, wxID_ANY, wxDefaultPosition, wxDefaultSize, (wxSP_3D | wxSP_LIVE_UPDATE));
		
		/* Force the splitter to occupy the whole window. */
		new_range->splitter->SetPosition(wxPoint(0, 0));
		new_range->splitter->SetSize(GetClientSize());
		
		new_range->splitter->SetMinimumPaneSize(20);
	}
	else{
		auto prev_range = std::prev(new_range);
		
		new_range->splitter = new wxSplitterWindow(
			prev_range->splitter, wxID_ANY, wxDefaultPosition, wxDefaultSize, (wxSP_3D | wxSP_LIVE_UPDATE));
		
		prev_range->splitter->Unsplit();
		prev_range->splitter->SplitVertically(prev_range->notebook, new_range->splitter);
		
		prev_range->splitter->SetMinimumPaneSize(20);
	}
	
	new_range->notebook = new wxAuiNotebook(new_range->splitter, wxID_ANY, wxDefaultPosition, wxDefaultSize, (wxAUI_NB_CLOSE_ON_ACTIVE_TAB | wxAUI_NB_TOP));
	
	new_range->doc_ctrl = new DocumentCtrl(new_range->notebook, new_range->doc);
	new_range->foo = new wxStaticText(new_range->splitter, wxID_ANY, "foo");
	
	new_range->notebook->AddPage(new_range->doc_ctrl, new_range->doc->get_title());
	
	doc_update(&*new_range);
	
	new_range->splitter->SplitVertically(new_range->notebook, new_range->foo);
	
	if(ranges.size() > 1)
	{
		// new_range->doc_ctrl->set_show_offsets(false);
		new_range->splitter->Unsplit();
	}
	
	/* If this is the first Range using this Document, set up event bindings. */
	
	bool first_of_doc = (std::find_if(ranges.begin(), new_range, [&](const Range &range) { return range.doc == new_range->doc; }) == new_range);
	if(first_of_doc)
	{
		new_range->doc->Bind(wxEVT_DESTROY, &REHex::DiffWindow::OnDocumentDestroy, this);
	}
	
	resize_splitters();
}

std::list<REHex::DiffWindow::Range>::iterator REHex::DiffWindow::remove_range(std::list<Range>::iterator range)
{
	auto next = std::next(range);
	
	if(range != ranges.begin())
	{
		/* We are the child of another splitter... */
		
		auto prev = std::prev(range);
		
		prev->splitter->Unsplit();
		
		if(next != ranges.end())
		{
			/* ...and we have a child, so reparent it to our parent. */
			
			next->splitter->Reparent(prev->splitter);
			prev->splitter->SplitVertically(prev->notebook, next->splitter);
		}
	}
	else if(next != ranges.end())
	{
		/* We are the top-level splitter, and we have a child. It must be reparented. */
		
		wxWindow *parent_window = range->splitter->GetParent();
		
		range->splitter->Unsplit();
		
		next->splitter->Reparent(parent_window);
		
		/* Force the next splitter to occupy the whole window. */
		next->splitter->SetPosition(wxPoint(0, 0));
		next->splitter->SetSize(parent_window->GetClientSize());
		
		/* Unsplitting our splitter hid the next one, so unhide it. */
		next->splitter->Show();
	}
	
	/* We can't actually destroy our windows yet, since we might be called from one of their
	 * event handlers (i.e. EVT_AUINOTEBOOK_PAGE_CLOSED), so hide them and queue them to be
	 * destroyed soon.
	*/
	
	range->splitter->Hide();
	
	wxWindow *destroy_me = range->splitter;
	CallAfter([destroy_me]() { destroy_me->Destroy(); });
	
	Document *range_doc  = range->doc;
	
	ranges.erase(range);
	
	/* If this was the last Range using this Document, remove event bindings. */
	
	bool last_of_doc = (std::find_if(ranges.begin(), ranges.end(), [&](const Range &range) { return range.doc == range_doc; }) == ranges.end());
	if(last_of_doc)
	{
		range->doc->Unbind(wxEVT_DESTROY, &REHex::DiffWindow::OnDocumentDestroy, this);
	}
	
	resize_splitters();
	
	return next;
}

void REHex::DiffWindow::doc_update(Range *range)
{
	std::list<DocumentCtrl::Region*> regions;
	regions.push_back(new DiffDataRegion(range->offset, range->length, this, range));
	
	range->doc_ctrl->replace_all_regions(regions);
}

void REHex::DiffWindow::resize_splitters()
{
	wxSize window_size = GetClientSize();
	
	for(auto r = ranges.begin(); r != ranges.end(); ++r)
	{
		r->splitter->SetSashPosition(window_size.GetWidth() / ranges.size());
	}
}

void REHex::DiffWindow::OnDocumentDestroy(wxWindowDestroyEvent &event)
{
	Document *destroyed = dynamic_cast<Document*>(event.GetWindow());
	assert(destroyed != NULL);
	
	for(auto i = ranges.begin(); i != ranges.end();)
	{
		if(i->doc == destroyed)
		{
			i = remove_range(i);
		}
		else{
			++i;
		}
	}
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::DiffWindow::OnNotebookClosed(wxAuiNotebookEvent &event)
{
	auto nb_range = std::find_if(ranges.begin(), ranges.end(), [event](const Range &range) { return range.notebook == event.GetEventObject(); });
	assert(nb_range != ranges.end());
	
	remove_range(nb_range);
}

REHex::DiffWindow::DiffDataRegion::DiffDataRegion(off_t d_offset, off_t d_length, DiffWindow *diff_window, Range *range):
	DataRegion(d_offset, d_length), diff_window(diff_window), range(range) {}

REHex::DocumentCtrl::DataRegion::Highlight REHex::DiffWindow::DiffDataRegion::highlight_at_off(off_t off) const
{
	std::vector<unsigned char> my_data = range->doc->read_data(off, 1);
	
	assert(off >= range->offset);
	off_t off_from_range_begin = off - range->offset;
	
	const std::list<Range> &ranges = diff_window->get_ranges();
	
	for(auto r = ranges.begin(); r != ranges.end(); ++r)
	{
		if(&*r == range)
		{
			/* This one is me. */
			continue;
		}
		
		std::vector<unsigned char> their_data = r->doc->read_data(r->offset + off_from_range_begin, 1);
		
		if(off_from_range_begin >= r->length || their_data != my_data)
		{
			return Highlight(
				Palette::PAL_DIRTY_TEXT_FG,
				Palette::PAL_DIRTY_TEXT_BG,
				true);
		}
	}
	
	return NoHighlight();
}
