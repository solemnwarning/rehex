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

#include "DiffWindow.hpp"
#include "Palette.hpp"

BEGIN_EVENT_TABLE(REHex::DiffWindow, wxFrame)
END_EVENT_TABLE()

REHex::DiffWindow::DiffWindow():
	wxFrame(NULL, wxID_ANY, "DiffWindow", wxDefaultPosition, wxSize(740, 540))
{}

REHex::DiffWindow::~DiffWindow()
{}

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
		
		new_range->splitter->SetMinimumPaneSize(20);
	}
	else{
		auto prev_range = std::prev(new_range);
		
		new_range->splitter = new wxSplitterWindow(
			prev_range->splitter, wxID_ANY, wxDefaultPosition, wxDefaultSize, (wxSP_3D | wxSP_LIVE_UPDATE));
		
		prev_range->splitter->Unsplit();
		prev_range->splitter->SplitVertically(prev_range->doc_ctrl, new_range->splitter);
		
		prev_range->splitter->SetMinimumPaneSize(20);
	}
	
	new_range->doc_ctrl = new DocumentCtrl(new_range->splitter, new_range->doc);
	new_range->foo = new wxStaticText(new_range->splitter, wxID_ANY, "foo");
	
	doc_update(&*new_range);
	
	new_range->splitter->SplitVertically(new_range->doc_ctrl, new_range->foo);
	
	if(ranges.size() > 1)
	{
		// new_range->doc_ctrl->set_show_offsets(false);
		new_range->splitter->Unsplit();
	}
	
	/* If this is the first Range using this Document, set up event bindings. */
	
	bool first_of_doc = (std::find_if(ranges.begin(), new_range, [&new_range](const Range &range) { return range.doc == new_range->doc; }) == ranges.end());
	if(first_of_doc)
	{
		new_range->doc->Bind(wxEVT_DESTROY, &REHex::DiffWindow::OnDocumentDestroy, this);
	}
}

std::list<REHex::DiffWindow::Range>::iterator REHex::DiffWindow::remove_range(std::list<Range>::iterator range)
{
	abort();
}

void REHex::DiffWindow::doc_update(Range *range)
{
	std::list<DocumentCtrl::Region*> regions;
	regions.push_back(new DiffDataRegion(range->offset, range->length, this, range));
	
	range->doc_ctrl->replace_all_regions(regions);
}

void REHex::DiffWindow::OnDocumentDestroy(wxWindowDestroyEvent &event)
{
	abort();
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
				Palette::PAL_SECONDARY_SELECTED_TEXT_FG,
				Palette::PAL_SECONDARY_SELECTED_TEXT_BG,
				true);
		}
	}
	
	return NoHighlight();
}
