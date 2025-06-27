/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <algorithm>
#include <set>
#include <stdint.h>
#include <stdio.h>
#include <tuple>
#include <wx/artprov.h>
#include <wx/clipbrd.h>
#include <wx/sizer.h>
#include <wx/stattext.h>

#include "App.hpp"
#include "ArtProvider.hpp"
#include "DiffWindow.hpp"
#include "mainwindow.hpp"
#include "Palette.hpp"
#include "SafeWindowPointer.hpp"
#include "util.hpp"

#include "../res/icon16.h"
#include "../res/icon32.h"
#include "../res/icon48.h"
#include "../res/icon64.h"

#ifdef __APPLE__
#include "../res/down32.h"
#include "../res/up32.h"
#endif

#ifdef DIFFWINDOW_PROFILING
#include "timespec.c"
#endif

enum {
	ID_SHOW_OFFSETS = 1,
	ID_SHOW_ASCII,
	ID_FOLD,
	ID_UPDATE_REGIONS_TIMER,
};

BEGIN_EVENT_TABLE(REHex::DiffWindow, wxFrame)
	EVT_SIZE(REHex::DiffWindow::OnSize)
	EVT_IDLE(REHex::DiffWindow::OnIdle)
	EVT_CHAR_HOOK(REHex::DiffWindow::OnCharHook)
	EVT_CLOSE(REHex::DiffWindow::OnWindowClose)
	
	EVT_AUINOTEBOOK_PAGE_CLOSED(wxID_ANY, REHex::DiffWindow::OnNotebookClosed)
	
	EVT_CURSORUPDATE(wxID_ANY, REHex::DiffWindow::OnCursorUpdate)
	
	EVT_COMMAND(wxID_ANY, REHex::DATA_RIGHT_CLICK, REHex::DiffWindow::OnDataRightClick)
	
	EVT_MENU(ID_SHOW_OFFSETS, REHex::DiffWindow::OnToggleOffsets)
	EVT_MENU(ID_SHOW_ASCII,   REHex::DiffWindow::OnToggleASCII)
	EVT_MENU(ID_FOLD,         REHex::DiffWindow::OnToggleFold)
	EVT_MENU(wxID_UP,         REHex::DiffWindow::OnPrevDifference)
	EVT_MENU(wxID_DOWN,       REHex::DiffWindow::OnNextDifference)
	
	EVT_TIMER(ID_UPDATE_REGIONS_TIMER, REHex::DiffWindow::OnUpdateRegionsTimer)
END_EVENT_TABLE()

REHex::DiffWindow *REHex::DiffWindow::instance = NULL;

REHex::DiffWindow::DiffWindow(wxWindow *parent):
	wxFrame(parent, wxID_ANY, "Compare data - Reverse Engineers' Hex Editor", wxDefaultPosition, wxSize(740, 540)),
	statbar(NULL),
	sb_gauge(NULL),
	enable_folding(true),
	recalc_bytes_per_line_pending(false),
	update_regions_timer(this, ID_UPDATE_REGIONS_TIMER),
	relative_cursor_pos(0),
	longest_range(0),
	searching_backwards(false),
	searching_forwards(false),
	search_modal(NULL),
	search_modal_updating(false),
	
	#ifdef DIFFWINDOW_PROFILING
	idle_ticks(0),
	idle_secs(0),
	idle_bytes(0),
	odsr_calls(0),
	#endif
	
	invisible_owner_window(NULL)
{
	wxToolBar *toolbar = CreateToolBar();
	
	show_offsets_button = toolbar->AddCheckTool(ID_SHOW_OFFSETS, "Show offsets",      wxArtProvider::GetBitmap(ART_OFFSETS_ICON,    wxART_TOOLBAR), wxNullBitmap, "Show offsets");
	show_ascii_button   = toolbar->AddCheckTool(ID_SHOW_ASCII,   "Show ASCII",        wxArtProvider::GetBitmap(ART_ASCII_ICON,      wxART_TOOLBAR), wxNullBitmap, "Show ASCII");
	fold_button         = toolbar->AddCheckTool(ID_FOLD,         "Collapse matches",  wxArtProvider::GetBitmap(ART_DIFF_FOLD_ICON,  wxART_TOOLBAR), wxNullBitmap, "Collapse long sequences of matching data");
	
	toolbar->AddSeparator();
	
	#ifdef __APPLE__
	toolbar->AddTool(wxID_UP,   "Previous difference", wxBITMAP_PNG_FROM_DATA(up32),   "Jump to previous difference (Shift+F6)");
	toolbar->AddTool(wxID_DOWN, "Next difference",     wxBITMAP_PNG_FROM_DATA(down32), "Jump to next difference (F6)");
	#else
	toolbar->AddTool(wxID_UP,   "Previous difference", wxArtProvider::GetBitmap(wxART_GO_UP,   wxART_TOOLBAR), "Jump to previous difference (Shift+F6)");
	toolbar->AddTool(wxID_DOWN, "Next difference",     wxArtProvider::GetBitmap(wxART_GO_DOWN, wxART_TOOLBAR), "Jump to next difference (F6)");
	#endif
	
	/* Enable offset and ASCII columns by default. */
	show_offsets_button->Toggle(true);
	show_ascii_button  ->Toggle(true);
	fold_button        ->Toggle(true);
	
	toolbar->Realize();
	
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
	
	statbar = CreateStatusBar(2);
	sb_gauge = new wxGauge(statbar, wxID_ANY, 100);
}

REHex::DiffWindow::~DiffWindow()
{
	/* Disconnect any remaining external Document event bindings. */
	
	std::set< std::pair<Document*, DocumentCtrl*> > unique_docs;
	
	for(auto r = ranges.begin(); r != ranges.end(); ++r)
	{
		unique_docs.insert(std::make_pair((Document*)(r->doc), (DocumentCtrl*)(r->main_doc_ctrl)));
	}
	
	for(auto d = unique_docs.begin(); d != unique_docs.end(); ++d)
	{
		if(d->second != NULL)
		{
			d->second->Unbind(EV_DISP_SETTING_CHANGED,  &REHex::DiffWindow::OnDocumentDisplaySettingsChange,  this);
		}
		
		d->first->Unbind(DATA_OVERWRITE, &REHex::DiffWindow::OnDocumentDataOverwrite, this);
		d->first->Unbind(DATA_INSERT,    &REHex::DiffWindow::OnDocumentDataInsert,    this);
		d->first->Unbind(DATA_ERASE,     &REHex::DiffWindow::OnDocumentDataErase,     this);
		
		d->first->Unbind(DOCUMENT_TITLE_CHANGED, &REHex::DiffWindow::OnDocumentTitleChange, this);
	}
	
	if(instance == this)
	{
		instance = NULL;
	}
}

void REHex::DiffWindow::set_invisible_owner_window(wxTopLevelWindow *window)
{
	invisible_owner_window.reset(window);
	invisible_owner_window.auto_cleanup_bind(wxEVT_SHOW, &DiffWindow::OnInvisibleOwnerWindowShow, this);
}

const std::list<REHex::DiffWindow::Range> &REHex::DiffWindow::get_ranges() const
{
	return ranges;
}

std::list<REHex::DiffWindow::Range>::iterator REHex::DiffWindow::add_range(const Range &range)
{
	auto new_range = ranges.insert(ranges.end(), range);
	
	update_longest_range();
	
	#ifdef DIFFWINDOW_PROFILING
	idle_ticks = 0;
	idle_secs  = 0;
	idle_bytes = 0;
	odsr_calls = 0;
	#endif
	
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
	
	{
		new_range->help_panel = new wxPanel(new_range->splitter);
		wxBoxSizer *v_sizer = new wxBoxSizer(wxVERTICAL);
		
		wxBoxSizer *h_sizer = new wxBoxSizer(wxHORIZONTAL);
		v_sizer->Add(h_sizer, 1, wxALIGN_CENTER_HORIZONTAL);
		
		static const char *HELP_TEXT = "Choose another file or selection to compare against";
		
		wxStaticText *help_text = new wxStaticText(new_range->help_panel, wxID_ANY, HELP_TEXT);
		h_sizer->Add(help_text, 1, wxALIGN_CENTER_VERTICAL);
		
		new_range->help_panel->SetSizerAndFit(v_sizer);
	}
	
	new_range->notebook->AddPage(new_range->doc_ctrl, range_title(&*new_range));
	
	doc_update(&*new_range);
	
	new_range->doc_ctrl->set_show_offsets(show_offsets_button->IsToggled());
	new_range->doc_ctrl->set_show_ascii  (show_ascii_button  ->IsToggled());
	
	new_range->doc_ctrl->set_cursor_position(new_range->offset);
	new_range->doc_ctrl->set_offset_display_base(new_range->main_doc_ctrl->get_offset_display_base());
	new_range->doc_ctrl->set_bytes_per_group    (new_range->main_doc_ctrl->get_bytes_per_group());
	
	new_range->splitter->SplitVertically(new_range->notebook, new_range->help_panel);
	
	if(ranges.size() > 1)
	{
		auto prev_range = std::prev(new_range);
		
		new_range->doc_ctrl->linked_scroll_insert_self_after(prev_range->doc_ctrl);
		
		new_range->splitter->Unsplit();
	}
	
	/* If this is the first Range using this Document, set up event bindings. */
	
	bool first_of_doc = (std::find_if(ranges.begin(), new_range, [&](const Range &range) { return range.doc == new_range->doc; }) == new_range);
	if(first_of_doc)
	{
		new_range->doc->Bind(DOCUMENT_TITLE_CHANGED, &REHex::DiffWindow::OnDocumentTitleChange, this);
		
		new_range->doc->Bind(DATA_ERASE,     &REHex::DiffWindow::OnDocumentDataErase,     this);
		new_range->doc->Bind(DATA_INSERT,    &REHex::DiffWindow::OnDocumentDataInsert,    this);
		new_range->doc->Bind(DATA_OVERWRITE, &REHex::DiffWindow::OnDocumentDataOverwrite, this);
		
		new_range->main_doc_ctrl->Bind(EV_DISP_SETTING_CHANGED, &REHex::DiffWindow::OnDocumentDisplaySettingsChange,  this);
	}
	
	resize_splitters();
	
	offsets_pending.clear_all();
	offsets_different.clear_all();
	
	if(ranges.size() > 1)
	{
		offsets_pending.set_range(0, longest_range);
	}
	
	for(auto r = ranges.begin(); r != ranges.end(); ++r)
	{
		doc_update(&(*r));
	}
	
	for(auto r = ranges.begin(); r != ranges.end(); ++r)
	{
		r->doc_ctrl->set_scroll_yoff(0);
	}
	
	return new_range;
}

std::list<REHex::DiffWindow::Range>::iterator REHex::DiffWindow::remove_range(std::list<Range>::iterator range, bool called_from_page_closed_handler)
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
	
	SharedDocumentPointer range_doc(range->doc);
	DocumentCtrl *range_mdc = range->main_doc_ctrl;

	if(!called_from_page_closed_handler)
	{
		/* There may still be a wxEVT_PAINT event pending on this range's DocumentCtrl,
		 * which would result in DiffDataRegion::highlight_at_off() being called with an
		 * invalid 'range' pointer after we erase it.
		 *
		 * We reinitialise the DocumentCtrl with a useless-but-valid DataRegion to work
		 * around this case. What gets drawn doesn't matter since the control will be
		 * destroyed when wxWidgets next runs idle events.
		*/

		std::vector<DocumentCtrl::Region*> regions;
		regions.push_back(new DocumentCtrl::DataRegion(range->doc, 0, 0, 0));

		range->doc_ctrl->replace_all_regions(regions);
	}

	ranges.erase(range);
	
	/* If this was the last Range using this Document, remove event bindings. */
	
	bool last_of_doc = (std::find_if(ranges.begin(), ranges.end(), [&](const Range &range) { return range.doc == range_doc; }) == ranges.end());
	if(last_of_doc)
	{
		if(range_mdc != NULL)
		{
			range_mdc->Unbind(EV_DISP_SETTING_CHANGED, &REHex::DiffWindow::OnDocumentDisplaySettingsChange,  this);
		}
		
		range_doc->Unbind(DATA_OVERWRITE, &REHex::DiffWindow::OnDocumentDataOverwrite, this);
		range_doc->Unbind(DATA_INSERT,    &REHex::DiffWindow::OnDocumentDataInsert,    this);
		range_doc->Unbind(DATA_ERASE,     &REHex::DiffWindow::OnDocumentDataErase,     this);
		
		range_doc->Unbind(DOCUMENT_TITLE_CHANGED, &REHex::DiffWindow::OnDocumentTitleChange, this);
	}
	
	if(ranges.size() == 1)
	{
		/* All but one tab has been closed, re-instate help text. */
		ranges.front().splitter->SplitVertically(ranges.front().notebook, ranges.front().help_panel);
	}
	
	resize_splitters();
	
	update_longest_range();
	
	offsets_pending.clear_all();
	offsets_different.clear_all();
	
	if(ranges.size() > 1)
	{
		offsets_pending.set_range(0, longest_range);
	}
	
	for(auto r = ranges.begin(); r != ranges.end(); ++r)
	{
		doc_update(&(*r));
	}
	
	for(auto r = ranges.begin(); r != ranges.end(); ++r)
	{
		r->doc_ctrl->set_scroll_yoff(0);
	}
	
	if(ranges.empty())
	{
		/* Last tab was closed. Destroy this DiffWindow. */
		Destroy();
	}
	
	return next;
}

void REHex::DiffWindow::set_folding(bool enable_folding)
{
	this->enable_folding = enable_folding;
	fold_button->Toggle(enable_folding);
}

void REHex::DiffWindow::doc_update(Range *range)
{
	std::vector<DocumentCtrl::Region*> regions;
	
	off_t CONTEXT_BYTES = 64;
	
	if(enable_folding)
	{
		off_t base = 0;
		bool has_data_region = false;
		
		while(base < range->length)
		{
			off_t end = range->length;
			
			auto pending_i   = offsets_pending.find_first_in(base, std::numeric_limits<off_t>::max());
			auto different_i = offsets_different.find_first_in(base, std::numeric_limits<off_t>::max());
			
			bool is_pending = false;
			bool is_different = false;
			
			if(pending_i != offsets_pending.end())
			{
				if(pending_i->offset <= base)
				{
					end = std::min(end, (pending_i->offset + pending_i->length));
					is_pending = true;
				}
				else{
					end = std::min(end, pending_i->offset);
				}
			}
			
			if(!is_pending && different_i != offsets_different.end())
			{
				if(different_i->offset <= (base + CONTEXT_BYTES))
				{
					end = std::min(end, (different_i->offset + different_i->length + CONTEXT_BYTES));
					is_different = true;
				}
				else{
					end = std::min(end, (different_i->offset - CONTEXT_BYTES));
				}
			}
			
			off_t length = end - base;
			
			if(is_pending)
			{
				regions.push_back(new MessageRegion(range->doc, (range->offset + base), "Processing..."));
			}
			else if(is_different)
			{
				regions.push_back(new DiffDataRegion((range->offset + base), length, this, range));
				has_data_region = true;
			}
			else{
				char text[64];
				snprintf(text, sizeof(text), "[ %jd identical bytes ]", (intmax_t)(length));
				
				regions.push_back(new MessageRegion(range->doc, (range->offset + base), text));
			}
			
			base += length;
			
		}
		
		if(!has_data_region)
		{
			/* DocumentCtrl always needs at least one data region, so if we aren't
			 * showing any data, we stick a zero-length, invisible region at the end
			 * to stop bad things from happening.
			*/
			
			regions.push_back(new InvisibleDataRegion(range->doc, (range->offset + range->length), 0));
		}
	}
	else{
		regions.push_back(new DiffDataRegion(range->offset, range->length, this, range));
	}
	
	range->doc_ctrl->replace_all_regions(regions);
}

std::string REHex::DiffWindow::range_title(Range *range)
{
	if(range->offset == 0)
	{
		return range->doc->get_title();
	}
	else{
		std::string offset_str = format_offset(range->offset, range->doc_ctrl->get_offset_display_base(), range->doc->buffer_length());
		return range->doc->get_title() + " @ " + offset_str;
	}
}

void REHex::DiffWindow::resize_splitters()
{
	wxSize window_size = GetClientSize();
	
	int pane_size = ranges.size() > 1
		? window_size.GetWidth() / ranges.size()
		: window_size.GetWidth() / 2;
	
	for(auto r = ranges.begin(); r != ranges.end(); ++r)
	{
		r->splitter->SetSashPosition(pane_size);
	}
	
	recalc_bytes_per_line_pending = true;
}

void REHex::DiffWindow::recalc_bytes_per_line()
{
	/* Calculate the number of bytes that can be displayed on a line in each DocumentCtrl and
	 * limit all DocumentCtrls to that value to ensure bytes line up. Each one should have the
	 * same width at this point, but check all to allow for rounding errors or weird UI crap.
	*/
	
	int bytes_per_line = -1;
	
	for(auto r = ranges.begin(); r != ranges.end(); ++r)
	{
		auto &dc_regions = r->doc_ctrl->get_regions();
		wxSize dc_client_size = r->doc_ctrl->GetClientSize();
		
		for(auto rr = dc_regions.begin(); rr != dc_regions.end(); ++rr)
		{
			const DocumentCtrl::DataRegion *ddr = dynamic_cast<const DocumentCtrl::DataRegion*>(*rr);
			if(ddr == NULL)
			{
				continue;
			}
			
			int ddr_max_bytes_per_line = 1;
			while(ddr->calc_width_for_bytes(*(r->doc_ctrl), (ddr_max_bytes_per_line + 1)) <= dc_client_size.GetWidth())
			{
				++ddr_max_bytes_per_line;
			}
			
			if(bytes_per_line < 0 || bytes_per_line > ddr_max_bytes_per_line)
			{
				bytes_per_line = ddr_max_bytes_per_line;
			}
		}
	}
	
	for(auto r = ranges.begin(); r != ranges.end(); ++r)
	{
		assert(bytes_per_line > 0);
		r->doc_ctrl->set_bytes_per_line(bytes_per_line);
	}
}

void REHex::DiffWindow::set_relative_cursor_pos(off_t relative_cursor_pos)
{
	assert(relative_cursor_pos >= 0);
	
	this->relative_cursor_pos = relative_cursor_pos;
	
	for(auto r = ranges.begin(); r != ranges.end(); ++r)
	{
		off_t abs_cursor_pos = r->offset + relative_cursor_pos;
		
		if(r->doc_ctrl->data_region_by_offset(abs_cursor_pos))
		{
			r->doc_ctrl->set_cursor_position(abs_cursor_pos);
		}
	}
}

off_t REHex::DiffWindow::process_now(off_t rel_offset, off_t length)
{
	try {
		std::vector<unsigned char> base_data;
		bool base_data_ready = false;
		
		for(auto r = ranges.begin(); r != ranges.end(); ++r)
		{
			if(r->length <= rel_offset)
			{
				length = offsets_pending.begin()->length;
				offsets_different.set_range(rel_offset, length);
				
				#ifdef DIFFWINDOW_PROFILING
				++odsr_calls;
				#endif
				
				break;
			}
			else if(r->length < (rel_offset + length))
			{
				length = r->length - rel_offset;
			}
			
			if(!base_data_ready)
			{
				base_data = r->doc->read_data(r->offset + rel_offset, length);
				assert((off_t)(base_data.size()) >= length);
				
				base_data_ready = true;
			}
			else{
				std::vector<unsigned char> r_data = r->doc->read_data(r->offset + rel_offset, length);
				assert((off_t)(r_data.size()) >= length);
				
				off_t diff_base = -1;
				off_t diff_end  = -1;
				
				for(off_t i = 0; i < length; ++i)
				{
					if(r_data[i] != base_data[i])
					{
						if(diff_end != i)
						{
							if(diff_end > diff_base)
							{
								offsets_different.set_range((rel_offset + diff_base), (diff_end - diff_base));
								
								#ifdef DIFFWINDOW_PROFILING
								++odsr_calls;
								#endif
							}
							
							diff_base = i;
							diff_end  = i + 1;
						}
						else{
							++diff_end;
						}
					}
				}
				
				if(diff_end > diff_base)
				{
					offsets_different.set_range((rel_offset + diff_base), (diff_end - diff_base));
					
					#ifdef DIFFWINDOW_PROFILING
					++odsr_calls;
					#endif
				}
			}
		}
	}
	catch(const std::exception &e)
	{
		wxGetApp().printf_error("Exception in REHex::DiffWindow::process_now: %s\n", e.what());
		return -1;
	}
	
	assert(length > 0);
	
	offsets_pending.clear_range(rel_offset, length);
	
	if(!update_regions_timer.IsRunning())
	{
		update_regions_timer.StartOnce(100);
	}
	
	return length;
}

void REHex::DiffWindow::update_longest_range()
{
	if(ranges.empty())
	{
		longest_range = 0;
		
		offsets_pending.clear_all();
		offsets_different.clear_all();
	}
	else{
		longest_range = std::max_element(ranges.begin(), ranges.end(),
			[](const Range &lhs, const Range &rhs) { return lhs.length < rhs.length; })->length;
		
		offsets_pending.clear_range(longest_range, std::numeric_limits<off_t>::max());
		offsets_different.clear_range(longest_range, std::numeric_limits<off_t>::max());
	}
}

void REHex::DiffWindow::goto_prev_difference()
{
	/* Find the first difference preceeding the cursor... */
	auto prev_diff = offsets_different.find_last_in(0, relative_cursor_pos);
	
	/* ...skip it if we're inside it... */
	if(prev_diff != offsets_different.end() && (prev_diff->offset + prev_diff->length) > relative_cursor_pos)
	{
		if(prev_diff != offsets_different.begin())
		{
			--prev_diff;
		}
		else{
			prev_diff = offsets_different.end();
		}
	}
	
	auto prev_to_process = offsets_pending.find_last_in(0, relative_cursor_pos);
	
	if(prev_diff != offsets_different.end() && (prev_to_process == offsets_pending.end() || prev_diff->offset > prev_to_process->offset))
	{
		/* ...and jump to it. */
		set_relative_cursor_pos(prev_diff->offset);
	}
	else{
		if(prev_to_process == offsets_pending.end())
		{
			/* No more differences. */
			wxBell();
		}
		else{
			assert(!searching_backwards);
			assert(!searching_forwards);
			
			wxProgressDialog pd("Searching", "Searching for differences...", 1000, this, wxPD_CAN_ABORT);
			search_modal = &pd;
			
			searching_backwards = true;
			search_modal->ShowModal();
			
			search_modal = NULL;
		}
	}
}

void REHex::DiffWindow::goto_next_difference()
{
	/* Find the first difference either encompassing or following the cursor... */
	auto next_diff = offsets_different.find_first_in(relative_cursor_pos, std::numeric_limits<off_t>::max());
	
	/* ...skip it if we're inside it... */
	if(next_diff != offsets_different.end() && next_diff->offset <= relative_cursor_pos)
	{
		++next_diff;
	}
	
	auto next_to_process = offsets_pending.find_first_in(relative_cursor_pos, std::numeric_limits<off_t>::max());
	
	if(next_diff != offsets_different.end() && (next_to_process == offsets_pending.end() || next_diff->offset < next_to_process->offset))
	{
		/* ...and jump to it. */
		set_relative_cursor_pos(next_diff->offset);
	}
	else{
		if(next_to_process == offsets_pending.end())
		{
			/* No more differences. */
			wxBell();
		}
		else{
			assert(!searching_backwards);
			assert(!searching_forwards);
			
			wxProgressDialog pd("Searching", "Searching for differences...", 1000, this, wxPD_CAN_ABORT);
			search_modal = &pd;
			
			searching_forwards = true;
			search_modal->ShowModal();
			
			search_modal = NULL;
		}
	}
}

void REHex::DiffWindow::OnSize(wxSizeEvent &event)
{
	resize_splitters();
	
	if(statbar != NULL && sb_gauge != NULL)
	{
		wxRect gauge_rect;
		statbar->GetFieldRect(1, gauge_rect);
		
		sb_gauge->SetSize(gauge_rect);
	}
	
	event.Skip();
}

void REHex::DiffWindow::OnIdle(wxIdleEvent &event)
{
	/* Close any tabs whose backing tab in MainWindow has been closed. */
	
	for(auto i = ranges.begin(); i != ranges.end();)
	{
		if((DocumentCtrl*)(i->main_doc_ctrl) == NULL)
		{
			i = remove_range(i, false);
		}
		else{
			++i;
		}
	}
	
	#ifdef DIFFWINDOW_PROFILING
	bool had_work = !offsets_pending.empty();
	
	struct timespec a;
	clock_gettime(CLOCK_MONOTONIC_RAW, &a);
	#endif
	
	size_t allowed_remaining = MAX_COMPARE_DATA;
	
	if(searching_backwards)
	{
		while(allowed_remaining > 0)
		{
			auto process_prev = offsets_pending.find_last_in(0, relative_cursor_pos);
			
			if(process_prev == offsets_pending.end())
			{
				searching_backwards = false;
				
				search_modal->EndModal(0);
				wxBell();
				
				break;
			}
			
			off_t process_end = std::min((process_prev->offset + process_prev->length), relative_cursor_pos);
			off_t process_begin = std::max(process_prev->offset, (process_end - (off_t)(allowed_remaining)));
			off_t process_length = process_end - process_begin;
			
			assert(process_length > 0);
			
			off_t processed = process_now(process_begin, process_length);
			if(processed < 0)
			{
				break;
			}
			
			auto last_diff_found = offsets_different.find_last_in(process_begin, processed);
			if(last_diff_found != offsets_different.end())
			{
				set_relative_cursor_pos(last_diff_found->offset);
				
				searching_backwards = false;
				search_modal->EndModal(0);
				
				break;
			}
			
			allowed_remaining -= processed;
		}
		
		if(!search_modal_updating)
		{
			search_modal_updating = true;
			
			ByteRangeSet backward_offsets;
			backward_offsets.set_range(0, relative_cursor_pos);
			
			ByteRangeSet pending_backward = ByteRangeSet::intersection(backward_offsets, offsets_pending);
			
			int sm_range = search_modal->GetRange();
			
			int sm_value = (double)(sm_range) - (((double)(pending_backward.total_bytes()) / (double)(backward_offsets.total_bytes())) * (double)(sm_range));
			sm_value = std::max(sm_value, 0);
			sm_value = std::min(sm_value, sm_range);
			
			search_modal->Update(sm_value);
			
			search_modal_updating = false;
		}
		
		if(searching_backwards && search_modal->WasCancelled())
		{
			searching_backwards = false;
			search_modal->EndModal(0);
		}
	}
	else if(searching_forwards)
	{
		while(allowed_remaining > 0)
		{
			auto process_next = offsets_pending.find_first_in(relative_cursor_pos, std::numeric_limits<off_t>::max());
			
			if(process_next == offsets_pending.end())
			{
				searching_forwards = false;
				
				search_modal->EndModal(0);
				wxBell();
				
				break;
			}
			
			off_t rel_offset = std::max(relative_cursor_pos, process_next->offset);
			off_t remain_in_pn = process_next->length - (relative_cursor_pos - process_next->offset);
			off_t length = std::min<off_t>(allowed_remaining, remain_in_pn);
			
			assert(length > 0);
			
			off_t processed = process_now(rel_offset, length);
			if(processed < 0)
			{
				break;
			}
			
			auto first_diff_found = offsets_different.find_first_in(rel_offset, processed);
			if(first_diff_found != offsets_different.end())
			{
				set_relative_cursor_pos(first_diff_found->offset);
				
				searching_forwards = false;
				search_modal->EndModal(0);
				
				break;
			}
			
			allowed_remaining -= processed;
		}
		
		if(!search_modal_updating)
		{
			search_modal_updating = true;
			
			ByteRangeSet forward_offsets;
			forward_offsets.set_range(relative_cursor_pos, longest_range);
			
			ByteRangeSet pending_forward = ByteRangeSet::intersection(forward_offsets, offsets_pending);
			
			int sm_range = search_modal->GetRange();
			
			int sm_value = (double)(sm_range) - (((double)(pending_forward.total_bytes()) / (double)(forward_offsets.total_bytes())) * (double)(sm_range));
			sm_value = std::max(sm_value, 0);
			sm_value = std::min(sm_value, sm_range);
			
			search_modal->Update(sm_value);
			
			search_modal_updating = false;
		}
		
		if(searching_forwards && search_modal->WasCancelled())
		{
			searching_forwards = false;
			search_modal->EndModal(0);
		}
	}
	else{
		while(!offsets_pending.empty() && allowed_remaining > 0)
		{
			off_t rel_offset = offsets_pending.begin()->offset;
			off_t length = std::min<off_t>(offsets_pending.begin()->length, allowed_remaining);
			
			assert(length > 0);
			
			off_t processed = process_now(rel_offset, length);
			if(processed < 0)
			{
				break;
			}
			
			allowed_remaining -= processed;
		}
	}
	
	#ifdef DIFFWINDOW_PROFILING
	if(had_work)
	{
		struct timespec b;
		clock_gettime(CLOCK_MONOTONIC_RAW, &b);
		
		idle_ticks += 1;
		idle_secs  += timespec_to_double(timespec_sub(b, a));
		idle_bytes += MAX_COMPARE_DATA - allowed_remaining;
		
		if(offsets_pending.empty())
		{
			wxGetApp().printf_debug("Processed %jd bytes in %f seconds over %u idle ticks (%fus avg) (%u offsets_different insertions)\n",
				(intmax_t)(idle_bytes), idle_secs, idle_ticks, ((idle_secs / (double)(idle_ticks)) * 1000000), odsr_calls);
			
			idle_ticks = 0;
			idle_secs  = 0;
			idle_bytes = 0;
			odsr_calls = 0;
		}
	}
	#endif
	
	if(!offsets_pending.empty())
	{
		SetStatusText("Processing...");
		
		off_t remaining_bytes = offsets_pending.total_bytes();
		
		int processed_percent = 100.0 - (((double)(remaining_bytes) / (double)(longest_range)) * 100.0);
		processed_percent = std::max(processed_percent, 0);
		processed_percent = std::min(processed_percent, 100);
		
		sb_gauge->Show();
		sb_gauge->SetValue(processed_percent);
		
		event.RequestMore();
	}
	else{
		SetStatusText("");
		sb_gauge->Hide();
	}
	
	if(recalc_bytes_per_line_pending)
	{
		recalc_bytes_per_line_pending = false;
		recalc_bytes_per_line();
	}
}

void REHex::DiffWindow::OnCharHook(wxKeyEvent &event)
{
	if(event.GetModifiers() == wxMOD_CMD && event.GetKeyCode() == 'C')
	{
		wxWindow *focus_window = wxWindow::FindFocus();
		
		for(auto r = ranges.begin(); r != ranges.end(); ++r)
		{
			if(r->doc_ctrl == focus_window)
			{
				copy_from_doc(r->doc, r->doc_ctrl, this, false);
				break;
			}
		}
	}
	else if(event.GetModifiers() == wxMOD_NONE && event.GetKeyCode() == WXK_F6)
	{
		goto_next_difference();
	}
	else if(event.GetModifiers() == wxMOD_SHIFT && event.GetKeyCode() == WXK_F6)
	{
		goto_prev_difference();
	}
	else{
		event.Skip();
	}
}

void REHex::DiffWindow::OnDocumentTitleChange(DocumentTitleEvent &event)
{
	wxObject *src = event.GetEventObject();
	
	for(auto r = ranges.begin(); r != ranges.end(); ++r)
	{
		if(r->doc == src)
		{
			r->notebook->SetPageText(0, range_title(&*r));
		}
	}
	
	event.Skip();
}

void REHex::DiffWindow::OnDocumentDataErase(OffsetLengthEvent &event)
{
	wxObject *src = event.GetEventObject();
	assert(dynamic_cast<Document*>(src) != NULL);
	
	for(auto r = ranges.begin(); r != ranges.end();)
	{
		if(r->doc == src)
		{
			if(event.offset < r->offset)
			{
				off_t shift  = std::min(event.length, (r->offset - event.offset));
				off_t shrink = std::min((event.length - shift), r->length);
				
				if(shrink > 0)
				{
					offsets_pending.set_range(0, longest_range);
					offsets_different.clear_all();
				}
				
				r->offset -= shift;
				assert(r->offset >= 0);
				
				r->length -= shrink;
				assert(r->length >= 0);
				
				update_longest_range();
				
				if(r->length == 0)
				{
					r = remove_range(r, false);
					continue;
				}
				else{
					doc_update(&*r);
				}
			}
			else if(event.offset < (r->offset + r->length))
			{
				off_t shrink = std::min(event.length, (r->length - (event.offset - r->offset)));
				
				if(shrink > 0)
				{
					offsets_pending.set_range(0, longest_range);
					offsets_different.clear_all();
				}
				
				r->length -= shrink;
				assert(r->length >= 0);
				
				update_longest_range();
				
				if(r->length == 0)
				{
					r = remove_range(r, false);
					continue;
				}
				else{
					doc_update(&*r);
				}
			}
			
			off_t cursor_pos = r->doc_ctrl->get_cursor_position().byte(); /* BITFIXUP */
			if(event.offset <= cursor_pos)
			{
				cursor_pos -= std::min(event.length, (cursor_pos - event.offset));
				
				if(cursor_pos >= (r->offset + r->length))
				{
					/* Move the cursor back if the end of the region is deleted under it. */
					cursor_pos = r->offset + r->length - 1;
				}
				
				assert(cursor_pos >= r->offset);
				assert(cursor_pos < (r->offset + r->length));
				
				r->doc_ctrl->set_cursor_position(cursor_pos);
			}
			
			if(r->doc_ctrl->has_selection())
			{
				BitOffset selection_first, selection_last;
				std::tie(selection_first, selection_last) = r->doc_ctrl->get_selection_raw();
				
				if((event.offset < selection_first.byte() && (event.offset + event.length) > selection_first.byte())
					|| (event.offset >= selection_first.byte() && event.offset <= selection_last.byte()))
				{
					r->doc_ctrl->clear_selection();
				}
				else if(event.offset < selection_first.byte())
				{
					selection_first -= BitOffset::BYTES(event.length);
					selection_last  -= BitOffset::BYTES(event.length);
					
					assert(selection_first.byte() >= r->offset);
					assert(selection_last.byte() < (r->offset + r->length));
					
					r->doc_ctrl->set_selection_raw(selection_first, selection_last);
				}
			}
		}
		
		++r;
	}
	
	event.Skip();
}

void REHex::DiffWindow::OnDocumentDataInsert(OffsetLengthEvent &event)
{
	wxObject *src = event.GetEventObject();
	assert(dynamic_cast<Document*>(src) != NULL);
	
	for(auto r = ranges.begin(); r != ranges.end(); ++r)
	{
		if(r->doc == src)
		{
			if(event.offset <= r->offset)
			{
				r->offset += event.length;
				doc_update(&*r);
			}
			else if(event.offset < (r->offset + r->length))
			{
				r->length += event.length;
				
				update_longest_range();
				doc_update(&*r);
				
				offsets_pending.set_range(0, longest_range);
				offsets_different.clear_all();
			}
			
			off_t cursor_pos = r->doc_ctrl->get_cursor_position().byte(); /* BITFIXUP */
			if(event.offset <= cursor_pos)
			{
				cursor_pos += event.length;
				
				assert(cursor_pos >= r->offset);
				assert(cursor_pos < (r->offset + r->length));
				
				r->doc_ctrl->set_cursor_position(cursor_pos);
			}
			
			if(r->doc_ctrl->has_selection())
			{
				BitOffset selection_first, selection_last;
				std::tie(selection_first, selection_last) = r->doc_ctrl->get_selection_raw();
				
				if(event.offset <= selection_first.byte())
				{
					selection_first += BitOffset::BYTES(event.length);
					selection_last  += BitOffset::BYTES(event.length);
					
					assert(selection_first.byte() >= r->offset);
					assert(selection_last.byte() < (r->offset + r->length));
					
					r->doc_ctrl->set_selection_raw(selection_first, selection_last);
				}
				else if(event.offset <= selection_last.byte())
				{
					r->doc_ctrl->clear_selection();
				}
			}
		}
	}
	
	event.Skip();
}

void REHex::DiffWindow::OnDocumentDataOverwrite(OffsetLengthEvent &event)
{
	wxObject *src = event.GetEventObject();
	assert(dynamic_cast<Document*>(src) != NULL);
	
	for(auto r = ranges.begin(); r != ranges.end(); ++r)
	{
		if(r->doc == src)
		{
			BitRangeSet selection = r->doc_ctrl->get_selection_ranges();
			
			if(selection.isset_any(BitOffset(event.offset, 0), BitOffset(event.length, 0)))
			{
				r->doc_ctrl->clear_selection();
			}
			
			off_t overlap_base = std::max(event.offset, r->offset);
			off_t overlap_end = std::min((event.offset + event.length), (r->offset + r->length));
			
			if(overlap_end > overlap_base)
			{
				offsets_pending.set_range((overlap_base - r->offset), (overlap_end - overlap_base));
				offsets_different.clear_range((overlap_base - r->offset), (overlap_end - overlap_base));
			}
			
			r->doc_ctrl->Refresh();
		}
	}
	
	event.Skip();
}

void REHex::DiffWindow::OnDocumentDisplaySettingsChange(wxCommandEvent &event)
{
	wxObject *src = event.GetEventObject();
	
	for(auto r = ranges.begin(); r != ranges.end(); ++r)
	{
		if(r->main_doc_ctrl == src)
		{
			r->doc_ctrl->set_offset_display_base(r->main_doc_ctrl->get_offset_display_base());
			r->doc_ctrl->set_bytes_per_group(r->main_doc_ctrl->get_bytes_per_group());
			r->notebook->SetPageText(0, range_title(&*r));
		}
	}
	
	/* Changing offset base or byte grouping may change how many bytes can fit on one line
	 * without scrolling.
	*/
	resize_splitters();
	
	event.Skip();
}

void REHex::DiffWindow::OnNotebookClosed(wxAuiNotebookEvent &event)
{
	auto nb_range = std::find_if(ranges.begin(), ranges.end(), [event](const Range &range) { return range.notebook == event.GetEventObject(); });
	assert(nb_range != ranges.end());
	
	remove_range(nb_range, true);
}

void REHex::DiffWindow::OnCursorUpdate(CursorUpdateEvent &event)
{
	/* Find the Range whose DocumentCtrl raised this event. */
	
	auto source_range = std::find_if(ranges.begin(), ranges.end(), [&](const Range &r) { return r.doc_ctrl == event.GetEventObject(); });
	assert(source_range != ranges.end());
	
	relative_cursor_pos = event.cursor_pos.byte() - source_range->offset; /* BITFIXUP */
	// assert(relative_cursor_pos >= 0);
	
	/* Update the cursors in every other tab to match. */
	
	for(auto r = ranges.begin(); r != ranges.end(); ++r)
	{
		off_t abs_cursor_pos = r->offset + relative_cursor_pos;
		
		if(r != source_range && r->doc_ctrl->data_region_by_offset(abs_cursor_pos) != NULL)
		{
			r->doc_ctrl->set_cursor_position(abs_cursor_pos, event.cursor_state);
		}
	}
}

void REHex::DiffWindow::OnDataRightClick(wxCommandEvent &event)
{
	/* Find the Range whose DocumentCtrl raised this event. */
	
	auto source_range = std::find_if(ranges.begin(), ranges.end(), [&](const Range &r) { return r.doc_ctrl == event.GetEventObject(); });
	assert(source_range != ranges.end());
	
	off_t cursor_pos = source_range->doc_ctrl->get_cursor_position().byte(); /* BITFIXUP */
	bool has_selection = source_range->doc_ctrl->has_selection();
	
	wxMenu menu;
	
	menu.Append(wxID_COPY, "&Copy");
	menu.Enable(wxID_COPY, has_selection);
	menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
	{
		copy_from_doc(source_range->doc, source_range->doc_ctrl, this, false);
	}, wxID_COPY, wxID_COPY);
	
	menu.AppendSeparator();
	
	wxMenuItem *offset_copy_hex = menu.Append(wxID_ANY, "Copy offset (in hexadecimal)");
	menu.Bind(wxEVT_MENU, [cursor_pos](wxCommandEvent &event)
	{
		ClipboardGuard cg;
		if(cg)
		{
			char offset_str[24];
			snprintf(offset_str, sizeof(offset_str), "0x%llX", (long long unsigned)(cursor_pos));
			
			wxTheClipboard->SetData(new wxTextDataObject(offset_str));
		}
	}, offset_copy_hex->GetId(), offset_copy_hex->GetId());
	
	wxMenuItem *offset_copy_dec = menu.Append(wxID_ANY, "Copy offset (in decimal)");
	menu.Bind(wxEVT_MENU, [cursor_pos](wxCommandEvent &event)
	{
		ClipboardGuard cg;
		if(cg)
		{
			char offset_str[24];
			snprintf(offset_str, sizeof(offset_str), "%llu", (long long unsigned)(cursor_pos));
			
			wxTheClipboard->SetData(new wxTextDataObject(offset_str));
		}
	}, offset_copy_dec->GetId(), offset_copy_dec->GetId());
	
	menu.AppendSeparator();
	
	wxMenuItem *offset_goto = menu.Append(wxID_ANY, "Jump to offset in main window");
	menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
	{
		/* Find MainWindow containing the document. */
		MainWindow *window = NULL;
		for(wxWindow *parent = source_range->main_doc_ctrl->GetParent();
			(window = dynamic_cast<MainWindow*>(parent)) == NULL;
			parent = parent->GetParent()) {}
		
		assert(window != NULL);
		
		if(source_range->main_doc_ctrl->data_region_by_offset(cursor_pos))
		{
			window->switch_tab(source_range->main_doc_ctrl);
			
			source_range->doc->set_cursor_position(cursor_pos);
			source_range->main_doc_ctrl->SetFocus();
			
			/* Wait until the menu is gone before bringing the MainWindow to the top
			 * or else we fight with it for focus.
			*/
			
			SafeWindowPointer<MainWindow> w(window);
			CallAfter([w]()
			{
				if(w)
				{
					w->Show();
					w->Raise();
				}
			});
		}
		else{
			/* Offset isn't currently available in main DocumentCtrl. */
			wxBell();
		}
	}, offset_goto->GetId(), offset_goto->GetId());
	
	PopupMenu(&menu);
}

void REHex::DiffWindow::OnToggleOffsets(wxCommandEvent &event)
{
	for(auto r = ranges.begin(); r != ranges.end(); ++r)
	{
		r->doc_ctrl->set_show_offsets(event.IsChecked());
	}
	
	resize_splitters();
}

void REHex::DiffWindow::OnToggleASCII(wxCommandEvent &event)
{
	for(auto r = ranges.begin(); r != ranges.end(); ++r)
	{
		r->doc_ctrl->set_show_ascii(event.IsChecked());
	}
	
	resize_splitters();
}

void REHex::DiffWindow::OnToggleFold(wxCommandEvent &event)
{
	enable_folding = event.IsChecked();
	
	for(auto r = ranges.begin(); r != ranges.end(); ++r)
	{
		doc_update(&(*r));
	}
	
	for(auto r = ranges.begin(); r != ranges.end(); ++r)
	{
		r->doc_ctrl->set_scroll_yoff(0);
	}
}

void REHex::DiffWindow::OnPrevDifference(wxCommandEvent &event)
{
	goto_prev_difference();
}

void REHex::DiffWindow::OnNextDifference(wxCommandEvent &event)
{
	goto_next_difference();
}

void REHex::DiffWindow::OnUpdateRegionsTimer(wxTimerEvent &event)
{
	std::list<int64_t> restore_scroll_ypos;
	
	for(auto r = ranges.begin(); r != ranges.end(); ++r)
	{
		restore_scroll_ypos.push_back(r->doc_ctrl->get_scroll_yoff());
	}
	
	for(auto r = ranges.begin(); r != ranges.end(); ++r)
	{
		doc_update(&(*r));
	}
	
	for(auto r = ranges.begin(); r != ranges.end(); ++r)
	{
		r->doc_ctrl->set_scroll_yoff(restore_scroll_ypos.front(), false);
		restore_scroll_ypos.pop_front();
	}
}

void REHex::DiffWindow::OnInvisibleOwnerWindowShow(wxShowEvent &event)
{
	if(event.IsShown())
	{
		invisible_owner_window.reset(NULL);
	}
	
	event.Skip();
}

void REHex::DiffWindow::OnWindowClose(wxCloseEvent &event)
{
	if(invisible_owner_window != NULL)
	{
		invisible_owner_window->Destroy();
	}
	
	/* Base implementation will deal with cleaning up the window. */
	event.Skip();
}

REHex::DiffWindow::DiffDataRegion::DiffDataRegion(off_t d_offset, off_t d_length, DiffWindow *diff_window, Range *range):
	DataRegion(range->doc, d_offset, d_length, d_offset), diff_window(diff_window), range(range) {}

int REHex::DiffWindow::DiffDataRegion::calc_width(REHex::DocumentCtrl &doc)
{
	int width = REHex::DocumentCtrl::DataRegion::calc_width(doc);
	
	/* Override padding set by base class. */
	first_line_pad_bytes = 0;
	
	return width;
}

REHex::DocumentCtrl::DataRegion::Highlight REHex::DiffWindow::DiffDataRegion::highlight_at_off(BitOffset off) const
{
	assert(off.byte_aligned());
	
	assert(off >= range->offset);
	off_t relative_off = off.byte() - range->offset;
	
	if(diff_window->offsets_pending.isset(off.byte()))
	{
		diff_window->process_now(off.byte(), 2048 /* Probably enough to process screen in one go. */);
	}
	
	if(diff_window->offsets_different.isset(relative_off))
	{
		return Highlight(
			(*active_palette)[Palette::PAL_DIRTY_TEXT_FG],
			(*active_palette)[Palette::PAL_DIRTY_TEXT_BG]);
	}
	else{
		return NoHighlight();
	}
}

REHex::DiffWindow::MessageRegion::MessageRegion(Document *document, off_t data_offset, const std::string &message):
	Region(data_offset, 0),
	document(document),
	data_offset(data_offset),
	message(message) {}

std::pair<REHex::BitOffset, REHex::BitOffset> REHex::DiffWindow::MessageRegion::indent_offset_at_y(DocumentCtrl &doc_ctrl, int64_t y_lines_rel)
{
	return std::make_pair(indent_offset, indent_offset);
}

int REHex::DiffWindow::MessageRegion::calc_width(REHex::DocumentCtrl &doc_ctrl)
{
	const FontCharacterCache &fcc = doc_ctrl.get_fcc();
	
	int offset_column_width = doc_ctrl.get_show_offsets()
		? doc_ctrl.get_offset_column_width()
		: 0;
	
	int message_width = fcc.fixed_string_width(message.length());
	
	return offset_column_width + message_width;
}

void REHex::DiffWindow::MessageRegion::calc_height(DocumentCtrl &doc_ctrl)
{
	y_lines = 2;
}

void REHex::DiffWindow::MessageRegion::draw(DocumentCtrl &doc_ctrl, wxDC &dc, int x, int64_t y)
{
	const FontCharacterCache &fcc = doc_ctrl.get_fcc();
	
	dc.SetFont(doc_ctrl.get_font());
	
	dc.SetTextBackground((*active_palette)[Palette::PAL_NORMAL_TEXT_BG]);
	dc.SetTextForeground((*active_palette)[Palette::PAL_NORMAL_TEXT_FG]);
	dc.SetPen(wxPen((*active_palette)[Palette::PAL_NORMAL_TEXT_FG]));
	
	bool show_offset = doc_ctrl.get_show_offsets();
	int offset_column_width = doc_ctrl.get_offset_column_width();
	
	int virtual_width = doc_ctrl.get_virtual_width();
	int text_width    = fcc.fixed_string_width(message.length());
	int text_height   = fcc.fixed_char_height();
	int char_width    = fcc.fixed_char_width();
	
	int text_x = offset_column_width + ((virtual_width - offset_column_width) / 2) - (text_width / 2);
	
	dc.DrawLine(0, y,                         virtual_width, y);
	dc.DrawLine(0, y + (text_height * 2) - 1, virtual_width, y + (text_height * 2) - 1);
	
	if(show_offset)
	{
		/* Draw the offsets to the left */
		
		std::string offset_str = format_offset(data_offset, doc_ctrl.get_offset_display_base(), document->buffer_length());
		dc.DrawText(offset_str.c_str(), x, y + (text_height / 2));
		
		int offset_vl_x = (x + offset_column_width) - (char_width / 2);
		dc.DrawLine(offset_vl_x, y, offset_vl_x, y + (2 * text_height));
	}
	
	dc.DrawText(message, x + text_x, y + (text_height / 2));
}

REHex::DiffWindow::InvisibleDataRegion::InvisibleDataRegion(SharedDocumentPointer &document, off_t d_offset, off_t d_length):
	DataRegion(document, d_offset, d_length, d_offset) {}

void REHex::DiffWindow::InvisibleDataRegion::draw(REHex::DocumentCtrl &doc_ctrl, wxDC &dc, int x, int64_t y) {}
