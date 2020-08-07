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

#include "platform.hpp"
#include <algorithm>
#include <set>
#include <stdio.h>
#include <tuple>
#include <wx/artprov.h>
#include <wx/clipbrd.h>
#include <wx/sizer.h>
#include <wx/stattext.h>

#include "ArtProvider.hpp"
#include "DiffWindow.hpp"
#include "Palette.hpp"
#include "util.hpp"

#include "../res/icon16.h"
#include "../res/icon32.h"
#include "../res/icon48.h"
#include "../res/icon64.h"

enum {
	ID_SHOW_OFFSETS = 1,
	ID_SHOW_ASCII,
};

BEGIN_EVENT_TABLE(REHex::DiffWindow, wxFrame)
	EVT_SIZE(REHex::DiffWindow::OnSize)
	EVT_IDLE(REHex::DiffWindow::OnIdle)
	EVT_CHAR_HOOK(REHex::DiffWindow::OnCharHook)
	
	EVT_AUINOTEBOOK_PAGE_CLOSED(wxID_ANY, REHex::DiffWindow::OnNotebookClosed)
	
	EVT_CURSORUPDATE(wxID_ANY, REHex::DiffWindow::OnCursorUpdate)
	
	EVT_COMMAND(wxID_ANY, REHex::DATA_RIGHT_CLICK, REHex::DiffWindow::OnDataRightClick)
	
	EVT_MENU(ID_SHOW_OFFSETS, REHex::DiffWindow::OnToggleOffsets)
	EVT_MENU(ID_SHOW_ASCII,   REHex::DiffWindow::OnToggleASCII)
END_EVENT_TABLE()

REHex::DiffWindow::DiffWindow(wxWindow *parent):
	wxFrame(parent, wxID_ANY, "Show differences - Reverse Engineers' Hex Editor", wxDefaultPosition, wxSize(740, 540))
{
	wxToolBar *toolbar = CreateToolBar();
	
	show_offsets_button = toolbar->AddCheckTool(ID_SHOW_OFFSETS, "Show offsets", wxArtProvider::GetBitmap(ART_OFFSETS_ICON, wxART_TOOLBAR), wxNullBitmap, "Show offsets");
	show_ascii_button   = toolbar->AddCheckTool(ID_SHOW_ASCII,   "Show ASCII",   wxArtProvider::GetBitmap(ART_ASCII_ICON,   wxART_TOOLBAR), wxNullBitmap, "Show ASCII");
	
	/* Enable offset and ASCII columns by default. */
	show_offsets_button->Toggle(true);
	show_ascii_button  ->Toggle(true);
	
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
}

const std::list<REHex::DiffWindow::Range> &REHex::DiffWindow::get_ranges() const
{
	return ranges;
}

std::list<REHex::DiffWindow::Range>::iterator REHex::DiffWindow::add_range(const Range &range)
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
	
	{
		new_range->help_panel = new wxPanel(new_range->splitter);
		wxBoxSizer *v_sizer = new wxBoxSizer(wxVERTICAL);
		
		wxBoxSizer *h_sizer = new wxBoxSizer(wxHORIZONTAL);
		v_sizer->Add(h_sizer, 1, wxALIGN_CENTER_HORIZONTAL);
		
		static const char *HELP_TEXT =
			"Make another selection and choose \"Compare...\"\n"
			"to compare this against another sequence of bytes";
		
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

		std::list<DocumentCtrl::Region*> regions;
		regions.push_back(new DocumentCtrl::DataRegion(0, 0));

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
	
	if(ranges.empty())
	{
		/* Last tab was closed. Destroy this DiffWindow. */
		Destroy();
	}
	
	return next;
}

void REHex::DiffWindow::doc_update(Range *range)
{
	std::list<DocumentCtrl::Region*> regions;
	regions.push_back(new DiffDataRegion(range->offset, range->length, this, range));
	
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
			const DiffDataRegion *ddr = dynamic_cast<const DiffDataRegion*>(*rr);
			assert(ddr != NULL);
			
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

void REHex::DiffWindow::OnSize(wxSizeEvent &event)
{
	resize_splitters();
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
				
				r->offset -= shift;
				assert(r->offset >= 0);
				
				r->length -= shrink;
				assert(r->length >= 0);
				
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
				
				r->length -= shrink;
				assert(r->length >= 0);
				
				if(r->length == 0)
				{
					r = remove_range(r, false);
					continue;
				}
				else{
					doc_update(&*r);
				}
			}
			
			off_t cursor_pos = r->doc_ctrl->get_cursor_position();
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
			
			off_t selection_off, selection_length;
			std::tie(selection_off, selection_length) = r->doc_ctrl->get_selection();
			
			if(selection_length > 0)
			{
				if((event.offset < selection_off && (event.offset + event.length) > selection_off)
					|| (event.offset >= selection_off && event.offset < (selection_off + selection_length)))
				{
					r->doc_ctrl->clear_selection();
				}
				else if(event.offset < selection_off)
				{
					selection_off -= event.length;
					
					assert(selection_off >= r->offset);
					assert((selection_off + selection_length) <= (r->offset + r->length));
					
					r->doc_ctrl->set_selection(selection_off, selection_length);
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
				doc_update(&*r);
			}
			
			off_t cursor_pos = r->doc_ctrl->get_cursor_position();
			if(event.offset <= cursor_pos)
			{
				cursor_pos += event.length;
				
				assert(cursor_pos >= r->offset);
				assert(cursor_pos < (r->offset + r->length));
				
				r->doc_ctrl->set_cursor_position(cursor_pos);
			}
			
			off_t selection_off, selection_length;
			std::tie(selection_off, selection_length) = r->doc_ctrl->get_selection();
			if(selection_length > 0)
			{
				if(event.offset <= selection_off)
				{
					selection_off += event.length;
					
					assert(selection_off >= r->offset);
					assert((selection_off + selection_length) <= (r->offset + r->length));
					
					r->doc_ctrl->set_selection(selection_off, selection_length);
				}
				else if(event.offset < (selection_off + selection_length))
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
			off_t selection_off, selection_length;
			std::tie(selection_off, selection_length) = r->doc_ctrl->get_selection();
			
			if(selection_length > 0 && (
				(event.offset < selection_off && (event.offset + event.length) > selection_off)
				|| (event.offset >= selection_off && event.offset < (selection_off + selection_length))))
			{
				r->doc_ctrl->clear_selection();
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
	
	off_t pos_from_source_range = event.cursor_pos - source_range->offset;
	
	/* Update the cursors in every other tab to match. */
	
	for(auto r = ranges.begin(); r != ranges.end(); ++r)
	{
		if(r != source_range)
		{
			off_t pos_from_r = r->offset + std::min(pos_from_source_range, (r->length - 1));
			r->doc_ctrl->set_cursor_position(pos_from_r, event.cursor_state);
		}
	}
}

void REHex::DiffWindow::OnDataRightClick(wxCommandEvent &event)
{
	/* Find the Range whose DocumentCtrl raised this event. */
	
	auto source_range = std::find_if(ranges.begin(), ranges.end(), [&](const Range &r) { return r.doc_ctrl == event.GetEventObject(); });
	assert(source_range != ranges.end());
	
	off_t cursor_pos = source_range->doc_ctrl->get_cursor_position();
	
	off_t selection_off, selection_length;
	std::tie(selection_off, selection_length) = source_range->doc_ctrl->get_selection();
	
	wxMenu menu;
	
	menu.Append(wxID_COPY, "&Copy");
	menu.Enable(wxID_COPY, (selection_length > 0));
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

REHex::DiffWindow::DiffDataRegion::DiffDataRegion(off_t d_offset, off_t d_length, DiffWindow *diff_window, Range *range):
	DataRegion(d_offset, d_length), diff_window(diff_window), range(range) {}

REHex::DocumentCtrl::DataRegion::Highlight REHex::DiffWindow::DiffDataRegion::highlight_at_off(off_t off) const
{
	try {
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
	catch(const std::exception &e)
	{
		/* Highlight byte if an exception was thrown - most likely a file I/O error. */
		
		fprintf(stderr, "Exception in REHex::DiffWindow::DiffDataRegion::highlight_at_off: %s\n", e.what());
		
		return Highlight(
			Palette::PAL_DIRTY_TEXT_FG,
			Palette::PAL_DIRTY_TEXT_BG,
			true);
	}
}
