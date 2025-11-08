/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <exception>
#include <inttypes.h>
#include <stack>
#include <tuple>
#include <vector>
#include <wx/artprov.h>
#include <wx/clipbrd.h>
#include <wx/dataobj.h>
#include <wx/sizer.h>

#include "App.hpp"
#include "BitArray.hpp"
#include "DataMapScrollbar.hpp"
#include "DataType.hpp"
#include "DiffWindow.hpp"
#include "CharacterEncoder.hpp"
#include "CustomMessageDialog.hpp"
#include "EditCommentDialog.hpp"
#include "profile.hpp"
#include "SettingsDialogHighlights.hpp"
#include "Tab.hpp"
#include "VirtualMappingDialog.hpp"

/* Is the given value a 7-bit ASCII character representing a hex digit? */
static bool isasciihex(int c)
{
	return (c >= '0' && c <= '9')
		|| (c >= 'A' && c <= 'F')
		|| (c >= 'a' && c <= 'f');
}

enum {
	ID_HTOOLS = 1,
	ID_VTOOLS,
	ID_HSPLITTER,
	ID_VSPLITTER,
};

wxDEFINE_EVENT(REHex::LAST_GOTO_OFFSET_CHANGED, wxCommandEvent);

BEGIN_EVENT_TABLE(REHex::Tab, wxPanel)
	EVT_BITRANGE(wxID_ANY, REHex::COMMENT_LEFT_CLICK,  REHex::Tab::OnCommentLeftClick)
	EVT_BITRANGE(wxID_ANY, REHex::COMMENT_RIGHT_CLICK, REHex::Tab::OnCommentRightClick)
	
	EVT_COMMAND(wxID_ANY, REHex::DATA_RIGHT_CLICK, REHex::Tab::OnDataRightClick)
END_EVENT_TABLE()

REHex::Tab::Tab(wxWindow *parent):
	wxPanel(parent),
	doc(SharedDocumentPointer::make()),
	inline_comment_mode(ICM_FULL_INDENT),
	document_display_mode(DDM_NORMAL),
	doc_properties(NULL),
	goto_offset_dialog(NULL),
	last_goto_offset(BitOffset::MIN),
	last_goto_offset_relative(false),
	data_map_scrollbar_type(DataMapScrollbarType::NONE),
	data_map_scrollbar(NULL),
	repopulate_regions_frozen(false),
	repopulate_regions_pending(false),
	child_windows_hidden(false),
	parent_window_active(true),
	file_deleted_dialog_pending(false),
	file_modified_dialog_pending(false),
	auto_reload(false)
{
	tool_dock = new ToolDock(this);
	
	doc_ctrl_panel = new wxPanel(tool_dock);
	tool_dock->AddMainPanel(doc_ctrl_panel);
	
	doc_ctrl = new REHex::DocumentCtrl(doc_ctrl_panel, doc);
	
	data_map_scrollbar_sizer = new wxBoxSizer(wxHORIZONTAL);
	data_map_scrollbar_sizer->Add(doc_ctrl, 1, wxEXPAND);
	doc_ctrl_panel->SetSizerAndFit(data_map_scrollbar_sizer);
	
	doc.auto_cleanup_bind(DATA_ERASE,     &REHex::Tab::OnDocumentDataErase,     this);
	doc.auto_cleanup_bind(DATA_INSERT,    &REHex::Tab::OnDocumentDataInsert,    this);
	doc.auto_cleanup_bind(DATA_OVERWRITE, &REHex::Tab::OnDocumentDataOverwrite, this);
	
	doc.auto_cleanup_bind(CURSOR_UPDATE,          &REHex::Tab::OnDocumentCursorUpdate,      this);
	doc_ctrl->Bind(       CURSOR_UPDATE,          &REHex::Tab::OnDocumentCtrlCursorUpdate,  this);
	doc.auto_cleanup_bind(EV_COMMENT_MODIFIED,    &REHex::Tab::OnDocumentCommentModified,   this);
	doc.auto_cleanup_bind(EV_HIGHLIGHTS_CHANGED,  &REHex::Tab::OnDocumenHighlightsChanged,  this);
	doc.auto_cleanup_bind(EV_TYPES_CHANGED,       &REHex::Tab::OnDocumentDataTypesChanged,  this);
	doc.auto_cleanup_bind(EV_MAPPINGS_CHANGED,    &REHex::Tab::OnDocumentMappingsChanged,   this);
	
	doc.auto_cleanup_bind(BACKING_FILE_DELETED,  &REHex::Tab::OnDocumentFileDeleted,  this);
	doc.auto_cleanup_bind(BACKING_FILE_MODIFIED, &REHex::Tab::OnDocumentFileModified, this);
	
	doc_ctrl->Bind(wxEVT_CHAR, &REHex::Tab::OnDocumentCtrlChar, this);
	
	doc.auto_cleanup_bind(CURSOR_UPDATE,           &REHex::Tab::OnEventToForward<CursorUpdateEvent>,   this);
	doc.auto_cleanup_bind(EV_UNDO_UPDATE,          &REHex::Tab::OnEventToForward<wxCommandEvent>,      this);
	doc.auto_cleanup_bind(EV_BECAME_DIRTY,         &REHex::Tab::OnEventToForward<wxCommandEvent>,      this);
	doc.auto_cleanup_bind(EV_BECAME_CLEAN,         &REHex::Tab::OnEventToForward<wxCommandEvent>,      this);
	doc.auto_cleanup_bind(DOCUMENT_TITLE_CHANGED,  &REHex::Tab::OnEventToForward<DocumentTitleEvent>,  this);
	
	repopulate_regions();
	
	init_default_doc_view();
	doc_ctrl->set_insert_mode(true);
	
	wxBoxSizer *sizer = new wxBoxSizer(wxHORIZONTAL);
	sizer->Add(tool_dock, 1, wxEXPAND);
	SetSizerAndFit(sizer);
	
	init_default_tools();
	
	wxGetApp().Bind(BULK_UPDATES_FROZEN, &REHex::Tab::OnBulkUpdatesFrozen, this);
	wxGetApp().Bind(BULK_UPDATES_THAWED, &REHex::Tab::OnBulkUpdatesThawed, this);
	
	CallAfter([&]()
	{
		doc_ctrl->set_scroll_yoff(0);
	});
}

REHex::Tab::Tab(wxWindow *parent, SharedDocumentPointer &document):
	wxPanel(parent),
	doc(document),
	inline_comment_mode(ICM_FULL_INDENT),
	document_display_mode(DDM_NORMAL),
	doc_properties(NULL),
	goto_offset_dialog(NULL),
	last_goto_offset(BitOffset::MIN),
	last_goto_offset_relative(false),
	data_map_scrollbar_type(DataMapScrollbarType::NONE),
	data_map_scrollbar(NULL),
	repopulate_regions_frozen(false),
	repopulate_regions_pending(false),
	child_windows_hidden(false),
	parent_window_active(true),
	file_deleted_dialog_pending(false),
	file_modified_dialog_pending(false),
	auto_reload(false)
{
	tool_dock = new ToolDock(this);
	
	doc_ctrl_panel = new wxPanel(tool_dock);
	tool_dock->AddMainPanel(doc_ctrl_panel);
	
	doc_ctrl = new REHex::DocumentCtrl(doc_ctrl_panel, doc);
	
	data_map_scrollbar_sizer = new wxBoxSizer(wxHORIZONTAL);
	data_map_scrollbar_sizer->Add(doc_ctrl, 1, wxEXPAND);
	doc_ctrl_panel->SetSizerAndFit(data_map_scrollbar_sizer);
	
	doc.auto_cleanup_bind(DATA_ERASE,     &REHex::Tab::OnDocumentDataErase,     this);
	doc.auto_cleanup_bind(DATA_INSERT,    &REHex::Tab::OnDocumentDataInsert,    this);
	doc.auto_cleanup_bind(DATA_OVERWRITE, &REHex::Tab::OnDocumentDataOverwrite, this);
	
	doc.auto_cleanup_bind(CURSOR_UPDATE,          &REHex::Tab::OnDocumentCursorUpdate,      this);
	doc_ctrl->Bind(       CURSOR_UPDATE,          &REHex::Tab::OnDocumentCtrlCursorUpdate,  this);
	doc.auto_cleanup_bind(EV_COMMENT_MODIFIED,    &REHex::Tab::OnDocumentCommentModified,   this);
	doc.auto_cleanup_bind(EV_HIGHLIGHTS_CHANGED,  &REHex::Tab::OnDocumenHighlightsChanged,  this);
	doc.auto_cleanup_bind(EV_TYPES_CHANGED,       &REHex::Tab::OnDocumentDataTypesChanged,  this);
	doc.auto_cleanup_bind(EV_MAPPINGS_CHANGED,    &REHex::Tab::OnDocumentMappingsChanged,   this);
	
	doc.auto_cleanup_bind(BACKING_FILE_DELETED,  &REHex::Tab::OnDocumentFileDeleted,  this);
	doc.auto_cleanup_bind(BACKING_FILE_MODIFIED, &REHex::Tab::OnDocumentFileModified, this);
	
	doc_ctrl->Bind(wxEVT_CHAR, &REHex::Tab::OnDocumentCtrlChar, this);
	
	doc.auto_cleanup_bind(CURSOR_UPDATE,           &REHex::Tab::OnEventToForward<CursorUpdateEvent>,   this);
	doc.auto_cleanup_bind(EV_UNDO_UPDATE,          &REHex::Tab::OnEventToForward<wxCommandEvent>,      this);
	doc.auto_cleanup_bind(EV_BECAME_DIRTY,         &REHex::Tab::OnEventToForward<wxCommandEvent>,      this);
	doc.auto_cleanup_bind(EV_BECAME_CLEAN,         &REHex::Tab::OnEventToForward<wxCommandEvent>,      this);
	doc.auto_cleanup_bind(DOCUMENT_TITLE_CHANGED,  &REHex::Tab::OnEventToForward<DocumentTitleEvent>,  this);
	
	repopulate_regions();
	
	init_default_doc_view();
	
	wxBoxSizer *sizer = new wxBoxSizer(wxHORIZONTAL);
	sizer->Add(tool_dock, 1, wxEXPAND);
	SetSizerAndFit(sizer);
	
	init_default_tools();
	
	wxGetApp().Bind(BULK_UPDATES_FROZEN, &REHex::Tab::OnBulkUpdatesFrozen, this);
	wxGetApp().Bind(BULK_UPDATES_THAWED, &REHex::Tab::OnBulkUpdatesThawed, this);
	
	CallAfter([&]()
	{
		doc_ctrl->set_scroll_yoff(0);
	});
}

REHex::Tab::~Tab()
{
	wxGetApp().Unbind(BULK_UPDATES_THAWED, &REHex::Tab::OnBulkUpdatesThawed, this);
	wxGetApp().Unbind(BULK_UPDATES_FROZEN, &REHex::Tab::OnBulkUpdatesFrozen, this);
	
	for(auto sdi = search_dialogs.begin(); sdi != search_dialogs.end(); ++sdi)
	{
		(*sdi)->Unbind(wxEVT_DESTROY, &REHex::Tab::OnSearchDialogDestroy, this);
	}
}

bool REHex::Tab::tool_active(const std::string &name)
{
	return tool_dock->ToolExists(name);
}

void REHex::Tab::tool_create(const std::string &name, bool switch_to, wxConfig *config)
{
	tool_dock->CreateTool(name, doc, doc_ctrl);
}

void REHex::Tab::tool_destroy(const std::string &name)
{
	tool_dock->DestroyTool(name);
}

void REHex::Tab::search_dialog_register(wxDialog *search_dialog)
{
	search_dialogs.insert(search_dialog);
	search_dialog->Bind(wxEVT_DESTROY, &REHex::Tab::OnSearchDialogDestroy, this);
}

void REHex::Tab::hide_child_windows()
{
	child_windows_hidden = true;
	
	tool_dock->HideFrames();
	
	for(auto sdi = search_dialogs.begin(); sdi != search_dialogs.end(); ++sdi)
	{
		(*sdi)->Hide();
	}
	
	if(doc_properties != NULL)
	{
		doc_properties->Hide();
	}
	
	if(goto_offset_dialog != NULL)
	{
		goto_offset_dialog->Hide();
	}
}

void REHex::Tab::unhide_child_windows()
{
	child_windows_hidden = false;
	
	tool_dock->UnhideFrames();
	
	for(auto sdi = search_dialogs.begin(); sdi != search_dialogs.end(); ++sdi)
	{
		(*sdi)->ShowWithoutActivating();
	}
	
	if(doc_properties != NULL)
	{
		doc_properties->ShowWithoutActivating();
	}
	
	if(goto_offset_dialog != NULL)
	{
		goto_offset_dialog->ShowWithoutActivating();
	}
	
	if(file_deleted_dialog_pending)
	{
		file_modified_dialog_pending = false;
		file_deleted_dialog();
	}
	else if(file_modified_dialog_pending)
	{
		file_modified_dialog();
	}
}

void REHex::Tab::set_parent_window_active(bool parent_window_active)
{
	this->parent_window_active = parent_window_active;
	
	if(parent_window_active && !child_windows_hidden)
	{
		if(file_deleted_dialog_pending)
		{
			file_modified_dialog_pending = false;
			file_deleted_dialog();
		}
		else if(file_modified_dialog_pending)
		{
			file_modified_dialog();
		}
	}
}

void REHex::Tab::save_view(wxConfig *config)
{
	// Ensure we are in the correct node
	config->SetPath("/default-view/");
	
	config->Write("bytes-per-line", doc_ctrl->get_bytes_per_line());
	config->Write("bytes-per-group", doc_ctrl->get_bytes_per_group());
	config->Write("show-offsets", doc_ctrl->get_show_offsets());
	config->Write("show-ascii", doc_ctrl->get_show_ascii());
	config->Write("inline-comments", (int)(inline_comment_mode));
	config->Write("highlight-selection-match", doc_ctrl->get_highlight_selection_match());
	config->Write("offset-display-base", (int)(doc_ctrl->get_offset_display_base()));
	config->Write("data-map-scrollbar-type", (int)(data_map_scrollbar_type));
	
	config->SetPath("tools/");
	tool_dock->SaveTools(config);
}

void REHex::Tab::handle_copy(bool cut)
{
	copy_from_doc(doc, doc_ctrl, this, cut);
}

void REHex::Tab::paste_text(const std::string &text)
{
	auto paste_data = [this](const unsigned char* data, size_t size)
	{
		BitOffset cursor_pos = doc_ctrl->get_cursor_position();
		bool insert_mode = doc_ctrl->get_insert_mode();
		
		BitOffset selection_off, selection_length;
		std::tie(selection_off, selection_length) = doc_ctrl->get_selection_linear();
		bool has_selection = doc_ctrl->has_selection();
		
		if(selection_length > BitOffset::ZERO)
		{
			/* Some data is selected, replace it. */
			
			if(selection_off.byte_aligned() && selection_length.byte_aligned())
			{
				doc->replace_data(selection_off.byte(), selection_length.byte(), data, size, (selection_off + BitOffset(size, 0)), Document::CSTATE_GOTO, "paste");
				doc_ctrl->clear_selection();
			}
			else{
				/* Selection isn't aligned on byte boundary. */
				wxBell();
			}
		}
		else if(has_selection)
		{
			/* Nonlinear selection. */
			wxBell();
		}
		else if(insert_mode)
		{
			/* We are in insert mode, insert at the cursor. */
			
			if(cursor_pos.byte_aligned())
			{
				doc->insert_data(cursor_pos.byte(), data, size, cursor_pos + BitOffset(size, 0), Document::CSTATE_GOTO, "paste");
			}
			else{
				/* Cursor isn't on a byte boundary. */
				wxBell();
			}
		}
		else{
			/* We are in overwrite mode, overwrite up to the end of the file. */
			
			off_t to_end = (BitOffset(doc->buffer_length(), 0) - cursor_pos).byte();
			off_t to_write = std::min(to_end, (off_t)(size));
			
			doc->overwrite_data(cursor_pos, data, to_write, cursor_pos + BitOffset(to_write, 0), Document::CSTATE_GOTO, "paste");
		}
	};
	
	auto paste_text = [this](const std::string &utf8_text)
	{
		BitOffset cursor_pos = doc_ctrl->get_cursor_position();
		bool insert_mode = doc_ctrl->get_insert_mode();
		
		BitOffset selection_off, selection_length;
		std::tie(selection_off, selection_length) = doc_ctrl->get_selection_linear();
		bool has_selection = doc_ctrl->has_selection();
		
		int write_flag;
		
		if(selection_length > 0)
		{
			/* Some data is selected, replace it. */
			
			if(selection_off.byte_aligned() && selection_length.byte_aligned())
			{
				write_flag = doc->replace_text(selection_off.byte(), selection_length.byte(), utf8_text, Document::WRITE_TEXT_GOTO_NEXT, Document::CSTATE_GOTO, "paste");
				doc_ctrl->clear_selection();
			}
			else{
				/* Selection isn't aligned to byte boundary. */
				write_flag = Document::WRITE_TEXT_BAD_OFFSET;
			}
		}
		else if(has_selection)
		{
			/* Nonlinear selection. */
			write_flag = Document::WRITE_TEXT_BAD_OFFSET;
		}
		else if(insert_mode)
		{
			/* We are in insert mode, insert at the cursor. */
			
			if(cursor_pos.byte_aligned())
			{
				write_flag = doc->insert_text(cursor_pos.byte(), utf8_text, Document::WRITE_TEXT_GOTO_NEXT, Document::CSTATE_GOTO, "paste");
			}
			else{
				/* Cursor isn't on byte boundary. */
				write_flag = Document::WRITE_TEXT_BAD_OFFSET;
			}
		}
		else{
			/* We are in overwrite mode, overwrite up to the end of the file. */
			write_flag = doc->overwrite_text(cursor_pos, utf8_text, Document::WRITE_TEXT_GOTO_NEXT, Document::CSTATE_GOTO, "paste");
		}
		
		if(write_flag != Document::WRITE_TEXT_OK)
		{
			wxBell();
		}
	};
	
	Document::CursorState cursor_state = doc_ctrl->get_cursor_state();
	
	if(cursor_state == Document::CSTATE_ASCII)
	{
		/* Paste into ASCII view, handle as string of characters. */
		paste_text(text);
	}
	else{
		/* Paste into hex view, handle as hex string of bytes. */
		
		try {
			std::vector<unsigned char> clipboard_data = REHex::parse_hex_string(text);
			paste_data(clipboard_data.data(), clipboard_data.size());
		}
		catch(const REHex::ParseError &)
		{
			/* Ignore paste if clipboard didn't contain a valid hex string. */
		}
	}
}

void REHex::Tab::compare_whole_file()
{
	compare_range(0, doc->buffer_length());
}

void REHex::Tab::compare_selection()
{
	BitOffset selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection_linear();
	
	if(selection_length > BitOffset::ZERO
		&& selection_off.byte_aligned()
		&& selection_length.byte_aligned())
	{
		compare_range(selection_off.byte(), selection_length.byte());
	}
	else{
		wxBell();
	}
}

void REHex::Tab::compare_range(off_t offset, off_t length)
{
	if(DiffWindow::instance == NULL)
	{
		/* Parent DiffWindow to our parent so it can outlive us but not the MainWindow. */
		DiffWindow::instance = new DiffWindow(GetParent());
		DiffWindow::instance->Show(true);
	}
	
	DiffWindow::instance->add_range(DiffWindow::Range(doc, doc_ctrl, offset, length));
	
	/* Raise the DiffWindow to the top of the Z order sometime after the
	 * current event has been processed, else the menu/mouse event handling
	 * will interfere and move the MainWindow back to the top.
	*/
	CallAfter([]()
	{
		if(DiffWindow::instance != NULL)
		{
			DiffWindow::instance->Iconize(false);
			DiffWindow::instance->Raise();
		}
	});
}

REHex::InlineCommentMode REHex::Tab::get_inline_comment_mode() const
{
	return inline_comment_mode;
}

void REHex::Tab::set_inline_comment_mode(InlineCommentMode inline_comment_mode)
{
	this->inline_comment_mode = inline_comment_mode;
	repopulate_regions();
}

REHex::DocumentDisplayMode REHex::Tab::get_document_display_mode() const
{
	return document_display_mode;
}

void REHex::Tab::set_document_display_mode(DocumentDisplayMode document_display_mode)
{
	this->document_display_mode = document_display_mode;
	repopulate_regions();
	
	set_dsm_type(data_map_scrollbar_type);
}

bool REHex::Tab::get_auto_reload() const
{
	return auto_reload;
}

void REHex::Tab::set_auto_reload(bool auto_reload)
{
	this->auto_reload = auto_reload;
}

void REHex::Tab::show_goto_offset_dialog()
{
	if(goto_offset_dialog != NULL)
	{
		goto_offset_dialog->Raise();
		return;
	}
	
	bool be_modal = wxGetApp().settings->get_goto_offset_modal();
	
	goto_offset_dialog.reset(new GotoOffsetDialog(this, this));
	
	if(be_modal)
	{
		goto_offset_dialog->ShowModal();
	}
	else{
		goto_offset_dialog->Show();
	}
}

std::pair<REHex::BitOffset, bool> REHex::Tab::get_last_goto_offset() const
{
	return std::make_pair(last_goto_offset, last_goto_offset_relative);
}

void REHex::Tab::set_last_goto_offset(BitOffset last_goto_offset, bool is_relative)
{
	this->last_goto_offset = last_goto_offset;
	this->last_goto_offset_relative = is_relative;
	
	wxCommandEvent event(LAST_GOTO_OFFSET_CHANGED);
	event.SetEventObject(this);
	
	ProcessEvent(event);
}

REHex::Tab::DataMapScrollbarType REHex::Tab::get_dsm_type() const
{
	return data_map_scrollbar_type;
}

void REHex::Tab::set_dsm_type(DataMapScrollbarType dsm_type)
{
	if(data_map_scrollbar)
	{
		data_map_scrollbar_sizer->Detach(data_map_scrollbar);
		data_map_scrollbar->Destroy();
		data_map_scrollbar = NULL;
	}
	
	const ByteRangeMap<off_t> &virt_to_real_segs = doc->get_virt_to_real_segs();
	
	SharedEvtHandler<DataView> view = (document_display_mode == DDM_VIRTUAL && !(virt_to_real_segs.empty()))
		? (SharedEvtHandler<DataView>)(SharedEvtHandler<LinearVirtualDocumentView>::make(doc))
		: (SharedEvtHandler<DataView>)(SharedEvtHandler<FlatDocumentView>::make(doc));
	
	switch(dsm_type)
	{
		case DataMapScrollbarType::NONE:
			break;
			
		case DataMapScrollbarType::ENTROPY:
			data_map_scrollbar = new DataMapScrollbar(doc_ctrl_panel, wxID_ANY, view, std::unique_ptr<EntropyDataMapSource>(new EntropyDataMapSource(view, 1, 1.0f)), doc_ctrl);
			data_map_scrollbar_sizer->Add(data_map_scrollbar, 0, wxEXPAND);
			break;
	}
	
	data_map_scrollbar_sizer->Layout();
	
	data_map_scrollbar_type = dsm_type;
}

void REHex::Tab::OnSearchDialogDestroy(wxWindowDestroyEvent &event)
{
	search_dialogs.erase((wxDialog*)(event.GetWindow()));
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::Tab::OnDocumentCtrlChar(wxKeyEvent &event)
{
	if(doc_ctrl->region_OnChar(event))
	{
		/* Key press handled by cursor region. */
		return;
	}
	
	int key       = event.GetKeyCode();
	wxChar ukey   = event.GetUnicodeKey();
	int modifiers = event.GetModifiers();
	
	BitOffset cursor_pos = doc_ctrl->get_cursor_position();
	
	DocumentCtrl::GenericDataRegion *region = doc_ctrl->data_region_by_offset(cursor_pos);
	assert(region != NULL);
	
	BitOffset cursor_pos_within_region = cursor_pos - region->d_offset;
	
	BitOffset selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection_linear();
	bool has_selection = doc_ctrl->has_selection();
	
	bool insert_mode = doc_ctrl->get_insert_mode();
	
	if(doc_ctrl->hex_view_active() && (modifiers == wxMOD_NONE || modifiers == wxMOD_SHIFT) && isasciihex(key))
	{
		unsigned char nibble = REHex::parse_ascii_nibble(key);
		
		if(insert_mode && (cursor_pos_within_region % BitOffset(1,0) != BitOffset(0, 4)))
		{
			if(!cursor_pos.byte_aligned())
			{
				wxBell();
				return;
			}
			
			/* Inserting a new byte. Initialise the most significant nibble then move
			 * onto overwriting the least significant.
			*/
			
			unsigned char byte = (nibble << 4);
			doc->insert_data(cursor_pos.byte(), &byte, 1, (cursor_pos + BitOffset(0, 4)), Document::CSTATE_GOTO, "change data");
		}
		else{
			std::vector<bool> nibble_bits = {
				((nibble & 8) != 0),
				((nibble & 4) != 0),
				((nibble & 2) != 0),
				((nibble & 1) != 0),
			};
			
			doc->overwrite_bits(cursor_pos, nibble_bits, (cursor_pos + BitOffset(0, 4)), Document::CSTATE_GOTO, "change data");
		}
		
		doc_ctrl->clear_selection();
		
		return;
	}
	else if(doc_ctrl->ascii_view_active() && (modifiers == wxMOD_NONE || modifiers == wxMOD_SHIFT) && ukey != WXK_NONE && key != '\t')
	{
		wxCharBuffer utf8_buf = wxString(wxUniChar(ukey)).utf8_str();
		std::string utf8_key(utf8_buf.data(), utf8_buf.length());
		
		if(insert_mode)
		{
			if(cursor_pos.byte_aligned())
			{
				doc->insert_text(cursor_pos.byte(), utf8_key, Document::WRITE_TEXT_GOTO_NEXT, Document::CSTATE_ASCII);
			}
			else{
				/* Cursor isn't byte aligned. */
				wxBell();
			}
		}
		else{
			doc->overwrite_text(cursor_pos, utf8_key, Document::WRITE_TEXT_GOTO_NEXT, Document::CSTATE_ASCII);
		}
		
		return;
	}
	else if(modifiers == wxMOD_NONE)
	{
		if(key == WXK_INSERT)
		{
			doc_ctrl->set_insert_mode(!insert_mode);
			return;
		}
		else if(key == WXK_DELETE)
		{
			if(selection_length > 0)
			{
				if(selection_off.byte_aligned() && selection_length.byte_aligned())
				{
					doc->erase_data(selection_off.byte(), selection_length.byte(), selection_off, Document::CSTATE_GOTO, "delete selection");
					doc_ctrl->clear_selection();
				}
				else{
					/* Selection isn't byte aligned. */
					wxBell();
				}
			}
			else if(has_selection)
			{
				/* Nonlinear selection. */
				wxBell();
			}
			else if(cursor_pos.byte_aligned()
				&& cursor_pos_within_region.byte_aligned()
				&& (cursor_pos.byte() + 1) < doc->buffer_length())
			{
				doc->erase_data(cursor_pos.byte(), 1, cursor_pos, Document::CSTATE_GOTO, "delete");
			}
			else if(cursor_pos.byte_aligned()
				&& cursor_pos_within_region.byte_aligned()
				&& cursor_pos.byte() < doc->buffer_length())
			{
				doc->erase_data(cursor_pos.byte(), 1, (cursor_pos - 1), Document::CSTATE_GOTO, "delete");
			}
			
			return;
		}
		else if(key == WXK_BACK)
		{
			if(selection_length > BitOffset::ZERO)
			{
				if(selection_off.byte_aligned() && selection_length.byte_aligned())
				{
					doc->erase_data(selection_off.byte(), selection_length.byte(), selection_off, Document::CSTATE_GOTO, "delete selection");
					doc_ctrl->clear_selection();
				}
				else{
					/* Selection isn't byte aligned. */
					wxBell();
				}
			}
			else if(has_selection)
			{
				/* Nonlinear selection. */
				wxBell();
			}
			else if(cursor_pos.bit() == 4 && cursor_pos_within_region.bit() == 4)
			{
				/* Backspace while waiting for the second nibble in a byte should erase the current byte
				 * rather than the previous one.
				*/
				doc->erase_data(cursor_pos.byte(), 1, (cursor_pos - BitOffset(1, 4)), Document::CSTATE_GOTO, "delete");
			}
			else if(cursor_pos.bit() == 0 && cursor_pos_within_region.bit() == 0)
			{
				doc->erase_data((cursor_pos.byte() - 1), 1, (cursor_pos - BitOffset(1, 0)), Document::CSTATE_GOTO, "delete");
			}
			else{
				/* Not aligned to byte. */
				wxBell();
			}
			
			return;
		}
		else if(key == '/')
		{
			if(cursor_pos < doc->buffer_length())
			{
				EditCommentDialog::run_modal(this, doc, cursor_pos, 0);
			}
			
			return;
		}
	}
	
	event.Skip();
}

void REHex::Tab::OnCommentLeftClick(BitRangeEvent &event)
{
	BitOffset c_offset = event.offset;
	BitOffset c_length = event.length;
	
	if(c_offset < 0)
	{
		return;
	}
	
	EditCommentDialog::run_modal(this, doc, c_offset, c_length);
}

void REHex::Tab::OnCommentRightClick(BitRangeEvent &event)
{
	BitOffset c_offset = event.offset;
	BitOffset c_length = event.length;
	
	if(c_offset < 0)
	{
		return;
	}
	
	wxMenu menu;
	
	wxMenuItem *edit_comment = menu.Append(wxID_ANY, "&Edit comment");
	menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
	{
		EditCommentDialog::run_modal(this, doc, c_offset, c_length);
	}, edit_comment->GetId(), edit_comment->GetId());
	
	wxMenuItem *delete_comment = menu.Append(wxID_ANY, "&Delete comment");
	menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
	{
		doc->erase_comment(c_offset, c_length);
	}, delete_comment->GetId(), delete_comment->GetId());
	
	wxMenuItem *delete_comment_rec = menu.Append(wxID_ANY, "Delete comment &and children");
	menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
	{
		doc->erase_comment_recursive(c_offset, c_length);
	}, delete_comment_rec->GetId(), delete_comment_rec->GetId());
	
	delete_comment_rec->Enable(c_length > 0);
	
	menu.AppendSeparator();
	
	wxMenuItem *copy_comments = menu.Append(wxID_ANY,  "&Copy comment(s)");
	menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
	{
		ClipboardGuard cg;
		if(cg)
		{
			const BitRangeTree<Document::Comment> &comments = doc->get_comments();
			const BitRangeTree<Document::Comment>::Node *root_comment = comments.find_node(BitRangeTreeKey(c_offset, c_length));
			
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
			
			assert(selected_comments.size() > 0);
			
			wxTheClipboard->SetData(new CommentsDataObject(selected_comments, c_offset));
		}
	}, copy_comments->GetId(), copy_comments->GetId());
	
	PopupMenu(&menu);
}

void REHex::Tab::OnDataRightClick(wxCommandEvent &event)
{
	BitOffset cursor_pos = doc_ctrl->get_cursor_position();
	
	BitOffset selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection_linear();
	
	const BitRangeTree<Document::Comment> &comments   = doc->get_comments();
	const BitRangeMap<int>                &highlights = doc->get_highlights();
	
	wxMenu menu;
	
	menu.Append(wxID_CUT, "Cu&t");
	menu.Enable(wxID_CUT,  (selection_length > 0));
	
	menu.Append(wxID_COPY,  "&Copy");
	menu.Enable(wxID_COPY, (selection_length > 0));
	
	menu.Append(wxID_PASTE, "&Paste");
	
	menu.AppendSeparator();
	
	wxMenuItem *offset_copy_hex = menu.Append(wxID_ANY, "Copy offset (in hexadecimal)");
	menu.Bind(wxEVT_MENU, [cursor_pos](wxCommandEvent &event)
	{
		ClipboardGuard cg;
		if(cg)
		{
			char offset_str[24];
			int len = snprintf(offset_str, sizeof(offset_str), "0x%llX", (long long unsigned)(cursor_pos.byte()));
			
			if(!cursor_pos.byte_aligned())
			{
				snprintf((offset_str + len), (sizeof(offset_str) - len), "+%db", cursor_pos.bit());
			}
			
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
			int len = snprintf(offset_str, sizeof(offset_str), "%llu", (long long unsigned)(cursor_pos.byte()));
			
			if(!cursor_pos.byte_aligned())
			{
				snprintf((offset_str + len), (sizeof(offset_str) - len), "+%db", cursor_pos.bit());
			}
			
			wxTheClipboard->SetData(new wxTextDataObject(offset_str));
		}
	}, offset_copy_dec->GetId(), offset_copy_dec->GetId());
	
	menu.AppendSeparator();
	
	for(auto comment = comments.find_most_specific_parent(cursor_pos);
		comment != NULL;
		comment = comment->get_parent())
	{
		wxString text = comment->value.menu_preview();
		wxMenuItem *itm = menu.Append(wxID_ANY, wxString("Edit \"") + text + "\"...");
		
		menu.Bind(wxEVT_MENU, [this, comment](wxCommandEvent &event)
		{
			EditCommentDialog::run_modal(this, doc, comment->key.offset, comment->key.length);
		}, itm->GetId(), itm->GetId());
	}
	
	if(comments.find(BitRangeTreeKey(cursor_pos, 0)) == comments.end()
		&& cursor_pos < doc->buffer_length())
	{
		wxMenuItem *itm = menu.Append(wxID_ANY, "Insert comment here...");
		
		menu.Bind(wxEVT_MENU, [this, cursor_pos](wxCommandEvent &event)
		{
			EditCommentDialog::run_modal(this, doc, cursor_pos, 0);
		}, itm->GetId(), itm->GetId());
	}
	
	if(selection_length > BitOffset::ZERO
		&& comments.find(BitRangeTreeKey(selection_off, selection_length)) == comments.end()
		&& comments.can_set(selection_off, selection_length))
	{
		char menu_label[64];
		snprintf(menu_label, sizeof(menu_label), "Set comment on %" PRId64 " bytes...", (int64_t)(selection_length.byte()));
		wxMenuItem *itm =  menu.Append(wxID_ANY, menu_label);
		
		menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
		{
			EditCommentDialog::run_modal(this, doc, selection_off, selection_length);
		}, itm->GetId(), itm->GetId());
	}
	
	menu.AppendSeparator();
	
	/* We need to maintain bitmap instances for lifespan of menu. */
	std::list<wxBitmap> bitmaps;
	
	BitOffset highlight_off;
	BitOffset highlight_length = BitOffset::ZERO;
	
	auto highlight_at_cur = highlights.get_range(cursor_pos);
	
	if(selection_length > BitOffset::ZERO)
	{
		highlight_off    = selection_off;
		highlight_length = selection_length;
	}
	else if(highlight_at_cur != highlights.end())
	{
		highlight_off    = highlight_at_cur->first.offset;
		highlight_length = highlight_at_cur->first.length;
	}
	else if(cursor_pos < doc->buffer_length())
	{
		highlight_off    = cursor_pos;
		highlight_length = 1;
	}
	
	if(highlight_length > BitOffset::ZERO)
	{
		wxMenu *hlmenu = new wxMenu();
		
		const HighlightColourMap &highlight_colours = doc->get_highlight_colours();
		
		int highlight_num = 0;
		for(auto i = highlight_colours.begin(); i != highlight_colours.end(); ++i, ++highlight_num)
		{
			wxMenuItem *itm = new wxMenuItem(hlmenu, wxID_ANY, i->second.label);
			
			size_t colour_idx = i->first;
			wxColour bg_colour = i->second.primary_colour;
			
			/* TODO: Get appropriate size for menu bitmap.
			 * TODO: Draw a character in image using foreground colour.
			*/
			wxImage img(16, 16);
			img.SetRGB(wxRect(0, 0, img.GetWidth(), img.GetHeight()),
				bg_colour.Red(), bg_colour.Green(), bg_colour.Blue());
			
			bitmaps.emplace_back(img);
			itm->SetBitmap(bitmaps.back());
			
			switch(highlight_num)
			{
				case 0: wxGetApp().settings->get_main_window_commands().set_menu_item_accelerator(itm, "set_highlight_1"); break;
				case 1: wxGetApp().settings->get_main_window_commands().set_menu_item_accelerator(itm, "set_highlight_2"); break;
				case 2: wxGetApp().settings->get_main_window_commands().set_menu_item_accelerator(itm, "set_highlight_3"); break;
				case 3: wxGetApp().settings->get_main_window_commands().set_menu_item_accelerator(itm, "set_highlight_4"); break;
				case 4: wxGetApp().settings->get_main_window_commands().set_menu_item_accelerator(itm, "set_highlight_5"); break;
				case 5: wxGetApp().settings->get_main_window_commands().set_menu_item_accelerator(itm, "set_highlight_6"); break;
				default: break;
			}
			
			hlmenu->Append(itm);
			
			/* On Windows, event bindings on a submenu don't work.
			 * On OS X, event bindings on a parent menu don't work.
			 * On GTK, both work.
			*/
			#ifdef _WIN32
			menu.Bind(wxEVT_MENU, [this, highlight_off, highlight_length, colour_idx](wxCommandEvent &event)
			#else
			hlmenu->Bind(wxEVT_MENU, [this, highlight_off, highlight_length, colour_idx](wxCommandEvent &event)
			#endif
			{
				doc->set_highlight(highlight_off, highlight_length, colour_idx);
			}, itm->GetId(), itm->GetId());
		}
		
		if(!highlight_colours.empty())
		{
			hlmenu->AppendSeparator();
		}
		
		wxMenuItem *edit_itm = hlmenu->Append(wxID_ANY, "Edit highlight colours...");
		
		#ifdef _WIN32
		menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
		#else
		hlmenu->Bind(wxEVT_MENU, [&](wxCommandEvent &event)
		#endif
		{
			CallAfter([this]()
			{
				if(doc_properties == NULL)
				{
					std::vector< std::unique_ptr<SettingsDialogPanel> > panels;
					panels.push_back(std::unique_ptr<SettingsDialogPanel>(new SettingsDialogDocHighlights(doc)));
					
					doc_properties.reset(new SettingsDialog(this, doc->get_title() + " - File properties", std::move(panels)));
					doc_properties->Show();
				}
				else{
					doc_properties->Raise();
				}
			});
			
		}, edit_itm->GetId(), edit_itm->GetId());
		
		menu.AppendSubMenu(hlmenu, "Set Highlight");
	}
	
	if(highlight_at_cur != highlights.end())
	{
		wxMenuItem *itm = menu.Append(wxID_ANY, "Remove Highlight");
		wxGetApp().settings->get_main_window_commands().set_menu_item_accelerator(itm, "remove_highlight");
		
		BitRangeMap<int>::Range key = highlight_at_cur->first;
		
		menu.Bind(wxEVT_MENU, [this, key](wxCommandEvent &event)
		{
			doc->erase_highlight(key.offset, key.length);
		}, itm->GetId(), itm->GetId());
	}
	
	if(selection_length > 0)
	{
		const BitRangeMap<Document::TypeInfo> &data_types = doc->get_data_types();
		
		auto selection_off_type = data_types.get_range(selection_off);
		assert(selection_off_type != data_types.end());
		
		/* "Set data type" > */
		
		wxMenu *dtmenu = new wxMenu();
		
		wxMenuItem *data_itm = dtmenu->AppendCheckItem(wxID_ANY, "Data");
		
		if((selection_off_type->first.offset + selection_off_type->first.length) >= (selection_off + selection_length)
			&& selection_off_type->second.name == "")
		{
			data_itm->Check(true);
		}
		
		dtmenu->AppendSeparator();
		
		#ifdef _WIN32
		menu.Bind(wxEVT_MENU, [this, selection_off, selection_length](wxCommandEvent &event)
		#else
		dtmenu->Bind(wxEVT_MENU, [this, selection_off, selection_length](wxCommandEvent &event)
		#endif
		{
			doc->set_data_type(selection_off, selection_length, "");
		}, data_itm->GetId(), data_itm->GetId());
		
		std::vector<const DataTypeRegistration*> sorted_dts = DataTypeRegistry::sorted_by_group();
		
		std::vector< std::pair<std::string, wxMenu*> > group_menus;
		
		for(auto dti = sorted_dts.begin(); dti != sorted_dts.end(); ++dti)
		{
			const DataTypeRegistration *dtr = *dti;
			
			if(!dtr->configurable())
			{
				auto dt = dtr->get_type(NULL);
				
				if((selection_length % dt->word_size) != BitOffset::ZERO)
				{
					/* Selection is too short/long for this type. */
					continue;
				}
			}
			
			wxMenu *group_menu = dtmenu;
			
			{
				auto g = dtr->groups.begin();
				auto p = group_menus.begin();
				
				for(; g != dtr->groups.end(); ++g, ++p)
				{
					if(p == group_menus.end() || p->first != *g)
					{
						wxMenu *m = new wxMenu;
						group_menu->AppendSubMenu(m, *g);
						group_menu = m;
						
						p = group_menus.emplace(p, *g, m);
					}
					
					group_menu = p->second;
				}
			}
			
			if(group_menus.size() > dtr->groups.size())
			{
				group_menus.erase(std::next(group_menus.begin(), dtr->groups.size()), group_menus.end());
			}
			
			std::string itm_label = dtr->configurable()
				? dtr->label + "..."
				: dtr->label;
			
			wxMenuItem *itm = group_menu->AppendCheckItem(wxID_ANY, itm_label);
			
			if((selection_off_type->first.offset + selection_off_type->first.length) >= (selection_off + selection_length)
				&& selection_off_type->second.name == dtr->name)
			{
				itm->Check(true);
			}
			
			#ifdef _WIN32
			menu.Bind(wxEVT_MENU, [this, dtr, selection_off, selection_length](wxCommandEvent &event)
			#else
			group_menu->Bind(wxEVT_MENU, [this, dtr, selection_off, selection_length](wxCommandEvent &event)
			#endif
			{
				if(dtr->configurable())
				{
					json_t *dt_config = dtr->configure(this);
					
					if(dt_config != NULL)
					{
						doc->set_data_type(selection_off, selection_length, dtr->name, dt_config);
						json_decref(dt_config);
					}
				}
				else{
					doc->set_data_type(selection_off, selection_length, dtr->name);
				}
			}, itm->GetId(), itm->GetId());
		}
		
		menu.AppendSubMenu(dtmenu, "Set data type");
		
		wxMenuItem *vm_itm = menu.Append(wxID_ANY, "Set virtual address mapping...");
		vm_itm->Enable(selection_off.byte_aligned() && selection_off.byte_aligned());
		
		menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
		{
			assert(selection_off.byte_aligned());
			assert(selection_length.byte_aligned());
			
			VirtualMappingDialog d(this, doc, selection_off.byte(), selection_length.byte());
			d.ShowModal();
		}, vm_itm->GetId(), vm_itm->GetId());
	}
	
	menu.AppendSeparator();
	
	{
		wxMenuItem *itm = menu.Append(wxID_ANY, "Compare selection...\tCtrl-Shift-K");
		itm->Enable(selection_length > BitOffset::ZERO && selection_off.byte_aligned() && selection_length.byte_aligned());
		
		menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
		{
			assert(selection_off.byte_aligned());
			assert(selection_length.byte_aligned());
			
			compare_range(selection_off.byte(), selection_length.byte());
		}, itm->GetId(), itm->GetId());
	}
	
	PopupMenu(&menu);
}

void REHex::Tab::OnDocumentDataErase(OffsetLengthEvent &event)
{
	repopulate_regions();
	event.Skip();
}

void REHex::Tab::OnDocumentDataInsert(OffsetLengthEvent &event)
{
	repopulate_regions();
	event.Skip();
}

void REHex::Tab::OnDocumentDataOverwrite(OffsetLengthEvent &event)
{
	doc_ctrl->Refresh();
	event.Skip();
}

void REHex::Tab::OnDocumentCursorUpdate(CursorUpdateEvent &event)
{
	doc_ctrl->set_cursor_position(doc->get_cursor_position(), event.cursor_state);
	event.Skip();
}

void REHex::Tab::OnDocumentCtrlCursorUpdate(CursorUpdateEvent &event)
{
	doc->set_cursor_position(doc_ctrl->get_cursor_position(), event.cursor_state);
	event.Skip();
}

void REHex::Tab::OnDocumentCommentModified(wxCommandEvent &event)
{
	repopulate_regions();
	event.Skip();
}

void REHex::Tab::OnDocumenHighlightsChanged(wxCommandEvent &event)
{
	doc_ctrl->Refresh();
	event.Skip();
}

void REHex::Tab::OnDocumentDataTypesChanged(wxCommandEvent &event)
{
	repopulate_regions();
	event.Skip();
}

void REHex::Tab::OnDocumentMappingsChanged(wxCommandEvent &event)
{
	if(document_display_mode == DDM_VIRTUAL)
	{
		repopulate_regions();
		set_dsm_type(data_map_scrollbar_type);
	}
	
	event.Skip();
}

void REHex::Tab::OnDocumentFileDeleted(wxCommandEvent &event)
{
	OnEventToForward(event);
	file_deleted_dialog();
}

void REHex::Tab::file_deleted_dialog()
{
	if(child_windows_hidden || !parent_window_active)
	{
		file_deleted_dialog_pending = true;
		return;
	}
	
	file_deleted_dialog_pending = false;
	
	wxMessageDialog confirm(
		this,
		(wxString("The file ") + doc->get_filename() + " has been deleted from disk."),
		"File deleted",
		(wxYES_NO | wxCANCEL | wxCENTER));
	
	confirm.SetYesNoCancelLabels("Save", "Save As", "Ignore");
	
	int response = confirm.ShowModal();
	switch(response)
	{
		case wxID_YES:
		{
			try {
				doc->save();
			}
			catch(const std::exception &e)
			{
				wxMessageBox(
					std::string("Error saving ") + doc->get_title() + ":\n" + e.what(),
					"Error", wxICON_ERROR, this);
			}
			
			break;
		}
		
		case wxID_NO:
		{
			std::string new_filename = document_save_as_dialog(this, doc);
			if(new_filename == "")
			{
				/* Cancelled. */
				return;
			}
			
			try {
				doc->save(new_filename);
			}
			catch(const std::exception &e)
			{
				wxMessageBox(
					std::string("Error saving ") + doc->get_title() + ":\n" + e.what(),
					"Error", wxICON_ERROR, this);
			}
			
			break;
		}
		
		default:
		{
			/* Ignore */
			break;
		}
	}
}

void REHex::Tab::OnDocumentFileModified(wxCommandEvent &event)
{
	file_modified_dialog();
	OnEventToForward(event);
}

void REHex::Tab::file_modified_dialog()
{
	if(child_windows_hidden || !parent_window_active)
	{
		file_modified_dialog_pending = true;
		return;
	}
	
	file_modified_dialog_pending = false;
	
	if(doc->is_dirty())
	{
		wxMessageDialog confirm(
			this,
			(wxString("The file ") + doc->get_filename() + " has been modified externally AND in the editor.\n"
				+ "DISCARD YOUR CHANGES and reload the file?"),
			"File modified",
			(wxYES_NO | wxICON_EXCLAMATION | wxCENTER));
		
		int response = confirm.ShowModal();
		if(response == wxID_NO)
		{
			return;
		}
	}
	else if(!auto_reload)
	{
		enum {
			ID_RELOAD = 1,
			ID_AUTO_RELOAD,
			ID_IGNORE
		};
		
		CustomMessageDialog confirm(
			this,
			(wxString("The file '") + doc->get_title() + "' has been modified externally.\n"
				+ "Reload this file?"),
			"File modified",
			(wxICON_EXCLAMATION | wxCENTER));
		
		confirm.AddButton(ID_RELOAD, "Yes");
		confirm.AddButton(ID_AUTO_RELOAD, "Yes (always)");
		confirm.AddButton(ID_IGNORE, "No");
		
		confirm.SetEscapeId(ID_IGNORE);
		confirm.SetAffirmativeId(ID_RELOAD);
		
		int response = confirm.ShowModal();
		if(response == ID_IGNORE)
		{
			return;
		}
		else if(response == ID_AUTO_RELOAD)
		{
			auto_reload = true;
		}
	}
	
	try {
		doc->reload();
	}
	catch(const std::exception &e)
	{
		wxMessageBox(
			std::string("Error reloading ") + doc->get_title() + ":\n" + e.what(),
			"Error", wxICON_ERROR, this);
	}
}

void REHex::Tab::OnBulkUpdatesFrozen(wxCommandEvent &event)
{
	repopulate_regions_freeze();
	event.Skip();
}

void REHex::Tab::OnBulkUpdatesThawed(wxCommandEvent &event)
{
	repopulate_regions_thaw();
	event.Skip();
}

void REHex::Tab::init_default_doc_view()
{
	wxConfig *config = wxGetApp().config;
	config->SetPath("/default-view/");
	
	doc_ctrl->set_bytes_per_line(             config->ReadLong("bytes-per-line",             doc_ctrl->get_bytes_per_line()));
	doc_ctrl->set_bytes_per_group(            config->Read    ("bytes-per-group",            doc_ctrl->get_bytes_per_group()));
	doc_ctrl->set_show_offsets(               config->ReadBool("show-offsets",               doc_ctrl->get_show_offsets()));
	doc_ctrl->set_show_ascii(                 config->ReadBool("show-ascii",                 doc_ctrl->get_show_ascii()));
	doc_ctrl->set_highlight_selection_match(  config->ReadBool("highlight-selection-match",  doc_ctrl->get_highlight_selection_match()));
	
	int inline_comments = config->Read("inline-comments", (int)(inline_comment_mode));
	if(inline_comments >= 0 && inline_comments <= ICM_MAX)
	{
		inline_comment_mode = (InlineCommentMode)(inline_comments);
		repopulate_regions();
	}
	
	int offset_display_base = config->Read("offset-display-base", (int)(doc_ctrl->get_offset_display_base()));
	if(offset_display_base >= OFFSET_BASE_MIN && offset_display_base <= OFFSET_BASE_MAX)
	{
		doc_ctrl->set_offset_display_base((OffsetBase)(offset_display_base));
	}
	
	int dsm_type = config->Read("data-map-scrollbar-type", (int)(data_map_scrollbar_type));
	set_dsm_type((DataMapScrollbarType)(dsm_type));

	int default_byte_colour_map = wxGetApp().settings->get_default_byte_colour_map();
	if(default_byte_colour_map >= 0)
	{
		auto maps = wxGetApp().settings->get_byte_colour_maps();

		auto map_it = maps.find(default_byte_colour_map);
		assert(map_it != maps.end());

		if(map_it != maps.end())
		{
			doc_ctrl->set_byte_colour_map(map_it->second);
		}
	}
}

void REHex::Tab::init_default_tools()
{
	wxConfig *config = wxGetApp().config;
	
	wxConfigPathChanger scoped_path(config, "/default-view/tools/");
	tool_dock->LoadTools(config, doc, doc_ctrl);
}

void REHex::Tab::repopulate_regions()
{
	PROFILE_BLOCK("REHex::Tab::repopulate_regions");
	
	if(repopulate_regions_frozen)
	{
		repopulate_regions_pending = true;
		return;
	}
	
	std::vector<DocumentCtrl::Region*> regions;
	
	if(document_display_mode == DDM_VIRTUAL)
	{
		/* Virtual segments view. */
		
		PROFILE_INNER_BLOCK("prepare regions (virtual)");
		
		const ByteRangeMap<off_t> &virt_to_real_segs = doc->get_virt_to_real_segs();
		
		if(virt_to_real_segs.empty())
		{
			static const wxString C_TEXT = "No virtual sections defined, displaying file data instead.";
			regions.push_back(new DocumentCtrl::CommentRegion(-1, 0, C_TEXT, false, -1, 0));
			
			goto DO_FILE_VIEW;
		}
		else{
			for(auto i = virt_to_real_segs.begin(); i != virt_to_real_segs.end(); ++i)
			{
				off_t real_offset_base = i->second;
				off_t virt_offset_base = i->first.offset;
				off_t length = i->first.length;
				
				std::vector<DocumentCtrl::Region*> v_regions = compute_regions(doc, real_offset_base, virt_offset_base, length, inline_comment_mode);
				regions.insert(regions.end(), v_regions.begin(), v_regions.end());
			}
		}
	}
	else{
		/* File view. */
		DO_FILE_VIEW:
		
		PROFILE_INNER_BLOCK("prepare regions (file)");
		
		std::vector<DocumentCtrl::Region*> file_regions = compute_regions(doc, 0, 0, doc->buffer_length(), inline_comment_mode);
		
		if(file_regions.empty())
		{
			assert(doc->buffer_length() == 0);
			
			/* Empty buffers need a data region too! */
			file_regions.push_back(new DocumentCtrl::DataRegionDocHighlight(doc, 0, 0, 0));
		}
		else if(dynamic_cast<DocumentCtrl::DataRegionDocHighlight*>(file_regions.back()) == NULL)
		{
			/* End region isn't a DataRegionDocHighlight - means its a comment or a custom
			 * data region type. Push one on the end so there's somewhere to put the cursor to
			 * insert more data at the end.
			*/
			
			file_regions.push_back(new DocumentCtrl::DataRegionDocHighlight(doc, doc->buffer_length(), 0, doc->buffer_length()));
		}
		
		regions.insert(regions.end(), file_regions.begin(), file_regions.end());
	}
	
	{
		PROFILE_INNER_BLOCK("replace regions");
		doc_ctrl->replace_all_regions(regions);
	}
}

void REHex::Tab::repopulate_regions_freeze()
{
	repopulate_regions_frozen = true;
}

void REHex::Tab::repopulate_regions_thaw()
{
	repopulate_regions_frozen = false;
	
	if(repopulate_regions_pending)
	{
		repopulate_regions();
		repopulate_regions_pending = false;
	}
}

std::vector<REHex::DocumentCtrl::Region*> REHex::Tab::compute_regions(SharedDocumentPointer doc, BitOffset real_offset_base, BitOffset virt_offset_base, BitOffset length, InlineCommentMode inline_comment_mode)
{
	auto &comments = doc->get_comments();
	auto &types = doc->get_data_types();
	
	bool nest = (inline_comment_mode == ICM_SHORT_INDENT || inline_comment_mode == ICM_FULL_INDENT);
	bool truncate = (inline_comment_mode == ICM_SHORT || inline_comment_mode == ICM_SHORT_INDENT);
	
	/* Construct a list of interlaced comment/data regions. */
	
	auto next_comment = comments.first_root_node();
	auto types_iter = types.begin();
	BitOffset next_data = real_offset_base, next_virt = virt_offset_base, remain_data = length;
	
	/* Skip over comments/types prior to real_offset_base. */
	while(next_comment != NULL && next_comment->key.offset < next_data)
	{
		auto first_child = next_comment->get_first_child();
		
		if(first_child != NULL && (first_child->key.offset == next_comment->key.offset || first_child->key.offset >= next_data))
		{
			next_comment = next_comment->get_first_child();
		}
		else{
			while(next_comment->get_next() == NULL && next_comment->get_parent() != NULL)
			{
				next_comment = next_comment->get_parent();
			}
			
			next_comment = next_comment->get_next();
		}
	}
	
	while(types_iter != types.end() && (types_iter->first.offset + types_iter->first.length <= next_data)) { ++types_iter; }
	
	if(inline_comment_mode == ICM_HIDDEN)
	{
		/* Inline comments are hidden. Skip over the comments. */
		next_comment = NULL;
	}
	
	std::vector<DocumentCtrl::Region*> regions;
	std::stack<BitOffset> dr_limit;
	
	while(remain_data > 0)
	{
		assert((next_data + remain_data) <= BitOffset(doc->buffer_length(), 0));
		assert(next_comment == NULL || next_comment->key.offset >= next_data);
		
		while(!dr_limit.empty() && dr_limit.top() <= next_data)
		{
			dr_limit.pop();
		}
		
		/* We process any comments at the same offset from largest to smallest, ensuring
		 * smaller comments are parented to the next-larger one at the same offset.
		*/
		
		while(next_comment != NULL && next_comment->key.offset == next_data)
		{
			BitOffset indent_offset = next_virt;
			BitOffset indent_length = nest
				? std::min(next_comment->key.length, remain_data)
				: BitOffset::ZERO;
			
			regions.push_back(new DocumentCtrl::CommentRegion(
				next_comment->key.offset,
				next_comment->key.length,
				*(next_comment->value.text),
				truncate,
				indent_offset,
				indent_length));
			
			if(nest && next_comment->key.length > 0)
			{
				assert(dr_limit.empty() || dr_limit.top() >= next_comment->key.offset + next_comment->key.length);
				dr_limit.push(next_comment->key.offset + next_comment->key.length);
			}
			
			if(next_comment->get_first_child() != NULL)
			{
				next_comment = next_comment->get_first_child();
			}
			else{
				while(next_comment->get_next() == NULL && next_comment->get_parent() != NULL)
				{
					next_comment = next_comment->get_parent();
				}
				
				next_comment = next_comment->get_next();
			}
		}
		
		BitOffset dr_length = remain_data;
		
		if(next_comment != NULL && dr_length > (next_comment->key.offset - next_data))
		{
			dr_length = next_comment->key.offset - next_data;
		}
		
		if(!dr_limit.empty() && (next_data + dr_length) >= dr_limit.top())
		{
			assert(dr_limit.top() > next_data);
			
			dr_length = dr_limit.top() - next_data;
		}
		
		assert(types_iter != types.end());
		assert(types_iter->first.offset <= next_data && (types_iter->first.offset + types_iter->first.length) > next_data);
		
		dr_length = std::min(
			dr_length,
			types_iter->first.length - (next_data - types_iter->first.offset));
		
		std::shared_ptr<const DataType> dt = DataTypeRegistry::get_type(types_iter->second.name, types_iter->second.options);
		
		if(dt != NULL && dt->region_factory && dt->region_fixed_size <= dr_length)
		{
			if(dt->region_fixed_size > BitOffset::ZERO && dr_length > dt->region_fixed_size)
			{
				dr_length = dt->region_fixed_size;
			}
			else if((dr_length % dt->word_size) != BitOffset::ZERO)
			{
				dr_length -= dr_length % dt->word_size;
			}
			
			assert(dr_length > BitOffset::ZERO);
			
			regions.push_back(dt->region_factory(doc, next_data, dr_length, next_virt));
		}
		else{
			/* DataRegion only allows whole-byte lengths, so if we have any spare bits
			 * in an untyped region we will make a little BitArrayRegion to cover them.
			*/
			
			if(dr_length < BitOffset(1, 0))
			{
				regions.push_back(new BitArrayRegion(doc, next_data, dr_length, next_virt));
			}
			else{
				if(!dr_length.byte_aligned())
				{
					dr_length = BitOffset(dr_length.byte(), 0);
				}
				
				regions.push_back(new DocumentCtrl::DataRegionDocHighlight(doc, next_data, dr_length, next_virt));
			}
		}
		
		next_data   += dr_length;
		next_virt   += dr_length;
		remain_data -= dr_length;
		
		if(next_data >= (types_iter->first.offset + types_iter->first.length))
		{
			++types_iter;
		}
	}
	
	return regions;
}
