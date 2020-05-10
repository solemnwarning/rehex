/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2020 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <exception>
#include <inttypes.h>
#include <stack>
#include <tuple>
#include <wx/clipbrd.h>
#include <wx/dataobj.h>
#include <wx/sizer.h>

#include "app.hpp"
#include "DiffWindow.hpp"
#include "EditCommentDialog.hpp"
#include "Tab.hpp"

/* Is the given byte a printable 7-bit ASCII character? */
static bool isasciiprint(int c)
{
	return (c >= ' ' && c <= '~');
}

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

BEGIN_EVENT_TABLE(REHex::Tab, wxPanel)
	EVT_SIZE(REHex::Tab::OnSize)
	
	EVT_NOTEBOOK_PAGE_CHANGED(ID_HTOOLS, REHex::Tab::OnHToolChange)
	EVT_NOTEBOOK_PAGE_CHANGED(ID_VTOOLS, REHex::Tab::OnVToolChange)
	
	EVT_SPLITTER_SASH_POS_CHANGING(ID_HSPLITTER, REHex::Tab::OnHSplitterSashPosChanging)
	EVT_SPLITTER_SASH_POS_CHANGING(ID_VSPLITTER, REHex::Tab::OnVSplitterSashPosChanging)
	
	EVT_OFFSETLENGTH(wxID_ANY, REHex::COMMENT_LEFT_CLICK,  REHex::Tab::OnCommentLeftClick)
	EVT_OFFSETLENGTH(wxID_ANY, REHex::COMMENT_RIGHT_CLICK, REHex::Tab::OnCommentRightClick)
	
	EVT_COMMAND(wxID_ANY, REHex::DATA_RIGHT_CLICK, REHex::Tab::OnDataRightClick)
END_EVENT_TABLE()

REHex::Tab::Tab(wxWindow *parent):
	wxPanel(parent),
	doc(SharedDocumentPointer::make())
{
	v_splitter = new wxSplitterWindow(this, ID_VSPLITTER, wxDefaultPosition, wxDefaultSize, (wxSP_3D | wxSP_LIVE_UPDATE));
	v_splitter->SetSashGravity(1.0);
	v_splitter->SetMinimumPaneSize(20);
	
	h_splitter = new wxSplitterWindow(v_splitter, ID_HSPLITTER, wxDefaultPosition, wxDefaultSize, (wxSP_3D | wxSP_LIVE_UPDATE));
	h_splitter->SetSashGravity(1.0);
	h_splitter->SetMinimumPaneSize(20);
	
	doc_ctrl = new REHex::DocumentCtrl(h_splitter, doc);
	
	doc.auto_cleanup_bind(DATA_ERASE,     &REHex::Tab::OnDocumentDataErase,     this);
	doc.auto_cleanup_bind(DATA_INSERT,    &REHex::Tab::OnDocumentDataInsert,    this);
	doc.auto_cleanup_bind(DATA_OVERWRITE, &REHex::Tab::OnDocumentDataOverwrite, this);
	
	doc.auto_cleanup_bind(CURSOR_UPDATE,          &REHex::Tab::OnDocumentCursorUpdate,      this);
	doc_ctrl->Bind(       CURSOR_UPDATE,          &REHex::Tab::OnDocumentCtrlCursorUpdate,  this);
	doc.auto_cleanup_bind(EV_COMMENT_MODIFIED,    &REHex::Tab::OnDocumentCommentModified,   this);
	doc.auto_cleanup_bind(EV_HIGHLIGHTS_CHANGED,  &REHex::Tab::OnDocumenHighlightsChanged,  this);
	
	doc_ctrl->Bind(wxEVT_CHAR, &REHex::Tab::OnDocumentCtrlChar, this);
	
	doc.auto_cleanup_bind(CURSOR_UPDATE,         &REHex::Tab::OnEventToForward<CursorUpdateEvent>, this);
	doc.auto_cleanup_bind(EV_UNDO_UPDATE,        &REHex::Tab::OnEventToForward<wxCommandEvent>,    this);
	doc.auto_cleanup_bind(EV_BECAME_DIRTY,       &REHex::Tab::OnEventToForward<wxCommandEvent>,    this);
	doc.auto_cleanup_bind(EV_BECAME_CLEAN,       &REHex::Tab::OnEventToForward<wxCommandEvent>,    this);
	
	repopulate_regions();
	
	init_default_doc_view();
	doc_ctrl->set_insert_mode(true);
	
	h_tools = new wxNotebook(h_splitter, ID_HTOOLS, wxDefaultPosition, wxDefaultSize, wxNB_BOTTOM);
	h_tools->SetFitToCurrentPage(true);
	
	v_tools = new wxNotebook(v_splitter, ID_VTOOLS, wxDefaultPosition, wxDefaultSize, wxNB_RIGHT);
	v_tools->SetFitToCurrentPage(true);
	
	h_splitter->SplitHorizontally(doc_ctrl, h_tools);
	v_splitter->SplitVertically(h_splitter, v_tools);
	
	wxBoxSizer *sizer = new wxBoxSizer(wxHORIZONTAL);
	sizer->Add(v_splitter, 1, wxEXPAND);
	SetSizerAndFit(sizer);
	
	init_default_tools();
	
	htools_adjust_on_idle();
	vtools_adjust_on_idle();
}

REHex::Tab::Tab(wxWindow *parent, const std::string &filename):
	wxPanel(parent),
	doc(SharedDocumentPointer::make(filename))
{
	v_splitter = new wxSplitterWindow(this, ID_VSPLITTER, wxDefaultPosition, wxDefaultSize, (wxSP_3D | wxSP_LIVE_UPDATE));
	v_splitter->SetSashGravity(1.0);
	v_splitter->SetMinimumPaneSize(20);
	
	h_splitter = new wxSplitterWindow(v_splitter, ID_HSPLITTER, wxDefaultPosition, wxDefaultSize, (wxSP_3D | wxSP_LIVE_UPDATE));
	h_splitter->SetSashGravity(1.0);
	h_splitter->SetMinimumPaneSize(20);
	
	doc_ctrl = new REHex::DocumentCtrl(h_splitter, doc);
	
	doc.auto_cleanup_bind(DATA_ERASE,     &REHex::Tab::OnDocumentDataErase,     this);
	doc.auto_cleanup_bind(DATA_INSERT,    &REHex::Tab::OnDocumentDataInsert,    this);
	doc.auto_cleanup_bind(DATA_OVERWRITE, &REHex::Tab::OnDocumentDataOverwrite, this);
	
	doc.auto_cleanup_bind(CURSOR_UPDATE,          &REHex::Tab::OnDocumentCursorUpdate,      this);
	doc_ctrl->Bind(       CURSOR_UPDATE,          &REHex::Tab::OnDocumentCtrlCursorUpdate,  this);
	doc.auto_cleanup_bind(EV_COMMENT_MODIFIED,    &REHex::Tab::OnDocumentCommentModified,   this);
	doc.auto_cleanup_bind(EV_HIGHLIGHTS_CHANGED,  &REHex::Tab::OnDocumenHighlightsChanged,  this);
	
	doc_ctrl->Bind(wxEVT_CHAR, &REHex::Tab::OnDocumentCtrlChar, this);
	
	doc.auto_cleanup_bind(CURSOR_UPDATE,         &REHex::Tab::OnEventToForward<CursorUpdateEvent>, this);
	doc.auto_cleanup_bind(EV_UNDO_UPDATE,        &REHex::Tab::OnEventToForward<wxCommandEvent>,    this);
	doc.auto_cleanup_bind(EV_BECAME_DIRTY,       &REHex::Tab::OnEventToForward<wxCommandEvent>,    this);
	doc.auto_cleanup_bind(EV_BECAME_CLEAN,       &REHex::Tab::OnEventToForward<wxCommandEvent>,    this);
	
	repopulate_regions();
	
	init_default_doc_view();
	
	h_tools = new wxNotebook(h_splitter, ID_HTOOLS, wxDefaultPosition, wxDefaultSize, wxNB_BOTTOM);
	h_tools->SetFitToCurrentPage(true);
	
	v_tools = new wxNotebook(v_splitter, ID_VTOOLS, wxDefaultPosition, wxDefaultSize, wxNB_RIGHT);
	v_tools->SetFitToCurrentPage(true);
	
	h_splitter->SplitHorizontally(doc_ctrl, h_tools);
	v_splitter->SplitVertically(h_splitter, v_tools);
	
	wxBoxSizer *sizer = new wxBoxSizer(wxHORIZONTAL);
	sizer->Add(v_splitter, 1, wxEXPAND);
	SetSizerAndFit(sizer);
	
	init_default_tools();
	
	htools_adjust_on_idle();
	vtools_adjust_on_idle();
}

REHex::Tab::~Tab()
{
	for(auto sdi = search_dialogs.begin(); sdi != search_dialogs.end(); ++sdi)
	{
		(*sdi)->Unbind(wxEVT_DESTROY, &REHex::Tab::OnSearchDialogDestroy, this);
	}
}

bool REHex::Tab::tool_active(const std::string &name)
{
	return tools.find(name) != tools.end();
}

void REHex::Tab::tool_create(const std::string &name, bool switch_to, wxConfig *config, bool adjust)
{
	if(tool_active(name))
	{
		return;
	}
	
	const ToolPanelRegistration *tpr = ToolPanelRegistry::by_name(name);
	assert(tpr != NULL);
	
	if(tpr->shape == ToolPanel::TPS_TALL)
	{
		ToolPanel *tool_window = tpr->factory(v_tools, doc, doc_ctrl);
		if(config)
		{
			tool_window->load_state(config);
		}
		
		v_tools->AddPage(tool_window, tpr->label, switch_to);
		
		tools.insert(std::make_pair(name, tool_window));
		
		if(adjust)
		{
			vtools_adjust_on_idle();
		}
	}
	else if(tpr->shape == ToolPanel::TPS_WIDE)
	{
		ToolPanel *tool_window = tpr->factory(h_tools, doc, doc_ctrl);
		if(config)
		{
			tool_window->load_state(config);
		}
		
		h_tools->AddPage(tool_window, tpr->label, switch_to);
		
		tools.insert(std::make_pair(name, tool_window));
		
		if(adjust)
		{
			htools_adjust_on_idle();
		}
	}
}

void REHex::Tab::tool_destroy(const std::string &name)
{
	auto ti = tools.find(name);
	if(ti == tools.end())
	{
		return;
	}
	
	wxWindow *tool_window = ti->second;
	tools.erase(ti);
	
	wxNotebook *notebook = dynamic_cast<wxNotebook*>(tool_window->GetParent());
	assert(notebook != NULL);
	
	int page_idx = notebook->FindPage(tool_window);
	assert(page_idx != wxNOT_FOUND);
	
	notebook->DeletePage(page_idx);
	
	if(notebook == v_tools)
	{
		vtools_adjust();
	}
	else if(notebook == h_tools)
	{
		htools_adjust();
	}
}

void REHex::Tab::search_dialog_register(wxDialog *search_dialog)
{
	search_dialogs.insert(search_dialog);
	search_dialog->Bind(wxEVT_DESTROY, &REHex::Tab::OnSearchDialogDestroy, this);
}

void REHex::Tab::hide_child_windows()
{
	for(auto sdi = search_dialogs.begin(); sdi != search_dialogs.end(); ++sdi)
	{
		(*sdi)->Hide();
	}
}

void REHex::Tab::unhide_child_windows()
{
	for(auto sdi = search_dialogs.begin(); sdi != search_dialogs.end(); ++sdi)
	{
		(*sdi)->ShowWithoutActivating();
	}
}

void REHex::Tab::save_view(wxConfig *config)
{
	config->SetPath("/");
	config->Write("theme", wxString(active_palette->get_name()));
	
	config->DeleteGroup("/default-view/");
	config->SetPath("/default-view/");
	
	config->Write("bytes-per-line", doc_ctrl->get_bytes_per_line());
	config->Write("bytes-per-group", doc_ctrl->get_bytes_per_group());
	config->Write("show-offsets", doc_ctrl->get_show_offsets());
	config->Write("show-ascii", doc_ctrl->get_show_ascii());
	config->Write("inline-comments", (int)(inline_comment_mode));
	config->Write("highlight-selection-match", doc_ctrl->get_highlight_selection_match());
	config->Write("offset-display-base", (int)(doc_ctrl->get_offset_display_base()));
	
	/* TODO: Save h_tools state */
	
	for(size_t i = 0; i < v_tools->GetPageCount(); ++i)
	{
		char path[64];
		snprintf(path, sizeof(path), "/default-view/vtools/panels/0/tab/%u/", (unsigned)(i));
		
		config->SetPath(path);
		
		wxWindow *page = v_tools->GetPage(i);
		assert(page != NULL);
		
		ToolPanel *tp = dynamic_cast<ToolPanel*>(page);
		assert(tp != NULL);
		
		config->Write("name", wxString(tp->name()));
		config->Write("selected", (page == v_tools->GetCurrentPage()));
		tp->save_state(config);
	}
}

void REHex::Tab::handle_copy(bool cut)
{
	Document::CursorState cursor_state = doc_ctrl->get_cursor_state();
	
	off_t selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection();
	
	if(selection_length <= 0)
	{
		/* Nothing selected - nothing to copy. */
		return;
	}
	
	/* Warn the user this might be a bad idea before dumping silly amounts
	 * of data (>16MiB) into the clipboard.
	*/
	
	static size_t COPY_MAX_SOFT = 16777216;
	
	size_t upper_limit = cursor_state == Document::CSTATE_ASCII
		? selection_length
		: (selection_length * 2);
	
	if(upper_limit > COPY_MAX_SOFT)
	{
		char msg[128];
		snprintf(msg, sizeof(msg),
			"You are about to copy %uMB into the clipboard.\n"
			"This may take a long time and/or crash some applications.",
			(unsigned)(upper_limit / 1000000));
		
		int result = wxMessageBox(msg, "Warning", (wxOK | wxCANCEL | wxICON_EXCLAMATION), this);
		if(result != wxOK)
		{
			return;
		}
	}
	
	wxTextDataObject *copy_data = NULL;
	try {
		std::vector<unsigned char> selection_data = doc->read_data(selection_off, selection_length);
		assert((off_t)(selection_data.size()) == selection_length);
		
		if(cursor_state == Document::CSTATE_ASCII)
		{
			std::string ascii_string;
			ascii_string.reserve(selection_data.size());
			
			for(auto c = selection_data.begin(); c != selection_data.end(); ++c)
			{
				if((*c >= ' ' && *c <= '~') || *c == '\t' || *c == '\n' || *c == '\r')
				{
					ascii_string.push_back(*c);
				}
			}
			
			if(!ascii_string.empty())
			{
				copy_data = new wxTextDataObject(ascii_string);
			}
		}
		else{
			std::string hex_string;
			hex_string.reserve(selection_data.size() * 2);
			
			for(auto c = selection_data.begin(); c != selection_data.end(); ++c)
			{
				const char *nibble_to_hex = "0123456789ABCDEF";
				
				unsigned char high_nibble = (*c & 0xF0) >> 4;
				unsigned char low_nibble  = (*c & 0x0F);
				
				hex_string.push_back(nibble_to_hex[high_nibble]);
				hex_string.push_back(nibble_to_hex[low_nibble]);
			}
			
			copy_data = new wxTextDataObject(hex_string);
		}
	}
	catch(const std::bad_alloc &e)
	{
		wxMessageBox(
			"Memory allocation failed while preparing clipboard buffer.",
			"Error", (wxOK | wxICON_ERROR), this);
		return;
	}
	catch(const std::exception &e)
	{
		wxMessageBox(e.what(), "Error", (wxOK | wxICON_ERROR), this);
		return;
	}
	
	if(copy_data != NULL)
	{
		ClipboardGuard cg;
		if(cg)
		{
			wxTheClipboard->SetData(copy_data);
			
			if(cut)
			{
				doc->erase_data(selection_off, selection_length, -1, Document::CSTATE_CURRENT, "cut selection");
			}
		}
		else{
			delete copy_data;
		}
	}
}

void REHex::Tab::paste_text(const std::string &text)
{
	auto paste_data = [this](const unsigned char* data, size_t size)
	{
		off_t cursor_pos = doc_ctrl->get_cursor_position();
		bool insert_mode = doc_ctrl->get_insert_mode();
		
		off_t selection_off, selection_length;
		std::tie(selection_off, selection_length) = doc_ctrl->get_selection();
		
		if(selection_length > 0)
		{
			/* Some data is selected, replace it. */
			
			doc->replace_data(selection_off, selection_length, data, size, selection_off + size, Document::CSTATE_GOTO, "paste");
			doc_ctrl->clear_selection();
		}
		else if(insert_mode)
		{
			/* We are in insert mode, insert at the cursor. */
			doc->insert_data(cursor_pos, data, size, cursor_pos + size, Document::CSTATE_GOTO, "paste");
		}
		else{
			/* We are in overwrite mode, overwrite up to the end of the file. */
			
			off_t to_end = doc->buffer_length() - cursor_pos;
			off_t to_write = std::min(to_end, (off_t)(size));
			
			doc->overwrite_data(cursor_pos, data, to_write, cursor_pos + to_write, Document::CSTATE_GOTO, "paste");
		}
	};
	
	Document::CursorState cursor_state = doc_ctrl->get_cursor_state();
	
	if(cursor_state == Document::CSTATE_ASCII)
	{
		/* Paste into ASCII view, handle as string of characters. */
		
		paste_data((const unsigned char*)(text.data()), text.size());
	}
	else{
		/* Paste into hex view, handle as hex string of bytes. */
		
		try {
			std::vector<unsigned char> clipboard_data = REHex::parse_hex_string(text);
			paste_data(clipboard_data.data(), clipboard_data.size());
		}
		catch(const REHex::ParseError &e)
		{
			/* Ignore paste if clipboard didn't contain a valid hex string. */
		}
	}
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

void REHex::Tab::OnSize(wxSizeEvent &event)
{
	if(h_splitter->IsSplit())
	{
		int hs_sp = h_splitter->GetSashPosition();
		int hs_cp = hsplit_clamp_sash(hs_sp);
		
		if(hs_sp != hs_cp)
		{
			h_splitter->SetSashPosition(hs_cp);
		}
	}
	
	if(v_splitter->IsSplit())
	{
		int vs_sp = v_splitter->GetSashPosition();
		int vs_cp = vsplit_clamp_sash(vs_sp);
		
		if(vs_sp != vs_cp)
		{
			v_splitter->SetSashPosition(vs_cp);
		}
	}
	
	/* Continue propogation of EVT_SIZE event. */
	event.Skip();
}

void REHex::Tab::OnHToolChange(wxNotebookEvent& event)
{
	htools_adjust();
}

void REHex::Tab::OnVToolChange(wxBookCtrlEvent &event)
{
	vtools_adjust();
}

void REHex::Tab::OnHSplitterSashPosChanging(wxSplitterEvent &event)
{
	int pos = event.GetSashPosition();
	int clamp = hsplit_clamp_sash(pos);
	
	if(pos != clamp)
	{
		event.SetSashPosition(clamp);
	}
}

void REHex::Tab::OnVSplitterSashPosChanging(wxSplitterEvent &event)
{
	int pos = event.GetSashPosition();
	int clamp = vsplit_clamp_sash(pos);
	
	if(pos != clamp)
	{
		event.SetSashPosition(clamp);
	}
}

void REHex::Tab::OnSearchDialogDestroy(wxWindowDestroyEvent &event)
{
	search_dialogs.erase((wxDialog*)(event.GetWindow()));
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::Tab::OnDocumentCtrlChar(wxKeyEvent &event)
{
	int key       = event.GetKeyCode();
	int modifiers = event.GetModifiers();
	
	off_t cursor_pos = doc_ctrl->get_cursor_position();
	
	auto selection = doc_ctrl->get_selection();
	off_t selection_off = selection.first;
	off_t selection_length = selection.second;
	
	bool insert_mode = doc_ctrl->get_insert_mode();
	
	Document::CursorState cursor_state = doc_ctrl->get_cursor_state();
	
	if(cursor_state != Document::CSTATE_ASCII && (modifiers == wxMOD_NONE || modifiers == wxMOD_SHIFT) && isasciihex(key))
	{
		unsigned char nibble = REHex::parse_ascii_nibble(key);
		
		if(cursor_state == Document::CSTATE_HEX_MID)
		{
			/* Overwrite least significant nibble of current byte, then move onto
			 * inserting or overwriting at the next byte.
			*/
			
			std::vector<unsigned char> cur_data = doc->read_data(cursor_pos, 1);
			assert(cur_data.size() == 1);
			
			unsigned char old_byte = cur_data[0];
			unsigned char new_byte = (old_byte & 0xF0) | nibble;
			
			doc->overwrite_data(cursor_pos, &new_byte, 1, cursor_pos + 1, Document::CSTATE_HEX, "change data");
		}
		else if(insert_mode)
		{
			/* Inserting a new byte. Initialise the most significant nibble then move
			 * onto overwriting the least significant.
			*/
			
			unsigned char byte = (nibble << 4);
			doc->insert_data(cursor_pos, &byte, 1, cursor_pos, Document::CSTATE_HEX_MID, "change data");
		}
		else{
			/* Overwrite most significant nibble of current byte, then move onto
			 * overwriting the least significant.
			*/
			
			std::vector<unsigned char> cur_data = doc->read_data(cursor_pos, 1);
			
			if(!cur_data.empty())
			{
				unsigned char old_byte = cur_data[0];
				unsigned char new_byte = (old_byte & 0x0F) | (nibble << 4);
				
				doc->overwrite_data(cursor_pos, &new_byte, 1, cursor_pos, Document::CSTATE_HEX_MID, "change data");
			}
		}
		
		doc_ctrl->clear_selection();
		
		return;
	}
	else if(cursor_state == Document::CSTATE_ASCII && (modifiers == wxMOD_NONE || modifiers == wxMOD_SHIFT) && isasciiprint(key))
	{
		unsigned char byte = key;
		
		if(insert_mode)
		{
			doc->insert_data(cursor_pos, &byte, 1, cursor_pos + 1, Document::CSTATE_ASCII, "change data");
		}
		else if(cursor_pos < doc->buffer_length())
		{
			std::vector<unsigned char> cur_data = doc->read_data(cursor_pos, 1);
			assert(cur_data.size() == 1);
			
			doc->overwrite_data(cursor_pos, &byte, 1, cursor_pos + 1, Document::CSTATE_ASCII, "change data");
		}
		
		doc_ctrl->clear_selection();
		
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
				doc->erase_data(selection_off, selection_length, (selection_off - 1), Document::CSTATE_GOTO, "delete selection");
				doc_ctrl->clear_selection();
			}
			else if((cursor_pos + 1) < doc->buffer_length())
			{
				doc->erase_data(cursor_pos, 1, cursor_pos, Document::CSTATE_GOTO, "delete");
			}
			else if(cursor_pos < doc->buffer_length())
			{
				doc->erase_data(cursor_pos, 1, (cursor_pos - 1), Document::CSTATE_GOTO, "delete");
			}
			
			return;
		}
		else if(key == WXK_BACK)
		{
			if(selection_length > 0)
			{
				doc->erase_data(selection_off, selection_length, (selection_off - 1), Document::CSTATE_GOTO, "delete selection");
				doc_ctrl->clear_selection();
			}
			else if(cursor_state == Document::CSTATE_HEX_MID)
			{
				/* Backspace while waiting for the second nibble in a byte should erase the current byte
				 * rather than the previous one.
				*/
				doc->erase_data(cursor_pos, 1, (cursor_pos - 1), Document::CSTATE_HEX, "delete");
			}
			else if(cursor_pos > 0)
			{
				doc->erase_data((cursor_pos - 1), 1, (cursor_pos - 1), Document::CSTATE_GOTO, "delete");
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

void REHex::Tab::OnCommentLeftClick(OffsetLengthEvent &event)
{
	EditCommentDialog::run_modal(this, doc, event.offset, event.length);
}

void REHex::Tab::OnCommentRightClick(OffsetLengthEvent &event)
{
	off_t c_offset = event.offset;
	off_t c_length = event.length;
	
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
	
	menu.AppendSeparator();
	
	wxMenuItem *copy_comments = menu.Append(wxID_ANY,  "&Copy comment(s)");
	menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
	{
		ClipboardGuard cg;
		if(cg)
		{
			const NestedOffsetLengthMap<Document::Comment> &comments = doc->get_comments();
			
			auto selected_comments = NestedOffsetLengthMap_get_recursive(comments, NestedOffsetLengthMapKey(c_offset, c_length));
			assert(selected_comments.size() > 0);
			
			wxTheClipboard->SetData(new CommentsDataObject(selected_comments, c_offset));
		}
	}, copy_comments->GetId(), copy_comments->GetId());
	
	PopupMenu(&menu);
}

void REHex::Tab::OnDataRightClick(wxCommandEvent &event)
{
	off_t cursor_pos = doc_ctrl->get_cursor_position();
	
	auto selection = doc_ctrl->get_selection();
	off_t selection_off = selection.first;
	off_t selection_length = selection.second;
	
	const NestedOffsetLengthMap<Document::Comment> &comments   = doc->get_comments();
	const NestedOffsetLengthMap<int>               &highlights = doc->get_highlights();
	
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
	
	auto comments_at_cur = NestedOffsetLengthMap_get_all(comments, cursor_pos);
	for(auto i = comments_at_cur.begin(); i != comments_at_cur.end(); ++i)
	{
		auto ci = *i;
		
		wxString text = ci->second.menu_preview();
		wxMenuItem *itm = menu.Append(wxID_ANY, wxString("Edit \"") + text + "\"...");
		
		menu.Bind(wxEVT_MENU, [this, ci](wxCommandEvent &event)
		{
			EditCommentDialog::run_modal(this, doc, ci->first.offset, ci->first.length);
		}, itm->GetId(), itm->GetId());
	}
	
	if(comments.find(NestedOffsetLengthMapKey(cursor_pos, 0)) == comments.end()
		&& cursor_pos < doc->buffer_length())
	{
		wxMenuItem *itm = menu.Append(wxID_ANY, "Insert comment here...");
		
		menu.Bind(wxEVT_MENU, [this, cursor_pos](wxCommandEvent &event)
		{
			EditCommentDialog::run_modal(this, doc, cursor_pos, 0);
		}, itm->GetId(), itm->GetId());
	}
	
	if(selection_length > 0
		&& comments.find(NestedOffsetLengthMapKey(selection_off, selection_length)) == comments.end()
		&& NestedOffsetLengthMap_can_set(comments, selection_off, selection_length))
	{
		char menu_label[64];
		snprintf(menu_label, sizeof(menu_label), "Set comment on %" PRId64 " bytes...", (int64_t)(selection_length));
		wxMenuItem *itm =  menu.Append(wxID_ANY, menu_label);
		
		menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
		{
			EditCommentDialog::run_modal(this, doc, selection_off, selection_length);
		}, itm->GetId(), itm->GetId());
	}
	
	menu.AppendSeparator();
	
	/* We need to maintain bitmap instances for lifespan of menu. */
	std::list<wxBitmap> bitmaps;
	
	off_t highlight_off;
	off_t highlight_length = 0;
	
	auto highlight_at_cur = NestedOffsetLengthMap_get(highlights, cursor_pos);
	
	if(selection_length > 0)
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
	
	if(highlight_length > 0 && NestedOffsetLengthMap_can_set(highlights, highlight_off, highlight_length))
	{
		wxMenu *hlmenu = new wxMenu();
		
		for(int i = 0; i < Palette::NUM_HIGHLIGHT_COLOURS; ++i)
		{
			wxMenuItem *itm = new wxMenuItem(hlmenu, wxID_ANY, " ");
			
			wxColour bg_colour = active_palette->get_highlight_bg(i);
			
			/* TODO: Get appropriate size for menu bitmap.
			 * TODO: Draw a character in image using foreground colour.
			*/
			wxImage img(16, 16);
			img.SetRGB(wxRect(0, 0, img.GetWidth(), img.GetHeight()),
				bg_colour.Red(), bg_colour.Green(), bg_colour.Blue());
			
			bitmaps.emplace_back(img);
			itm->SetBitmap(bitmaps.back());
			
			hlmenu->Append(itm);
			
			/* On Windows, event bindings on a submenu don't work.
			 * On OS X, event bindings on a parent menu don't work.
			 * On GTK, both work.
			*/
			#ifdef _WIN32
			menu.Bind(wxEVT_MENU, [this, highlight_off, highlight_length, i](wxCommandEvent &event)
			#else
			hlmenu->Bind(wxEVT_MENU, [this, highlight_off, highlight_length, i](wxCommandEvent &event)
			#endif
			{
				int colour = i;
				doc->set_highlight(highlight_off, highlight_length, colour);
			}, itm->GetId(), itm->GetId());
		}
		
		menu.AppendSubMenu(hlmenu, "Set Highlight");
	}
	
	if(highlight_at_cur != highlights.end())
	{
		wxMenuItem *itm = menu.Append(wxID_ANY, "Remove Highlight");
		
		NestedOffsetLengthMapKey key = highlight_at_cur->first;
		
		menu.Bind(wxEVT_MENU, [this, key](wxCommandEvent &event)
		{
			doc->erase_highlight(key.offset, key.length);
		}, itm->GetId(), itm->GetId());
	}
	
	if(selection_length > 0)
	{
		menu.AppendSeparator();
		wxMenuItem *itm = menu.Append(wxID_ANY, "Compare...");
		
		menu.Bind(wxEVT_MENU, [this, selection_off, selection_length](wxCommandEvent &event)
		{
			static DiffWindow *diff_window = NULL;
			if(diff_window == NULL)
			{
				/* Parent DiffWindow to our parent so it can outlive us but not the MainWindow. */
				diff_window = new DiffWindow(GetParent());
				
				diff_window->Bind(wxEVT_DESTROY, [](wxWindowDestroyEvent &event)
				{
					if(event.GetWindow() == diff_window)
					{
						diff_window = NULL;
					}
				});
				
				diff_window->Show(true);
			}
			
			diff_window->add_range(DiffWindow::Range(doc, doc_ctrl, selection_off, selection_length));
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
	doc_ctrl->set_cursor_position(event.cursor_pos, event.cursor_state);
	event.Skip();
}

void REHex::Tab::OnDocumentCtrlCursorUpdate(CursorUpdateEvent &event)
{
	doc->set_cursor_position(event.cursor_pos, event.cursor_state);
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

int REHex::Tab::hsplit_clamp_sash(int sash_position)
{
	/* Prevent the user resizing a tool panel beyond its min/max size.
	 * NOTE: Minimuim size is clamped >= 0 to prevent the size shrinking past the wxNotebook
	 * control itself, else weird rendering/input glitches happen.
	*/
	
	wxWindow *ht_current_page = h_tools->GetCurrentPage();
	if(ht_current_page == NULL)
	{
		/* No active page to reference. */
		return sash_position;
	}
	
	int htp_mh = std::max(ht_current_page->GetMinSize().GetHeight(), 0);
	int htp_Mh = ht_current_page->GetMaxSize().GetHeight();
	
	int hs_ch = h_splitter->GetClientSize().GetHeight();
	int hs_ss = h_splitter->GetSashSize();
	
	/* Size oherhead added by h_tools wxNotebook. */
	int extra_h = h_tools->GetSize().GetHeight() - ht_current_page->GetSize().GetHeight();
	
	int sash_max = hs_ch - (htp_mh + extra_h + hs_ss);
	if(sash_position > sash_max)
	{
		return sash_max;
	}
	
	if(htp_Mh > 0)
	{
		int sash_min = hs_ch - (htp_Mh + extra_h + hs_ss);
		if(sash_position < sash_min)
		{
			return sash_min;
		}
	}
	
	return sash_position;
}

int REHex::Tab::vsplit_clamp_sash(int sash_position)
{
	/* Prevent the user resizing a tool panel beyond its min/max size.
	 * NOTE: Minimuim size is clamped >= 0 to prevent the size shrinking past the wxNotebook
	 * control itself, else weird rendering/input glitches happen.
	*/
	
	wxWindow *vt_current_page = v_tools->GetCurrentPage();
	if(vt_current_page == NULL)
	{
		/* No active page to reference. */
		return sash_position;
	}
	
	int vtp_mw = std::max(vt_current_page->GetMinSize().GetWidth(), 0);
	int vtp_Mw = vt_current_page->GetMaxSize().GetWidth();
	
	int vs_cw = v_splitter->GetClientSize().GetWidth();
	int vs_ss = v_splitter->GetSashSize();
	
	/* Size overhead added by v_tools wxNotebook. */
	int extra_w = v_tools->GetSize().GetWidth() - vt_current_page->GetSize().GetWidth();
	
	int sash_max = vs_cw - (vtp_mw + extra_w + vs_ss);
	if(sash_position > sash_max)
	{
		return sash_max;
	}
	
	if(vtp_Mw > 0)
	{
		int sash_min = vs_cw - (vtp_Mw + extra_w + vs_ss);
		if(sash_position < sash_min)
		{
			return sash_min;
		}
	}
	
	return sash_position;
}

void REHex::Tab::vtools_adjust()
{
	wxWindow *vt_current_page = v_tools->GetCurrentPage();
	
	if(vt_current_page == NULL || !vt_current_page->IsShown())
	{
		/* Vertical tool pane has no pages, or the page is hidden. Hide it. */
		if(v_splitter->IsSplit())
		{
			v_splitter->Unsplit();
		}
	}
	else{
		if(!v_splitter->IsSplit())
		{
			v_splitter->SplitVertically(h_splitter, v_tools);
		}
		
		int vtp_bw = std::max(vt_current_page->GetBestSize().GetWidth(), 0);
		
		/* Size overhead added by v_tools wxNotebook. */
		int extra_w = v_tools->GetSize().GetWidth() - vt_current_page->GetSize().GetWidth();
		
		/* Set the current position of the splitter to display the best size of the current
		 * page and overhead.
		*/
		int vs_cw = v_splitter->GetClientSize().GetWidth();
		v_splitter->SetSashPosition(vs_cw - (vtp_bw + extra_w + v_splitter->GetSashSize()));
	}
}

void REHex::Tab::htools_adjust()
{
	wxWindow *ht_current_page = h_tools->GetCurrentPage();
	
	if(ht_current_page == NULL || !ht_current_page->IsShown())
	{
		/* Horizontal tool pane has no pages, or the page is hidden. Hide it. */
		if(h_splitter->IsSplit())
		{
			h_splitter->Unsplit();
		}
	}
	else{
		if(!h_splitter->IsSplit())
		{
			h_splitter->SplitHorizontally(doc_ctrl, h_tools);
		}
		
		int htp_bh = std::max(ht_current_page->GetBestSize().GetHeight(), 0);
		
		/* Size overhead added by h_tools wxNotebook. */
		int extra_h = h_tools->GetSize().GetHeight() - ht_current_page->GetSize().GetHeight();
		
		/* Set the sash position to display the tool page's best size. */
		int hs_ch = h_splitter->GetClientSize().GetHeight();
		h_splitter->SetSashPosition(hs_ch - (htp_bh + extra_h + h_splitter->GetSashSize()));
	}
}

/* The size of a wxNotebook page doesn't seem to be set correctly during
 * initialisation (or immediately after adding a page), so we can't use it to
 * determine how much size overhead the wxNotebook adds at that point. Instead
 * we defer setting of the tool pane sizes until the first idle tick, by which
 * point the sizes seem to have been set up properly (on GTK anyway).
*/

void REHex::Tab::vtools_adjust_on_idle()
{
	Bind(wxEVT_IDLE, &REHex::Tab::vtools_adjust_now_idle, this);
}

void REHex::Tab::vtools_adjust_now_idle(wxIdleEvent &event)
{
	Unbind(wxEVT_IDLE, &REHex::Tab::vtools_adjust_now_idle, this);
	event.Skip();
	
	vtools_adjust();
}

void REHex::Tab::htools_adjust_on_idle()
{
	Bind(wxEVT_IDLE, &REHex::Tab::htools_adjust_now_idle, this);
}

void REHex::Tab::htools_adjust_now_idle(wxIdleEvent &event)
{
	Unbind(wxEVT_IDLE, &REHex::Tab::htools_adjust_now_idle, this);
	event.Skip();
	
	htools_adjust();
}

void REHex::Tab::init_default_doc_view()
{
	wxConfig *config = wxGetApp().config;
	config->SetPath("/default-view/");
	
	doc_ctrl->set_bytes_per_line(             config->Read    ("bytes-per-line",             doc_ctrl->get_bytes_per_line()));
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
}

void REHex::Tab::init_default_tools()
{
	wxConfig *config = wxGetApp().config;
	
	/* TODO: Load h_tools state. */
	
	for(unsigned int i = 0;; ++i)
	{
		char base_p[64];
		snprintf(base_p, sizeof(base_p), "/default-view/vtools/panels/0/tab/%u/", i);
		
		if(config->HasGroup(base_p))
		{
			config->SetPath(base_p);
			
			std::string name = config->Read    ("name", "").ToStdString();
			bool selected    = config->ReadBool("selected", false);
			
			if(ToolPanelRegistry::by_name(name) != NULL)
			{
				tool_create(name, selected, config, false);
			}
			else{
				/* TODO: Some kind of warning? */
			}
		}
		else{
			break;
		}
	}
}

void REHex::Tab::repopulate_regions()
{
	if(inline_comment_mode == ICM_HIDDEN)
	{
		/* Inline comments are hidden. Just show a single big data region. */
		
		std::list<DocumentCtrl::Region*> regions;
		regions.push_back(new DocumentCtrl::DataRegionDocHighlight(0, doc->buffer_length(), *doc));
		doc_ctrl->replace_all_regions(regions);
		
		return;
	}
	
	auto comments = doc->get_comments();
	
	bool nest = (inline_comment_mode == ICM_SHORT_INDENT || inline_comment_mode == ICM_FULL_INDENT);
	bool truncate = (inline_comment_mode == ICM_SHORT || inline_comment_mode == ICM_SHORT_INDENT);
	
	/* Construct a list of interlaced comment/data regions. */
	
	auto offset_base = comments.begin();
	off_t next_data = 0, remain_data = doc->buffer_length();
	
	std::list<DocumentCtrl::Region*> regions;
	std::stack<off_t> dr_limit;
	
	while(remain_data > 0)
	{
		assert(offset_base == comments.end() || offset_base->first.offset >= next_data);
		
		/* We process any comments at the same offset from largest to smallest, ensuring
		 * smaller comments are parented to the next-larger one at the same offset.
		 *
		 * This could be optimised by changing the order of keys in the comments map, but
		 * that'll probably break something...
		*/
		
		if(offset_base != comments.end() && offset_base->first.offset == next_data)
		{
			auto next_offset = offset_base;
			while(next_offset != comments.end() && next_offset->first.offset == offset_base->first.offset)
			{
				++next_offset;
			}
			
			auto c = next_offset;
			do {
				--c;
				
				regions.push_back(new DocumentCtrl::CommentRegion(c->first.offset, c->first.length, *(c->second.text), nest, truncate));
				
				if(nest && c->first.length > 0)
				{
					assert(dr_limit.empty() || dr_limit.top() >= c->first.offset + c->first.length);
					dr_limit.push(c->first.offset + c->first.length);
				}
			} while(c != offset_base);
			
			offset_base = next_offset;
		}
		
		off_t dr_length = remain_data;
		
		if(offset_base != comments.end() && dr_length > (offset_base->first.offset - next_data))
		{
			dr_length = offset_base->first.offset - next_data;
		}
		
		while(!dr_limit.empty() && (next_data + dr_length) >= dr_limit.top())
		{
			assert(dr_limit.top() > next_data);
			
			dr_length = dr_limit.top() - next_data;
			dr_limit.pop();
		}
		
		regions.push_back(new DocumentCtrl::DataRegionDocHighlight(next_data, dr_length, *doc));
		
		next_data   += dr_length;
		remain_data -= dr_length;
	}
	
	if(regions.empty())
	{
		assert(doc->buffer_length() == 0);
		
		/* Empty buffers need a data region too! */
		regions.push_back(new DocumentCtrl::DataRegionDocHighlight(0, 0, *doc));
	}
	
	doc_ctrl->replace_all_regions(regions);
}
