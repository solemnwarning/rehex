/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2022 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <exception>
#include <inttypes.h>
#include <stack>
#include <tuple>
#include <vector>
#include <wx/clipbrd.h>
#include <wx/dataobj.h>
#include <wx/sizer.h>

#include "App.hpp"
#include "DataType.hpp"
#include "DiffWindow.hpp"
#include "CharacterEncoder.hpp"
#include "EditCommentDialog.hpp"
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
	doc(SharedDocumentPointer::make()),
	inline_comment_mode(ICM_FULL_INDENT),
	document_display_mode(DDM_NORMAL),
	vtools_adjust_pending(false),
	vtools_adjust_force(false),
	vtools_initial_size(-1),
	htools_adjust_pending(false),
	htools_adjust_force(false),
	htools_initial_size(-1),
	repopulate_regions_frozen(false),
	repopulate_regions_pending(false)
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
	doc.auto_cleanup_bind(EV_TYPES_CHANGED,       &REHex::Tab::OnDocumentDataTypesChanged,  this);
	doc.auto_cleanup_bind(EV_MAPPINGS_CHANGED,    &REHex::Tab::OnDocumentMappingsChanged,   this);
	
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
	
	htools_adjust_on_idle(true);
	vtools_adjust_on_idle(true);
	
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
	vtools_adjust_pending(false),
	vtools_adjust_force(false),
	vtools_initial_size(-1),
	htools_adjust_pending(false),
	htools_adjust_force(false),
	htools_initial_size(-1),
	repopulate_regions_frozen(false),
	repopulate_regions_pending(false)
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
	doc.auto_cleanup_bind(EV_TYPES_CHANGED,       &REHex::Tab::OnDocumentDataTypesChanged,  this);
	doc.auto_cleanup_bind(EV_MAPPINGS_CHANGED,    &REHex::Tab::OnDocumentMappingsChanged,   this);
	
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
	
	vtools_adjust_on_idle(true);
	htools_adjust_on_idle(true);
	
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
	return tools.find(name) != tools.end();
}

void REHex::Tab::tool_create(const std::string &name, bool switch_to, wxConfig *config)
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
		
		xtools_fix_visibility(v_tools);
		vtools_adjust_on_idle(false);
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
		
		xtools_fix_visibility(h_tools);
		htools_adjust_on_idle(false);
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
	
	xtools_fix_visibility(notebook);
	
	if(notebook == v_tools)
	{
		vtools_adjust();
	}
	else if(notebook == h_tools)
	{
		htools_adjust();
	}
}

REHex::ToolPanel *REHex::Tab::tool_get(const std::string &name)
{
	auto t = tools.find(name);
	if(t != tools.end())
	{
		return t->second;
	}
	else{
		return NULL;
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
	// Ensure we are in the correct node
	config->SetPath("/default-view/");
	
	config->Write("bytes-per-line", doc_ctrl->get_bytes_per_line());
	config->Write("bytes-per-group", doc_ctrl->get_bytes_per_group());
	config->Write("show-offsets", doc_ctrl->get_show_offsets());
	config->Write("show-ascii", doc_ctrl->get_show_ascii());
	config->Write("inline-comments", (int)(inline_comment_mode));
	config->Write("highlight-selection-match", doc_ctrl->get_highlight_selection_match());
	config->Write("offset-display-base", (int)(doc_ctrl->get_offset_display_base()));
	
	wxWindow *ht_current_page = h_tools->GetCurrentPage();
	if(ht_current_page != NULL)
	{
		config->SetPath("/default-view/htools/");
		config->Write("height", ht_current_page->GetSize().y);
	}
	
	for(size_t i = 0; i < h_tools->GetPageCount(); ++i)
	{
		char path[64];
		snprintf(path, sizeof(path), "/default-view/htools/panels/0/tab/%u/", (unsigned)(i));
		
		config->SetPath(path);
		
		wxWindow *page = h_tools->GetPage(i);
		assert(page != NULL);
		
		ToolPanel *tp = dynamic_cast<ToolPanel*>(page);
		assert(tp != NULL);
		
		config->Write("name", wxString(tp->name()));
		config->Write("selected", (page == h_tools->GetCurrentPage()));
		tp->save_state(config);
	}
	
	wxWindow *vt_current_page = v_tools->GetCurrentPage();
	if(vt_current_page != NULL)
	{
		config->SetPath("/default-view/vtools/");
		config->Write("width", vt_current_page->GetSize().x);
	}
	
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
	copy_from_doc(doc, doc_ctrl, this, cut);
}

void REHex::Tab::paste_text(const std::string &text)
{
	auto paste_data = [this](const unsigned char* data, size_t size)
	{
		off_t cursor_pos = doc_ctrl->get_cursor_position();
		bool insert_mode = doc_ctrl->get_insert_mode();
		
		off_t selection_off, selection_length;
		std::tie(selection_off, selection_length) = doc_ctrl->get_selection_linear();
		bool has_selection = doc_ctrl->has_selection();
		
		if(selection_length > 0)
		{
			/* Some data is selected, replace it. */
			
			doc->replace_data(selection_off, selection_length, data, size, selection_off + size, Document::CSTATE_GOTO, "paste");
			doc_ctrl->clear_selection();
		}
		else if(has_selection)
		{
			/* Nonlinear selection. */
			wxBell();
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
	
	auto paste_text = [this](const std::string &utf8_text)
	{
		off_t cursor_pos = doc_ctrl->get_cursor_position();
		bool insert_mode = doc_ctrl->get_insert_mode();
		
		off_t selection_off, selection_length;
		std::tie(selection_off, selection_length) = doc_ctrl->get_selection_linear();
		bool has_selection = doc_ctrl->has_selection();
		
		int write_flag;
		
		if(selection_length > 0)
		{
			/* Some data is selected, replace it. */
			
			write_flag = doc->replace_text(selection_off, selection_length, utf8_text, Document::WRITE_TEXT_GOTO_NEXT, Document::CSTATE_GOTO, "paste");
			doc_ctrl->clear_selection();
		}
		else if(has_selection)
		{
			/* Nonlinear selection. */
			write_flag = Document::WRITE_TEXT_BAD_OFFSET;
		}
		else if(insert_mode)
		{
			/* We are in insert mode, insert at the cursor. */
			write_flag = doc->insert_text(cursor_pos, utf8_text, Document::WRITE_TEXT_GOTO_NEXT, Document::CSTATE_GOTO, "paste");
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
	off_t selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection_linear();
	
	if(selection_length > 0)
	{
		compare_range(selection_off, selection_length);
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
	if (event.GetOldSelection() != wxNOT_FOUND)
	{
		wxWindow* page = h_tools->GetPage(event.GetOldSelection());
		assert(page != NULL);
		
		ToolPanel* tp = dynamic_cast<ToolPanel*>(page);
		assert(tp != NULL);
		tp->set_visible(false);
	}
	
	if (event.GetSelection() != wxNOT_FOUND)
	{
		wxWindow* page = h_tools->GetPage(event.GetSelection());
		assert(page != NULL);
		
		ToolPanel* tp = dynamic_cast<ToolPanel*>(page);
		assert(tp != NULL);
		tp->set_visible(true);
	}
	
	htools_adjust_on_idle(false);
}

void REHex::Tab::OnVToolChange(wxBookCtrlEvent &event)
{
	if (event.GetOldSelection() != wxNOT_FOUND)
	{
		wxWindow* page = v_tools->GetPage(event.GetOldSelection());
		assert(page != NULL);

		ToolPanel* tp = dynamic_cast<ToolPanel*>(page);
		assert(tp != NULL);
		tp->set_visible(false);
	}
	
	if (event.GetSelection() != wxNOT_FOUND)
	{
		wxWindow* page = v_tools->GetPage(event.GetSelection());
		assert(page != NULL);

		ToolPanel* tp = dynamic_cast<ToolPanel*>(page);
		assert(tp != NULL);
		tp->set_visible(true);
	}
	
	vtools_adjust_on_idle(false);
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
	if(doc_ctrl->region_OnChar(event))
	{
		/* Key press handled by cursor region. */
		return;
	}
	
	int key       = event.GetKeyCode();
	wxChar ukey   = event.GetUnicodeKey();
	int modifiers = event.GetModifiers();
	
	off_t cursor_pos = doc_ctrl->get_cursor_position();
	
	off_t selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection_linear();
	bool has_selection = doc_ctrl->has_selection();
	
	bool insert_mode = doc_ctrl->get_insert_mode();
	
	Document::CursorState cursor_state = doc_ctrl->get_cursor_state();
	
	if(doc_ctrl->hex_view_active() && (modifiers == wxMOD_NONE || modifiers == wxMOD_SHIFT) && isasciihex(key))
	{
		unsigned char nibble = REHex::parse_ascii_nibble(key);
		
		if(cursor_state == Document::CSTATE_HEX_MID)
		{
			/* Overwrite least significant nibble of current byte, then move onto
			 * inserting or overwriting at the next byte.
			*/
			
			std::vector<unsigned char> cur_data;
			try {
				cur_data = doc->read_data(cursor_pos, 1);
				assert(cur_data.size() == 1);
			}
			catch(const std::exception &e)
			{
				wxGetApp().printf_error("Exception in REHex::Tab::OnDocumentCtrlChar: %s\n", e.what());
				return;
			}
			
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
			
			std::vector<unsigned char> cur_data;
			try {
				cur_data = doc->read_data(cursor_pos, 1);
			}
			catch(const std::exception &e)
			{
				wxGetApp().printf_error("Exception in REHex::Tab::OnDocumentCtrlChar: %s\n", e.what());
				return;
			}
			
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
	else if(doc_ctrl->ascii_view_active() && (modifiers == wxMOD_NONE || modifiers == wxMOD_SHIFT) && ukey != WXK_NONE && key != '\t')
	{
		wxCharBuffer utf8_buf = wxString(wxUniChar(ukey)).utf8_str();
		std::string utf8_key(utf8_buf.data(), utf8_buf.length());
		
		if(insert_mode)
		{
			doc->insert_text(cursor_pos, utf8_key, Document::WRITE_TEXT_GOTO_NEXT, Document::CSTATE_ASCII);
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
				doc->erase_data(selection_off, selection_length, selection_off, Document::CSTATE_GOTO, "delete selection");
				doc_ctrl->clear_selection();
			}
			else if(has_selection)
			{
				/* Nonlinear selection. */
				wxBell();
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
				doc->erase_data(selection_off, selection_length, selection_off, Document::CSTATE_GOTO, "delete selection");
				doc_ctrl->clear_selection();
			}
			else if(has_selection)
			{
				/* Nonlinear selection. */
				wxBell();
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
	off_t c_offset = event.offset;
	off_t c_length = event.length;
	
	if(c_offset < 0)
	{
		return;
	}
	
	EditCommentDialog::run_modal(this, doc, c_offset, c_length);
}

void REHex::Tab::OnCommentRightClick(OffsetLengthEvent &event)
{
	off_t c_offset = event.offset;
	off_t c_length = event.length;
	
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
	
	off_t selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection_linear();
	
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
			/* Hardcoded list of names for the highlight colours.
			 * This will need to be done better soon... but for now all the highlight
			 * colours used in each pallette are the same and we don't have any more
			 * specific names for them (#60).
			*/
			static const char *highlight_strings[] = {
				"Red",
				"Orange",
				"Yellow",
				"Green",
				"Violet",
				"Grey",
			};
			
			wxMenuItem *itm = new wxMenuItem(hlmenu, wxID_ANY, highlight_strings[i]);
			
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
		const ByteRangeMap<std::string> &data_types = doc->get_data_types();
		
		auto selection_off_type = data_types.get_range(selection_off);
		assert(selection_off_type != data_types.end());
		
		/* "Set data type" > */
		
		wxMenu *dtmenu = new wxMenu();
		
		wxMenuItem *data_itm = dtmenu->AppendCheckItem(wxID_ANY, "Data");
		
		if((selection_off_type->first.offset + selection_off_type->first.length) >= (selection_off + selection_length)
			&& selection_off_type->second == "")
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
			const DataTypeRegistration *dt = *dti;
			
			if(dt->fixed_size >= 0 && (selection_length % dt->fixed_size) != 0)
			{
				/* Selection is too short/long for this type. */
				continue;
			}
			
			wxMenu *group_menu = dtmenu;
			
			{
				auto g = dt->groups.begin();
				auto p = group_menus.begin();
				
				for(; g != dt->groups.end(); ++g, ++p)
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
			
			if(group_menus.size() > dt->groups.size())
			{
				group_menus.erase(std::next(group_menus.begin(), dt->groups.size()), group_menus.end());
			}
			
			wxMenuItem *itm = group_menu->AppendCheckItem(wxID_ANY, dt->label);
			
			if((selection_off_type->first.offset + selection_off_type->first.length) >= (selection_off + selection_length)
				&& selection_off_type->second == dt->name)
			{
				itm->Check(true);
			}
			
			#ifdef _WIN32
			menu.Bind(wxEVT_MENU, [this, dt, selection_off, selection_length](wxCommandEvent &event)
			#else
			group_menu->Bind(wxEVT_MENU, [this, dt, selection_off, selection_length](wxCommandEvent &event)
			#endif
			{
				doc->set_data_type(selection_off, selection_length, dt->name);
			}, itm->GetId(), itm->GetId());
		}
		
		menu.AppendSubMenu(dtmenu, "Set data type");
		
		wxMenuItem *vm_itm = menu.Append(wxID_ANY, "Set virtual address mapping...");
		
		menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
		{
			VirtualMappingDialog d(this, doc, selection_off, selection_length);
			d.ShowModal();
		}, vm_itm->GetId(), vm_itm->GetId());
	}
	
	menu.AppendSeparator();
	
	{
		wxMenuItem *itm = menu.Append(wxID_ANY, "Compare selection...\tCtrl-Shift-K");
		itm->Enable(selection_length > 0);
		
		menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
		{
			compare_range(selection_off, selection_length);
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
	}
	
	event.Skip();
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

void REHex::Tab::vtools_adjust(bool force_resize)
{
	if(vtools_adjust_pending)
	{
		vtools_adjust_on_idle(force_resize);
		return;
	}
	
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
			
			vtools_adjust_on_idle(true);
			return;
		}
		
		int vtp_bw = std::max(vt_current_page->GetBestSize().GetWidth(), 0);
		int vtp_mw = vt_current_page->GetMinSize().GetWidth();
		int vtp_Mw = vt_current_page->GetMaxSize().GetWidth();
		
		int vtp_cw = vt_current_page->GetSize().GetWidth();
		
		if(vtools_initial_size > 0)
		{
			/* Adjust sash to fit saved ToolPanel size. */
			
			int adj_width = vtools_initial_size - vtp_cw;
			v_splitter->SetSashPosition(v_splitter->GetSashPosition() - adj_width);
		}
		else if(force_resize)
		{
			/* Adjust sash to fit ToolPanel best size. */
			
			int adj_width = vtp_bw - vtp_cw;
			v_splitter->SetSashPosition(v_splitter->GetSashPosition() - adj_width);
		}
		else if(vtp_mw > 0 && vtp_cw < vtp_mw)
		{
			/* Adjust sash to fit ToolPanel minimum size. */
			
			int adj_width = vtp_mw - vtp_cw;
			v_splitter->SetSashPosition(v_splitter->GetSashPosition() - adj_width);
		}
		else if(vtp_Mw > 0 && vtp_cw > vtp_Mw)
		{
			/* Adjust sash to fit ToolPanel maximum size. */
			
			int adj_width = vtp_Mw - vtp_cw;
			v_splitter->SetSashPosition(v_splitter->GetSashPosition() - adj_width);
		}
	}
	
	vtools_adjust_force = false;
	vtools_initial_size = -1;
}

void REHex::Tab::htools_adjust(bool force_resize)
{
	if(htools_adjust_pending)
	{
		htools_adjust_on_idle(force_resize);
		return;
	}
	
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
			
			htools_adjust_on_idle(true);
			return;
		}
		
		int htp_bh = std::max(ht_current_page->GetBestSize().GetHeight(), 0);
		int htp_mh = ht_current_page->GetMinSize().GetHeight();
		int htp_Mh = ht_current_page->GetMaxSize().GetHeight();
		
		int htp_ch = ht_current_page->GetSize().GetHeight();
		
		if(htools_initial_size > 0)
		{
			/* Adjust sash to fit saved ToolPanel size. */
			
			int adj_height = htools_initial_size - htp_ch;
			h_splitter->SetSashPosition(h_splitter->GetSashPosition() - adj_height);
		}
		else if(force_resize)
		{
			/* Adjust sash to fit ToolPanel best size. */
			
			int adj_height = htp_bh - htp_ch;
			h_splitter->SetSashPosition(h_splitter->GetSashPosition() - adj_height);
		}
		else if(htp_mh > 0 && htp_ch < htp_mh)
		{
			/* Adjust sash to fit ToolPanel minimum size. */
			
			int adj_height = htp_mh - htp_ch;
			h_splitter->SetSashPosition(h_splitter->GetSashPosition() - adj_height);
		}
		else if(htp_Mh > 0 && htp_ch > htp_Mh)
		{
			/* Adjust sash to fit ToolPanel maximum size. */
			
			int adj_height = htp_Mh - htp_ch;
			h_splitter->SetSashPosition(h_splitter->GetSashPosition() - adj_height);
		}
	}
	
	htools_initial_size = -1;
}

/* The size of a wxNotebook page doesn't seem to be set correctly during
 * initialisation (or immediately after adding a page), so we can't use it to
 * determine how much size overhead the wxNotebook adds at that point. Instead
 * we defer setting of the tool pane sizes until the first idle tick, by which
 * point the sizes seem to have been set up properly (on GTK anyway).
*/

void REHex::Tab::vtools_adjust_on_idle(bool force_resize)
{
	if(force_resize)
	{
		vtools_adjust_force = true;
	}
	
	if(!vtools_adjust_pending)
	{
		Bind(wxEVT_IDLE, &REHex::Tab::vtools_adjust_now_idle, this);
		vtools_adjust_pending = true;
	}
}

void REHex::Tab::vtools_adjust_now_idle(wxIdleEvent &event)
{
	Unbind(wxEVT_IDLE, &REHex::Tab::vtools_adjust_now_idle, this);
	event.Skip();
	
	bool force_resize = vtools_adjust_force;
	
	vtools_adjust_pending = false;
	vtools_adjust_force = false;
	
	vtools_adjust(force_resize);
}

void REHex::Tab::htools_adjust_on_idle(bool force_resize)
{
	if(force_resize)
	{
		htools_adjust_force = true;
	}
	
	if(!htools_adjust_pending)
	{
		Bind(wxEVT_IDLE, &REHex::Tab::htools_adjust_now_idle, this);
		htools_adjust_pending = true;
	}
}

void REHex::Tab::htools_adjust_now_idle(wxIdleEvent &event)
{
	Unbind(wxEVT_IDLE, &REHex::Tab::htools_adjust_now_idle, this);
	event.Skip();
	
	bool force_resize = htools_adjust_force;
	
	htools_adjust_pending = false;
	htools_adjust_force = false;
	
	htools_adjust(force_resize);
}

/* wxEVT_NOTEBOOK_PAGE_CHANGED events aren't generated consistently between platforms and versions
 * of wxWidgets when the selected tab is changed due to adding/removing a page, so this method is
 * used to correct the visible state of all ToolPanel's in a notebook after adding or removing one.
*/
void REHex::Tab::xtools_fix_visibility(wxNotebook *notebook)
{
	size_t n_pages    = notebook->GetPageCount();
	int selected_page = notebook->GetSelection();
	
	for(size_t i = 0; i < n_pages; ++i)
	{
		wxWindow* page = notebook->GetPage(i);
		assert(page != NULL);
		
		ToolPanel* tp = dynamic_cast<ToolPanel*>(page);
		assert(tp != NULL);
		
		bool this_tab_is_selected = ((int)(i) == selected_page);
		tp->set_visible(this_tab_is_selected);
	}
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
}

void REHex::Tab::init_default_tools()
{
	wxConfig *config = wxGetApp().config;
	
	htools_initial_size = config->ReadLong("/default-view/htools/height", -1);
	vtools_initial_size = config->ReadLong("/default-view/vtools/width", -1);
	
	for(unsigned int i = 0;; ++i)
	{
		char base_p[64];
		snprintf(base_p, sizeof(base_p), "/default-view/htools/panels/0/tab/%u/", i);
		
		if(config->HasGroup(base_p))
		{
			config->SetPath(base_p);
			
			std::string name = config->Read    ("name", "").ToStdString();
			bool selected    = config->ReadBool("selected", false);
			
			if(ToolPanelRegistry::by_name(name) != NULL)
			{
				tool_create(name, selected, config);
			}
			else{
				/* TODO: Some kind of warning? */
			}
		}
		else{
			break;
		}
	}
	
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
				tool_create(name, selected, config);
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
	if(repopulate_regions_frozen)
	{
		repopulate_regions_pending = true;
		return;
	}
	
	std::vector<DocumentCtrl::Region*> regions;
	
	if(document_display_mode == DDM_VIRTUAL)
	{
		/* Virtual segments view. */
		
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
	
	doc_ctrl->replace_all_regions(regions);
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

std::vector<REHex::DocumentCtrl::Region*> REHex::Tab::compute_regions(SharedDocumentPointer doc, off_t real_offset_base, off_t virt_offset_base, off_t length, InlineCommentMode inline_comment_mode)
{
	auto comments = doc->get_comments();
	auto types = doc->get_data_types();
	
	bool nest = (inline_comment_mode == ICM_SHORT_INDENT || inline_comment_mode == ICM_FULL_INDENT);
	bool truncate = (inline_comment_mode == ICM_SHORT || inline_comment_mode == ICM_SHORT_INDENT);
	
	/* Construct a list of interlaced comment/data regions. */
	
	auto offset_base = comments.begin();
	auto types_iter = types.begin();
	off_t next_data = real_offset_base, next_virt = virt_offset_base, remain_data = length;
	
	/* Skip over comments/types prior to real_offset_base. */
	while(offset_base != comments.end() && offset_base->first.offset < next_data) { ++offset_base; }
	while(types_iter != types.end() && (types_iter->first.offset + types_iter->first.length <= next_data)) { ++types_iter; }
	
	if(inline_comment_mode == ICM_HIDDEN)
	{
		/* Inline comments are hidden. Skip over the comments. */
		offset_base = comments.end();
	}
	
	std::vector<DocumentCtrl::Region*> regions;
	std::stack<off_t> dr_limit;
	
	while(remain_data > 0)
	{
		assert((next_data + remain_data) <= doc->buffer_length());
		assert(offset_base == comments.end() || offset_base->first.offset >= next_data);
		
		while(!dr_limit.empty() && dr_limit.top() <= next_data)
		{
			dr_limit.pop();
		}
		
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
				
				assert(c->first.offset == next_data);
				
				off_t indent_offset = next_virt;
				off_t indent_length = nest
					? std::min(c->first.length, remain_data)
					: 0;
				
				regions.push_back(new DocumentCtrl::CommentRegion(
					c->first.offset,
					c->first.length,
					*(c->second.text),
					truncate,
					indent_offset,
					indent_length));
				
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
		
		const DataTypeRegistration *dtr = DataTypeRegistry::by_name(types_iter->second);
		
		if(dtr != NULL && dtr->fixed_size <= dr_length)
		{
			if(dtr->fixed_size >= 0 && dr_length > dtr->fixed_size)
			{
				dr_length = dtr->fixed_size;
			}
			
			regions.push_back(dtr->region_factory(doc, next_data, dr_length, next_virt));
		}
		else{
			regions.push_back(new DocumentCtrl::DataRegionDocHighlight(doc, next_data, dr_length, next_virt));
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
