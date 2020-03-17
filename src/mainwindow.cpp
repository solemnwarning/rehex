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
#include <limits>
#include <new>
#include <wx/artprov.h>
#include <wx/clipbrd.h>
#include <wx/dataobj.h>
#include <wx/event.h>
#include <wx/filename.h>
#include <wx/msgdlg.h>
#include <wx/aui/auibook.h>
#include <wx/numdlg.h>
#include <wx/sizer.h>

#include "AboutDialog.hpp"
#include "app.hpp"
#include "CommentTree.hpp"
#include "decodepanel.hpp"
#include "disassemble.hpp"
#include "mainwindow.hpp"
#include "NumericEntryDialog.hpp"
#include "Palette.hpp"
#include "search.hpp"
#include "SelectRangeDialog.hpp"
#include "ToolPanel.hpp"
#include "util.hpp"

#include "../res/icon16.h"
#include "../res/icon32.h"
#include "../res/icon48.h"
#include "../res/icon64.h"

#ifdef __APPLE__
#include "../res/document_new32.h"
#include "../res/document_open32.h"
#include "../res/document_save32.h"
#include "../res/document_save_as32.h"
#endif

enum {
	ID_BYTES_LINE = 1,
	ID_BYTES_GROUP,
	ID_SHOW_OFFSETS,
	ID_SHOW_ASCII,
	ID_SEARCH_TEXT,
	ID_SEARCH_BSEQ,
	ID_SEARCH_VALUE,
	ID_GOTO_OFFSET,
	ID_OVERWRITE_MODE,
	ID_SAVE_VIEW,
	ID_INLINE_COMMENTS_HIDDEN,
	ID_INLINE_COMMENTS_FULL,
	ID_INLINE_COMMENTS_SHORT,
	ID_INLINE_COMMENTS_INDENT,
	ID_HIGHLIGHT_SELECTION_MATCH,
	ID_SELECT_RANGE,
	ID_SYSTEM_PALETTE,
	ID_LIGHT_PALETTE,
	ID_DARK_PALETTE,
	ID_CLOSE_ALL,
	ID_CLOSE_OTHERS,
	ID_GITHUB,
	ID_DONATE,
};

BEGIN_EVENT_TABLE(REHex::MainWindow, wxFrame)
	EVT_CLOSE(REHex::MainWindow::OnWindowClose)
	
	EVT_MENU(wxID_NEW,        REHex::MainWindow::OnNew)
	EVT_MENU(wxID_OPEN,       REHex::MainWindow::OnOpen)
	EVT_MENU(wxID_SAVE,       REHex::MainWindow::OnSave)
	EVT_MENU(wxID_SAVEAS,     REHex::MainWindow::OnSaveAs)
	EVT_MENU(wxID_CLOSE,      REHex::MainWindow::OnClose)
	EVT_MENU(ID_CLOSE_ALL,    REHex::MainWindow::OnCloseAll)
	EVT_MENU(ID_CLOSE_OTHERS, REHex::MainWindow::OnCloseOthers)
	EVT_MENU(wxID_EXIT,       REHex::MainWindow::OnExit)
	
	EVT_MENU(wxID_FILE1, REHex::MainWindow::OnRecentOpen)
	EVT_MENU(wxID_FILE2, REHex::MainWindow::OnRecentOpen)
	EVT_MENU(wxID_FILE3, REHex::MainWindow::OnRecentOpen)
	EVT_MENU(wxID_FILE4, REHex::MainWindow::OnRecentOpen)
	EVT_MENU(wxID_FILE5, REHex::MainWindow::OnRecentOpen)
	EVT_MENU(wxID_FILE6, REHex::MainWindow::OnRecentOpen)
	EVT_MENU(wxID_FILE7, REHex::MainWindow::OnRecentOpen)
	EVT_MENU(wxID_FILE8, REHex::MainWindow::OnRecentOpen)
	EVT_MENU(wxID_FILE9, REHex::MainWindow::OnRecentOpen)
	
	EVT_MENU(wxID_UNDO, REHex::MainWindow::OnUndo)
	EVT_MENU(wxID_REDO, REHex::MainWindow::OnRedo)
	
	EVT_MENU(wxID_SELECTALL, REHex::MainWindow::OnSelectAll)
	EVT_MENU(ID_SELECT_RANGE, REHex::MainWindow::OnSelectRange)
	
	EVT_MENU(ID_OVERWRITE_MODE, REHex::MainWindow::OnOverwriteMode)
	
	EVT_MENU(ID_SEARCH_TEXT, REHex::MainWindow::OnSearchText)
	EVT_MENU(ID_SEARCH_BSEQ,  REHex::MainWindow::OnSearchBSeq)
	EVT_MENU(ID_SEARCH_VALUE,  REHex::MainWindow::OnSearchValue)
	
	EVT_MENU(ID_GOTO_OFFSET, REHex::MainWindow::OnGotoOffset)
	
	EVT_MENU(wxID_CUT,   REHex::MainWindow::OnCut)
	EVT_MENU(wxID_COPY,  REHex::MainWindow::OnCopy)
	EVT_MENU(wxID_PASTE, REHex::MainWindow::OnPaste)
	
	EVT_MENU(ID_BYTES_LINE,   REHex::MainWindow::OnSetBytesPerLine)
	EVT_MENU(ID_BYTES_GROUP,  REHex::MainWindow::OnSetBytesPerGroup)
	EVT_MENU(ID_SHOW_OFFSETS, REHex::MainWindow::OnShowOffsets)
	EVT_MENU(ID_SHOW_ASCII,   REHex::MainWindow::OnShowASCII)
	EVT_MENU(ID_SAVE_VIEW,    REHex::MainWindow::OnSaveView)
	
	EVT_MENU(ID_INLINE_COMMENTS_HIDDEN, REHex::MainWindow::OnInlineCommentsMode)
	EVT_MENU(ID_INLINE_COMMENTS_FULL,   REHex::MainWindow::OnInlineCommentsMode)
	EVT_MENU(ID_INLINE_COMMENTS_SHORT,  REHex::MainWindow::OnInlineCommentsMode)
	EVT_MENU(ID_INLINE_COMMENTS_INDENT, REHex::MainWindow::OnInlineCommentsMode)
	
	EVT_MENU(ID_HIGHLIGHT_SELECTION_MATCH, REHex::MainWindow::OnHighlightSelectionMatch)
	
	EVT_MENU(ID_SYSTEM_PALETTE, REHex::MainWindow::OnPalette)
	EVT_MENU(ID_LIGHT_PALETTE,  REHex::MainWindow::OnPalette)
	EVT_MENU(ID_DARK_PALETTE,   REHex::MainWindow::OnPalette)
	
	EVT_MENU(ID_GITHUB,  REHex::MainWindow::OnGithub)
	EVT_MENU(ID_DONATE,  REHex::MainWindow::OnDonate)
	EVT_MENU(wxID_ABOUT, REHex::MainWindow::OnAbout)
	
	EVT_AUINOTEBOOK_PAGE_CHANGED(  wxID_ANY, REHex::MainWindow::OnDocumentChange)
	EVT_AUINOTEBOOK_PAGE_CLOSE(    wxID_ANY, REHex::MainWindow::OnDocumentClose)
	EVT_AUINOTEBOOK_PAGE_CLOSED(   wxID_ANY, REHex::MainWindow::OnDocumentClosed)
	EVT_AUINOTEBOOK_TAB_RIGHT_DOWN(wxID_ANY, REHex::MainWindow::OnDocumentMenu)
	
	EVT_COMMAND(wxID_ANY, REHex::EV_CURSOR_MOVED,      REHex::MainWindow::OnCursorMove)
	EVT_COMMAND(wxID_ANY, REHex::EV_SELECTION_CHANGED, REHex::MainWindow::OnSelectionChange)
	EVT_COMMAND(wxID_ANY, REHex::EV_INSERT_TOGGLED,    REHex::MainWindow::OnInsertToggle)
	EVT_COMMAND(wxID_ANY, REHex::EV_UNDO_UPDATE,       REHex::MainWindow::OnUndoUpdate)
	EVT_COMMAND(wxID_ANY, REHex::EV_BECAME_DIRTY,      REHex::MainWindow::OnBecameDirty)
	EVT_COMMAND(wxID_ANY, REHex::EV_BECAME_CLEAN,      REHex::MainWindow::OnBecameClean)
END_EVENT_TABLE()

REHex::MainWindow::MainWindow():
	wxFrame(NULL, wxID_ANY, "Reverse Engineers' Hex Editor", wxDefaultPosition, wxSize(740, 540))
{
	file_menu = new wxMenu;
	recent_files_menu = new wxMenu;
	
	file_menu->Append(wxID_NEW,    "&New\tCtrl-N");
	file_menu->Append(wxID_OPEN,   "&Open\tCtrl-O");
	file_menu->AppendSubMenu(recent_files_menu, "Open &Recent");
	file_menu->Append(wxID_SAVE,   "&Save\tCtrl-S");
	file_menu->Append(wxID_SAVEAS, "&Save As");
	file_menu->AppendSeparator();
	file_menu->Append(wxID_CLOSE,  "&Close\tCtrl-W");
	file_menu->Append(ID_CLOSE_ALL, "Close All");
	file_menu->Append(ID_CLOSE_OTHERS, "Close Others");
	file_menu->AppendSeparator();
	file_menu->Append(wxID_EXIT,   "&Exit");
	
	edit_menu = new wxMenu;
	
	edit_menu->Append(wxID_UNDO, "&Undo\tCtrl-Z");
	edit_menu->Append(wxID_REDO, "&Redo\tCtrl-Shift-Z");
	
	edit_menu->AppendSeparator();
	
	edit_menu->Append(wxID_SELECTALL, "Select &All\tCtrl-A");
	edit_menu->Append(ID_SELECT_RANGE, "Select range...");
	
	edit_menu->AppendSeparator();
	
	#ifdef __APPLE__
	edit_menu->AppendCheckItem(ID_OVERWRITE_MODE, "Overwrite mode");
	#else
	edit_menu->AppendCheckItem(ID_OVERWRITE_MODE, "Overwrite mode\tIns");
	#endif
	
	edit_menu->AppendSeparator();
	
	edit_menu->Append(ID_SEARCH_TEXT,  "Search for text...");
	edit_menu->Append(ID_SEARCH_BSEQ,  "Search for byte sequence...");
	edit_menu->Append(ID_SEARCH_VALUE, "Search for value...");
	
	edit_menu->AppendSeparator();
	
	edit_menu->Append(ID_GOTO_OFFSET, "Jump to offset...\tCtrl-G");
	
	edit_menu->AppendSeparator();
	
	edit_menu->Append(wxID_CUT,   "Cu&t\tCtrl-X");
	edit_menu->Append(wxID_COPY,  "&Copy\tCtrl-C");
	edit_menu->Append(wxID_PASTE, "&Paste\tCtrl-V");
	
	view_menu = new wxMenu;
	
	view_menu->Append(ID_BYTES_LINE,  "Set bytes per line");
	view_menu->Append(ID_BYTES_GROUP, "Set bytes per group");
	view_menu->AppendCheckItem(ID_SHOW_OFFSETS, "Show offsets");
	view_menu->AppendCheckItem(ID_SHOW_ASCII, "Show ASCII");
	
	inline_comments_menu = new wxMenu;
	view_menu->AppendSubMenu(inline_comments_menu, "Inline comments");
	
	view_menu->AppendCheckItem(ID_HIGHLIGHT_SELECTION_MATCH, "Highlight data matching selection");
	
	inline_comments_menu->AppendRadioItem(ID_INLINE_COMMENTS_HIDDEN, "Hidden");
	inline_comments_menu->AppendRadioItem(ID_INLINE_COMMENTS_SHORT,  "Short");
	inline_comments_menu->AppendRadioItem(ID_INLINE_COMMENTS_FULL,   "Full");
	inline_comments_menu->AppendSeparator();
	inline_comments_menu->AppendCheckItem(ID_INLINE_COMMENTS_INDENT, "Nest comments");
	
	tool_panels_menu = new wxMenu;
	view_menu->AppendSubMenu(tool_panels_menu, "Tool panels");
	
	for(auto i = ToolPanelRegistry::begin(); i != ToolPanelRegistry::end(); ++i)
	{
		const ToolPanelRegistration *tpr = i->second;
		wxMenuItem *itm = tool_panels_menu->AppendCheckItem(wxID_ANY, tpr->label);
		
		Bind(wxEVT_MENU, [this, tpr](wxCommandEvent &event)
		{
			OnShowToolPanel(event, tpr);
		}, itm->GetId(), itm->GetId());
		
		tool_panel_name_to_tpm_id[tpr->name] = itm->GetId();
	}
	
	view_menu->AppendSeparator();
	
	wxMenu *palette_menu = new wxMenu;
	view_menu->AppendSubMenu(palette_menu, "Colour scheme");
	
	palette_menu->AppendRadioItem(ID_SYSTEM_PALETTE, "System");
	palette_menu->AppendRadioItem(ID_LIGHT_PALETTE,  "Light");
	palette_menu->AppendRadioItem(ID_DARK_PALETTE,   "Dark");
	
	std::string palette_name = active_palette->get_name();
	if(palette_name == "light")
	{
		palette_menu->Check(ID_LIGHT_PALETTE, true);
	}
	else if(palette_name == "dark")
	{
		palette_menu->Check(ID_DARK_PALETTE, true);
	}
	else /* if(palette_name == "system") */
	{
		palette_menu->Check(ID_SYSTEM_PALETTE, true);
	}
	
	view_menu->AppendSeparator();
	
	view_menu->Append(ID_SAVE_VIEW, "Save current view as default");
	
	wxMenu *help_menu = new wxMenu;
	
	help_menu->Append(ID_GITHUB, "Visit &Github page");
	help_menu->Append(ID_DONATE, "Donate with &Paypal");
	help_menu->Append(wxID_ABOUT, "&About");
	
	wxMenuBar *menu_bar = new wxMenuBar;
	menu_bar->Append(file_menu, "&File");
	menu_bar->Append(edit_menu, "&Edit");
	menu_bar->Append(view_menu,  "&View");
	menu_bar->Append(help_menu, "&Help");
	
	SetMenuBar(menu_bar);
	
	wxGetApp().recent_files->UseMenu(recent_files_menu);
	wxGetApp().recent_files->AddFilesToMenu(recent_files_menu);
	
	wxToolBar *toolbar = CreateToolBar();
	wxArtProvider artp;
	
	/* Toolbar icons are expected to be 32x32 on OS X. wxWidgets ships 16x16 and 24x24 Tango
	 * icons and scales them as needed, which produces blurry 32x32 images. So on OS X, we
	 * embed 32x32 versions instead.
	*/
	
	#ifdef __APPLE__
	toolbar->AddTool(wxID_NEW,    "New",     wxBITMAP_PNG_FROM_DATA(document_new32));
	toolbar->AddTool(wxID_OPEN,   "Open",    wxBITMAP_PNG_FROM_DATA(document_open32));
	toolbar->AddTool(wxID_SAVE,   "Save",    wxBITMAP_PNG_FROM_DATA(document_save32));
	toolbar->AddTool(wxID_SAVEAS, "Save As", wxBITMAP_PNG_FROM_DATA(document_save_as32));
	#else
	toolbar->AddTool(wxID_NEW,    "New",     artp.GetBitmap(wxART_NEW,          wxART_TOOLBAR));
	toolbar->AddTool(wxID_OPEN,   "Open",    artp.GetBitmap(wxART_FILE_OPEN,    wxART_TOOLBAR));
	toolbar->AddTool(wxID_SAVE,   "Save",    artp.GetBitmap(wxART_FILE_SAVE,    wxART_TOOLBAR));
	toolbar->AddTool(wxID_SAVEAS, "Save As", artp.GetBitmap(wxART_FILE_SAVE_AS, wxART_TOOLBAR));
	#endif
	
	toolbar->Realize();
	
	notebook = new wxAuiNotebook(this, wxID_ANY, wxDefaultPosition, wxDefaultSize,
		(wxAUI_NB_TOP | wxAUI_NB_TAB_MOVE | wxAUI_NB_SCROLL_BUTTONS | wxAUI_NB_CLOSE_ON_ALL_TABS));
	
	notebook_dirty_bitmap = artp.GetBitmap(wxART_FILE_SAVE, wxART_MENU);
	assert(!notebook_dirty_bitmap.IsSameAs(wxNullBitmap));
	
	CreateStatusBar(3);
	
	SetDropTarget(new DropTarget(this));
	
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

REHex::MainWindow::~MainWindow()
{
	wxGetApp().recent_files->RemoveMenu(recent_files_menu);
}

void REHex::MainWindow::new_file()
{
	Tab *tab = new Tab(notebook);
	notebook->AddPage(tab, tab->doc->get_title(), true);
	tab->doc->SetFocus();
}

void REHex::MainWindow::open_file(const std::string &filename)
{
	Tab *tab;
	try {
		tab = new Tab(notebook, filename);
	}
	catch(const std::exception &e)
	{
		wxMessageBox(
			std::string("Error opening ") + filename + ":\n" + e.what(),
			"Error", wxICON_ERROR, this);
		return;
	}
	
	/* Discard default "Untitled" tab if not modified. */
	if(notebook->GetPageCount() == 1)
	{
		wxWindow *page = notebook->GetPage(0);
		assert(page != NULL);
		
		auto page_tab = dynamic_cast<REHex::MainWindow::Tab*>(page);
		assert(page_tab != NULL);
		
		if(page_tab->doc->get_filename() == "" && !page_tab->doc->is_dirty())
		{
			notebook->DeletePage(0);
		}
	}
	
	wxFileName wxfn(filename);
	wxfn.MakeAbsolute();
	wxGetApp().recent_files->AddFileToHistory(wxfn.GetFullPath());
	
	notebook->AddPage(tab, tab->doc->get_title(), true);
	tab->doc->SetFocus();
}

void REHex::MainWindow::OnWindowClose(wxCloseEvent &event)
{
	if(!unsaved_confirm())
	{
		/* Stop the window from being closed. */
		event.Veto();
		return;
	}
	
	/* Base implementation will deal with cleaning up the window. */
	event.Skip();
}

void REHex::MainWindow::OnNew(wxCommandEvent &event)
{
	new_file();
}

void REHex::MainWindow::OnOpen(wxCommandEvent &event)
{
	std::string dir;
	std::string doc_filename = active_document()->get_filename();
	
	if(doc_filename != "")
	{
		wxFileName wxfn(doc_filename);
		wxfn.MakeAbsolute();
		
		dir = wxfn.GetPath();
	}
	else{
		dir = wxGetApp().get_last_directory();
	}
	
	wxFileDialog openFileDialog(this, "Open File", dir, "", "", wxFD_OPEN | wxFD_FILE_MUST_EXIST);
	if(openFileDialog.ShowModal() == wxID_CANCEL)
		return;
	
	std::string filename = openFileDialog.GetPath().ToStdString();
	
	{
		wxFileName wxfn(filename);
		wxString dirname = wxfn.GetPath();
		
		wxGetApp().set_last_directory(dirname.ToStdString());
	}
	
	open_file(filename);
}

void REHex::MainWindow::OnRecentOpen(wxCommandEvent &event)
{
	wxFileHistory *recent_files = wxGetApp().recent_files;
	wxString file = recent_files->GetHistoryFile(event.GetId() - recent_files->GetBaseId());
	
	open_file(file.ToStdString());
}

void REHex::MainWindow::OnSave(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	if(tab->doc->get_filename() == "")
	{
		OnSaveAs(event);
		return;
	}
	
	try {
		tab->doc->save();
		_update_dirty(tab->doc);
	}
	catch(const std::exception &e)
	{
		wxMessageBox(
			std::string("Error saving ") + tab->doc->get_title() + ":\n" + e.what(),
			"Error", wxICON_ERROR, this);
		return;
	}
}

void REHex::MainWindow::OnSaveAs(wxCommandEvent &event)
{
	std::string dir, name;
	std::string doc_filename = active_document()->get_filename();
	
	if(doc_filename != "")
	{
		wxFileName wxfn(doc_filename);
		wxfn.MakeAbsolute();
		
		dir  = wxfn.GetPath();
		name = wxfn.GetFullName();
	}
	else{
		dir  = wxGetApp().get_last_directory();
		name = "";
	}
	
	wxFileDialog saveFileDialog(this, "Save As", dir, name, "", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
	if(saveFileDialog.ShowModal() == wxID_CANCEL)
		return;
	
	std::string filename = saveFileDialog.GetPath().ToStdString();
	
	{
		wxFileName wxfn(filename);
		wxString dirname = wxfn.GetPath();
		
		wxGetApp().set_last_directory(dirname.ToStdString());
	}
	
	Tab *tab = active_tab();
	
	try {
		tab->doc->save(filename);
		_update_dirty(tab->doc);
	}
	catch(const std::exception &e)
	{
		wxMessageBox(
			std::string("Error saving ") + tab->doc->get_title() + ":\n" + e.what(),
			"Error", wxICON_ERROR, this);
		return;
	}
	
	notebook->SetPageText(notebook->GetSelection(), tab->doc->get_title());
}

void REHex::MainWindow::OnClose(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	close_tab(tab);
}

void REHex::MainWindow::OnCloseAll(wxCommandEvent &event)
{
	close_all_tabs();
}

void REHex::MainWindow::OnCloseOthers(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	close_other_tabs(tab);
}

void REHex::MainWindow::OnExit(wxCommandEvent &event)
{
	Close();
}

void REHex::MainWindow::OnSearchText(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	REHex::Search::Text *sd = new REHex::Search::Text(tab, *(tab->doc));
	sd->Show(true);
	
	tab->search_dialog_register(sd);
}

void REHex::MainWindow::OnSearchBSeq(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	REHex::Search::ByteSequence *sd = new REHex::Search::ByteSequence(tab, *(tab->doc));
	sd->Show(true);
	
	tab->search_dialog_register(sd);
}

void REHex::MainWindow::OnSearchValue(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	REHex::Search::Value *sd = new REHex::Search::Value(tab, *(tab->doc));
	sd->Show(true);
	
	tab->search_dialog_register(sd);
}

void REHex::MainWindow::OnGotoOffset(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	off_t current_pos = tab->doc->get_cursor_position();
	off_t max_pos     = tab->doc->buffer_length() - !tab->doc->get_insert_mode();
	
	REHex::NumericEntryDialog<off_t> ni(this,
		"Jump to offset",
		"Prefix offset with -/+ to jump relative to current cursor position",
		current_pos, 0, max_pos, current_pos);
	
	int rc = ni.ShowModal();
	if(rc == wxID_OK)
	{
		tab->doc->set_cursor_position(ni.GetValue());
	}
}

void REHex::MainWindow::OnCut(wxCommandEvent &event)
{
	_clipboard_copy(true);
}

void REHex::MainWindow::OnCopy(wxCommandEvent &event)
{
	_clipboard_copy(false);
}

void REHex::MainWindow::OnPaste(wxCommandEvent &event)
{
	REHex::Document *doc = active_document();
	
	ClipboardGuard cg;
	if(cg)
	{
		if(wxTheClipboard->IsSupported(CommentsDataObject::format))
		{
			CommentsDataObject data;
			wxTheClipboard->GetData(data);
			
			auto clipboard_comments = data.get_comments();
			
			doc->handle_paste(clipboard_comments);
		}
		else if(wxTheClipboard->IsSupported(wxDF_TEXT))
		{
			wxTextDataObject data;
			wxTheClipboard->GetData(data);
			
			try {
				doc->handle_paste(data.GetText().ToStdString());
			}
			catch(const std::exception &e)
			{
				wxMessageBox(e.what(), "Error", (wxOK | wxICON_ERROR), this);
			}
		}
	}
}

void REHex::MainWindow::OnUndo(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	tab->doc->undo();
}

void REHex::MainWindow::OnRedo(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	tab->doc->redo();
}

void REHex::MainWindow::OnSelectAll(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	tab->doc->set_selection(0, tab->doc->buffer_length());
}

void REHex::MainWindow::OnSelectRange(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	REHex::SelectRangeDialog srd(this, *(tab->doc));
	srd.ShowModal();
}

void REHex::MainWindow::OnOverwriteMode(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	tab->doc->set_insert_mode(!event.IsChecked());
}

void REHex::MainWindow::OnSetBytesPerLine(wxCommandEvent &event)
{
	/* There are rendering/performance issues with very large values here, which we just bypass
	 * with a nice arbitrary limit for now.
	*/
	const int MAX_BYTES_PER_LINE = 128;
	
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	/* TODO: Make a dialog with an explicit "auto" radio choice? */
	int new_value = wxGetNumberFromUser(
		"Number of bytes to show on each line\n(0 fits to the window width)",
		"Bytes",
		"Set bytes per line",
		tab->doc->get_bytes_per_line(),
		0,
		MAX_BYTES_PER_LINE,
		this);
	
	/* We get a negative value if the user cancels. */
	if(new_value >= 0)
	{
		tab->doc->set_bytes_per_line(new_value);
	}
}

void REHex::MainWindow::OnSetBytesPerGroup(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	int new_value = wxGetNumberFromUser(
		"Number of bytes to group",
		"Bytes",
		"Set bytes per group",
		tab->doc->get_bytes_per_group(),
		1,
		std::numeric_limits<int>::max(),
		this);
	
	/* We get a negative value if the user cancels. */
	if(new_value >= 0)
	{
		tab->doc->set_bytes_per_group(new_value);
	}
}

void REHex::MainWindow::OnShowOffsets(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	tab->doc->set_show_offsets(event.IsChecked());
}

void REHex::MainWindow::OnShowASCII(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	tab->doc->set_show_ascii(event.IsChecked());
}

void REHex::MainWindow::OnInlineCommentsMode(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	if(inline_comments_menu->IsChecked(ID_INLINE_COMMENTS_HIDDEN))
	{
		tab->doc->set_inline_comment_mode(REHex::Document::ICM_HIDDEN);
		inline_comments_menu->Enable(ID_INLINE_COMMENTS_INDENT, false);
	}
	else if(inline_comments_menu->IsChecked(ID_INLINE_COMMENTS_FULL))
	{
		tab->doc->set_inline_comment_mode(
			inline_comments_menu->IsChecked(ID_INLINE_COMMENTS_INDENT)
				? REHex::Document::ICM_FULL_INDENT
				: REHex::Document::ICM_FULL);
		inline_comments_menu->Enable(ID_INLINE_COMMENTS_INDENT, true);
	}
	else if(inline_comments_menu->IsChecked(ID_INLINE_COMMENTS_SHORT))
	{
		tab->doc->set_inline_comment_mode(
			inline_comments_menu->IsChecked(ID_INLINE_COMMENTS_INDENT)
				? REHex::Document::ICM_SHORT_INDENT
				: REHex::Document::ICM_SHORT);
		inline_comments_menu->Enable(ID_INLINE_COMMENTS_INDENT, true);
	}
}

void REHex::MainWindow::OnHighlightSelectionMatch(wxCommandEvent &event)
{
	Document *doc = active_document();
	doc->set_highlight_selection_match(event.IsChecked());
}

void REHex::MainWindow::OnShowToolPanel(wxCommandEvent &event, const REHex::ToolPanelRegistration *tpr)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	if(event.IsChecked())
	{
		tab->tool_create(tpr->name, true);
	}
	else{
		tab->tool_destroy(tpr->name);
	}
}

void REHex::MainWindow::OnPalette(wxCommandEvent &event)
{
	delete active_palette;
	
	switch(event.GetId())
	{
		case ID_SYSTEM_PALETTE:
			active_palette = Palette::create_system_palette();
			break;
			
		case ID_LIGHT_PALETTE:
			active_palette = Palette::create_light_palette();
			break;
			
		case ID_DARK_PALETTE:
			active_palette = Palette::create_dark_palette();
			break;
			
		default:
			abort();
	}
	
	Refresh();
}

void REHex::MainWindow::OnSaveView(wxCommandEvent &event)
{
	wxConfig *config = wxGetApp().config;
	
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	tab->save_view(config);
}

void REHex::MainWindow::OnGithub(wxCommandEvent &event)
{
	wxLaunchDefaultBrowser("https://github.com/solemnwarning/rehex/");
}

void REHex::MainWindow::OnDonate(wxCommandEvent &event)
{
	wxLaunchDefaultBrowser("https://www.solemnwarning.net/rehex/donate");
}

void REHex::MainWindow::OnAbout(wxCommandEvent &event)
{
	REHex::AboutDialog about(this);
	about.ShowModal();
}

void REHex::MainWindow::OnDocumentChange(wxAuiNotebookEvent& event)
{
	int old_page_id = event.GetOldSelection();
	if(old_page_id != wxNOT_FOUND && old_page_id < (int)(notebook->GetPageCount()))
	{
		/* Hide any search dialogs attached to previous tab. */
		
		wxWindow *old_page = notebook->GetPage(old_page_id);
		assert(old_page != NULL);
		
		auto old_tab = dynamic_cast<REHex::MainWindow::Tab*>(old_page);
		assert(old_tab != NULL);
		
		for(auto sdi = old_tab->search_dialogs.begin(); sdi != old_tab->search_dialogs.end(); ++sdi)
		{
			(*sdi)->Hide();
		}
	}
	
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	edit_menu->Check(ID_OVERWRITE_MODE, !tab->doc->get_insert_mode());
	view_menu->Check(ID_SHOW_OFFSETS, tab->doc->get_show_offsets());
	view_menu->Check(ID_SHOW_ASCII,   tab->doc->get_show_ascii());
	
	REHex::Document::InlineCommentMode icm = tab->doc->get_inline_comment_mode();
	switch(icm)
	{
		case REHex::Document::ICM_HIDDEN:
			inline_comments_menu->Check(ID_INLINE_COMMENTS_HIDDEN, true);
			inline_comments_menu->Enable(ID_INLINE_COMMENTS_INDENT, false);
			break;
			
		case REHex::Document::ICM_FULL:
		case REHex::Document::ICM_FULL_INDENT:
			inline_comments_menu->Check(ID_INLINE_COMMENTS_FULL, true);
			inline_comments_menu->Check(ID_INLINE_COMMENTS_INDENT, (icm == REHex::Document::ICM_FULL_INDENT));
			inline_comments_menu->Enable(ID_INLINE_COMMENTS_INDENT, true);
			break;
			
		case REHex::Document::ICM_SHORT:
		case REHex::Document::ICM_SHORT_INDENT:
			inline_comments_menu->Check(ID_INLINE_COMMENTS_SHORT, true);
			inline_comments_menu->Check(ID_INLINE_COMMENTS_INDENT, (icm == REHex::Document::ICM_SHORT_INDENT));
			inline_comments_menu->Enable(ID_INLINE_COMMENTS_INDENT, true);
			break;
	};
	
	view_menu->Check(ID_HIGHLIGHT_SELECTION_MATCH, tab->doc->get_highlight_selection_match());
	
	for(auto i = ToolPanelRegistry::begin(); i != ToolPanelRegistry::end(); ++i)
	{
		const ToolPanelRegistration *tpr = i->second;
		
		int menu_id = tool_panel_name_to_tpm_id[tpr->name];
		bool active = tab->tool_active(tpr->name);
		
		tool_panels_menu->Check(menu_id, active);
	}
	
	_update_status_offset(tab->doc);
	_update_status_selection(tab->doc);
	_update_status_mode(tab->doc);
	_update_undo(tab->doc);
	_update_dirty(tab->doc);
	
	/* Show any search dialogs attached to this tab. */
	for(auto sdi = tab->search_dialogs.begin(); sdi != tab->search_dialogs.end(); ++sdi)
	{
		(*sdi)->ShowWithoutActivating();
	}
}

void REHex::MainWindow::OnDocumentClose(wxAuiNotebookEvent& event)
{
	wxWindow *page = notebook->GetPage(event.GetSelection());
	assert(page != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(page);
	assert(tab != NULL);
	
	if(tab->doc->is_dirty())
	{
		wxMessageDialog confirm(this, (wxString("The file ") + tab->doc->get_title() + " has unsaved changes.\nClose anyway?"), "Unsaved changes",
			(wxYES | wxNO | wxCENTER));
		
		int response = confirm.ShowModal();
		
		if(response == wxID_NO)
		{
			event.Veto();
		}
	}
}

void REHex::MainWindow::OnDocumentClosed(wxAuiNotebookEvent &event)
{
	/* Create a new tab if the only one was just closed. */
	if(notebook->GetPageCount() == 0)
	{
		ProcessCommand(wxID_NEW);
	}
}

void REHex::MainWindow::OnDocumentMenu(wxAuiNotebookEvent &event)
{
	int tab_idx = event.GetSelection();
	
	wxWindow *tab_page = notebook->GetPage(tab_idx);
	assert(tab_page != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(tab_page);
	assert(tab != NULL);
	
	std::string filename = tab->doc->get_filename();
	
	wxMenu menu;
	
	wxMenuItem *open_dir = menu.Append(wxID_ANY, "Open Folder");
	open_dir->Enable(filename != "");
	
	menu.Bind(wxEVT_MENU, [&filename](wxCommandEvent &event)
	{
		REHex::file_manager_show_file(filename);
	}, open_dir->GetId(), open_dir->GetId());
	
	menu.AppendSeparator();
	
	wxMenuItem *close = menu.Append(wxID_ANY, "Close");
	menu.Bind(wxEVT_MENU, [this, tab](wxCommandEvent &event)
	{
		close_tab(tab);
	}, close->GetId(), close->GetId());
	
	wxMenuItem *close_all = menu.Append(wxID_ANY, "Close All");
	menu.Bind(wxEVT_MENU, [this](wxCommandEvent &event)
	{
		close_all_tabs();
	}, close_all->GetId(), close_all->GetId());
	
	wxMenuItem *close_others = menu.Append(wxID_ANY, "Close Others");
	menu.Bind(wxEVT_MENU, [this, tab](wxCommandEvent &event)
	{
		close_other_tabs(tab);
	}, close_others->GetId(), close_others->GetId());
	
	PopupMenu(&menu);
}

void REHex::MainWindow::OnCursorMove(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	auto doc = dynamic_cast<REHex::Document*>(event.GetEventObject());
	assert(doc != NULL);
	
	if(doc == tab->doc)
	{
		/* Only update the status bar if the event originated from the
		 * active document.
		*/
		_update_status_offset(doc);
	}
}

void REHex::MainWindow::OnSelectionChange(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	auto doc = dynamic_cast<REHex::Document*>(event.GetEventObject());
	assert(doc != NULL);
	
	if(doc == tab->doc)
	{
		/* Only update the status bar if the event originated from the
		 * active document.
		*/
		_update_status_selection(doc);
	}
}

void REHex::MainWindow::OnInsertToggle(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	auto doc = dynamic_cast<REHex::Document*>(event.GetEventObject());
	assert(doc != NULL);
	
	if(doc == tab->doc)
	{
		/* Only update the status bar if the event originated from the
		 * active document.
		*/
		_update_status_mode(doc);
		edit_menu->Check(ID_OVERWRITE_MODE, !tab->doc->get_insert_mode());
	}
}

void REHex::MainWindow::OnUndoUpdate(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	auto doc = dynamic_cast<REHex::Document*>(event.GetEventObject());
	assert(doc != NULL);
	
	if(doc == tab->doc)
	{
		/* Only update the menu if the event originated from the active document. */
		_update_undo(tab->doc);
	}
}

void REHex::MainWindow::OnBecameDirty(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	auto doc = dynamic_cast<REHex::Document*>(event.GetEventObject());
	assert(doc != NULL);
	
	if(doc == tab->doc)
	{
		/* Only update the window if the event originated from the active document. */
		_update_dirty(tab->doc);
	}
}

void REHex::MainWindow::OnBecameClean(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	auto doc = dynamic_cast<REHex::Document*>(event.GetEventObject());
	assert(doc != NULL);
	
	if(doc == tab->doc)
	{
		/* Only update the window if the event originated from the active document. */
		_update_dirty(tab->doc);
	}
}

REHex::MainWindow::Tab *REHex::MainWindow::active_tab()
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	return tab;
}

REHex::Document *REHex::MainWindow::active_document()
{
	return active_tab()->doc;
}

void REHex::MainWindow::_update_status_offset(REHex::Document *doc)
{
	off_t off = doc->get_cursor_position();
	
	char buf[64];
	snprintf(buf, sizeof(buf), "Offset: %08x:%08x",
		(unsigned int)((off & 0x00000000FFFFFFFF) << 32),
		(unsigned int)(off & 0xFFFFFFFF));
	
	SetStatusText(buf, 0);
}

void REHex::MainWindow::_update_status_selection(REHex::Document *doc)
{
	std::pair<off_t,off_t> selection = doc->get_selection();
	
	off_t selection_off    = selection.first;
	off_t selection_length = selection.second;
	
	if(selection_length > 0)
	{
		off_t selection_end = (selection_off + selection_length) - 1;
		
		char buf[64];
		snprintf(buf, sizeof(buf), "Selection: %08x:%08x - %08x:%08x (%u bytes)",
			(unsigned int)((selection_off & 0x00000000FFFFFFFF) << 32),
			(unsigned int)(selection_off & 0xFFFFFFFF),
			
			(unsigned int)((selection_end & 0x00000000FFFFFFFF) << 32),
			(unsigned int)(selection_end & 0xFFFFFFFF),
			
			(unsigned int)(selection_length));
		
		SetStatusText(buf, 1);
	}
	else{
		SetStatusText("", 1);
	}
}

void REHex::MainWindow::_update_status_mode(REHex::Document *doc)
{
	if(doc->get_insert_mode())
	{
		SetStatusText("Mode: Insert", 2);
	}
	else{
		SetStatusText("Mode: Overwrite", 2);
	}
}

void REHex::MainWindow::_update_undo(REHex::Document *doc)
{
	const char *undo_desc = doc->undo_desc();
	if(undo_desc != NULL)
	{
		char label[64];
		snprintf(label, sizeof(label), "&Undo %s\tCtrl-Z", undo_desc);
		
		edit_menu->SetLabel(wxID_UNDO, label);
		edit_menu->Enable(wxID_UNDO, true);
	}
	else{
		edit_menu->SetLabel(wxID_UNDO, "&Undo\tCtrl-Z");
		edit_menu->Enable(wxID_UNDO, false);
	}
	
	const char *redo_desc = doc->redo_desc();
	if(redo_desc != NULL)
	{
		char label[64];
		snprintf(label, sizeof(label), "&Redo %s\tCtrl-Shift-Z", redo_desc);
		
		edit_menu->SetLabel(wxID_REDO, label);
		edit_menu->Enable(wxID_REDO, true);
	}
	else{
		edit_menu->SetLabel(wxID_REDO, "&Redo\tCtrl-Shift-Z");
		edit_menu->Enable(wxID_REDO, false);
	}
}

void REHex::MainWindow::_update_dirty(REHex::Document *doc)
{
	bool dirty = doc->is_dirty();
	bool has_file = (doc->get_filename() != "");
	
	bool enable_save = dirty || !has_file;
	
	SetTitle((dirty ? "[UNSAVED] " : "") + doc->get_title() + " - Reverse Engineers' Hex Editor");
	
	file_menu->Enable(wxID_SAVE,   enable_save);
	file_menu->Enable(wxID_SAVEAS, enable_save);
	
	wxToolBar *toolbar = GetToolBar();
	toolbar->EnableTool(wxID_SAVE,   enable_save);
	toolbar->EnableTool(wxID_SAVEAS, enable_save);
	
	notebook->SetPageBitmap(notebook->GetSelection(), (dirty ? notebook_dirty_bitmap : wxNullBitmap));
}

void REHex::MainWindow::_clipboard_copy(bool cut)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	/* Warn the user this might be a bad idea before dumping silly amounts
	 * of data (>16MiB) into the clipboard.
	*/
	
	static size_t COPY_MAX_SOFT = 16777216;
	size_t upper_limit = tab->doc->copy_upper_limit();
	
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
		std::string copy_text = tab->doc->handle_copy(cut);
		if(!copy_text.empty())
		{
			copy_data = new wxTextDataObject(copy_text);
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
		}
		else{
			delete copy_data;
		}
	}
}

bool REHex::MainWindow::unsaved_confirm()
{
	std::vector<wxString> dirty_files;
	
	size_t num_tabs = notebook->GetPageCount();
	for(size_t i = 0; i < num_tabs; ++i)
	{
		wxWindow *page = notebook->GetPage(i);
		assert(page != NULL);
		
		auto tab = dynamic_cast<REHex::MainWindow::Tab*>(page);
		assert(tab != NULL);
		
		if(tab->doc->is_dirty())
		{
			dirty_files.push_back(tab->doc->get_title());
		}
	}
	
	return unsaved_confirm(dirty_files);
}

bool REHex::MainWindow::unsaved_confirm(const std::vector<wxString> &files)
{
	if(files.size() == 1)
	{
		wxMessageDialog confirm(this, (wxString("The file ") + files[0] + " has unsaved changes.\nClose anyway?"), "Unsaved changes",
			(wxYES | wxNO | wxCENTER));
		
		int response = confirm.ShowModal();
		
		return response == wxID_YES;
	}
	else if(files.size() > 1)
	{
		wxString message = "The following files have unsaved changes, close anyway?\n";
		
		for(auto i = files.begin(); i != files.end(); ++i)
		{
			message.Append('\n');
			message.Append(*i);
		}
		
		wxMessageDialog confirm(this, message, "Unsaved changes",
			(wxYES | wxNO | wxCENTER));
		
		int response = confirm.ShowModal();
		
		return response == wxID_YES;
	}

	return true;
}

void REHex::MainWindow::close_tab(REHex::MainWindow::Tab *tab)
{
	if(tab->doc->is_dirty())
	{
		std::vector<wxString> dirty_titles;
		dirty_titles.push_back(tab->doc->get_title());
		
		if(!unsaved_confirm(dirty_titles))
		{
			/* User didn't really want to close unsaved tabs. */
			return;
		}
	}
	
	notebook->DeletePage(notebook->GetPageIndex(tab));
	
	if(notebook->GetPageCount() == 0)
	{
		ProcessCommand(wxID_NEW);
	}
}

void REHex::MainWindow::close_all_tabs()
{
	if(!unsaved_confirm())
	{
		/* User didn't really want to close unsaved tabs. */
		return;
	}
	
	notebook->DeleteAllPages();
	ProcessCommand(wxID_NEW);
}

void REHex::MainWindow::close_other_tabs(REHex::MainWindow::Tab *tab)
{
	std::vector<wxString> dirty_others;
	
	size_t num_tabs = notebook->GetPageCount();
	for(size_t i = 0; i < num_tabs; ++i)
	{
		wxWindow *page = notebook->GetPage(i);
		assert(page != NULL);
		
		if(page == tab)
		{
			continue;
		}
		
		auto p_tab = dynamic_cast<REHex::MainWindow::Tab*>(page);
		assert(p_tab != NULL);
		
		if(p_tab->doc->is_dirty())
		{
			dirty_others.push_back(p_tab->doc->get_title());
		}
	}
	
	if(!unsaved_confirm(dirty_others))
	{
		/* User didn't really want to close unsaved tabs. */
		return;
	}
	
	for(size_t i = 0; i < notebook->GetPageCount();)
	{
		wxWindow *page = notebook->GetPage(i);
		assert(page != NULL);
		
		if(page == tab)
		{
			++i;
		}
		else{
			notebook->DeletePage(i);
		}
	}
}

BEGIN_EVENT_TABLE(REHex::MainWindow::Tab, wxPanel)
	EVT_SIZE(REHex::MainWindow::Tab::OnSize)
	
	EVT_NOTEBOOK_PAGE_CHANGED(ID_HTOOLS, REHex::MainWindow::Tab::OnHToolChange)
	EVT_NOTEBOOK_PAGE_CHANGED(ID_VTOOLS, REHex::MainWindow::Tab::OnVToolChange)
	
	EVT_SPLITTER_SASH_POS_CHANGING(ID_HSPLITTER, REHex::MainWindow::Tab::OnHSplitterSashPosChanging)
	EVT_SPLITTER_SASH_POS_CHANGING(ID_VSPLITTER, REHex::MainWindow::Tab::OnVSplitterSashPosChanging)
END_EVENT_TABLE()

REHex::MainWindow::Tab::Tab(wxWindow *parent):
	wxPanel(parent)
{
	v_splitter = new wxSplitterWindow(this, ID_VSPLITTER, wxDefaultPosition, wxDefaultSize, (wxSP_3D | wxSP_LIVE_UPDATE));
	v_splitter->SetSashGravity(1.0);
	v_splitter->SetMinimumPaneSize(20);
	
	h_splitter = new wxSplitterWindow(v_splitter, ID_HSPLITTER, wxDefaultPosition, wxDefaultSize, (wxSP_3D | wxSP_LIVE_UPDATE));
	h_splitter->SetSashGravity(1.0);
	h_splitter->SetMinimumPaneSize(20);
	
	doc = new REHex::Document(h_splitter);
	init_default_doc_view();
	doc->set_insert_mode(true);
	
	h_tools = new wxNotebook(h_splitter, ID_HTOOLS, wxDefaultPosition, wxDefaultSize, wxNB_BOTTOM);
	h_tools->SetFitToCurrentPage(true);
	
	v_tools = new wxNotebook(v_splitter, ID_VTOOLS, wxDefaultPosition, wxDefaultSize, wxNB_RIGHT);
	v_tools->SetFitToCurrentPage(true);
	
	h_splitter->SplitHorizontally(doc, h_tools);
	v_splitter->SplitVertically(h_splitter, v_tools);
	
	wxBoxSizer *sizer = new wxBoxSizer(wxHORIZONTAL);
	sizer->Add(v_splitter, 1, wxEXPAND);
	SetSizerAndFit(sizer);
	
	init_default_tools();
	
	htools_adjust_on_idle();
	vtools_adjust_on_idle();
}

REHex::MainWindow::Tab::Tab(wxWindow *parent, const std::string &filename):
	wxPanel(parent)
{
	v_splitter = new wxSplitterWindow(this, ID_VSPLITTER, wxDefaultPosition, wxDefaultSize, (wxSP_3D | wxSP_LIVE_UPDATE));
	v_splitter->SetSashGravity(1.0);
	v_splitter->SetMinimumPaneSize(20);
	
	h_splitter = new wxSplitterWindow(v_splitter, ID_HSPLITTER, wxDefaultPosition, wxDefaultSize, (wxSP_3D | wxSP_LIVE_UPDATE));
	h_splitter->SetSashGravity(1.0);
	h_splitter->SetMinimumPaneSize(20);
	
	doc = new REHex::Document(h_splitter, filename);
	init_default_doc_view();
	
	h_tools = new wxNotebook(h_splitter, ID_HTOOLS, wxDefaultPosition, wxDefaultSize, wxNB_BOTTOM);
	h_tools->SetFitToCurrentPage(true);
	
	v_tools = new wxNotebook(v_splitter, ID_VTOOLS, wxDefaultPosition, wxDefaultSize, wxNB_RIGHT);
	v_tools->SetFitToCurrentPage(true);
	
	h_splitter->SplitHorizontally(doc, h_tools);
	v_splitter->SplitVertically(h_splitter, v_tools);
	
	wxBoxSizer *sizer = new wxBoxSizer(wxHORIZONTAL);
	sizer->Add(v_splitter, 1, wxEXPAND);
	SetSizerAndFit(sizer);
	
	init_default_tools();
	
	htools_adjust_on_idle();
	vtools_adjust_on_idle();
}

REHex::MainWindow::Tab::~Tab()
{
	for(auto sdi = search_dialogs.begin(); sdi != search_dialogs.end(); ++sdi)
	{
		(*sdi)->Unbind(wxEVT_DESTROY, &REHex::MainWindow::Tab::OnSearchDialogDestroy, this);
	}
}

bool REHex::MainWindow::Tab::tool_active(const std::string &name)
{
	return tools.find(name) != tools.end();
}

void REHex::MainWindow::Tab::tool_create(const std::string &name, bool switch_to, wxConfig *config, bool adjust)
{
	if(tool_active(name))
	{
		return;
	}
	
	const ToolPanelRegistration *tpr = ToolPanelRegistry::by_name(name);
	assert(tpr != NULL);
	
	if(tpr->shape == ToolPanel::TPS_TALL)
	{
		ToolPanel *tool_window = tpr->factory(v_tools, doc);
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
		ToolPanel *tool_window = tpr->factory(h_tools, doc);
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

void REHex::MainWindow::Tab::tool_destroy(const std::string &name)
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

void REHex::MainWindow::Tab::search_dialog_register(wxDialog *search_dialog)
{
	search_dialogs.insert(search_dialog);
	search_dialog->Bind(wxEVT_DESTROY, &REHex::MainWindow::Tab::OnSearchDialogDestroy, this);
}

void REHex::MainWindow::Tab::save_view(wxConfig *config)
{
	config->SetPath("/");
	config->Write("theme", wxString(active_palette->get_name()));
	
	config->DeleteGroup("/default-view/");
	config->SetPath("/default-view/");
	
	config->Write("bytes-per-line", doc->get_bytes_per_line());
	config->Write("bytes-per-group", doc->get_bytes_per_group());
	config->Write("show-offsets", doc->get_show_offsets());
	config->Write("show-ascii", doc->get_show_ascii());
	config->Write("inline-comments", (int)(doc->get_inline_comment_mode()));
	config->Write("highlight-selection-match", doc->get_highlight_selection_match());
	
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

void REHex::MainWindow::Tab::OnSize(wxSizeEvent &event)
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

void REHex::MainWindow::Tab::OnHToolChange(wxNotebookEvent& event)
{
	htools_adjust();
}

void REHex::MainWindow::Tab::OnVToolChange(wxBookCtrlEvent &event)
{
	vtools_adjust();
}

void REHex::MainWindow::Tab::OnHSplitterSashPosChanging(wxSplitterEvent &event)
{
	int pos = event.GetSashPosition();
	int clamp = hsplit_clamp_sash(pos);
	
	if(pos != clamp)
	{
		event.SetSashPosition(clamp);
	}
}

void REHex::MainWindow::Tab::OnVSplitterSashPosChanging(wxSplitterEvent &event)
{
	int pos = event.GetSashPosition();
	int clamp = vsplit_clamp_sash(pos);
	
	if(pos != clamp)
	{
		event.SetSashPosition(clamp);
	}
}

void REHex::MainWindow::Tab::OnSearchDialogDestroy(wxWindowDestroyEvent &event)
{
	search_dialogs.erase((wxDialog*)(event.GetWindow()));
	
	/* Continue propogation. */
	event.Skip();
}

int REHex::MainWindow::Tab::hsplit_clamp_sash(int sash_position)
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

int REHex::MainWindow::Tab::vsplit_clamp_sash(int sash_position)
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

void REHex::MainWindow::Tab::vtools_adjust()
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

void REHex::MainWindow::Tab::htools_adjust()
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
			h_splitter->SplitHorizontally(doc, h_tools);
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

void REHex::MainWindow::Tab::vtools_adjust_on_idle()
{
	Bind(wxEVT_IDLE, &REHex::MainWindow::Tab::vtools_adjust_now_idle, this);
}

void REHex::MainWindow::Tab::vtools_adjust_now_idle(wxIdleEvent &event)
{
	Unbind(wxEVT_IDLE, &REHex::MainWindow::Tab::vtools_adjust_now_idle, this);
	event.Skip();
	
	vtools_adjust();
}

void REHex::MainWindow::Tab::htools_adjust_on_idle()
{
	Bind(wxEVT_IDLE, &REHex::MainWindow::Tab::htools_adjust_now_idle, this);
}

void REHex::MainWindow::Tab::htools_adjust_now_idle(wxIdleEvent &event)
{
	Unbind(wxEVT_IDLE, &REHex::MainWindow::Tab::htools_adjust_now_idle, this);
	event.Skip();
	
	htools_adjust();
}

void REHex::MainWindow::Tab::init_default_doc_view()
{
	wxConfig *config = wxGetApp().config;
	config->SetPath("/default-view/");
	
	doc->set_bytes_per_line(             config->Read("bytes-per-line",             doc->get_bytes_per_line()));
	doc->set_bytes_per_group(            config->Read("bytes-per-group",            doc->get_bytes_per_group()));
	doc->set_show_offsets(               config->Read("show-offsets",               doc->get_show_offsets()));
	doc->set_show_ascii(                 config->Read("show-ascii",                 doc->get_show_ascii()));
	doc->set_highlight_selection_match(  config->Read("highlight-selection-match",  doc->get_highlight_selection_match()));
	
	int inline_comments = config->Read("inline-comments", (int)(doc->get_inline_comment_mode()));
	if(inline_comments >= 0 && inline_comments <= REHex::Document::ICM_MAX)
	{
		doc->set_inline_comment_mode((REHex::Document::InlineCommentMode)(inline_comments));
	}
}

void REHex::MainWindow::Tab::init_default_tools()
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
			
			std::string name = config->Read("name", "").ToStdString();
			bool selected    = config->Read("selected", false);
			
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

REHex::MainWindow::DropTarget::DropTarget(MainWindow *window):
	window(window) {}

REHex::MainWindow::DropTarget::~DropTarget() {}

bool REHex::MainWindow::DropTarget::OnDropFiles(wxCoord x, wxCoord y, const wxArrayString &filenames)
{
	for(size_t i = 0; i < filenames.GetCount(); ++i)
	{
		window->open_file(filenames[i].ToStdString());
	}
	
	return true;
}
