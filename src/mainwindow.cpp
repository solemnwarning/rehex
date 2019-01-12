/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2019 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <wx/artprov.h>
#include <wx/clipbrd.h>
#include <wx/dataobj.h>
#include <wx/event.h>
#include <wx/filename.h>
#include <wx/msgdlg.h>
#include <wx/aui/auibook.h>
#include <wx/numdlg.h>
#include <wx/sizer.h>

#include "app.hpp"
#include "decodepanel.hpp"
#include "disassemble.hpp"
#include "mainwindow.hpp"
#include "NumericEntryDialog.hpp"
#include "search.hpp"

#include "../res/icon16.h"
#include "../res/icon32.h"
#include "../res/icon48.h"
#include "../res/icon64.h"

enum {
	ID_BYTES_LINE = 1,
	ID_BYTES_GROUP,
	ID_SHOW_OFFSETS,
	ID_SHOW_ASCII,
	ID_SHOW_DECODES,
	ID_SEARCH_TEXT,
	ID_SEARCH_BSEQ,
	ID_SEARCH_VALUE,
	ID_GOTO_OFFSET,
};

BEGIN_EVENT_TABLE(REHex::MainWindow, wxFrame)
	EVT_CLOSE(REHex::MainWindow::OnWindowClose)
	
	EVT_MENU(wxID_NEW,    REHex::MainWindow::OnNew)
	EVT_MENU(wxID_OPEN,   REHex::MainWindow::OnOpen)
	EVT_MENU(wxID_SAVE,   REHex::MainWindow::OnSave)
	EVT_MENU(wxID_SAVEAS, REHex::MainWindow::OnSaveAs)
	EVT_MENU(wxID_CLOSE,  REHex::MainWindow::OnClose)
	EVT_MENU(wxID_EXIT,   REHex::MainWindow::OnExit)
	
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
	EVT_MENU(ID_SHOW_DECODES, REHex::MainWindow::OnShowDecodes)
	
	EVT_AUINOTEBOOK_PAGE_CHANGED(wxID_ANY, REHex::MainWindow::OnDocumentChange)
	EVT_AUINOTEBOOK_PAGE_CLOSE(  wxID_ANY, REHex::MainWindow::OnDocumentClose)
	EVT_AUINOTEBOOK_PAGE_CLOSED( wxID_ANY, REHex::MainWindow::OnDocumentClosed)
	
	EVT_COMMAND(wxID_ANY, REHex::EV_CURSOR_MOVED,      REHex::MainWindow::OnCursorMove)
	EVT_COMMAND(wxID_ANY, REHex::EV_SELECTION_CHANGED, REHex::MainWindow::OnSelectionChange)
	EVT_COMMAND(wxID_ANY, REHex::EV_INSERT_TOGGLED,    REHex::MainWindow::OnInsertToggle)
END_EVENT_TABLE()

REHex::MainWindow::MainWindow():
	wxFrame(NULL, wxID_ANY, wxT("Reverse Engineer's Hex Editor"))
{
	wxMenu *file_menu = new wxMenu;
	recent_files_menu = new wxMenu;
	
	file_menu->Append(wxID_NEW,    wxT("&New"));
	file_menu->Append(wxID_OPEN,   wxT("&Open"));
	file_menu->AppendSubMenu(recent_files_menu, wxT("Open &Recent"));
	file_menu->Append(wxID_SAVE,   wxT("&Save"));
	file_menu->Append(wxID_SAVEAS, wxT("&Save As"));
	file_menu->Append(wxID_CLOSE,  wxT("&Close"));
	file_menu->AppendSeparator();
	file_menu->Append(wxID_EXIT,   wxT("&Exit"));
	
	wxMenu *edit_menu = new wxMenu;
	
	edit_menu->Append(wxID_UNDO, "&Undo\tCtrl-Z");
	edit_menu->Append(wxID_REDO, "&Redo\tCtrl-Shift-Z");
	
	edit_menu->AppendSeparator();
	
	edit_menu->Append(ID_SEARCH_TEXT,  "Search for text...");
	edit_menu->Append(ID_SEARCH_BSEQ,  "Search for byte sequence...");
	edit_menu->Append(ID_SEARCH_VALUE, "Search for value...");
	
	edit_menu->AppendSeparator();
	
	edit_menu->Append(ID_GOTO_OFFSET, "Jump to offset...\tCtrl-G");
	
	edit_menu->AppendSeparator();
	
	edit_menu->Append(wxID_CUT,   "&Cut");
	edit_menu->Append(wxID_COPY,  "&Copy");
	edit_menu->Append(wxID_PASTE, "&Paste");
	
	doc_menu = new wxMenu;
	
	doc_menu->Append(ID_BYTES_LINE,  wxT("Set bytes per line"));
	doc_menu->Append(ID_BYTES_GROUP, wxT("Set bytes per group"));
	doc_menu->AppendCheckItem(ID_SHOW_OFFSETS, wxT("Show offsets"));
	doc_menu->AppendCheckItem(ID_SHOW_ASCII, wxT("Show ASCII"));
	doc_menu->AppendCheckItem(ID_SHOW_DECODES, wxT("Show decode table"));
	
	wxMenuBar *menu_bar = new wxMenuBar;
	menu_bar->Append(file_menu, wxT("&File"));
	menu_bar->Append(edit_menu, wxT("&Edit"));
	menu_bar->Append(doc_menu,  wxT("&Document"));
	
	SetMenuBar(menu_bar);
	
	wxGetApp().recent_files->UseMenu(recent_files_menu);
	wxGetApp().recent_files->AddFilesToMenu(recent_files_menu);
	
	wxToolBar *toolbar = CreateToolBar();
	wxArtProvider artp;
	
	toolbar->AddTool(wxID_NEW,    "New",     artp.GetBitmap(wxART_NEW,          wxART_TOOLBAR));
	toolbar->AddTool(wxID_OPEN,   "Open",    artp.GetBitmap(wxART_FILE_OPEN,    wxART_TOOLBAR));
	toolbar->AddTool(wxID_SAVE,   "Save",    artp.GetBitmap(wxART_FILE_SAVE,    wxART_TOOLBAR));
	toolbar->AddTool(wxID_SAVEAS, "Save As", artp.GetBitmap(wxART_FILE_SAVE_AS, wxART_TOOLBAR));
	
	toolbar->Realize();
	
	notebook = new wxAuiNotebook(this, wxID_ANY, wxDefaultPosition, wxDefaultSize,
		(wxAUI_NB_TOP | wxAUI_NB_TAB_MOVE | wxAUI_NB_SCROLL_BUTTONS | wxAUI_NB_CLOSE_ON_ALL_TABS));
	
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
	
	/* Start with an "Untitled" tab. */
	ProcessCommand(wxID_NEW);
	
	/* NOTE: wxAuiNotebook doesn't seem to implement GetBestSize() correctly, so we just use
	 * the best size of the Tab instead.
	*/
	
	SetClientSize(notebook->GetPage(0)->GetBestSize());
}

REHex::MainWindow::~MainWindow()
{
	wxGetApp().recent_files->RemoveMenu(recent_files_menu);
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
	
	if(dirty_files.size() == 1)
	{
		wxMessageDialog confirm(this, (wxString("The file ") + dirty_files[0] + " has unsaved changes.\nClose anyway?"), wxT("Unsaved changes"),
			(wxYES | wxNO | wxCENTER));
		
		int response = confirm.ShowModal();
		
		if(response == wxID_NO)
		{
			/* Stop the window from being closed. */
			event.Veto();
			return;
		}
	}
	else if(dirty_files.size() > 1)
	{
		wxString message = "The following files have unsaved changes, close anyway?\n";
		
		for(auto i = dirty_files.begin(); i != dirty_files.end(); ++i)
		{
			message.Append('\n');
			message.Append(*i);
		}
		
		wxMessageDialog confirm(this, message, wxT("Unsaved changes"),
			(wxYES | wxNO | wxCENTER));
		
		int response = confirm.ShowModal();
		
		if(response == wxID_NO)
		{
			/* Stop the window from being closed. */
			event.Veto();
			return;
		}
	}
	
	/* Base implementation will deal with cleaning up the window. */
	event.Skip();
}

void REHex::MainWindow::OnNew(wxCommandEvent &event)
{
	Tab *tab = new Tab(notebook);
	notebook->AddPage(tab, tab->doc->get_title(), true);
	tab->doc->SetFocus();
}

void REHex::MainWindow::OnOpen(wxCommandEvent &event)
{
	wxFileDialog openFileDialog(this, wxT("Open File"), "", "", "", wxFD_OPEN | wxFD_FILE_MUST_EXIST);
	if(openFileDialog.ShowModal() == wxID_CANCEL)
		return;
	
	open_file(openFileDialog.GetPath().ToStdString());
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
	
	try {
		tab->doc->save();
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
	wxFileDialog saveFileDialog(this, wxT("Save As"), "", "", "", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
	if(saveFileDialog.ShowModal() == wxID_CANCEL)
		return;
	
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	try {
		tab->doc->save(saveFileDialog.GetPath().ToStdString());
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
	
	if(tab->doc->is_dirty())
	{
		wxMessageDialog confirm(this, (wxString("The file ") + tab->doc->get_title() + " has unsaved changes.\nClose anyway?"), wxT("Unsaved changes"),
			(wxYES | wxNO | wxCENTER));
		
		int response = confirm.ShowModal();
		
		if(response == wxID_NO)
		{
			return;
		}
	}
	
	notebook->DeletePage(notebook->GetPageIndex(cpage));
	
	if(notebook->GetPageCount() == 0)
	{
		ProcessCommand(wxID_NEW);
	}
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
	
	REHex::Search::Text *t = new REHex::Search::Text(tab, *(tab->doc));
	t->Show(true);
}

void REHex::MainWindow::OnSearchBSeq(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	REHex::Search::ByteSequence *t = new REHex::Search::ByteSequence(tab, *(tab->doc));
	t->Show(true);
}

void REHex::MainWindow::OnSearchValue(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	REHex::Search::Value *t = new REHex::Search::Value(tab, *(tab->doc));
	t->Show(true);
}

void REHex::MainWindow::OnGotoOffset(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	off_t current_pos = tab->doc->get_cursor_position();
	off_t max_pos     = tab->doc->buffer_length() - !tab->doc->get_insert_mode();
	
	REHex::NumericEntryDialog<off_t> ni(this, "Jump to offset", current_pos, 0, max_pos);
	
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
	if(wxTheClipboard->Open())
	{
		if(wxTheClipboard->IsSupported(wxDF_TEXT))
		{
			wxTextDataObject data;
			wxTheClipboard->GetData(data);
			
			wxWindow *cpage = notebook->GetCurrentPage();
			assert(cpage != NULL);
			
			auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
			assert(tab != NULL);
			
			tab->doc->handle_paste(data.GetText().ToStdString());
		}
		
		wxTheClipboard->Close();
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

void REHex::MainWindow::OnShowDecodes(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	tab->dp->Show(event.IsChecked());
	tab->vtools_adjust();
}

void REHex::MainWindow::OnDocumentChange(wxAuiNotebookEvent& event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	doc_menu->Check(ID_SHOW_OFFSETS, tab->doc->get_show_offsets());
	doc_menu->Check(ID_SHOW_ASCII,   tab->doc->get_show_ascii());
	doc_menu->Check(ID_SHOW_DECODES, tab->dp->IsShown());
	
	_update_status_offset(tab->doc);
	_update_status_selection(tab->doc);
	_update_status_mode(tab->doc);
}

void REHex::MainWindow::OnDocumentClose(wxAuiNotebookEvent& event)
{
	wxWindow *page = notebook->GetPage(event.GetSelection());
	assert(page != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(page);
	assert(tab != NULL);
	
	if(tab->doc->is_dirty())
	{
		wxMessageDialog confirm(this, (wxString("The file ") + tab->doc->get_title() + " has unsaved changes.\nClose anyway?"), wxT("Unsaved changes"),
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
	}
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

void REHex::MainWindow::_clipboard_copy(bool cut)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	/* TODO: Open clipboard in a RAII-y way. */
	
	if(wxTheClipboard->Open())
	{
		std::string copy_text = tab->doc->handle_copy(cut);
		
		if(!copy_text.empty())
		{
			wxTheClipboard->SetData(new wxTextDataObject(copy_text));
			wxTheClipboard->Close();
		}
	}
}

BEGIN_EVENT_TABLE(REHex::MainWindow::Tab, wxPanel)
	EVT_COMMAND(wxID_ANY, REHex::EV_CURSOR_MOVED, REHex::MainWindow::Tab::OnCursorMove)
	EVT_COMMAND(wxID_ANY, REHex::EV_VALUE_CHANGE, REHex::MainWindow::Tab::OnValueChange)
	EVT_COMMAND(wxID_ANY, REHex::EV_VALUE_FOCUS,  REHex::MainWindow::Tab::OnValueFocus)
	
	EVT_NOTEBOOK_PAGE_CHANGED(ID_HTOOLS, REHex::MainWindow::Tab::OnHToolChange)
	EVT_NOTEBOOK_PAGE_CHANGED(ID_VTOOLS, REHex::MainWindow::Tab::OnVToolChange)
END_EVENT_TABLE()

REHex::MainWindow::Tab::Tab(wxWindow *parent):
	wxPanel(parent)
{
	v_splitter = new wxSplitterWindow(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, (wxSP_3D | wxSP_LIVE_UPDATE));
	v_splitter->SetSashGravity(1.0);
	v_splitter->SetMinimumPaneSize(20);
	
	h_splitter = new wxSplitterWindow(v_splitter, wxID_ANY, wxDefaultPosition, wxDefaultSize, (wxSP_3D | wxSP_LIVE_UPDATE));
	h_splitter->SetSashGravity(1.0);
	h_splitter->SetMinimumPaneSize(20);
	
	doc = new REHex::Document(h_splitter);
	
	h_tools = new wxNotebook(h_splitter, ID_HTOOLS, wxDefaultPosition, wxDefaultSize, wxNB_BOTTOM);
	h_tools->SetFitToCurrentPage(true);
	
	v_tools = new wxNotebook(v_splitter, ID_VTOOLS, wxDefaultPosition, wxDefaultSize, wxNB_RIGHT);
	v_tools->SetFitToCurrentPage(true);
	
	h_splitter->SplitHorizontally(doc, h_tools);
	v_splitter->SplitVertically(h_splitter, v_tools);
	
	wxBoxSizer *sizer = new wxBoxSizer(wxHORIZONTAL);
	sizer->Add(v_splitter, 1, wxEXPAND);
	SetSizerAndFit(sizer);
	
	dp = new REHex::DecodePanel(v_tools);
	v_tools->AddPage(dp, "Decode values", true);
	
	disasm = new REHex::Disassemble(v_tools, *doc);
	v_tools->AddPage(disasm, "Disassembly", true);
	
	vtools_adjust();
	htools_adjust();
	
	std::vector<unsigned char> data_at_off = doc->read_data(doc->get_cursor_position(), 8);
	dp->update(data_at_off.data(), data_at_off.size());
}

REHex::MainWindow::Tab::Tab(wxWindow *parent, const std::string &filename):
	wxPanel(parent)
{
	v_splitter = new wxSplitterWindow(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, (wxSP_3D | wxSP_LIVE_UPDATE));
	v_splitter->SetSashGravity(1.0);
	v_splitter->SetMinimumPaneSize(20);
	
	h_splitter = new wxSplitterWindow(v_splitter, wxID_ANY, wxDefaultPosition, wxDefaultSize, (wxSP_3D | wxSP_LIVE_UPDATE));
	h_splitter->SetSashGravity(1.0);
	h_splitter->SetMinimumPaneSize(20);
	
	doc = new REHex::Document(h_splitter, filename);
	
	h_tools = new wxNotebook(h_splitter, ID_HTOOLS, wxDefaultPosition, wxDefaultSize, wxNB_BOTTOM);
	h_tools->SetFitToCurrentPage(true);
	
	v_tools = new wxNotebook(v_splitter, ID_VTOOLS, wxDefaultPosition, wxDefaultSize, wxNB_RIGHT);
	v_tools->SetFitToCurrentPage(true);
	
	h_splitter->SplitHorizontally(doc, h_tools);
	v_splitter->SplitVertically(h_splitter, v_tools);
	
	wxBoxSizer *sizer = new wxBoxSizer(wxHORIZONTAL);
	sizer->Add(v_splitter, 1, wxEXPAND);
	SetSizerAndFit(sizer);
	
	dp = new REHex::DecodePanel(v_tools);
	v_tools->AddPage(dp, "Decode values", true);
	
	disasm = new REHex::Disassemble(v_tools, *doc);
	v_tools->AddPage(disasm, "Disassembly", true);
	
	vtools_adjust();
	htools_adjust();
	
	std::vector<unsigned char> data_at_off = doc->read_data(doc->get_cursor_position(), 8);
	dp->update(data_at_off.data(), data_at_off.size());
}

void REHex::MainWindow::Tab::OnCursorMove(wxCommandEvent &event)
{
	std::vector<unsigned char> data_at_off = doc->read_data(doc->get_cursor_position(), 8);
	dp->update(data_at_off.data(), data_at_off.size());
	
	disasm->set_position(doc->get_cursor_position());
	
	/* Let the event propogate on up to MainWindow to update the status bar. */
	event.Skip();
}

void REHex::MainWindow::Tab::OnValueChange(wxCommandEvent &event)
{
	auto vc = dynamic_cast<REHex::ValueChange*>(&event);
	assert(vc != NULL);
	
	off_t offset = doc->get_cursor_position();
	std::vector<unsigned char> data = vc->get_data();
	
	doc->overwrite_data(offset, data.data(), data.size());
	
	std::vector<unsigned char> data_at_off = doc->read_data(offset, 8);
	dp->update(data_at_off.data(), data_at_off.size(), vc->get_source());
	
	disasm->update();
}

void REHex::MainWindow::Tab::OnValueFocus(wxCommandEvent &event)
{
	auto vf = dynamic_cast<REHex::ValueFocus*>(&event);
	assert(vf != NULL);
	
	off_t cur_pos = doc->get_cursor_position();
	off_t length  = vf->get_size();
	
	doc->set_selection(cur_pos, length);
}

/* When changing tool, we make the wxNotebook recalculate its "best" size, which
 * is derived from the minimum size of the selected page and the extra space
 * occupied by the wxNotebook itself, then we make that the minimum size of the
 * wxNotebook, preventing the user from shrinking the wxSplitterWindow pane
 * beyond the minimum size enforced by the page, THEN, finally, we reposition
 * the split as far left/down as allowable.
*/

void REHex::MainWindow::Tab::OnHToolChange(wxNotebookEvent& event)
{
	htools_adjust();
}

void REHex::MainWindow::Tab::OnVToolChange(wxBookCtrlEvent &event)
{
	vtools_adjust();
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
		
		/* Invalidate cached best size in wxNotebook. */
		v_tools->SetMinSize(wxSize(0,0));
		v_tools->InvalidateBestSize();
		
		wxSize vt_s = v_tools->GetBestSize();
		v_tools->SetMinSize(vt_s);
		
		wxSize vs_s = v_splitter->GetClientSize();
		v_splitter->SetSashPosition(vs_s.GetWidth() - (vt_s.GetWidth() + v_splitter->GetSashSize()));
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
		
		/* Invalidate cached best size in wxNotebook. */
		h_tools->SetMinSize(wxSize(0,0));
		h_tools->InvalidateBestSize();
		
		wxSize ht_s = h_tools->GetBestSize();
		h_tools->SetMinSize(ht_s);
		
		wxSize hs_s = h_splitter->GetClientSize();
		h_splitter->SetSashPosition(hs_s.GetHeight() - (ht_s.GetHeight() + h_splitter->GetSashSize()));
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
