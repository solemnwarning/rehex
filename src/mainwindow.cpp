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

#include "AboutDialog.hpp"
#include "app.hpp"
#include "CommentTree.hpp"
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
	ID_OVERWRITE_MODE,
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
	EVT_MENU(ID_SHOW_DECODES, REHex::MainWindow::OnShowDecodes)
	
	EVT_MENU(wxID_ABOUT, REHex::MainWindow::OnAbout)
	
	EVT_AUINOTEBOOK_PAGE_CHANGED(wxID_ANY, REHex::MainWindow::OnDocumentChange)
	EVT_AUINOTEBOOK_PAGE_CLOSE(  wxID_ANY, REHex::MainWindow::OnDocumentClose)
	EVT_AUINOTEBOOK_PAGE_CLOSED( wxID_ANY, REHex::MainWindow::OnDocumentClosed)
	
	EVT_COMMAND(wxID_ANY, REHex::EV_CURSOR_MOVED,      REHex::MainWindow::OnCursorMove)
	EVT_COMMAND(wxID_ANY, REHex::EV_SELECTION_CHANGED, REHex::MainWindow::OnSelectionChange)
	EVT_COMMAND(wxID_ANY, REHex::EV_INSERT_TOGGLED,    REHex::MainWindow::OnInsertToggle)
END_EVENT_TABLE()

REHex::MainWindow::MainWindow():
	wxFrame(NULL, wxID_ANY, wxT("Reverse Engineers' Hex Editor"), wxDefaultPosition, wxSize(740, 540))
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
	
	edit_menu = new wxMenu;
	
	edit_menu->Append(wxID_UNDO, "&Undo\tCtrl-Z");
	edit_menu->Append(wxID_REDO, "&Redo\tCtrl-Shift-Z");
	
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
	
	edit_menu->Append(wxID_CUT,   "&Cut");
	edit_menu->Append(wxID_COPY,  "&Copy");
	edit_menu->Append(wxID_PASTE, "&Paste");
	
	doc_menu = new wxMenu;
	
	doc_menu->Append(ID_BYTES_LINE,  wxT("Set bytes per line"));
	doc_menu->Append(ID_BYTES_GROUP, wxT("Set bytes per group"));
	doc_menu->AppendCheckItem(ID_SHOW_OFFSETS, wxT("Show offsets"));
	doc_menu->AppendCheckItem(ID_SHOW_ASCII, wxT("Show ASCII"));
	doc_menu->AppendCheckItem(ID_SHOW_DECODES, wxT("Show decode table"));
	
	wxMenu *help_menu = new wxMenu;
	
	help_menu->Append(wxID_ABOUT, "&About");
	
	wxMenuBar *menu_bar = new wxMenuBar;
	menu_bar->Append(file_menu, wxT("&File"));
	menu_bar->Append(edit_menu, wxT("&Edit"));
	menu_bar->Append(doc_menu,  wxT("&Document"));
	menu_bar->Append(help_menu, "&Help");
	
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
	new_file();
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
	
	if(tab->doc->get_filename() == "")
	{
		OnSaveAs(event);
		return;
	}
	
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
	SetTitle(tab->doc->get_title() + " - Reverse Engineers' Hex Editor");
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

void REHex::MainWindow::OnShowDecodes(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	tab->dp->Show(event.IsChecked());
	tab->vtools_adjust();
}

void REHex::MainWindow::OnAbout(wxCommandEvent &event)
{
	REHex::AboutDialog about(this);
	about.ShowModal();
}

void REHex::MainWindow::OnDocumentChange(wxAuiNotebookEvent& event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	SetTitle(tab->doc->get_title() + " - Reverse Engineers' Hex Editor");
	
	edit_menu->Check(ID_OVERWRITE_MODE, !tab->doc->get_insert_mode());
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
		edit_menu->Check(ID_OVERWRITE_MODE, !tab->doc->get_insert_mode());
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
	EVT_SIZE(REHex::MainWindow::Tab::OnSize)
	
	EVT_COMMAND(wxID_ANY, REHex::EV_CURSOR_MOVED, REHex::MainWindow::Tab::OnCursorMove)
	
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
	
	h_tools = new wxNotebook(h_splitter, ID_HTOOLS, wxDefaultPosition, wxDefaultSize, wxNB_BOTTOM);
	h_tools->SetFitToCurrentPage(true);
	
	v_tools = new wxNotebook(v_splitter, ID_VTOOLS, wxDefaultPosition, wxDefaultSize, wxNB_RIGHT);
	v_tools->SetFitToCurrentPage(true);
	
	h_splitter->SplitHorizontally(doc, h_tools);
	v_splitter->SplitVertically(h_splitter, v_tools);
	
	wxBoxSizer *sizer = new wxBoxSizer(wxHORIZONTAL);
	sizer->Add(v_splitter, 1, wxEXPAND);
	SetSizerAndFit(sizer);
	
	dp = new REHex::DecodePanel(v_tools, doc);
	v_tools->AddPage(dp, "Decode values", true);
	
	disasm = new REHex::Disassemble(v_tools, *doc);
	v_tools->AddPage(disasm, "Disassembly", true);
	
	REHex::CommentTree *ct = new REHex::CommentTree(v_tools, doc);
	v_tools->AddPage(ct, "Comments");
	
	Bind(wxEVT_IDLE, &REHex::MainWindow::Tab::OnFirstIdle, this);
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
	
	h_tools = new wxNotebook(h_splitter, ID_HTOOLS, wxDefaultPosition, wxDefaultSize, wxNB_BOTTOM);
	h_tools->SetFitToCurrentPage(true);
	
	v_tools = new wxNotebook(v_splitter, ID_VTOOLS, wxDefaultPosition, wxDefaultSize, wxNB_RIGHT);
	v_tools->SetFitToCurrentPage(true);
	
	h_splitter->SplitHorizontally(doc, h_tools);
	v_splitter->SplitVertically(h_splitter, v_tools);
	
	wxBoxSizer *sizer = new wxBoxSizer(wxHORIZONTAL);
	sizer->Add(v_splitter, 1, wxEXPAND);
	SetSizerAndFit(sizer);
	
	dp = new REHex::DecodePanel(v_tools, doc);
	v_tools->AddPage(dp, "Decode values", true);
	
	disasm = new REHex::Disassemble(v_tools, *doc);
	v_tools->AddPage(disasm, "Disassembly", true);
	
	REHex::CommentTree *ct = new REHex::CommentTree(v_tools, doc);
	v_tools->AddPage(ct, "Comments");
	
	Bind(wxEVT_IDLE, &REHex::MainWindow::Tab::OnFirstIdle, this);
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

void REHex::MainWindow::Tab::OnCursorMove(wxCommandEvent &event)
{
	disasm->set_position(doc->get_cursor_position());
	
	/* Let the event propogate on up to MainWindow to update the status bar. */
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

/* The size of a wxNotebook page doesn't seem to be set correctly during
 * initialisation, so we can't use it to determine how much size overhead the
 * wxNotebook adds at that point. Instead we defer initial setting of the tool
 * pane sizes until the first idle tick, by which point the sizes seem to have
 * been set up properly (on GTK anyway).
*/
void REHex::MainWindow::Tab::OnFirstIdle(wxIdleEvent &event)
{
	Unbind(wxEVT_IDLE, &REHex::MainWindow::Tab::OnFirstIdle, this);
	
	htools_adjust();
	vtools_adjust();
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
