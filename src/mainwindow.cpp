/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <wx/artprov.h>
#include <wx/event.h>
#include <wx/msgdlg.h>
#include <wx/notebook.h>
#include <wx/numdlg.h>
#include <wx/sizer.h>

#include "app.hpp"
#include "decodepanel.hpp"
#include "mainwindow.hpp"

enum {
	ID_BYTES_LINE = 1,
	ID_BYTES_GROUP,
	ID_SHOW_OFFSETS,
	ID_SHOW_ASCII,
	ID_SHOW_DECODES,
};

BEGIN_EVENT_TABLE(REHex::MainWindow, wxFrame)
	EVT_MENU(wxID_NEW,    REHex::MainWindow::OnNew)
	EVT_MENU(wxID_OPEN,   REHex::MainWindow::OnOpen)
	EVT_MENU(wxID_SAVE,   REHex::MainWindow::OnSave)
	EVT_MENU(wxID_SAVEAS, REHex::MainWindow::OnSaveAs)
	EVT_MENU(wxID_EXIT,   REHex::MainWindow::OnExit)
	
	EVT_MENU(ID_BYTES_LINE,   REHex::MainWindow::OnSetBytesPerLine)
	EVT_MENU(ID_BYTES_GROUP,  REHex::MainWindow::OnSetBytesPerGroup)
	EVT_MENU(ID_SHOW_OFFSETS, REHex::MainWindow::OnShowOffsets)
	EVT_MENU(ID_SHOW_ASCII,   REHex::MainWindow::OnShowASCII)
	EVT_MENU(ID_SHOW_DECODES, REHex::MainWindow::OnShowDecodes)
	
	EVT_NOTEBOOK_PAGE_CHANGED(wxID_ANY, REHex::MainWindow::OnDocumentChange)
	
	EVT_COMMAND(wxID_ANY, REHex::EV_CURSOR_MOVED,   REHex::MainWindow::OnCursorMove)
	EVT_COMMAND(wxID_ANY, REHex::EV_INSERT_TOGGLED, REHex::MainWindow::OnInsertToggle)
END_EVENT_TABLE()

REHex::MainWindow::MainWindow():
	wxFrame(NULL, wxID_ANY, wxT("Reverse Engineer's Hex Editor"))
{
	wxMenu *file_menu = new wxMenu;
	
	file_menu->Append(wxID_NEW,    wxT("&New"));
	file_menu->Append(wxID_OPEN,   wxT("&Open"));
	file_menu->Append(wxID_SAVE,   wxT("&Save"));
	file_menu->Append(wxID_SAVEAS, wxT("&Save As"));
	file_menu->AppendSeparator();
	file_menu->Append(wxID_EXIT,   wxT("&Exit"));
	
	doc_menu = new wxMenu;
	
	doc_menu->Append(ID_BYTES_LINE,  wxT("Set bytes per line"));
	doc_menu->Append(ID_BYTES_GROUP, wxT("Set bytes per group"));
	doc_menu->AppendCheckItem(ID_SHOW_OFFSETS, wxT("Show offsets"));
	doc_menu->AppendCheckItem(ID_SHOW_ASCII, wxT("Show ASCII"));
	doc_menu->AppendCheckItem(ID_SHOW_DECODES, wxT("Show decode table"));
	
	wxMenuBar *menu_bar = new wxMenuBar;
	menu_bar->Append(file_menu, wxT("&File"));
	menu_bar->Append(doc_menu,  wxT("&Document"));
	
	SetMenuBar(menu_bar);
	
	wxToolBar *toolbar = CreateToolBar();
	wxArtProvider artp;
	
	toolbar->AddTool(wxID_NEW,    "New",     artp.GetBitmap(wxART_NEW,          wxART_TOOLBAR));
	toolbar->AddTool(wxID_OPEN,   "Open",    artp.GetBitmap(wxART_FILE_OPEN,    wxART_TOOLBAR));
	toolbar->AddTool(wxID_SAVE,   "Save",    artp.GetBitmap(wxART_FILE_SAVE,    wxART_TOOLBAR));
	toolbar->AddTool(wxID_SAVEAS, "Save As", artp.GetBitmap(wxART_FILE_SAVE_AS, wxART_TOOLBAR));
	
	notebook = new wxNotebook(this, wxID_ANY);
	
	CreateStatusBar(2);
	
	/* Temporary hack to open files provided on the command line */
	
	REHex::App &app = wxGetApp();
	
	if(app.argc > 1)
	{
		for(int i = 1; i < app.argc; ++i)
		{
			Tab *tab = new Tab(notebook, app.argv[i].ToStdString());
			notebook->AddPage(tab, tab->doc->get_title(), true);
		}
	}
	else{
		ProcessCommand(wxID_NEW);
	}
}

void REHex::MainWindow::OnNew(wxCommandEvent &event)
{
	Tab *tab = new Tab(notebook);
	notebook->AddPage(tab, tab->doc->get_title(), true);
}

void REHex::MainWindow::OnOpen(wxCommandEvent &event)
{
	wxFileDialog openFileDialog(this, wxT("Open File"), "", "", "", wxFD_OPEN | wxFD_FILE_MUST_EXIST);
	if(openFileDialog.ShowModal() == wxID_CANCEL)
		return;
	
	Tab *tab;
	try {
		tab = new Tab(notebook, openFileDialog.GetPath().ToStdString());
	}
	catch(const std::exception &e)
	{
		wxMessageBox(
			std::string("Error opening ") + openFileDialog.GetFilename().ToStdString() + ":\n" + e.what(),
			"Error", wxICON_ERROR, this);
		return;
	}
	
	notebook->AddPage(tab, tab->doc->get_title(), true);
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

void REHex::MainWindow::OnExit(wxCommandEvent &event)
{
	Close();
}

void REHex::MainWindow::OnSetBytesPerLine(wxCommandEvent &event)
{
	/* I doubt anyone even wants remotely this many. We enforce a limit just
	 * to avoid performance/rendering issues with insanely long lines.
	*/
	const int MAX_BYTES_PER_LINE = 512;
	
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
	/* There's no real limit to this, but wxWidgets needs one. */
	const int MAX_BYTES_PER_GROUP = 1024;
	
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	int new_value = wxGetNumberFromUser(
		"Number of bytes to group",
		"Bytes",
		"Set bytes per group",
		tab->doc->get_bytes_per_group(),
		0,
		MAX_BYTES_PER_GROUP,
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
	tab->GetSizer()->Layout();
}

void REHex::MainWindow::OnDocumentChange(wxBookCtrlEvent& event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<REHex::MainWindow::Tab*>(cpage);
	assert(tab != NULL);
	
	doc_menu->Check(ID_SHOW_OFFSETS, tab->doc->get_show_offsets());
	doc_menu->Check(ID_SHOW_ASCII,   tab->doc->get_show_ascii());
	doc_menu->Check(ID_SHOW_DECODES, tab->dp->IsShown());
	
	_update_status_offset(tab->doc);
	_update_status_mode(tab->doc);
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
	off_t off = doc->get_offset();
	
	char buf[64];
	snprintf(buf, sizeof(buf), "Offset: %08x:%08x",
		(unsigned int)((off & 0x00000000FFFFFFFF) << 32),
		(unsigned int)(off & 0xFFFFFFFF));
	
	SetStatusText(buf, 0);
}

void REHex::MainWindow::_update_status_mode(REHex::Document *doc)
{
	if(doc->get_insert_mode())
	{
		SetStatusText("Mode: Insert", 1);
	}
	else{
		SetStatusText("Mode: Overwrite", 1);
	}
}

REHex::MainWindow::Tab::Tab(wxWindow *parent):
	wxPanel(parent), doc(NULL), dp(NULL)
{
	wxBoxSizer *v_sizer = NULL;
	
	try {
		v_sizer = new wxBoxSizer(wxVERTICAL);
		
		doc = new REHex::Document(this);
		v_sizer->Add(doc, 1, wxEXPAND | wxALL, 0);
		
		dp = new REHex::DecodePanel(this);
		v_sizer->Add(dp, 0, wxALIGN_LEFT, 0);
		
		SetSizerAndFit(v_sizer);
	}
	catch(const std::exception &e)
	{
		delete dp;
		delete doc;
		delete v_sizer;
		
		throw e;
	}
}


REHex::MainWindow::Tab::Tab(wxWindow *parent, const std::string &filename):
	wxPanel(parent), doc(NULL), dp(NULL)
{
	wxBoxSizer *v_sizer = NULL;
	
	try {
		v_sizer = new wxBoxSizer(wxVERTICAL);
		
		doc = new REHex::Document(this, filename);
		v_sizer->Add(doc, 1, wxEXPAND | wxALL, 0);
		
		dp = new REHex::DecodePanel(this);
		v_sizer->Add(dp, 0, wxALIGN_LEFT, 0);
		
		SetSizerAndFit(v_sizer);
	}
	catch(const std::exception &e)
	{
		delete dp;
		delete doc;
		delete v_sizer;
		
		throw e;
	}
}
