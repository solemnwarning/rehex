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

#include <wx/artprov.h>
#include <wx/notebook.h>
#include <wx/numdlg.h>

#include "app.hpp"
#include "mainwindow.hpp"

enum {
	ID_BYTES_LINE = 1,
	ID_BYTES_GROUP,
};

BEGIN_EVENT_TABLE(REHex::MainWindow, wxFrame)
	EVT_MENU(wxID_NEW,    REHex::MainWindow::OnNew)
	EVT_MENU(wxID_OPEN,   REHex::MainWindow::OnOpen)
	EVT_MENU(wxID_SAVE,   REHex::MainWindow::OnSave)
	EVT_MENU(wxID_SAVEAS, REHex::MainWindow::OnSaveAs)
	EVT_MENU(wxID_EXIT,   REHex::MainWindow::OnExit)
	
	EVT_MENU(ID_BYTES_LINE,  REHex::MainWindow::OnSetBytesPerLine)
	EVT_MENU(ID_BYTES_GROUP, REHex::MainWindow::OnSetBytesPerGroup)
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
	
	wxMenu *doc_menu = new wxMenu;
	
	doc_menu->Append(ID_BYTES_LINE,  wxT("Set bytes per line"));
	doc_menu->Append(ID_BYTES_GROUP, wxT("Set bytes per group"));
	
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
	SetStatusText(wxT("Test"));
	
	/* Temporary hack to open files provided on the command line */
	
	REHex::App &app = wxGetApp();
	
	if(app.argc > 1)
	{
		for(int i = 1; i < app.argc; ++i)
		{
			REHex::Buffer *buffer = new REHex::Buffer(app.argv[i].ToStdString());
			
			REHex::Document *doc = new REHex::Document(notebook, wxID_ANY, buffer);
			notebook->AddPage(doc, app.argv[i], true);
		}
	}
	else{
		ProcessCommand(wxID_NEW);
	}
}

void REHex::MainWindow::OnNew(wxCommandEvent &event)
{
	REHex::Document *doc = new REHex::Document(notebook, wxID_ANY, new REHex::Buffer());
	notebook->AddPage(doc, "New file", true);
}

void REHex::MainWindow::OnOpen(wxCommandEvent &event)
{
	wxFileDialog openFileDialog(this, wxT("Open File"), "", "", "", wxFD_OPEN | wxFD_FILE_MUST_EXIST);
	if(openFileDialog.ShowModal() == wxID_CANCEL)
		return;
	
	REHex::Buffer *buffer = new REHex::Buffer(openFileDialog.GetPath().ToStdString());
	
	REHex::Document *doc = new REHex::Document(notebook, wxID_ANY, buffer);
	notebook->AddPage(doc, openFileDialog.GetFilename(), true);
}

void REHex::MainWindow::OnSave(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto doc = dynamic_cast<REHex::Document*>(cpage);
	assert(doc != NULL);
	
	doc->save();
}

void REHex::MainWindow::OnSaveAs(wxCommandEvent &event)
{
	wxFileDialog saveFileDialog(this, wxT("Save As"), "", "", "", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
	if(saveFileDialog.ShowModal() == wxID_CANCEL)
		return;
	
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto doc = dynamic_cast<REHex::Document*>(cpage);
	assert(doc != NULL);
	
	doc->save(saveFileDialog.GetPath().ToStdString());
	
	notebook->SetPageText(notebook->GetSelection(), saveFileDialog.GetFilename());
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
	
	auto doc = dynamic_cast<REHex::Document*>(cpage);
	assert(doc != NULL);
	
	/* TODO: Make a dialog with an explicit "auto" radio choice? */
	int new_value = wxGetNumberFromUser(
		"Number of bytes to show on each line\n(0 fits to the window width)",
		"Bytes",
		"Set bytes per line",
		doc->get_bytes_per_line(),
		0,
		MAX_BYTES_PER_LINE,
		this);
	
	/* We get a negative value if the user cancels. */
	if(new_value >= 0)
	{
		doc->set_bytes_per_line(new_value);
	}
}

void REHex::MainWindow::OnSetBytesPerGroup(wxCommandEvent &event)
{
	/* There's no real limit to this, but wxWidgets needs one. */
	const int MAX_BYTES_PER_GROUP = 1024;
	
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto doc = dynamic_cast<REHex::Document*>(cpage);
	assert(doc != NULL);
	
	int new_value = wxGetNumberFromUser(
		"Number of bytes to group",
		"Bytes",
		"Set bytes per group",
		doc->get_bytes_per_group(),
		0,
		MAX_BYTES_PER_GROUP,
		this);
	
	/* We get a negative value if the user cancels. */
	if(new_value >= 0)
	{
		doc->set_bytes_per_group(new_value);
	}
}
