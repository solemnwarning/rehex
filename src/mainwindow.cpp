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

#include "app.hpp"
#include "mainwindow.hpp"

BEGIN_EVENT_TABLE(REHex::MainWindow, wxFrame)
	EVT_MENU(wxID_NEW,    REHex::MainWindow::OnNew)
	EVT_MENU(wxID_OPEN,   REHex::MainWindow::OnOpen)
	EVT_MENU(wxID_SAVE,   REHex::MainWindow::OnSave)
	EVT_MENU(wxID_SAVEAS, REHex::MainWindow::OnSaveAs)
	EVT_MENU(wxID_EXIT,   REHex::MainWindow::OnExit)
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
	
	wxMenuBar *menu_bar = new wxMenuBar;
	menu_bar->Append(file_menu, wxT("&File"));
	
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
	wxFileDialog openFileDialog(this, wxT("Open File"), "", "", "*.*", wxFD_OPEN | wxFD_FILE_MUST_EXIST);
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
	wxFileDialog saveFileDialog(this, wxT("Save As"), "", "", "*.*", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
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
