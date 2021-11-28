/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2021 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <limits>
#include <new>
#include <wx/artprov.h>
#include <wx/clipbrd.h>
#include <wx/dataobj.h>
#include <wx/event.h>
#include <wx/filename.h>
#include <wx/fontenum.h>
#include <wx/msgdlg.h>
#include <wx/aui/auibook.h>
#include <wx/numdlg.h>

#include "AboutDialog.hpp"
#include "App.hpp"
#include "BytesPerLineDialog.hpp"
#include "FillRangeDialog.hpp"
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
#include "../res/backward32.h"
#include "../res/document_new32.h"
#include "../res/document_open32.h"
#include "../res/document_save32.h"
#include "../res/document_save_as32.h"
#include "../res/forward32.h"
#endif

enum {
	ID_BYTES_LINE = 1,
	ID_BYTES_GROUP,
	ID_SHOW_OFFSETS,
	ID_SHOW_ASCII,
	ID_SEARCH_TEXT,
	ID_SEARCH_BSEQ,
	ID_SEARCH_VALUE,
	ID_COMPARE_FILE,
	ID_GOTO_OFFSET,
	ID_OVERWRITE_MODE,
	ID_WRITE_PROTECT,
	ID_SAVE_VIEW,
	ID_INLINE_COMMENTS_HIDDEN,
	ID_INLINE_COMMENTS_FULL,
	ID_INLINE_COMMENTS_SHORT,
	ID_INLINE_COMMENTS_INDENT,
	ID_HIGHLIGHT_SELECTION_MATCH,
	ID_HEX_OFFSETS,
	ID_DEC_OFFSETS,
	ID_DDM_NORMAL,
	ID_DDM_VIRTUAL,
	ID_SELECT_RANGE,
	ID_FILL_RANGE,
	ID_SYSTEM_PALETTE,
	ID_LIGHT_PALETTE,
	ID_DARK_PALETTE,
	ID_FSA_INCREASE,
	ID_FSA_DECREASE,
	ID_CLOSE_ALL,
	ID_CLOSE_OTHERS,
	ID_GITHUB,
	ID_DONATE,
};

BEGIN_EVENT_TABLE(REHex::MainWindow, wxFrame)
	EVT_CLOSE(REHex::MainWindow::OnWindowClose)
	EVT_CHAR_HOOK(REHex::MainWindow::OnCharHook)
	
	EVT_MENU(wxID_NEW,        REHex::MainWindow::OnNew)
	EVT_MENU(wxID_OPEN,       REHex::MainWindow::OnOpen)
	EVT_MENU(wxID_SAVE,       REHex::MainWindow::OnSave)
	EVT_MENU(wxID_SAVEAS,     REHex::MainWindow::OnSaveAs)
	EVT_MENU(wxID_CLOSE,      REHex::MainWindow::OnClose)
	EVT_MENU(ID_CLOSE_ALL,    REHex::MainWindow::OnCloseAll)
	EVT_MENU(ID_CLOSE_OTHERS, REHex::MainWindow::OnCloseOthers)
	EVT_MENU(wxID_EXIT,       REHex::MainWindow::OnExit)
	
	EVT_MENU(wxID_BACKWARD, REHex::MainWindow::OnCursorPrev)
	EVT_MENU(wxID_FORWARD,  REHex::MainWindow::OnCursorNext)
	
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
	
	EVT_MENU(ID_FILL_RANGE, REHex::MainWindow::OnFillRange)
	EVT_MENU(ID_OVERWRITE_MODE, REHex::MainWindow::OnOverwriteMode)
	EVT_MENU(ID_WRITE_PROTECT, REHex::MainWindow::OnWriteProtect)
	
	EVT_MENU(ID_SEARCH_TEXT, REHex::MainWindow::OnSearchText)
	EVT_MENU(ID_SEARCH_BSEQ,  REHex::MainWindow::OnSearchBSeq)
	EVT_MENU(ID_SEARCH_VALUE,  REHex::MainWindow::OnSearchValue)
	
	EVT_MENU(ID_COMPARE_FILE,  REHex::MainWindow::OnCompareFile)
	
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
	
	EVT_MENU(ID_FSA_INCREASE, REHex::MainWindow::OnFSAIncrease)
	EVT_MENU(ID_FSA_DECREASE, REHex::MainWindow::OnFSADecrease)
	
	EVT_MENU(ID_HEX_OFFSETS,   REHex::MainWindow::OnHexOffsets)
	EVT_MENU(ID_DEC_OFFSETS,   REHex::MainWindow::OnDecOffsets)
	
	EVT_MENU(ID_DDM_NORMAL,     REHex::MainWindow::OnDocumentDisplayMode)
	EVT_MENU(ID_DDM_VIRTUAL,    REHex::MainWindow::OnDocumentDisplayMode)
	
	EVT_MENU(ID_GITHUB,  REHex::MainWindow::OnGithub)
	EVT_MENU(ID_DONATE,  REHex::MainWindow::OnDonate)
	EVT_MENU(wxID_ABOUT, REHex::MainWindow::OnAbout)
	
	EVT_AUINOTEBOOK_PAGE_CHANGED(  wxID_ANY, REHex::MainWindow::OnDocumentChange)
	EVT_AUINOTEBOOK_PAGE_CLOSE(    wxID_ANY, REHex::MainWindow::OnDocumentClose)
	EVT_AUINOTEBOOK_PAGE_CLOSED(   wxID_ANY, REHex::MainWindow::OnDocumentClosed)
	EVT_AUINOTEBOOK_TAB_RIGHT_DOWN(wxID_ANY, REHex::MainWindow::OnDocumentMenu)
	EVT_AUINOTEBOOK_TAB_MIDDLE_UP( wxID_ANY, REHex::MainWindow::OnDocumentMiddleMouse)
	
	EVT_CURSORUPDATE(wxID_ANY, REHex::MainWindow::OnCursorUpdate)
	
	EVT_COMMAND(wxID_ANY, REHex::EV_SELECTION_CHANGED, REHex::MainWindow::OnSelectionChange)
	EVT_COMMAND(wxID_ANY, REHex::EV_INSERT_TOGGLED,    REHex::MainWindow::OnInsertToggle)
	EVT_COMMAND(wxID_ANY, REHex::EV_UNDO_UPDATE,       REHex::MainWindow::OnUndoUpdate)
	EVT_COMMAND(wxID_ANY, REHex::EV_BECAME_DIRTY,      REHex::MainWindow::OnBecameDirty)
	EVT_COMMAND(wxID_ANY, REHex::EV_BECAME_CLEAN,      REHex::MainWindow::OnBecameClean)
END_EVENT_TABLE()

REHex::MainWindow::MainWindow(const wxSize& size):
	wxFrame(NULL, wxID_ANY, "Reverse Engineers' Hex Editor", wxDefaultPosition, size),
	menu_bar(NULL),
	file_menu(NULL),
	edit_menu(NULL),
	view_menu(NULL),
	tools_menu(NULL),
	help_menu(NULL)
{
	menu_bar = new wxMenuBar;
	
	{
		call_setup_hooks(SetupPhase::FILE_MENU_PRE);
		
		file_menu = new wxMenu;
		
		call_setup_hooks(SetupPhase::FILE_MENU_TOP);
		
		file_menu->Append(wxID_NEW,  "&New\tCtrl-N");
		file_menu->Append(wxID_OPEN, "&Open\tCtrl-O");
		
		recent_files_menu = new wxMenu;
		file_menu->AppendSubMenu(recent_files_menu, "Open &Recent");
		
		file_menu->Append(wxID_SAVE,   "&Save\tCtrl-S");
		file_menu->Append(wxID_SAVEAS, "&Save As");
		
		file_menu->AppendSeparator(); /* ---- */
		
		file_menu->Append(wxID_CLOSE,  "&Close\tCtrl-W");
		file_menu->Append(ID_CLOSE_ALL, "Close All");
		file_menu->Append(ID_CLOSE_OTHERS, "Close Others");
		
		file_menu->AppendSeparator(); /* ---- */
		
		file_menu->Append(wxID_EXIT, "&Exit");
		
		call_setup_hooks(SetupPhase::FILE_MENU_BOTTOM);
		
		menu_bar->Append(file_menu, "&File");
		
		call_setup_hooks(SetupPhase::FILE_MENU_POST);
	}
	
	{
		call_setup_hooks(SetupPhase::EDIT_MENU_PRE);
		
		edit_menu = new wxMenu;
		
		call_setup_hooks(SetupPhase::EDIT_MENU_TOP);
		
		edit_menu->Append(wxID_UNDO, "&Undo\tCtrl-Z");
		edit_menu->Append(wxID_REDO, "&Redo\tCtrl-Shift-Z");
		
		edit_menu->AppendSeparator(); /* ---- */
		
		edit_menu->Append(wxID_SELECTALL, "Select &All\tCtrl-A");
		edit_menu->Append(ID_SELECT_RANGE, "Select range...");
		
		edit_menu->AppendSeparator(); /* ---- */
		
		edit_menu->Append(ID_FILL_RANGE, "Fill range...");
		
		#ifdef __APPLE__
		edit_menu->AppendCheckItem(ID_OVERWRITE_MODE, "Overwrite mode");
		#else
		edit_menu->AppendCheckItem(ID_OVERWRITE_MODE, "Overwrite mode\tIns");
		#endif
		
		edit_menu->AppendCheckItem(ID_WRITE_PROTECT, "Write protect file data");
		
		edit_menu->AppendSeparator(); /* ---- */
		
		edit_menu->Append(ID_SEARCH_TEXT,  "Search for text...");
		edit_menu->Append(ID_SEARCH_BSEQ,  "Search for byte sequence...");
		edit_menu->Append(ID_SEARCH_VALUE, "Search for value...");
		
		edit_menu->AppendSeparator(); /* ---- */
		
		edit_menu->Append(ID_COMPARE_FILE, "Compare whole file...\tCtrl-K");
		
		edit_menu->AppendSeparator(); /* ---- */
		
		edit_menu->Append(ID_GOTO_OFFSET, "Jump to offset...\tCtrl-G");
		
		edit_menu->AppendSeparator(); /* ---- */
		
		edit_menu->Append(wxID_CUT,   "Cu&t\tCtrl-X");
		edit_menu->Append(wxID_COPY,  "&Copy\tCtrl-C");
		edit_menu->Append(wxID_PASTE, "&Paste\tCtrl-V");
		
		call_setup_hooks(SetupPhase::EDIT_MENU_BOTTOM);
		
		menu_bar->Append(edit_menu, "&Edit");
		
		call_setup_hooks(SetupPhase::EDIT_MENU_POST);
	}
	
	{
		call_setup_hooks(SetupPhase::VIEW_MENU_PRE);
		
		view_menu = new wxMenu;
		
		call_setup_hooks(SetupPhase::VIEW_MENU_TOP);
		
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
		
		view_menu->AppendSeparator(); /* ---- */
		
		view_menu->AppendRadioItem(ID_HEX_OFFSETS, "Display offsets in hexadecimal");
		view_menu->AppendRadioItem(ID_DEC_OFFSETS, "Display offsets in decimal");
		
		view_menu->AppendSeparator(); /* ---- */
		
		view_menu->AppendRadioItem(ID_DDM_NORMAL,  "Display file data");
		view_menu->AppendRadioItem(ID_DDM_VIRTUAL, "Display virtual sections");
		
		view_menu->AppendSeparator(); /* ---- */
		
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
		
		view_menu->AppendSeparator(); /* ---- */
		
		wxMenu *font_menu = new wxMenu;
		view_menu->AppendSubMenu(font_menu, "Select font");
		
		wxArrayString font_names = wxFontEnumerator::GetFacenames(wxFONTENCODING_SYSTEM, true);
		
		for(size_t i = 0; i < font_names.GetCount(); ++i)
		{
			std::string font_name = font_names[i].ToStdString();
			
			wxMenuItem *itm = font_menu->AppendRadioItem(wxID_ANY, font_name);
			if(font_name == wxGetApp().get_font_name())
			{
				itm->Check(true);
			}
			
			Bind(wxEVT_MENU, [font_name, itm](wxCommandEvent &event)
			{
				wxGetApp().set_font_name(font_name);
				itm->Check(true);
			}, itm->GetId(), itm->GetId());
		}
		
		view_menu->Append(ID_FSA_INCREASE, "Increase font size");
		view_menu->Append(ID_FSA_DECREASE, "Decrease font size");
		
		view_menu->AppendSeparator();  /* ---- */
		
		view_menu->Append(ID_SAVE_VIEW, "Save current view as default");
		
		call_setup_hooks(SetupPhase::VIEW_MENU_BOTTOM);
		
		menu_bar->Append(view_menu, "&View");
		
		call_setup_hooks(SetupPhase::VIEW_MENU_POST);
	}
	
	{
		call_setup_hooks(SetupPhase::TOOLS_MENU_PRE);
		
		tools_menu = new wxMenu;
		
		call_setup_hooks(SetupPhase::TOOLS_MENU_TOP);
		call_setup_hooks(SetupPhase::TOOLS_MENU_BOTTOM);
		
		if(tools_menu->GetMenuItemCount() > 0)
		{
			menu_bar->Append(tools_menu, "&Tools");
		}
		else{
			/* No plugins created an item under the "Tools" menu - get rid of it. */
			
			delete tools_menu;
			tools_menu = NULL;
		}
		
		call_setup_hooks(SetupPhase::TOOLS_MENU_POST);
	}
	
	{
		call_setup_hooks(SetupPhase::HELP_MENU_PRE);
		
		help_menu = new wxMenu;
		
		call_setup_hooks(SetupPhase::HELP_MENU_TOP);
		
		help_menu->Append(ID_GITHUB, "Visit &Github page");
		help_menu->Append(ID_DONATE, "Donate with &Paypal");
		help_menu->Append(wxID_ABOUT, "&About");
		
		call_setup_hooks(SetupPhase::HELP_MENU_BOTTOM);
		
		menu_bar->Append(help_menu, "&Help");
		
		call_setup_hooks(SetupPhase::HELP_MENU_POST);
	}
	
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
	
	toolbar->AddSeparator();
	
	toolbar->AddTool(wxID_BACKWARD, "Previous cursor position", wxBITMAP_PNG_FROM_DATA(backward32));
	toolbar->AddTool(wxID_FORWARD,  "Next cursor position",     wxBITMAP_PNG_FROM_DATA(forward32));
	#else
	toolbar->AddTool(wxID_NEW,    "New",     artp.GetBitmap(wxART_NEW,          wxART_TOOLBAR));
	toolbar->AddTool(wxID_OPEN,   "Open",    artp.GetBitmap(wxART_FILE_OPEN,    wxART_TOOLBAR));
	toolbar->AddTool(wxID_SAVE,   "Save",    artp.GetBitmap(wxART_FILE_SAVE,    wxART_TOOLBAR));
	toolbar->AddTool(wxID_SAVEAS, "Save As", artp.GetBitmap(wxART_FILE_SAVE_AS, wxART_TOOLBAR));
	
	toolbar->AddSeparator();
	
	toolbar->AddTool(wxID_BACKWARD, "Previous cursor position", artp.GetBitmap(wxART_GO_BACK,    wxART_TOOLBAR));
	toolbar->AddTool(wxID_FORWARD,  "Next cursor position",     artp.GetBitmap(wxART_GO_FORWARD, wxART_TOOLBAR));
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
	
	call_setup_hooks(SetupPhase::DONE);
}

REHex::MainWindow::~MainWindow()
{
	wxGetApp().recent_files->RemoveMenu(recent_files_menu);
}

void REHex::MainWindow::new_file()
{
	Tab *tab = new Tab(notebook);
	notebook->AddPage(tab, tab->doc->get_title(), true);
	tab->doc_ctrl->SetFocus();
	
	TabCreatedEvent event(this, tab);
	wxPostEvent(this, event);
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
		
		auto page_tab = dynamic_cast<Tab*>(page);
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
	tab->doc_ctrl->SetFocus();
	
	TabCreatedEvent event(this, tab);
	wxPostEvent(this, event);
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

void REHex::MainWindow::OnCharHook(wxKeyEvent &event)
{
	int modifiers = event.GetModifiers();
	int key = event.GetKeyCode();
	
	if(modifiers == (wxMOD_CMD | wxMOD_SHIFT) && key == 'K')
	{
		Tab *tab = active_tab();
		tab->compare_selection();
	}
	else{
		event.Skip();
	}
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
	
	auto tab = dynamic_cast<Tab*>(cpage);
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
	
	auto tab = dynamic_cast<Tab*>(cpage);
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
	
	auto tab = dynamic_cast<Tab*>(cpage);
	assert(tab != NULL);
	
	close_other_tabs(tab);
}

void REHex::MainWindow::OnExit(wxCommandEvent &event)
{
	Close();
}

void REHex::MainWindow::OnCursorPrev(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	tab->doc_ctrl->goto_prev_cursor_position();
}

void REHex::MainWindow::OnCursorNext(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	tab->doc_ctrl->goto_next_cursor_position();
}

void REHex::MainWindow::OnSearchText(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<Tab*>(cpage);
	assert(tab != NULL);
	
	REHex::Search::Text *sd = new REHex::Search::Text(tab, tab->doc);
	sd->Show(true);
	
	tab->search_dialog_register(sd);
}

void REHex::MainWindow::OnSearchBSeq(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<Tab*>(cpage);
	assert(tab != NULL);
	
	REHex::Search::ByteSequence *sd = new REHex::Search::ByteSequence(tab, tab->doc);
	sd->Show(true);
	
	tab->search_dialog_register(sd);
}

void REHex::MainWindow::OnSearchValue(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<Tab*>(cpage);
	assert(tab != NULL);
	
	REHex::Search::Value *sd = new REHex::Search::Value(tab, tab->doc);
	sd->Show(true);
	
	tab->search_dialog_register(sd);
}

void REHex::MainWindow::OnCompareFile(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	tab->compare_whole_file();
}

void REHex::MainWindow::OnGotoOffset(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	
	off_t current_pos = tab->doc->get_cursor_position();
	off_t max_pos     = tab->doc->buffer_length() - !tab->doc_ctrl->get_insert_mode();
	
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
	Tab *tab = active_tab();
	tab->handle_copy(true);
}

void REHex::MainWindow::OnCopy(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	tab->handle_copy(false);
}

void REHex::MainWindow::OnPaste(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	
	ClipboardGuard cg;
	if(cg)
	{
		/* If there is a selection and it is entirely contained within a Region, give that
		 * region the chance to handle the paste event.
		*/
		
		if(tab->doc_ctrl->has_selection())
		{
			off_t selection_first, selection_last;
			std::tie(selection_first, selection_last) = tab->doc_ctrl->get_selection_raw();
			
			REHex::DocumentCtrl::GenericDataRegion *selection_region = tab->doc_ctrl->data_region_by_offset(selection_first);
			assert(selection_region != NULL);
			
			assert(selection_region->d_offset <= selection_last);
			assert((selection_region->d_offset + (selection_region->d_length)) > selection_first);
			
			if((selection_region->d_offset + selection_region->d_length) > selection_last)
			{
				if(selection_region->OnPaste(tab->doc_ctrl))
				{
					/* Region consumed the paste event. */
					return;
				}
			}
		}
		
		/* Give the region the cursor is in a chance to handle the paste event. */
		
		off_t cursor_pos = tab->doc_ctrl->get_cursor_position();
		
		REHex::DocumentCtrl::GenericDataRegion *cursor_region = tab->doc_ctrl->data_region_by_offset(cursor_pos);
		assert(cursor_region != NULL);
		
		if(cursor_region->OnPaste(tab->doc_ctrl))
		{
			/* Region consumed the paste event. */
			return;
		}
		
		/* No region consumed the event. Fallback to default handling. */
		
		if(wxTheClipboard->IsSupported(CommentsDataObject::format))
		{
			CommentsDataObject data;
			wxTheClipboard->GetData(data);
			
			auto clipboard_comments = data.get_comments();
			
			tab->doc->handle_paste(tab, clipboard_comments);
		}
		else if(wxTheClipboard->IsSupported(wxDF_TEXT))
		{
			wxTextDataObject data;
			wxTheClipboard->GetData(data);
			
			try {
				wxString clipboard_text = data.GetText();
				const wxScopedCharBuffer clipboard_utf8 = clipboard_text.utf8_str();
				
				tab->paste_text(std::string(clipboard_utf8.data(), clipboard_utf8.length()));
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
	
	auto tab = dynamic_cast<Tab*>(cpage);
	assert(tab != NULL);
	
	tab->doc->undo();
}

void REHex::MainWindow::OnRedo(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<Tab*>(cpage);
	assert(tab != NULL);
	
	tab->doc->redo();
}

void REHex::MainWindow::OnSelectAll(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	
	DocumentCtrl::GenericDataRegion *first_region = tab->doc_ctrl->get_data_regions().front();
	DocumentCtrl::GenericDataRegion *last_region = tab->doc_ctrl->get_data_regions().back();
	
	off_t first_off = first_region->d_offset;
	off_t last_off  = last_region->d_offset + last_region->d_length - (last_region->d_length > 0);
	
	tab->doc_ctrl->set_selection_raw(first_off, last_off);
}

void REHex::MainWindow::OnSelectRange(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	
	REHex::SelectRangeDialog srd(this, *(tab->doc), *(tab->doc_ctrl));
	srd.ShowModal();
}

void REHex::MainWindow::OnFillRange(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	
	REHex::FillRangeDialog frd(this, *(tab->doc), *(tab->doc_ctrl));
	frd.ShowModal();
}

void REHex::MainWindow::OnOverwriteMode(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	tab->doc_ctrl->set_insert_mode(!event.IsChecked());
}

void REHex::MainWindow::OnWriteProtect(wxCommandEvent &event)
{
	Document *doc = active_document();
	
	if(event.IsChecked() && doc->is_buffer_dirty())
	{
		std::string msg
			= "The content of " + doc->get_title() + " has already been modified.\n"
			+ "Enable write protect to prevent FURTHER changes?";
		
		int res = wxMessageBox(msg, "File data modified", (wxYES_NO | wxICON_EXCLAMATION), this);
		if(res == wxNO)
		{
			edit_menu->Check(ID_WRITE_PROTECT, false);
			return;
		}
	}
	
	doc->set_write_protect(event.IsChecked());
}

void REHex::MainWindow::OnSetBytesPerLine(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	
	BytesPerLineDialog bpld(this, tab->doc_ctrl->get_bytes_per_line());
	if(bpld.ShowModal() == wxID_OK)
	{
		tab->doc_ctrl->set_bytes_per_line(bpld.get_bytes_per_line());
	}
}

void REHex::MainWindow::OnSetBytesPerGroup(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<Tab*>(cpage);
	assert(tab != NULL);
	
	int new_value = wxGetNumberFromUser(
		"Number of bytes to group",
		"Bytes",
		"Set bytes per group",
		tab->doc_ctrl->get_bytes_per_group(),
		1,
		std::numeric_limits<int>::max(),
		this);
	
	/* We get a negative value if the user cancels. */
	if(new_value >= 0)
	{
		tab->doc_ctrl->set_bytes_per_group(new_value);
	}
}

void REHex::MainWindow::OnShowOffsets(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	tab->doc_ctrl->set_show_offsets(event.IsChecked());
}

void REHex::MainWindow::OnShowASCII(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	tab->doc_ctrl->set_show_ascii(event.IsChecked());
}

void REHex::MainWindow::OnInlineCommentsMode(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<Tab*>(cpage);
	assert(tab != NULL);
	
	if(inline_comments_menu->IsChecked(ID_INLINE_COMMENTS_HIDDEN))
	{
		tab->set_inline_comment_mode(ICM_HIDDEN);
		inline_comments_menu->Enable(ID_INLINE_COMMENTS_INDENT, false);
	}
	else if(inline_comments_menu->IsChecked(ID_INLINE_COMMENTS_FULL))
	{
		tab->set_inline_comment_mode(
			inline_comments_menu->IsChecked(ID_INLINE_COMMENTS_INDENT)
				? ICM_FULL_INDENT
				: ICM_FULL);
		
		inline_comments_menu->Enable(ID_INLINE_COMMENTS_INDENT, true);
	}
	else if(inline_comments_menu->IsChecked(ID_INLINE_COMMENTS_SHORT))
	{
		tab->set_inline_comment_mode(
			inline_comments_menu->IsChecked(ID_INLINE_COMMENTS_INDENT)
				? ICM_SHORT_INDENT
				: ICM_SHORT);
		
		inline_comments_menu->Enable(ID_INLINE_COMMENTS_INDENT, true);
	}
}

void REHex::MainWindow::OnDocumentDisplayMode(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	
	if(view_menu->IsChecked(ID_DDM_NORMAL))
	{
		tab->set_document_display_mode(DDM_NORMAL);
	}
	else if(view_menu->IsChecked(ID_DDM_VIRTUAL))
	{
		tab->set_document_display_mode(DDM_VIRTUAL);
	}
}

void REHex::MainWindow::OnHighlightSelectionMatch(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	tab->doc_ctrl->set_highlight_selection_match(event.IsChecked());
}

void REHex::MainWindow::OnShowToolPanel(wxCommandEvent &event, const REHex::ToolPanelRegistration *tpr)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<Tab*>(cpage);
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
	
	wxCommandEvent pc_event(PALETTE_CHANGED);
	wxGetApp().ProcessEvent(pc_event);
	
	Refresh();
}

void REHex::MainWindow::OnFSAIncrease(wxCommandEvent &event)
{
	App &app = wxGetApp();
	app.set_font_size_adjustment(app.get_font_size_adjustment() + 1);
}

void REHex::MainWindow::OnFSADecrease(wxCommandEvent &event)
{
	App &app = wxGetApp();
	app.set_font_size_adjustment(app.get_font_size_adjustment() - 1);
}

void REHex::MainWindow::OnHexOffsets(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	
	tab->doc_ctrl->set_offset_display_base(OFFSET_BASE_HEX);
	
	_update_status_offset(tab);
	_update_status_selection(tab->doc_ctrl);
}

void REHex::MainWindow::OnDecOffsets(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	
	tab->doc_ctrl->set_offset_display_base(OFFSET_BASE_DEC);
	
	_update_status_offset(tab);
	_update_status_selection(tab->doc_ctrl);
}

void REHex::MainWindow::OnSaveView(wxCommandEvent &event)
{
	wxConfig *config = wxGetApp().config;
	
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<Tab*>(cpage);
	assert(tab != NULL);
	
	// Save the active theme
	config->SetPath("/");
	config->Write("theme", wxString(active_palette->get_name()));
	config->Write("font-size-adjustment", (long)(wxGetApp().get_font_size_adjustment()));
	config->Write("font-name", wxString(wxGetApp().get_font_name()));
	
	// Clean out all previous settings
	config->DeleteGroup("/default-view/");
	config->SetPath("/default-view/");
	
	#ifndef __APPLE__
	// Save our current window size
	wxSize size = GetSize();
	config->Write("window-width", size.x);
	config->Write("window-height", size.y);
	
	bool maximised = IsMaximized();
	config->Write("window-maximised", maximised);
	#endif
	
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
		
		auto old_tab = dynamic_cast<Tab*>(old_page);
		assert(old_tab != NULL);
		
		old_tab->hide_child_windows();
	}
	
	Tab *tab = active_tab();
	
	edit_menu->Check(ID_OVERWRITE_MODE, !tab->doc_ctrl->get_insert_mode());
	edit_menu->Check(ID_WRITE_PROTECT, tab->doc->get_write_protect());
	view_menu->Check(ID_SHOW_OFFSETS, tab->doc_ctrl->get_show_offsets());
	view_menu->Check(ID_SHOW_ASCII,   tab->doc_ctrl->get_show_ascii());
	
	OffsetBase offset_display_base = tab->doc_ctrl->get_offset_display_base();
	switch(offset_display_base)
	{
		case OFFSET_BASE_HEX:
			view_menu->Check(ID_HEX_OFFSETS, true);
			break;
			
		case OFFSET_BASE_DEC:
			view_menu->Check(ID_DEC_OFFSETS, true);
			break;
	}
	
	InlineCommentMode icm = tab->get_inline_comment_mode();
	switch(icm)
	{
		case ICM_HIDDEN:
			inline_comments_menu->Check(ID_INLINE_COMMENTS_HIDDEN, true);
			inline_comments_menu->Enable(ID_INLINE_COMMENTS_INDENT, false);
			break;
			
		case ICM_FULL:
		case ICM_FULL_INDENT:
			inline_comments_menu->Check(ID_INLINE_COMMENTS_FULL, true);
			inline_comments_menu->Check(ID_INLINE_COMMENTS_INDENT, (icm == ICM_FULL_INDENT));
			inline_comments_menu->Enable(ID_INLINE_COMMENTS_INDENT, true);
			break;
			
		case ICM_SHORT:
		case ICM_SHORT_INDENT:
			inline_comments_menu->Check(ID_INLINE_COMMENTS_SHORT, true);
			inline_comments_menu->Check(ID_INLINE_COMMENTS_INDENT, (icm == ICM_SHORT_INDENT));
			inline_comments_menu->Enable(ID_INLINE_COMMENTS_INDENT, true);
			break;
	};
	
	DocumentDisplayMode ddm = tab->get_document_display_mode();
	switch(ddm)
	{
		case DDM_NORMAL:
			view_menu->Check(ID_DDM_NORMAL, true);
			break;
			
		case DDM_VIRTUAL:
			view_menu->Check(ID_DDM_VIRTUAL, true);
			break;
	}
	
	view_menu->Check(ID_HIGHLIGHT_SELECTION_MATCH, tab->doc_ctrl->get_highlight_selection_match());
	
	for(auto i = ToolPanelRegistry::begin(); i != ToolPanelRegistry::end(); ++i)
	{
		const ToolPanelRegistration *tpr = i->second;
		
		int menu_id = tool_panel_name_to_tpm_id[tpr->name];
		bool active = tab->tool_active(tpr->name);
		
		tool_panels_menu->Check(menu_id, active);
	}
	
	_update_status_offset(tab);
	_update_status_selection(tab->doc_ctrl);
	_update_status_mode(tab->doc_ctrl);
	_update_undo(tab->doc);
	_update_dirty(tab->doc);
	_update_cpos_buttons(tab->doc_ctrl);
	
	/* Show any search dialogs attached to this tab. */
	tab->unhide_child_windows();
}

void REHex::MainWindow::OnDocumentClose(wxAuiNotebookEvent& event)
{
	wxWindow *page = notebook->GetPage(event.GetSelection());
	assert(page != NULL);
	
	auto tab = dynamic_cast<Tab*>(page);
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
	
	auto tab = dynamic_cast<Tab*>(tab_page);
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

void REHex::MainWindow::OnDocumentMiddleMouse(wxAuiNotebookEvent& event)
{
	wxWindow* page = notebook->GetPage(event.GetSelection());
	assert(page != NULL);

	auto tab = dynamic_cast<Tab*>(page);
	assert(tab != NULL);

	close_tab(tab);
}

void REHex::MainWindow::OnCursorUpdate(CursorUpdateEvent &event)
{
	Tab *active_tab = this->active_tab();
	
	wxObject *event_src = event.GetEventObject();
	
	if(event_src == active_tab->doc)
	{
		/* Only update the status bar if the event originated from the
		 * active document.
		*/
		_update_status_offset(active_tab);
	}
	
	if(event_src == active_tab->doc || event_src == active_tab->doc_ctrl)
	{
		_update_cpos_buttons(active_tab->doc_ctrl);
	}
	
	event.Skip();
}

void REHex::MainWindow::OnSelectionChange(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto active_tab = dynamic_cast<Tab*>(cpage);
	assert(active_tab != NULL);
	
	DocumentCtrl *doc_ctrl = dynamic_cast<REHex::DocumentCtrl*>(event.GetEventObject());
	assert(doc_ctrl != NULL);
	
	if(doc_ctrl == active_tab->doc_ctrl)
	{
		/* Only update the status bar if the event originated from the
		 * active document.
		*/
		_update_status_selection(doc_ctrl);
	}
}

void REHex::MainWindow::OnInsertToggle(wxCommandEvent &event)
{
	Tab *active_tab = this->active_tab();
	
	DocumentCtrl *event_src = dynamic_cast<DocumentCtrl*>(event.GetEventObject());
	assert(event_src != NULL);
	
	if(event_src == active_tab->doc_ctrl)
	{
		/* Only update the status bar if the event originated from the
		 * active document.
		*/
		
		_update_status_mode(active_tab->doc_ctrl);
		edit_menu->Check(ID_OVERWRITE_MODE, !active_tab->doc_ctrl->get_insert_mode());
	}
}

void REHex::MainWindow::OnUndoUpdate(wxCommandEvent &event)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<Tab*>(cpage);
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
	
	auto tab = dynamic_cast<Tab*>(cpage);
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
	
	auto tab = dynamic_cast<Tab*>(cpage);
	assert(tab != NULL);
	
	auto doc = dynamic_cast<REHex::Document*>(event.GetEventObject());
	assert(doc != NULL);
	
	if(doc == tab->doc)
	{
		/* Only update the window if the event originated from the active document. */
		_update_dirty(tab->doc);
	}
}

REHex::Tab *REHex::MainWindow::active_tab()
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<Tab*>(cpage);
	assert(tab != NULL);
	
	return tab;
}

REHex::Document *REHex::MainWindow::active_document()
{
	return active_tab()->doc;
}

void REHex::MainWindow::switch_tab(DocumentCtrl *doc_ctrl)
{
	size_t num_tabs = notebook->GetPageCount();
	
	for(size_t i = 0; i < num_tabs; ++i)
	{
		wxWindow *page = notebook->GetPage(i);
		
		auto tab = dynamic_cast<Tab*>(page);
		assert(tab != NULL);
		
		if(tab->doc_ctrl == doc_ctrl)
		{
			notebook->SetSelection(i);
			break;
		}
	}
}

void REHex::MainWindow::_update_status_offset(Tab *tab)
{
	off_t off = tab->doc->get_cursor_position();
	
	std::string off_text = format_offset(off, tab->doc_ctrl->get_offset_display_base());
	
	SetStatusText(off_text, 0);
}

void REHex::MainWindow::_update_status_selection(REHex::DocumentCtrl *doc_ctrl)
{
	if(doc_ctrl->has_selection())
	{
		off_t selection_first, selection_last;
		std::tie(selection_first, selection_last) = doc_ctrl->get_selection_raw();
		
		std::string from_text = format_offset(selection_first, doc_ctrl->get_offset_display_base(), selection_last);
		std::string to_text   = format_offset(selection_last,  doc_ctrl->get_offset_display_base(), selection_last);
		
		ByteRangeSet selection = doc_ctrl->get_selection_ranges();
		off_t selection_bytes = selection.total_bytes();
		
		char buf[64];
		snprintf(buf, sizeof(buf), "Selection: %s - %s (%u bytes)",
			from_text.c_str(),
			to_text.c_str(),
			
			(unsigned int)(selection_bytes));
		
		SetStatusText(buf, 1);
	}
	else{
		SetStatusText("", 1);
	}
}

void REHex::MainWindow::_update_status_mode(REHex::DocumentCtrl *doc_ctrl)
{
	if(doc_ctrl->get_insert_mode())
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
	
	wxToolBar *toolbar = GetToolBar();
	toolbar->EnableTool(wxID_SAVE,   enable_save);
	
	notebook->SetPageBitmap(notebook->GetSelection(), (dirty ? notebook_dirty_bitmap : wxNullBitmap));
}

void REHex::MainWindow::_update_cpos_buttons(DocumentCtrl *doc_ctrl)
{
	wxToolBar *toolbar = GetToolBar();
	
	toolbar->EnableTool(wxID_BACKWARD, doc_ctrl->has_prev_cursor_position());
	toolbar->EnableTool(wxID_FORWARD,  doc_ctrl->has_next_cursor_position());
}

bool REHex::MainWindow::unsaved_confirm()
{
	std::vector<wxString> dirty_files;
	
	size_t num_tabs = notebook->GetPageCount();
	for(size_t i = 0; i < num_tabs; ++i)
	{
		wxWindow *page = notebook->GetPage(i);
		assert(page != NULL);
		
		auto tab = dynamic_cast<Tab*>(page);
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

void REHex::MainWindow::close_tab(Tab *tab)
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

void REHex::MainWindow::close_other_tabs(Tab *tab)
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
		
		auto p_tab = dynamic_cast<Tab*>(page);
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

wxMenuBar *REHex::MainWindow::get_menu_bar() const
{
	return menu_bar;
}

wxMenu *REHex::MainWindow::get_file_menu() const
{
	return file_menu;
}

wxMenu *REHex::MainWindow::get_edit_menu() const
{
	return edit_menu;
}

wxMenu *REHex::MainWindow::get_view_menu() const
{
	return view_menu;
}

wxMenu *REHex::MainWindow::get_tools_menu() const
{
	return tools_menu;
}

wxMenu *REHex::MainWindow::get_help_menu() const
{
	return help_menu;
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

std::multimap<REHex::MainWindow::SetupPhase, const REHex::MainWindow::SetupHookFunction*> *REHex::MainWindow::setup_hooks = NULL;

void REHex::MainWindow::register_setup_hook(SetupPhase phase, const SetupHookFunction *func)
{
	if(setup_hooks == NULL)
	{
		setup_hooks = new std::multimap<SetupPhase, const SetupHookFunction*>;
	}
	
	setup_hooks->insert(std::make_pair(phase, func));
}

void REHex::MainWindow::unregister_setup_hook(SetupPhase phase, const SetupHookFunction *func)
{
	auto i = std::find_if(
		setup_hooks->begin(), setup_hooks->end(),
		[&](const std::pair<SetupPhase, const SetupHookFunction*> &elem) { return elem.first == phase && elem.second == func; });
	
	setup_hooks->erase(i);
	
	if(setup_hooks->empty())
	{
		delete setup_hooks;
		setup_hooks = NULL;
	}
}

void REHex::MainWindow::call_setup_hooks(SetupPhase phase)
{
	if(setup_hooks == NULL)
	{
		/* No hooks registered. */
		return;
	}
	
	for(auto i = setup_hooks->begin(); i != setup_hooks->end(); ++i)
	{
		if(i->first == phase)
		{
			const SetupHookFunction &func = *(i->second);
			func(this);
		}
	}
}

REHex::MainWindow::SetupHookRegistration::SetupHookRegistration(SetupPhase phase, const SetupHookFunction &func):
	phase(phase),
	func(func)
{
	MainWindow::register_setup_hook(phase, &(this->func));
}

REHex::MainWindow::SetupHookRegistration::~SetupHookRegistration()
{
	MainWindow::unregister_setup_hook(phase, &func);
}

wxDEFINE_EVENT(REHex::TAB_CREATED, REHex::TabCreatedEvent);

REHex::TabCreatedEvent::TabCreatedEvent(MainWindow *source, Tab *tab):
	wxEvent(source->GetId(), TAB_CREATED), tab(tab)
{
	SetEventObject(source);
}

wxEvent *REHex::TabCreatedEvent::Clone() const
{
	return new TabCreatedEvent(*this);
}
