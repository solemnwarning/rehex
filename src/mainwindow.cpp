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
#include <exception>
#include <limits>
#include <memory>
#include <new>
#include <wx/artprov.h>
#include <wx/clipbrd.h>
#include <wx/dataobj.h>
#include <wx/event.h>
#include <wx/filename.h>
#include <wx/fontenum.h>
#include <wx/html/helpctrl.h>
#include <wx/msgdlg.h>
#include <wx/aui/auibook.h>
#include <wx/numdlg.h>

#include "AboutDialog.hpp"
#include "App.hpp"
#include "BytesPerLineDialog.hpp"
#include "EditCommentDialog.hpp"
#include "FillRangeDialog.hpp"
#include "GotoOffsetDialog.hpp"
#include "IntelHexExport.hpp"
#include "IntelHexImport.hpp"
#include "mainwindow.hpp"
#include "NumericEntryDialog.hpp"
#include "NumericTextCtrl.hpp"
#include "Palette.hpp"
#include "RangeDialog.hpp"
#include "search.hpp"
#include "SettingsDialog.hpp"
#include "SettingsDialogByteColour.hpp"
#include "SettingsDialogHighlights.hpp"
#include "SettingsDialogGeneral.hpp"
#include "SettingsDialogKeyboard.hpp"
#include "SharedDocumentPointer.hpp"
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
	ID_COMPARE_SELECTION,
	ID_GOTO_OFFSET,
	ID_REPEAT_GOTO_OFFSET,
	ID_OVERWRITE_MODE,
	ID_WRITE_PROTECT,
	ID_SAVE_VIEW,
	ID_INLINE_COMMENTS_HIDDEN,
	ID_INLINE_COMMENTS_FULL,
	ID_INLINE_COMMENTS_SHORT,
	ID_INLINE_COMMENTS_INDENT,
	ID_DATA_MAP_SCROLLBAR_HIDDEN,
	ID_DATA_MAP_SCROLLBAR_ENTROPY,
	ID_ASM_SYNTAX_INTEL,
	ID_ASM_SYNTAX_ATT,
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
	ID_HELP,
	ID_IMPORT_HEX,
	ID_EXPORT_HEX,
	ID_AUTO_RELOAD,
	ID_IMPORT_METADATA,
	ID_EXPORT_METADATA,
	
	ID_SET_COMMENT_CURSOR,
	ID_SET_COMMENT_SELECTION,
	
	ID_SET_HIGHLIGHT_1,
	ID_SET_HIGHLIGHT_2,
	ID_SET_HIGHLIGHT_3,
	ID_SET_HIGHLIGHT_4,
	ID_SET_HIGHLIGHT_5,
	ID_SET_HIGHLIGHT_6,
	ID_REMOVE_HIGHLIGHT,
	
	ID_COLOUR_MAP_MENU_MIN,
	ID_COLOUR_MAP_MENU_MAX = (ID_COLOUR_MAP_MENU_MIN + 100),
};

BEGIN_EVENT_TABLE(REHex::MainWindow, wxFrame)
	EVT_CLOSE(REHex::MainWindow::OnWindowClose)
	EVT_ACTIVATE(REHex::MainWindow::OnWindowActivate)
	EVT_CHAR_HOOK(REHex::MainWindow::OnCharHook)
	
	EVT_MENU(wxID_NEW,            REHex::MainWindow::OnNew)
	EVT_MENU(wxID_OPEN,           REHex::MainWindow::OnOpen)
	EVT_MENU(wxID_SAVE,           REHex::MainWindow::OnSave)
	EVT_MENU(wxID_SAVEAS,         REHex::MainWindow::OnSaveAs)
	EVT_MENU(wxID_REFRESH,        REHex::MainWindow::OnReload)
	EVT_MENU(ID_AUTO_RELOAD,      REHex::MainWindow::OnAutoReload)
	EVT_MENU(ID_IMPORT_HEX,       REHex::MainWindow::OnImportHex)
	EVT_MENU(ID_EXPORT_HEX,       REHex::MainWindow::OnExportHex)
	EVT_MENU(ID_IMPORT_METADATA,  REHex::MainWindow::OnImportMetadata)
	EVT_MENU(ID_EXPORT_METADATA,  REHex::MainWindow::OnExportMetadata)
	EVT_MENU(wxID_CLOSE,          REHex::MainWindow::OnClose)
	EVT_MENU(ID_CLOSE_ALL,        REHex::MainWindow::OnCloseAll)
	EVT_MENU(ID_CLOSE_OTHERS,     REHex::MainWindow::OnCloseOthers)
	EVT_MENU(wxID_EXIT,           REHex::MainWindow::OnExit)
	
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
	
	EVT_MENU(ID_COMPARE_FILE,       REHex::MainWindow::OnCompareFile)
	EVT_MENU(ID_COMPARE_SELECTION,  REHex::MainWindow::OnCompareSelection)
	
	EVT_MENU(ID_GOTO_OFFSET,        REHex::MainWindow::OnGotoOffset)
	EVT_MENU(ID_REPEAT_GOTO_OFFSET, REHex::MainWindow::OnRepeatGotoOffset)
	
	EVT_MENU(wxID_PREFERENCES, REHex::MainWindow::OnSettings)
	
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
	
	EVT_MENU(ID_DATA_MAP_SCROLLBAR_HIDDEN,       REHex::MainWindow::OnDataMapScrollbar)
	EVT_MENU(ID_DATA_MAP_SCROLLBAR_ENTROPY,      REHex::MainWindow::OnDataMapScrollbar)
	
	EVT_MENU(ID_ASM_SYNTAX_INTEL, REHex::MainWindow::OnAsmSyntax)
	EVT_MENU(ID_ASM_SYNTAX_ATT,   REHex::MainWindow::OnAsmSyntax)
	
	EVT_MENU(ID_HIGHLIGHT_SELECTION_MATCH, REHex::MainWindow::OnHighlightSelectionMatch)
	
	EVT_MENU_RANGE(ID_COLOUR_MAP_MENU_MIN, ID_COLOUR_MAP_MENU_MAX, REHex::MainWindow::OnColourMap)
	
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
	#ifdef BUILD_HELP
	EVT_MENU(ID_HELP,    REHex::MainWindow::OnHelp)
	#endif
	EVT_MENU(wxID_ABOUT, REHex::MainWindow::OnAbout)
	
	EVT_MENU(ID_SET_COMMENT_CURSOR,     REHex::MainWindow::OnSetCommentAtCursor)
	EVT_MENU(ID_SET_COMMENT_SELECTION,  REHex::MainWindow::OnSetCommentOnSelection)
	
	EVT_MENU_RANGE(ID_SET_HIGHLIGHT_1, ID_SET_HIGHLIGHT_6, REHex::MainWindow::OnSetHighlight)
	EVT_MENU(ID_REMOVE_HIGHLIGHT, REHex::MainWindow::OnRemoveHighlight)
	
	EVT_AUINOTEBOOK_PAGE_CHANGED(  wxID_ANY, REHex::MainWindow::OnDocumentChange)
	EVT_AUINOTEBOOK_PAGE_CLOSE(    wxID_ANY, REHex::MainWindow::OnDocumentClose)
	EVT_AUINOTEBOOK_PAGE_CLOSED(   wxID_ANY, REHex::MainWindow::OnDocumentClosed)
	EVT_AUINOTEBOOK_TAB_RIGHT_DOWN(wxID_ANY, REHex::MainWindow::OnDocumentMenu)
	EVT_AUINOTEBOOK_TAB_MIDDLE_UP( wxID_ANY, REHex::MainWindow::OnDocumentMiddleMouse)
	EVT_DETACHABLENOTEBOOK_PAGE_DETACHED(wxID_ANY, REHex::MainWindow::OnDocumentDetached)
	
	EVT_CURSORUPDATE(wxID_ANY, REHex::MainWindow::OnCursorUpdate)
	
	EVT_COMMAND(wxID_ANY, REHex::EV_SELECTION_CHANGED, REHex::MainWindow::OnSelectionChange)
	EVT_COMMAND(wxID_ANY, REHex::EV_INSERT_TOGGLED,    REHex::MainWindow::OnInsertToggle)
	EVT_COMMAND(wxID_ANY, REHex::EV_UNDO_UPDATE,       REHex::MainWindow::OnUndoUpdate)
	EVT_COMMAND(wxID_ANY, REHex::EV_BECAME_DIRTY,      REHex::MainWindow::OnBecameDirty)
	EVT_COMMAND(wxID_ANY, REHex::EV_BECAME_CLEAN,      REHex::MainWindow::OnBecameClean)
	EVT_COMMAND(wxID_ANY, REHex::BACKING_FILE_DELETED, REHex::MainWindow::OnFileDeleted)
	EVT_COMMAND(wxID_ANY, REHex::BACKING_FILE_MODIFIED, REHex::MainWindow::OnFileModified)
	EVT_COMMAND(wxID_ANY, REHex::LAST_GOTO_OFFSET_CHANGED,  REHex::MainWindow::OnLastGotoOffsetChanged)
	EVT_COMMAND(wxID_ANY, REHex::TOOLPANEL_CLOSED, REHex::MainWindow::OnToolPanelClosed)
	
	EVT_DOCUMENTTITLE(wxID_ANY, REHex::MainWindow::OnTitleChanged)
END_EVENT_TABLE()

std::list<REHex::MainWindow*> REHex::MainWindow::instances;

const std::list<REHex::MainWindow*> &REHex::MainWindow::get_instances()
{
	return instances;
}

REHex::MainWindow::MainWindow(const wxSize& size):
	wxFrame(NULL, wxID_ANY, "Reverse Engineers' Hex Editor", wxDefaultPosition, size),
	menu_bar(NULL),
	file_menu(NULL),
	edit_menu(NULL),
	view_menu(NULL),
	tools_menu(NULL),
	help_menu(NULL),
	window_commands(wxGetApp().settings->get_main_window_commands().get_commands(), this)
{
	menu_bar = new wxMenuBar;
	
	{
		call_setup_hooks(SetupPhase::FILE_MENU_PRE);
		
		file_menu = new wxMenu;
		
		call_setup_hooks(SetupPhase::FILE_MENU_TOP);
		
		file_menu->Append(wxID_NEW,  "&New");
		file_menu->Append(wxID_OPEN, "&Open");
		
		recent_files_menu = new wxMenu;
		file_menu->AppendSubMenu(recent_files_menu, "Open &Recent");
		
		file_menu->Append(wxID_SAVE,   "&Save");
		file_menu->Append(wxID_SAVEAS, "&Save As");
		
		file_menu->AppendSeparator(); /* ---- */
		
		file_menu->Append(wxID_REFRESH, "&Reload");
		file_menu->AppendCheckItem(ID_AUTO_RELOAD, "Reload automatically", "Reload the file automatically when it is modified");
		
		file_menu->AppendSeparator(); /* ---- */
		
		file_menu->Append(ID_IMPORT_HEX, "&Import Intel Hex File");
		file_menu->Append(ID_EXPORT_HEX, "E&xport Intel Hex File");
		
		file_menu->AppendSeparator(); /* ---- */
		
		file_menu->Append(ID_IMPORT_METADATA, "Import Metadata");
		file_menu->Append(ID_EXPORT_METADATA, "Export Metadata");
		
		file_menu->AppendSeparator(); /* ---- */
		
		file_menu->Append(wxID_CLOSE,  "&Close");
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
		
		edit_menu->Append(wxID_UNDO, "&Undo");
		edit_menu->Append(wxID_REDO, "&Redo");
		
		edit_menu->AppendSeparator(); /* ---- */
		
		edit_menu->Append(wxID_SELECTALL, "Select &All");
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
		
		edit_menu->Append(ID_COMPARE_FILE, "Compare whole file...");
		edit_menu->Append(ID_COMPARE_SELECTION, "Compare selection...");
		
		edit_menu->AppendSeparator(); /* ---- */
		
		edit_menu->Append(ID_GOTO_OFFSET, "Jump to offset...");
		edit_menu->Append(ID_REPEAT_GOTO_OFFSET, "Repeat last 'Jump to offset'");
		
		edit_menu->AppendSeparator(); /* ---- */
		
		edit_menu->Append(wxID_PREFERENCES, "Preferences");
		
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
		
		data_map_scrollbar_menu = new wxMenu;
		view_menu->AppendSubMenu(data_map_scrollbar_menu, "Visual scrollbar");
		
		view_menu->AppendCheckItem(ID_HIGHLIGHT_SELECTION_MATCH, "Highlight data matching selection");
		
		colour_map_menu = new wxMenu;
		view_menu->AppendSubMenu(colour_map_menu, "Value colour map");
		
		inline_comments_menu->AppendRadioItem(ID_INLINE_COMMENTS_HIDDEN, "Hidden");
		inline_comments_menu->AppendRadioItem(ID_INLINE_COMMENTS_SHORT,  "Short");
		inline_comments_menu->AppendRadioItem(ID_INLINE_COMMENTS_FULL,   "Full");
		inline_comments_menu->AppendSeparator();
		inline_comments_menu->AppendCheckItem(ID_INLINE_COMMENTS_INDENT, "Nest comments");
		
		data_map_scrollbar_menu->AppendRadioItem(ID_DATA_MAP_SCROLLBAR_HIDDEN, "Hidden");
		data_map_scrollbar_menu->AppendRadioItem(ID_DATA_MAP_SCROLLBAR_ENTROPY, "Entropy");
		
		tool_panels_menu = new wxMenu;
		view_menu->AppendSubMenu(tool_panels_menu, "Tool panels");
		
		std::vector<const ToolPanelRegistration*> tools;
		
		for(auto i = ToolPanelRegistry::begin(); i != ToolPanelRegistry::end(); ++i)
		{
			tools.emplace_back(i->second);
		}
		
		std::sort(tools.begin(), tools.end(), [](const ToolPanelRegistration *a, const ToolPanelRegistration *b)
		{
			return a->label < b->label;
		});
		
		for(auto i = tools.begin(); i != tools.end(); ++i)
		{
			const ToolPanelRegistration *tpr = *i;
			wxMenuItem *itm = tool_panels_menu->AppendCheckItem(wxID_ANY, tpr->label);
			
			Bind(wxEVT_MENU, [this, tpr](wxCommandEvent &event)
			{
				OnShowToolPanel(event, tpr);
			}, itm->GetId(), itm->GetId());
			
			tool_panel_name_to_tpm_id[tpr->name] = itm->GetId();
		}
		
		asm_syntax_menu = new wxMenu;
		view_menu->AppendSubMenu(asm_syntax_menu, "x86 disassembly syntax");
		
		asm_syntax_menu->AppendRadioItem(ID_ASM_SYNTAX_INTEL, "Intel");
		asm_syntax_menu->AppendRadioItem(ID_ASM_SYNTAX_ATT,   "AT&T");
		
		switch(wxGetApp().settings->get_preferred_asm_syntax())
		{
			case AsmSyntax::INTEL:
				asm_syntax_menu->Check(ID_ASM_SYNTAX_INTEL, true);
				break;
				
			case AsmSyntax::ATT:
				asm_syntax_menu->Check(ID_ASM_SYNTAX_ATT, true);
				break;
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
		
		#ifdef BUILD_HELP
		help_menu->Append(ID_HELP, "View &help\tF1");
		#endif
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
	
	static int DOCUMENT_PAGE_GROUP;
	notebook = new DetachableNotebook(this, wxID_ANY, &DOCUMENT_PAGE_GROUP, &(wxGetApp()), wxDefaultPosition, wxDefaultSize,
		(wxAUI_NB_TOP | wxAUI_NB_TAB_MOVE | wxAUI_NB_SCROLL_BUTTONS | wxAUI_NB_CLOSE_ON_ALL_TABS));
	
	notebook_dirty_bitmap = artp.GetBitmap(wxART_FILE_SAVE, wxART_MENU);
	assert(!notebook_dirty_bitmap.IsSameAs(wxNullBitmap));
	
	notebook_bad_bitmap = artp.GetBitmap(wxART_MISSING_IMAGE, wxART_MENU);
	assert(!notebook_bad_bitmap.IsSameAs(wxNullBitmap));
	
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
	
	instances.push_back(this);
	instances_iter = std::prev(instances.end());
	
	window_commands.update_window_accelerators();
	
	call_setup_hooks(SetupPhase::DONE);
	
	wxGetApp().settings->Bind(BYTE_COLOUR_MAPS_CHANGED, &REHex::MainWindow::OnByteColourMapsChanged, this);
	wxGetApp().settings->Bind(MAIN_WINDOW_ACCELERATORS_CHANGED, &REHex::MainWindow::OnAcceleratorsChanged, this);
}

REHex::MainWindow::~MainWindow()
{
	wxGetApp().settings->Unbind(MAIN_WINDOW_ACCELERATORS_CHANGED, &REHex::MainWindow::OnAcceleratorsChanged, this);
	wxGetApp().settings->Unbind(BYTE_COLOUR_MAPS_CHANGED, &REHex::MainWindow::OnByteColourMapsChanged, this);
	
	wxGetApp().recent_files->RemoveMenu(recent_files_menu);
	instances.erase(instances_iter);
}

void REHex::MainWindow::new_file()
{
	Tab *tab = new Tab(notebook);
	notebook->AddPage(tab, tab->doc->get_title(), true);
	tab->doc_ctrl->SetFocus();
	
	TabCreatedEvent event(this, tab);
	wxPostEvent(this, event);
}

REHex::Tab *REHex::MainWindow::open_file(const std::string &filename)
{
	Tab *tab;
	try {
		SharedDocumentPointer doc(SharedDocumentPointer::make(filename));
		tab = new Tab(notebook, doc);
	}
	catch(const std::exception &e)
	{
		wxMessageBox(
			std::string("Error opening ") + filename + ":\n" + e.what(),
			"Error", wxICON_ERROR, this);
		return NULL;
	}
	
	/* Discard default "Untitled" tab if not modified. */
	if(notebook->GetPageCount() == 1)
	{
		wxWindow *page = notebook->GetPage(0);
		assert(page != NULL);
		
		auto page_tab = dynamic_cast<Tab*>(page);
		assert(page_tab != NULL);
		
		if(page_tab->doc->get_filename() == "" && page_tab->doc->get_title() == "Untitled" && !page_tab->doc->is_dirty())
		{
			notebook->DeletePage(0);
		}
	}
	
	wxFileName wxfn(filename);
	wxfn.MakeAbsolute();
	
	wxGetApp().recent_files->AddFileToHistory(filename);
	
	notebook->AddPage(tab, tab->doc->get_title(), true);
	tab->doc_ctrl->SetFocus();
	
	TabCreatedEvent event(this, tab);
	wxPostEvent(this, event);
	
	return tab;
}

#ifdef __APPLE__
REHex::Tab *REHex::MainWindow::open_file(MacFileName &&macfn)
{
	std::string filename = macfn.GetFileName().GetFullPath().ToStdString();
	
	wxGetApp().recent_files->AddFileToHistory(macfn);
	
	Tab *tab;
	try {
		SharedDocumentPointer doc(SharedDocumentPointer::make(std::move(macfn)));
		tab = new Tab(notebook, doc);
	}
	catch(const std::exception &e)
	{
		wxMessageBox(
			std::string("Error opening ") + filename + ":\n" + e.what(),
					 "Error", wxICON_ERROR, this);
		return NULL;
	}
	
	/* Discard default "Untitled" tab if not modified. */
	if(notebook->GetPageCount() == 1)
	{
		wxWindow *page = notebook->GetPage(0);
		assert(page != NULL);
		
		auto page_tab = dynamic_cast<Tab*>(page);
		assert(page_tab != NULL);
		
		if(page_tab->doc->get_filename() == "" && page_tab->doc->get_title() == "Untitled" && !page_tab->doc->is_dirty())
		{
			notebook->DeletePage(0);
		}
	}
	
	notebook->AddPage(tab, tab->doc->get_title(), true);
	tab->doc_ctrl->SetFocus();
	
	TabCreatedEvent event(this, tab);
	wxPostEvent(this, event);
	
	return tab;
}
#endif /* __APPLE__ */

REHex::Tab *REHex::MainWindow::import_hex_file(const std::string &filename)
{
	Tab *tab;
	try {
		SharedDocumentPointer doc(load_hex_file(filename.c_str()));
		tab = new Tab(notebook, doc);
	}
	catch(const std::exception &e)
	{
		wxMessageBox(
			std::string("Error opening ") + filename + ":\n" + e.what(),
			"Error", wxICON_ERROR, this);
		return NULL;
	}
	
	/* Discard default "Untitled" tab if not modified. */
	if(notebook->GetPageCount() == 1)
	{
		wxWindow *page = notebook->GetPage(0);
		assert(page != NULL);
		
		auto page_tab = dynamic_cast<Tab*>(page);
		assert(page_tab != NULL);
		
		if(page_tab->doc->get_filename() == "" && page_tab->doc->get_title() == "Untitled" && !page_tab->doc->is_dirty())
		{
			notebook->DeletePage(0);
		}
	}
	
	notebook->AddPage(tab, tab->doc->get_title(), true);
	tab->doc_ctrl->SetFocus();
	
	TabCreatedEvent event(this, tab);
	wxPostEvent(this, event);
	
	if(!tab->doc->get_real_to_virt_segs().empty())
	{
		tab->set_document_display_mode(DDM_VIRTUAL);
		view_menu->Check(ID_DDM_VIRTUAL, true);
	}
	
	return tab;
}

void REHex::MainWindow::OnWindowClose(wxCloseEvent &event)
{
	std::vector<Tab*> closing_tabs;
	
	size_t num_tabs = notebook->GetPageCount();
	for(size_t i = 0; i < num_tabs; ++i)
	{
		wxWindow *page = notebook->GetPage(i);
		assert(page != NULL);
		
		auto p_tab = dynamic_cast<Tab*>(page);
		assert(p_tab != NULL);
		
		closing_tabs.push_back(p_tab);
	}
	
	if(!confirm_close_tabs(closing_tabs))
	{
		/* Stop the window from being closed. */
		event.Veto();
		return;
	}
	
	/* Base implementation will deal with cleaning up the window. */
	event.Skip();
}

void REHex::MainWindow::OnWindowActivate(wxActivateEvent &event)
{
	if(event.GetActive())
	{
		instances.erase(instances_iter);
		
		instances.push_front(this);
		instances_iter = instances.begin();
	}
	
	size_t num_tabs = notebook->GetPageCount();
	for(size_t i = 0; i < num_tabs; ++i)
	{
		wxWindow *page = notebook->GetPage(i);
		assert(page != NULL);
		
		auto p_tab = dynamic_cast<Tab*>(page);
		assert(p_tab != NULL);
		
		p_tab->set_parent_window_active(event.GetActive());
	}
	
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
	auto *recent_files = wxGetApp().recent_files;
	
	#ifdef __APPLE__
	MacFileName macfn = recent_files->GetHistoryMacFile(event.GetId() - recent_files->GetBaseId());
	open_file(std::move(macfn));
	
	#else
	wxString file = recent_files->GetHistoryFile(event.GetId() - recent_files->GetBaseId());
	open_file(file.ToStdString());
	
	#endif
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
	Tab *tab = active_tab();
	
	std::string filename = document_save_as_dialog(this, tab->doc);
	if(filename == "")
	{
		/* Cancelled. */
		return;
	}
	
	try {
		tab->doc->save(filename);
	}
	catch(const std::exception &e)
	{
		wxMessageBox(
			std::string("Error saving ") + tab->doc->get_title() + ":\n" + e.what(),
			"Error", wxICON_ERROR, this);
		return;
	}
}

void REHex::MainWindow::OnReload(wxCommandEvent &event)
{
	Document *doc = active_document();
	
	assert(!doc->get_filename().empty());
	
	if(doc->is_dirty())
	{
		std::string msg
			= "The content of " + doc->get_title() + " has been modified.\n"
			+ "Discard changes and reload file?";
		
		int res = wxMessageBox(msg, "File data modified", (wxYES_NO | wxICON_EXCLAMATION), this);
		if(res == wxNO)
		{
			return;
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

void REHex::MainWindow::OnAutoReload(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	tab->set_auto_reload(event.IsChecked());
}

void REHex::MainWindow::OnImportHex(wxCommandEvent &event)
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
	
	wxFileDialog openFileDialog(this, "Import Hex File", dir, "", "", wxFD_OPEN | wxFD_FILE_MUST_EXIST);
	if(openFileDialog.ShowModal() == wxID_CANCEL)
		return;
	
	std::string filename = openFileDialog.GetPath().ToStdString();
	
	{
		wxFileName wxfn(filename);
		wxString dirname = wxfn.GetPath();
		
		wxGetApp().set_last_directory(dirname.ToStdString());
	}
	
	import_hex_file(filename);
}

void REHex::MainWindow::OnExportHex(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	
	/* === Get export filename === */
	
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
	
	wxFileDialog saveFileDialog(this, "Export Hex File", dir, name, "", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
	if(saveFileDialog.ShowModal() == wxID_CANCEL)
		return;
	
	std::string filename = saveFileDialog.GetPath().ToStdString();
	
	{
		wxFileName wxfn(filename);
		wxString dirname = wxfn.GetPath();
		
		wxGetApp().set_last_directory(dirname.ToStdString());
	}
	
	/* === Get export settings === */
	
	wxDialog conf_dialog(this, wxID_ANY, "Export Hex File");
	wxBoxSizer *conf_sizer = new wxBoxSizer(wxVERTICAL);
	
	wxStaticBoxSizer *export_mode_sizer = new wxStaticBoxSizer(wxVERTICAL, &conf_dialog, "Export mode");
	conf_sizer->Add(export_mode_sizer, 0, wxEXPAND);
	
	wxRadioButton *export_mode_raw = new wxRadioButton(export_mode_sizer->GetStaticBox(), wxID_ANY, "Export raw file contents");
	export_mode_sizer->Add(export_mode_raw, 0, wxALL, 4);
	
	wxRadioButton *export_mode_virt = new wxRadioButton(export_mode_sizer->GetStaticBox(), wxID_ANY, "Export virtual segments");
	export_mode_sizer->Add(export_mode_virt, 0, (wxALL & ~wxTOP), 4);
	
	if(tab->doc->get_real_to_virt_segs().empty())
	{
		export_mode_raw->SetValue(true);
		export_mode_virt->Disable();
	}
	else{
		export_mode_virt->SetValue(true);
	}
	
	wxStaticBoxSizer *address_mode_sizer = new wxStaticBoxSizer(wxVERTICAL, &conf_dialog, "Addressing");
	conf_sizer->Add(address_mode_sizer, 0, wxEXPAND);
	
	wxRadioButton *address_mode_16bit = new wxRadioButton(address_mode_sizer->GetStaticBox(), wxID_ANY, "No extended addressing (\"I8HEX\") - up to 64KiB");
	address_mode_sizer->Add(address_mode_16bit, 0, wxALL, 4);
	
	wxRadioButton *address_mode_segmented = new wxRadioButton(address_mode_sizer->GetStaticBox(), wxID_ANY, "Segmented addressing (\"I16HEX\") - up to 1MiB");
	address_mode_sizer->Add(address_mode_segmented, 0, (wxALL & ~wxTOP), 4);
	
	wxRadioButton *address_mode_linear = new wxRadioButton(address_mode_sizer->GetStaticBox(), wxID_ANY, "Linear addressing (\"I32HEX\") - up to 4GiB");
	address_mode_sizer->Add(address_mode_linear, 0, (wxALL & ~wxTOP), 4);
	
	wxStaticBoxSizer *other_box_sizer_outer = new wxStaticBoxSizer(wxVERTICAL, &conf_dialog, "");
	conf_sizer->Add(other_box_sizer_outer, 0, wxEXPAND);
	
	wxStaticBox *other_box = other_box_sizer_outer->GetStaticBox();
	
	wxBoxSizer *other_box_sizer_wrapper = new wxBoxSizer(wxVERTICAL);
	other_box_sizer_outer->Add(other_box_sizer_wrapper, 0, wxEXPAND | wxLEFT | wxRIGHT, 6);
	
	wxGridSizer *other_box_sizer = new wxGridSizer(2, 2, 2);
	other_box_sizer_wrapper->Add(other_box_sizer, 0, wxEXPAND | wxBOTTOM, 8);
	
	other_box_sizer->Add(
		new wxStaticText(other_box, wxID_ANY, "Start segment address"),
		0, wxALIGN_CENTER_VERTICAL);
	
	NumericTextCtrl *start_segment_address = new NumericTextCtrl(other_box, wxID_ANY);
	other_box_sizer->Add(start_segment_address, 0, wxALIGN_CENTER_VERTICAL | wxEXPAND);
	
	other_box_sizer->Add(
		new wxStaticText(other_box, wxID_ANY, "Start linear address"),
		0, wxALIGN_CENTER_VERTICAL);
	
	NumericTextCtrl *start_linear_address = new NumericTextCtrl(other_box, wxID_ANY);
	other_box_sizer->Add(start_linear_address, 1, wxALIGN_CENTER_VERTICAL | wxEXPAND);
	
	wxBoxSizer *button_sizer = new wxBoxSizer(wxHORIZONTAL);
	conf_sizer->Add(button_sizer, 0, wxALIGN_RIGHT);
	
	wxButton *ok = new wxButton(&conf_dialog, wxID_OK, "OK");
	button_sizer->Add(ok, 0, wxALL, 6);
	
	wxButton *cancel = new wxButton(&conf_dialog, wxID_CANCEL, "Cancel");
	button_sizer->Add(cancel, 0, wxALL, 6);
	
	conf_dialog.SetSizerAndFit(conf_sizer);
	
	auto &comments = tab->doc->get_comments();
	auto comment = comments.find(BitRangeTreeKey(BitOffset(0, 0), BitOffset(0, 0)));
	if(comment != comments.end())
	{
		const wxString &comment_text = *(comment->second.text);
		
		if(comment_text.find("Extended Segment Addressing") != wxString::npos)
		{
			address_mode_segmented->SetValue(true);
		}
		else{
			address_mode_linear->SetValue(true);
		}
		
		size_t ssa_begin = comment_text.find("Start Segment Address = ");
		if(ssa_begin != wxString::npos)
		{
			ssa_begin += strlen("Start Segment Address = ");
			
			size_t ssa_end = comment_text.find_first_of("\n", ssa_begin);
			if(ssa_end == wxString::npos)
			{
				ssa_end = comment_text.length();
			}
			
			start_segment_address->SetValue(comment_text.substr(ssa_begin, (ssa_end - ssa_begin)));
		}
		
		size_t sla_begin = comment_text.find("Start Linear Address = ");
		if(sla_begin != wxString::npos)
		{
			sla_begin += strlen("Start Linear Address = ");
			
			size_t sla_end = comment_text.find_first_not_of("\n", sla_begin);
			if(sla_end == wxString::npos)
			{
				sla_end = comment_text.length();
			}
			
			start_linear_address->SetValue(comment_text.substr(sla_begin, (sla_end - sla_begin)));
		}
	}
	
	bool use_segments;
	IntelHexAddressingMode address_mode;
	uint32_t start_linear_address_buf;
	uint32_t *start_linear_address_ptr;
	uint32_t start_segment_address_buf;
	uint32_t *start_segment_address_ptr;
	
	while(true)
	{
		if(conf_dialog.ShowModal() == wxID_CANCEL)
		{
			return;
		}
		
		use_segments = export_mode_virt->GetValue();
		
		if(address_mode_16bit->GetValue())
		{
			address_mode = IntelHexAddressingMode::IHA_16BIT;
		}
		else if(address_mode_segmented)
		{
			address_mode = IntelHexAddressingMode::IHA_SEGMENTED;
		}
		else{
			address_mode = IntelHexAddressingMode::IHA_LINEAR;
		}
		
		if(((wxTextCtrl*)(start_segment_address))->GetValue() != "")
		{
			try {
				start_segment_address_buf = start_segment_address->GetValue<uint32_t>();
			}
			catch(const NumericTextCtrl::InputError &e)
			{
				wxMessageBox(
					std::string("Invalid Start Segment Address (") + + e.what() + ")",
					"Error", wxICON_ERROR, this);
				continue;
			}
			
			start_segment_address_ptr = &start_segment_address_buf;
		}
		else{
			start_segment_address_ptr = NULL;
		}
		
		if(((wxTextCtrl*)(start_linear_address))->GetValue() != "")
		{
			try {
				start_linear_address_buf = start_linear_address->GetValue<uint32_t>();
			}
			catch(const NumericTextCtrl::InputError &e)
			{
				wxMessageBox(
					std::string("Invalid Start Linear Address (") + + e.what() + ")",
					"Error", wxICON_ERROR, this);
				continue;
			}
			
			start_linear_address_ptr = &start_linear_address_buf;
		}
		else{
			start_linear_address_ptr = NULL;
		}
		
		break;
	}
	
	try {
		write_hex_file(filename, tab->doc, use_segments, address_mode, start_segment_address_ptr, start_linear_address_ptr);
	}
	catch(const std::exception &e)
	{
		wxMessageBox(
			std::string("Error exporting ") + tab->doc->get_title() + ":\n" + e.what(),
			"Error", wxICON_ERROR, this);
		return;
	}
}

void REHex::MainWindow::OnImportMetadata(wxCommandEvent &event)
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
	
	wxFileDialog openFileDialog(this, "Import Metadata", dir, "", "REHex metadata files (*.rehex-meta)|*.rehex-meta", wxFD_OPEN | wxFD_FILE_MUST_EXIST);
	if(openFileDialog.ShowModal() == wxID_CANCEL)
		return;
	
	std::string filename = openFileDialog.GetPath().ToStdString();
	
	{
		wxFileName wxfn(filename);
		wxString dirname = wxfn.GetPath();
		
		wxGetApp().set_last_directory(dirname.ToStdString());
	}
	
	std::string msg
		= "Any existing metadata (comments, types, etc) will be replaced.\n"
		"Proceed with import?";
	
	int res = wxMessageBox(msg, "Import Metadata", (wxYES_NO | wxICON_EXCLAMATION), this);
	if(res == wxNO)
	{
		return;
	}
	
	try {
		active_document()->load_metadata(filename);
	}
	catch(const std::exception &e)
	{
		wxMessageBox(
			std::string("Error importing metadata:\n") + e.what(),
			"Error", wxICON_ERROR, this);
	}
}

void REHex::MainWindow::OnExportMetadata(wxCommandEvent &event)
{
	std::string dir, name;
	std::string doc_filename = active_document()->get_filename();
	
	if(doc_filename != "")
	{
		wxFileName wxfn(doc_filename);
		wxfn.MakeAbsolute();
		
		dir  = wxfn.GetPath();
		name = wxfn.GetName();
	}
	else{
		dir  = wxGetApp().get_last_directory();
		name = "";
	}
	
	wxFileDialog saveFileDialog(this, "Export Metadata", dir, name, "REHex metadata files (*.rehex-meta)|*.rehex-meta", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
	if(saveFileDialog.ShowModal() == wxID_CANCEL)
		return;
	
	std::string filename = saveFileDialog.GetPath().ToStdString();
	
	{
		wxFileName wxfn(filename);
		wxString dirname = wxfn.GetPath();
		
		wxGetApp().set_last_directory(dirname.ToStdString());
	}
	
	try {
		active_document()->save_metadata(filename);
	}
	catch(const std::exception &e)
	{
		wxMessageBox(
			std::string("Error exporting metadata:\n") + e.what(),
			"Error", wxICON_ERROR, this);
	}
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

void REHex::MainWindow::OnCompareSelection(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	tab->compare_selection();
}

void REHex::MainWindow::OnGotoOffset(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	tab->show_goto_offset_dialog();
}

void REHex::MainWindow::OnRepeatGotoOffset(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	
	BitOffset last_goto_offset;
	bool is_relative;
	
	std::tie(last_goto_offset, is_relative) = tab->get_last_goto_offset();
	
	if(last_goto_offset == BitOffset::MIN)
	{
		return;
	}
	
	if(is_relative)
	{
		last_goto_offset += tab->doc->get_cursor_position();
	}
	
	/* Check if desired offset is valid/reachable in the DocumentCtrl. */
	if(!(tab->doc_ctrl->check_cursor_position(last_goto_offset)))
	{
		wxBell();
		return;
	}
	
	tab->doc->set_cursor_position(last_goto_offset);
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
			BitOffset selection_first, selection_last;
			std::tie(selection_first, selection_last) = tab->doc_ctrl->get_selection_raw();
			
			REHex::DocumentCtrl::GenericDataRegion *selection_region = tab->doc_ctrl->data_region_by_offset(selection_first);
			assert(selection_region != NULL);
			
			assert(selection_region->d_offset <= selection_last);
			assert((selection_region->d_offset + selection_region->d_length) >= selection_first);
			
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
		
		BitOffset cursor_pos = tab->doc_ctrl->get_cursor_position();
		
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
	
	BitOffset first_off = first_region->d_offset;
	BitOffset last_off  = last_region->d_offset + last_region->d_length - (last_region->d_length > BitOffset::ZERO ? BitOffset::BITS(1) : BitOffset::ZERO);
	
	tab->doc_ctrl->set_selection_raw(first_off, last_off);
}

void REHex::MainWindow::OnSelectRange(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	
	REHex::RangeDialog rd(this, tab->doc_ctrl, "Select range", true, true, true);
	
	if(tab->doc_ctrl->has_selection())
	{
		BitOffset selection_first, selection_last;
		std::tie(selection_first, selection_last) = tab->doc_ctrl->get_selection_raw();
		
		rd.set_range_raw(selection_first, selection_last);
	}
	else{
		rd.set_offset_hint(tab->doc_ctrl->get_cursor_position());
	}
	
	int s = rd.ShowModal();
	if(s == wxID_OK)
	{
		assert(rd.range_valid());
		
		BitOffset range_first, range_last;
		std::tie(range_first, range_last) = rd.get_range_raw();
		
		tab->doc_ctrl->set_selection_raw(range_first, range_last);
	}
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

void REHex::MainWindow::OnSettings(wxCommandEvent &event)
{
	static SafeWindowPointer<SettingsDialog> dialog(NULL);
	
	if(dialog == NULL)
	{
		std::vector< std::unique_ptr<SettingsDialogPanel> > panels;
		panels.push_back(std::unique_ptr<SettingsDialogPanel>(new SettingsDialogGeneral()));
		panels.push_back(std::unique_ptr<SettingsDialogPanel>(new SettingsDialogByteColour()));
		panels.push_back(std::unique_ptr<SettingsDialogPanel>(new SettingsDialogAppHighlights()));
		panels.push_back(std::unique_ptr<SettingsDialogPanel>(new SettingsDialogKeyboard()));
		
		dialog.reset(new SettingsDialog(this, "Preferences", std::move(panels)));
		
		dialog->Show();
	}
	else{
		dialog->Raise();
	}
	
	//wxAcceleratorTable *at = GetAcceleratorTable();
	
	wxMenuItem *itm = GetMenuBar()->FindItem(ID_SELECT_RANGE);
	
	wxAcceleratorEntry a(wxACCEL_CTRL | wxACCEL_SHIFT, 'R', ID_SELECT_RANGE);
	wxAcceleratorTable at(1, &a);
	
	itm->SetAccel(&a);
	
	// SetAcceleratorTable(at);
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

void REHex::MainWindow::OnAsmSyntax(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	
	if(asm_syntax_menu->IsChecked(ID_ASM_SYNTAX_INTEL))
	{
		wxGetApp().settings->set_preferred_asm_syntax(AsmSyntax::INTEL);
		tab->doc_ctrl->Refresh();
	}
	else if(asm_syntax_menu->IsChecked(ID_ASM_SYNTAX_ATT))
	{
		wxGetApp().settings->set_preferred_asm_syntax(AsmSyntax::ATT);
		tab->doc_ctrl->Refresh();
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

void REHex::MainWindow::OnDataMapScrollbar(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	
	if(data_map_scrollbar_menu->IsChecked(ID_DATA_MAP_SCROLLBAR_HIDDEN))
	{
		tab->set_dsm_type(Tab::DataMapScrollbarType::NONE);
	}
	else if(data_map_scrollbar_menu->IsChecked(ID_DATA_MAP_SCROLLBAR_ENTROPY))
	{
		tab->set_dsm_type(Tab::DataMapScrollbarType::ENTROPY);
	}
}

void REHex::MainWindow::OnHighlightSelectionMatch(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	tab->doc_ctrl->set_highlight_selection_match(event.IsChecked());
}

void REHex::MainWindow::OnColourMap(wxCommandEvent &event)
{
	int menu_item_id = event.GetId();
	
	Tab *tab = active_tab();
	
	if(menu_item_id == ID_COLOUR_MAP_MENU_MIN)
	{
		tab->doc_ctrl->set_byte_colour_map(nullptr);
	}
	else{
		assert(colour_map_menu_id_to_bcm_id.find(menu_item_id) != colour_map_menu_id_to_bcm_id.end());
		int colour_map_id = colour_map_menu_id_to_bcm_id[menu_item_id];
		
		auto maps = wxGetApp().settings->get_byte_colour_maps();
		
		auto colour_map = maps.find(colour_map_id);
		assert(colour_map != maps.end());
		
		tab->doc_ctrl->set_byte_colour_map(colour_map->second);
	}
}

void REHex::MainWindow::OnShowToolPanel(wxCommandEvent &event, const REHex::ToolPanelRegistration *tpr)
{
	wxWindow *cpage = notebook->GetCurrentPage();
	assert(cpage != NULL);
	
	auto tab = dynamic_cast<Tab*>(cpage);
	assert(tab != NULL);
	
	
	if(event.IsChecked())
	{
		assert(!(tab->tool_active(tpr->name)));
		tab->tool_create(tpr->name, true);
	}
	else{
		assert(tab->tool_active(tpr->name));
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

#ifdef BUILD_HELP
void REHex::MainWindow::OnHelp(wxCommandEvent &event)
{
	wxGetApp().show_help_contents(this);
}
#endif

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
	
	file_menu->Enable(wxID_REFRESH, !tab->doc->get_filename().empty());
	file_menu->Check(ID_AUTO_RELOAD, tab->get_auto_reload());
	
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
	
	Tab::DataMapScrollbarType dsm = tab->get_dsm_type();
	switch(dsm)
	{
		case Tab::DataMapScrollbarType::NONE:
			data_map_scrollbar_menu->Check(ID_DATA_MAP_SCROLLBAR_HIDDEN, true);
			break;
			
		case Tab::DataMapScrollbarType::ENTROPY:
			data_map_scrollbar_menu->Check(ID_DATA_MAP_SCROLLBAR_ENTROPY, true);
			break;
	}
	
	DocumentDisplayMode ddm = tab->get_document_display_mode();
	switch(ddm)
	{
		case DDM_NORMAL:
			view_menu->Check(ID_DDM_NORMAL, true);
			break;
			
		case DDM_VIRTUAL:
			view_menu->Check(ID_DDM_VIRTUAL, true);
			break;
			
		default:
			abort(); /* Unreachable */
	}
	
	view_menu->Check(ID_HIGHLIGHT_SELECTION_MATCH, tab->doc_ctrl->get_highlight_selection_match());
	
	for(auto i = ToolPanelRegistry::begin(); i != ToolPanelRegistry::end(); ++i)
	{
		const ToolPanelRegistration *tpr = i->second;
		
		int menu_id = tool_panel_name_to_tpm_id[tpr->name];
		bool active = tab->tool_active(tpr->name);
		
		tool_panels_menu->Check(menu_id, active);
	}
	
	BitOffset last_goto_offset;
	bool is_relative;
	
	std::tie(last_goto_offset, is_relative) = tab->get_last_goto_offset();
	
	edit_menu->Enable(ID_REPEAT_GOTO_OFFSET, last_goto_offset != BitOffset::MIN);
	
	_update_status_offset(tab);
	_update_status_selection(tab->doc_ctrl);
	_update_status_mode(tab->doc_ctrl);
	_update_undo(tab->doc);
	_update_dirty(tab->doc);
	_update_cpos_buttons(tab->doc_ctrl);
	_update_colour_map_menu(tab->doc_ctrl);
	
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

void REHex::MainWindow::OnDocumentDetached(DetachedPageEvent &event)
{
	if(notebook->GetPageCount() == 0)
	{
		/* Detached the last tab - close the window. */
		Destroy();
	}
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
	Document *event_doc = (Document*)(event.GetEventObject());
	_update_dirty(event_doc);
}

void REHex::MainWindow::OnBecameClean(wxCommandEvent &event)
{
	Document *event_doc = (Document*)(event.GetEventObject());
	_update_dirty(event_doc);
}

void REHex::MainWindow::OnFileDeleted(wxCommandEvent &event)
{
	Document *event_doc = (Document*)(event.GetEventObject());
	_update_dirty(event_doc);
}

void REHex::MainWindow::OnTitleChanged(DocumentTitleEvent &event)
{
	Document *event_doc = (Document*)(event.GetEventObject());
	
	size_t num_tabs = notebook->GetPageCount();
	for(size_t i = 0; i < num_tabs; ++i)
	{
		wxWindow *page = notebook->GetPage(i);
		assert(page != NULL);
		
		assert(dynamic_cast<Tab*>(page) != NULL);
		Tab *tab = (Tab*)(page);
		
		if(tab->doc == event_doc)
		{
			notebook->SetPageText(i, tab->doc->get_title());
			break;
		}
	}
	
	if(event_doc == active_document())
	{
		/* Document has a backing file (if it didn't already), enable refresh command. */
		file_menu->Enable(wxID_REFRESH, true);
	}
	
	event.Skip();
}

void REHex::MainWindow::OnFileModified(wxCommandEvent &event)
{
	Document *event_doc = (Document*)(event.GetEventObject());
	_update_dirty(event_doc);
}

void REHex::MainWindow::OnLastGotoOffsetChanged(wxCommandEvent &event)
{
	Tab *active_tab = this->active_tab();
	
	wxObject *event_src = event.GetEventObject();
	
	if(event_src == active_tab)
	{
		/* Only enable the menu command if the event originated from the active tab. */
		
		BitOffset last_goto_offset;
		bool is_relative;
		
		std::tie(last_goto_offset, is_relative) = active_tab->get_last_goto_offset();
		
		edit_menu->Enable(ID_REPEAT_GOTO_OFFSET, last_goto_offset != BitOffset::MIN);
	}
}

void REHex::MainWindow::OnToolPanelClosed(wxCommandEvent &event)
{
	auto id_it = tool_panel_name_to_tpm_id.find(event.GetString().ToStdString());
	assert(id_it != tool_panel_name_to_tpm_id.end());
	
	if(id_it != tool_panel_name_to_tpm_id.end())
	{
		tool_panels_menu->Check(id_it->second, false);
	}
}

void REHex::MainWindow::OnByteColourMapsChanged(wxCommandEvent &event)
{
	_update_colour_map_menu(active_tab()->doc_ctrl);
	event.Skip();
}

void REHex::MainWindow::OnAcceleratorsChanged(wxCommandEvent &event)
{
	window_commands.replace_accelerators(wxGetApp().settings->get_main_window_commands());
	event.Skip();
}

void REHex::MainWindow::OnSetCommentAtCursor(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	
	BitOffset cursor_pos = tab->doc_ctrl->get_cursor_position();
	
	if(cursor_pos < BitOffset(tab->doc->buffer_length(), 0))
	{
		EditCommentDialog::run_modal(this, tab->doc, cursor_pos, 0);
	}
}

void REHex::MainWindow::OnSetCommentOnSelection(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	
	BitOffset selection_off, selection_length;
	std::tie(selection_off, selection_length) = tab->doc_ctrl->get_selection_linear();
	
	if(selection_length > BitOffset::ZERO)
	{
		EditCommentDialog::run_modal(this, tab->doc, selection_off, selection_length);
	}
}

void REHex::MainWindow::OnSetHighlight(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	
	int command_id = event.GetId();
	int highlight_num = command_id - ID_SET_HIGHLIGHT_1;
	
	assert(highlight_num >= 0);
	
	const HighlightColourMap highlight_colours = tab->doc->get_highlight_colours();
	if(highlight_colours.size() < (size_t)(highlight_num))
	{
		return;
	}
	
	size_t highlight_id = std::next(highlight_colours.begin(), highlight_num)->first;
	
	BitOffset selection_off, selection_length;
	std::tie(selection_off, selection_length) = tab->doc_ctrl->get_selection_linear();
	
	if(selection_length == BitOffset::ZERO)
	{
		return;
	}
	
	tab->doc->set_highlight(selection_off, selection_length, highlight_id);
}

void REHex::MainWindow::OnRemoveHighlight(wxCommandEvent &event)
{
	Tab *tab = active_tab();
	
	BitOffset cursor_pos = tab->doc->get_cursor_position();
	
	const auto &highlights = tab->doc->get_highlights();
	auto highlight_at_cur  = highlights.get_range(cursor_pos);
	
	if(highlight_at_cur != highlights.end())
	{
		tab->doc->erase_highlight(highlight_at_cur->first.offset, highlight_at_cur->first.length);
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

void REHex::MainWindow::insert_tab(Tab *tab, int position)
{
	if(position < 0)
	{
		position = notebook->GetPageCount();
	}
	
	tab->Reparent(notebook);
	notebook->InsertPage(position, tab, tab->doc->get_title(), true);
}

REHex::DetachableNotebook *REHex::MainWindow::get_notebook()
{
	return notebook;
}

void REHex::MainWindow::_update_status_offset(Tab *tab)
{
	BitOffset off   = tab->doc->get_cursor_position();
	OffsetBase base = tab->doc_ctrl->get_offset_display_base();
	
	switch(base)
	{
		case OFFSET_BASE_HEX:
		{
			std::string off_text = format_offset(off, OFFSET_BASE_HEX) + " (" + format_offset(off, OFFSET_BASE_DEC) + ")";
			SetStatusText(off_text, 0);
			break;
		}
		
		case OFFSET_BASE_DEC:
		{
			std::string off_text = format_offset(off, OFFSET_BASE_DEC) + " (" + format_offset(off, OFFSET_BASE_HEX) + ")";
			SetStatusText(off_text, 0);
			break;
		}
		
		default:
			assert(false); /* Unreachable. */
			break;
	}
}

void REHex::MainWindow::_update_status_selection(REHex::DocumentCtrl *doc_ctrl)
{
	if(doc_ctrl->has_selection())
	{
		BitOffset selection_first, selection_last;
		std::tie(selection_first, selection_last) = doc_ctrl->get_selection_raw();
		
		if(selection_first.byte_aligned() && selection_last.bit() == 7)
		{
			selection_last = BitOffset(selection_last.byte(), 0);
		}
		
		std::string from_text = format_offset(selection_first, doc_ctrl->get_offset_display_base(), selection_last.byte());
		std::string to_text   = format_offset(selection_last,  doc_ctrl->get_offset_display_base(), selection_last.byte());
		
		BitRangeSet selection = doc_ctrl->get_selection_ranges();
		BitOffset selection_total = selection.total_bytes();
		
		std::string len_text = selection_total.byte_aligned()
			//? (std::to_string(selection_total.byte()) + " bytes")
			? format_size(selection_total.byte())
			: (std::to_string(selection_total.byte()) + " bytes, " + std::to_string(selection_total.bit()) + " bits");
		
		std::string text = "Selection: " + from_text + " - " + to_text + " (" + len_text + ")";
		SetStatusText(text, 1);
	}
	else{
		SetStatusText("", 1);
	}
	
	edit_menu->Enable(ID_COMPARE_SELECTION, doc_ctrl->has_selection());
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
	wxMenuItem *undo_menu_item = edit_menu->FindItem(wxID_UNDO);
	wxMenuItem *redo_menu_item = edit_menu->FindItem(wxID_REDO);
	
	const char *undo_desc = doc->undo_desc();
	if(undo_desc != NULL)
	{
		char label[64];
		snprintf(label, sizeof(label), "&Undo %s", undo_desc);
		
		edit_menu->SetLabel(wxID_UNDO, label);
		edit_menu->Enable(wxID_UNDO, true);
	}
	else{
		edit_menu->SetLabel(wxID_UNDO, "&Undo");
		edit_menu->Enable(wxID_UNDO, false);
	}
	
	window_commands.set_menu_item_accelerator(undo_menu_item, wxID_UNDO);
	
	const char *redo_desc = doc->redo_desc();
	if(redo_desc != NULL)
	{
		char label[64];
		snprintf(label, sizeof(label), "&Redo %s", redo_desc);
		
		edit_menu->SetLabel(wxID_REDO, label);
		edit_menu->Enable(wxID_REDO, true);
	}
	else{
		edit_menu->SetLabel(wxID_REDO, "&Redo");
		edit_menu->Enable(wxID_REDO, false);
	}
	
	window_commands.set_menu_item_accelerator(redo_menu_item, wxID_REDO);
}

void REHex::MainWindow::_update_dirty(REHex::Document *doc)
{
	bool        enable_save  = doc->get_filename() == "";
	std::string window_title = doc->get_title() + " - Reverse Engineers' Hex Editor";
	wxBitmap    tab_bitmap   = wxNullBitmap;
	
	if(doc->file_deleted())
	{
		enable_save  = true;
		window_title = "[DELETED] " + window_title;
		tab_bitmap   = notebook_bad_bitmap;
	}
	else if(doc->is_dirty() || doc->file_modified())
	{
		enable_save  = true;
		window_title = "[UNSAVED] " + window_title;
		tab_bitmap   = notebook_dirty_bitmap;
	}
	
	Tab *active_tab = this->active_tab();
	if(doc == active_tab->doc)
	{
		file_menu->Enable(wxID_SAVE, enable_save);
		file_menu->Check(ID_AUTO_RELOAD, active_tab->get_auto_reload());
		
		wxToolBar *toolbar = GetToolBar();
		toolbar->EnableTool(wxID_SAVE, enable_save);
		
		SetTitle(window_title);
		notebook->SetPageBitmap(notebook->GetSelection(), tab_bitmap);
	}
	else{
		size_t num_tabs = notebook->GetPageCount();
		for(size_t i = 0; i < num_tabs; ++i)
		{
			wxWindow *page = notebook->GetPage(i);
			assert(page != NULL);
			
			auto tab = dynamic_cast<Tab*>(page);
			assert(tab != NULL);
			
			if(tab->doc == doc)
			{
				notebook->SetPageBitmap(i, tab_bitmap);
				break;
			}
		}
	}
}

void REHex::MainWindow::_update_cpos_buttons(DocumentCtrl *doc_ctrl)
{
	wxToolBar *toolbar = GetToolBar();
	
	toolbar->EnableTool(wxID_BACKWARD, doc_ctrl->has_prev_cursor_position());
	toolbar->EnableTool(wxID_FORWARD,  doc_ctrl->has_next_cursor_position());
}

void REHex::MainWindow::_update_colour_map_menu(DocumentCtrl *doc_ctrl)
{
	/* Purge the current menu items. */
	
	for(auto i = colour_map_menu_id_to_bcm_id.begin(); i != colour_map_menu_id_to_bcm_id.end();)
	{
		colour_map_menu->Destroy(i->first);
		i = colour_map_menu_id_to_bcm_id.erase(i);
	}
	
	/* Repopulate the menu items. */
	
	auto maps = wxGetApp().settings->get_byte_colour_maps();
	
	int id = ID_COLOUR_MAP_MENU_MIN;
	
	colour_map_menu->AppendRadioItem(id, "None");
	colour_map_menu_id_to_bcm_id[id] = -1;
	++id;
	
	for(auto i = maps.begin(); i != maps.end() && id < ID_COLOUR_MAP_MENU_MAX; ++i, ++id)
	{
		colour_map_menu->AppendRadioItem(id, i->second->get_label());
		colour_map_menu_id_to_bcm_id[id] = i->first;
		
		if(i->second == doc_ctrl->get_byte_colour_map())
		{
			colour_map_menu->Check(id, true);
		}
	}
}

bool REHex::MainWindow::confirm_close_tabs(const std::vector<Tab*> &tabs)
{
	std::vector<Tab*> deleted_tabs;
	std::copy_if(tabs.begin(), tabs.end(), std::back_inserter(deleted_tabs),
		[](Tab *tab) { return tab->doc->file_deleted(); });
	
	if(deleted_tabs.size() == 1)
	{
		Tab *tab = deleted_tabs[0];
		
		wxMessageDialog confirm(
			this,
			(wxString("The file ") + tab->doc->get_filename() + " has been deleted from disk."),
			"File deleted",
			(wxYES_NO | wxCANCEL | wxCENTER));
		
		confirm.SetYesNoCancelLabels("Close anyway", "Save and close", "Cancel");
		
		int response = confirm.ShowModal();
		switch(response)
		{
			case wxID_YES:
			{
				/* Close anyway */
				return true;
			}
			
			case wxID_NO:
			{
				/* Save and close */
				
				try {
					tab->doc->save();
					_update_dirty(tab->doc);
					
					file_menu->Enable(wxID_REFRESH, true);
				}
				catch(const std::exception &e)
				{
					wxMessageBox(
						std::string("Error saving ") + tab->doc->get_title() + ":\n" + e.what(),
						"Error", wxICON_ERROR, this);
					
					return false;
				}
				
				return true;
			}
			
			default:
			{
				/* Cancel */
				return false;
			}
		}
	}
	else if(deleted_tabs.size() > 1)
	{
		wxString message = "The following files have been deleted from disk:\n";
		
		for(auto t = deleted_tabs.begin(); t != deleted_tabs.end(); ++t)
		{
			message.Append('\n');
			message.Append((*t)->doc->get_filename());
		}
		
		wxMessageDialog confirm(this, message, "Files deleted",
			(wxYES | wxNO | wxCENTER));
		
		confirm.SetYesNoLabels("Close anyway", "Cancel");
		
		int response = confirm.ShowModal();
		return response == wxID_YES;
	}
	
	std::vector<Tab*> modified_tabs;
	std::copy_if(tabs.begin(), tabs.end(), std::back_inserter(modified_tabs),
		[](Tab *tab) { return tab->doc->file_modified(); });
	
	if(modified_tabs.size() > 0)
	{
		wxString message = "The following files have been modified by another application:\n";
		
		for(auto t = modified_tabs.begin(); t != modified_tabs.end(); ++t)
		{
			message.Append('\n');
			message.Append((*t)->doc->get_filename());
		}
		
		wxMessageDialog confirm(this, message, "Files modified",
			(wxYES | wxNO | wxCENTER));
		
		confirm.SetYesNoLabels("Close anyway", "Cancel");
		
		int response = confirm.ShowModal();
		return response == wxID_YES;
	}
	
	std::vector<Tab*> dirty_tabs;
	std::copy_if(tabs.begin(), tabs.end(), std::back_inserter(dirty_tabs),
		[](Tab *tab) { return tab->doc->is_dirty(); });
	
	if(dirty_tabs.size() > 0)
	{
		wxString message = "The following files have unsaved changes:\n";
		
		for(auto t = dirty_tabs.begin(); t != dirty_tabs.end(); ++t)
		{
			message.Append('\n');
			message.Append((*t)->doc->get_filename());
		}
		
		wxMessageDialog confirm(this, message, "Unsaved changes",
			(wxYES | wxNO | wxCENTER));
		
		confirm.SetYesNoLabels("Close anyway", "Cancel");
		
		int response = confirm.ShowModal();
		return response == wxID_YES;
	}
	
	return true;
}

void REHex::MainWindow::close_tab(Tab *tab)
{
	std::vector<Tab*> closing_tabs = { tab };
	if(!confirm_close_tabs(closing_tabs))
	{
		/* User didn't want to discard unsaved changes. */
		return;
	}
	
	notebook->DeletePage(notebook->GetPageIndex(tab));
	
	if(notebook->GetPageCount() == 0)
	{
		ProcessCommand(wxID_NEW);
	}
}

void REHex::MainWindow::close_all_tabs()
{
	std::vector<Tab*> closing_tabs;
	
	size_t num_tabs = notebook->GetPageCount();
	for(size_t i = 0; i < num_tabs; ++i)
	{
		wxWindow *page = notebook->GetPage(i);
		assert(page != NULL);
		
		auto p_tab = dynamic_cast<Tab*>(page);
		assert(p_tab != NULL);
		
		closing_tabs.push_back(p_tab);
	}
	
	if(!confirm_close_tabs(closing_tabs))
	{
		/* User didn't really want to close unsaved tabs. */
		return;
	}
	
	notebook->DeleteAllPages();
	ProcessCommand(wxID_NEW);
}

void REHex::MainWindow::close_other_tabs(Tab *tab)
{
	std::vector<Tab*> closing_tabs;
	
	size_t num_tabs = notebook->GetPageCount();
	for(size_t i = 0; i < num_tabs; ++i)
	{
		wxWindow *page = notebook->GetPage(i);
		assert(page != NULL);
		
		auto p_tab = dynamic_cast<Tab*>(page);
		assert(p_tab != NULL);
		
		if(p_tab != tab)
		{
			closing_tabs.push_back(p_tab);
		}
	}
	
	if(!confirm_close_tabs(closing_tabs))
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

std::vector<REHex::WindowCommand> REHex::MainWindow::get_template_commands()
{
	return std::vector<WindowCommand>({
		WindowCommand( "file_new",           "New",           wxID_NEW,         wxACCEL_CTRL, 'N' ),
		WindowCommand( "file_open",          "Open",          wxID_OPEN,        wxACCEL_CTRL, 'O' ),
		WindowCommand( "file_save",          "Save",          wxID_SAVE,        wxACCEL_CTRL, 'S' ),
		WindowCommand( "file_save_as",       "Save as",       wxID_SAVEAS                         ),
		WindowCommand( "file_reload",        "Reload",        wxID_REFRESH                        ),
		WindowCommand( "file_close",         "Close",         wxID_CLOSE,       wxACCEL_CTRL, 'W' ),
		WindowCommand( "file_close_all",     "Close all",     ID_CLOSE_ALL                        ),
		WindowCommand( "file_close_others",  "Close others",  ID_CLOSE_OTHERS                     ),
		
		WindowCommand( "cursor_prev",        "Previous cursor position",      wxID_BACKWARD,          wxACCEL_ALT, WXK_LEFT             ),
		WindowCommand( "cursor_next",        "Next cursor position",          wxID_FORWARD,           wxACCEL_ALT, WXK_RIGHT            ),
		WindowCommand( "undo",               "Undo",                          wxID_UNDO,              wxACCEL_CTRL, 'Z'                 ),
		WindowCommand( "redo",               "Redo",                          wxID_REDO,              wxACCEL_CTRL | wxACCEL_SHIFT, 'Z' ),
		WindowCommand( "select_all",         "Select all",                    wxID_SELECTALL,         wxACCEL_CTRL, 'A'                 ),
		WindowCommand( "select_range",       "Select range",                  ID_SELECT_RANGE                                          ),
		WindowCommand( "fill_range",         "Fill range",                    ID_FILL_RANGE),
		WindowCommand( "overwrite_mode",     "Overwrite mode",                ID_OVERWRITE_MODE),
		WindowCommand( "write_protect",      "Write protect",                 ID_WRITE_PROTECT),
		WindowCommand( "search_text",        "Search for text",               ID_SEARCH_TEXT),
		WindowCommand( "search_bseq",        "Search for byte sequence",      ID_SEARCH_BSEQ),
		WindowCommand( "search_value",       "Search for value",              ID_SEARCH_VALUE),
		WindowCommand( "compare_file",       "Compare whole file",            ID_COMPARE_FILE,        wxACCEL_CTRL,                 'K'),
		WindowCommand( "compare_selection",  "Compare selection",             ID_COMPARE_SELECTION,   wxACCEL_CTRL | wxACCEL_SHIFT, 'K'),
		WindowCommand( "goto_offset",        "Jump to offset",                ID_GOTO_OFFSET,         wxACCEL_CTRL,                 'G'),
		WindowCommand( "repeat_goto_offset", "Repeat last 'Jump to offset'",  ID_REPEAT_GOTO_OFFSET,  wxACCEL_CTRL | wxACCEL_SHIFT, 'G'),
		
		WindowCommand("set_comment_at_cursor",     "Set comment at cursor position",  ID_SET_COMMENT_CURSOR),
		WindowCommand("set_comment_on_selection",  "Set comment on selected data",    ID_SET_COMMENT_SELECTION),
		
		WindowCommand("set_highlight_1",  "Set highlight 1",  ID_SET_HIGHLIGHT_1,  wxACCEL_CTRL, '1'),
		WindowCommand("set_highlight_2",  "Set highlight 2",  ID_SET_HIGHLIGHT_2,  wxACCEL_CTRL, '2'),
		WindowCommand("set_highlight_3",  "Set highlight 3",  ID_SET_HIGHLIGHT_3,  wxACCEL_CTRL, '3'),
		WindowCommand("set_highlight_4",  "Set highlight 4",  ID_SET_HIGHLIGHT_4,  wxACCEL_CTRL, '4'),
		WindowCommand("set_highlight_5",  "Set highlight 5",  ID_SET_HIGHLIGHT_5,  wxACCEL_CTRL, '5'),
		WindowCommand("set_highlight_6",  "Set highlight 6",  ID_SET_HIGHLIGHT_6,  wxACCEL_CTRL, '6'),
		WindowCommand("remove_highlight", "Remove highlight", ID_REMOVE_HIGHLIGHT, wxACCEL_CTRL, '0'),
	});
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
