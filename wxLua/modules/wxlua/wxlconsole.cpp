/////////////////////////////////////////////////////////////////////////////
// Purpose:     A console to help debug/use wxLua
// Author:      John Labenski, J Winwood
// Created:     14/11/2001
// Copyright:   (c) 2012 John Labenski
// Copyright:   (c) 2001-2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/wxprec.h>

#ifdef __STRICT_ANSI__
#undef __STRICT_ANSI__
#include <cstdio>
#define __STRICT_ANSI__
#else
#include <cstdio>
#endif

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include <wx/wx.h>
#endif

#if defined(__WXGTK__) || defined(__WXMOTIF__) || defined(__WXMAC__)
    #include "art/wxlua.xpm"
#endif

#include <wx/splitter.h>
#include <wx/toolbar.h>
#include <wx/filename.h>
#include <wx/numdlg.h>
#include <wx/artprov.h>
#include <wx/dynlib.h>

#include "wxlua/wxlua.h"
#include "wxlconsole.h"

// ----------------------------------------------------------------------------
// wxLuaConsole
// ----------------------------------------------------------------------------

wxLuaConsole* wxLuaConsole::sm_wxluaConsole = NULL;

BEGIN_EVENT_TABLE(wxLuaConsole, wxFrame)
    EVT_CLOSE (          wxLuaConsole::OnCloseWindow)
    EVT_MENU  (wxID_ANY, wxLuaConsole::OnMenu)
END_EVENT_TABLE()

wxLuaConsole::wxLuaConsole(wxWindow* parent, wxWindowID id, const wxString& title,
                           const wxPoint& pos, const wxSize& size,
                           long style, const wxString& name)
             :wxFrame(parent, id, title, pos, size, style, name),
              m_exit_when_closed(false)
{
    m_max_lines = 2000;
    m_saveFilename = wxT("log.txt");
    m_saveFilename .Normalize();

    SetIcon(wxICON(LUA));

    wxToolBar* tb = CreateToolBar();

    tb->AddTool(wxID_NEW,    wxT("Clear window"), wxArtProvider::GetBitmap(wxART_NEW,       wxART_TOOLBAR), wxT("Clear console window"), wxITEM_NORMAL);
    tb->AddTool(wxID_SAVEAS, wxT("Save output"),  wxArtProvider::GetBitmap(wxART_FILE_SAVE, wxART_TOOLBAR), wxT("Save contents to file..."), wxITEM_NORMAL);
    tb->AddTool(wxID_COPY,   wxT("Copy text"),    wxArtProvider::GetBitmap(wxART_COPY,      wxART_TOOLBAR), wxT("Copy contents to clipboard"), wxITEM_NORMAL);
    tb->AddTool(ID_WXLUACONSOLE_SCROLLBACK_LINES, wxT("Scrollback"), wxArtProvider::GetBitmap(wxART_LIST_VIEW, wxART_TOOLBAR), wxT("Set the number of scrollback lines..."), wxITEM_NORMAL);
    //tb->AddTool(ID_WXLUACONSOLE_BACKTRACE, wxT("Backtrace"), wxArtProvider::GetBitmap(wxART_QUESTION, wxART_TOOLBAR), wxT("Show the current Lua stack..."), wxITEM_NORMAL);
    tb->Realize();

    m_textCtrl = new wxTextCtrl(this, wxID_ANY, wxEmptyString,
                                wxDefaultPosition, wxDefaultSize,
                                wxTE_MULTILINE | wxTE_READONLY | wxTE_RICH2 | wxTE_DONTWRAP);
    wxFont monoFont(10, wxFONTFAMILY_TELETYPE, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL); // monospace
    m_textCtrl->SetFont(monoFont);

    // Only set it to this if it wasn't already set, typically there will only be one of these.
    if (sm_wxluaConsole == NULL)
        sm_wxluaConsole = this;
}

wxLuaConsole::~wxLuaConsole()
{
    if (sm_wxluaConsole == this)
        sm_wxluaConsole = NULL;
}

bool wxLuaConsole::Destroy()
{
    if (sm_wxluaConsole == this)
        sm_wxluaConsole = NULL;

    return wxFrame::Destroy();
}

// static
wxLuaConsole* wxLuaConsole::GetConsole(bool create_on_demand)
{
    if (!create_on_demand || (sm_wxluaConsole != NULL))
        return sm_wxluaConsole;

    new wxLuaConsole(NULL, ID_WXLUACONSOLE);
    return sm_wxluaConsole;
}

// static
bool wxLuaConsole::HasConsole()
{
    return (sm_wxluaConsole != NULL) && !sm_wxluaConsole->IsBeingDeleted();
}


void wxLuaConsole::OnCloseWindow(wxCloseEvent&)
{
    // Must NULL the console so nobody will try to still use it.
    if (sm_wxluaConsole == this)
        sm_wxluaConsole = NULL;

    Destroy();
    if (m_exit_when_closed)
        wxExit();
}

void wxLuaConsole::OnMenu(wxCommandEvent& event)
{
    switch (event.GetId())
    {
        case wxID_NEW :
        {
            m_textCtrl->Clear();
            break;
        }
        case wxID_SAVEAS :
        {
            wxString filename = wxFileSelector(wxT("Select file to save output to"),
                                               m_saveFilename.GetPath(),
                                               m_saveFilename.GetFullName(),
                                               wxT("txt"),
                                               wxT("Text files (*.txt)|*.txt|All files (*.*)|*.*"),
                                               wxFD_SAVE|wxFD_OVERWRITE_PROMPT,
                                               this);

            if (!filename.IsEmpty())
            {
                m_saveFilename = wxFileName(filename);
                m_textCtrl->SaveFile(filename);
            }
            break;
        }
        case wxID_COPY :
        {
            long from = 0, to = 0;
            m_textCtrl->GetSelection(&from, &to);
            m_textCtrl->SetSelection(-1, -1);
            m_textCtrl->Copy();
            m_textCtrl->SetSelection(from, to);
            break;
        }
        case ID_WXLUACONSOLE_SCROLLBACK_LINES :
        {
            long lines = wxGetNumberFromUser(wxT("Set the number of printed lines to remember, 0 to 10000.\nSet to 0 for infinite history."),
                                             wxT("Lines : "),
                                             wxT("Set Number of Scrollback Lines"),
                                             m_max_lines, 0, 10000,
                                             this);
            if (lines >= 0)
                SetMaxLines(lines);

            break;
        }
        case ID_WXLUACONSOLE_BACKTRACE :
        {
            if (m_luaState.IsOk())
            {
                DisplayStack(m_luaState);
                //wxLuaStackDialog dlg(m_wxlState, this);
                //dlg.ShowModal();
            }

            break;
        }
        default : break;
    }
}

void wxLuaConsole::AppendText(const wxString& msg)
{
    m_textCtrl->Freeze();

    // Probably the best we can do to maintain the cursor pos while appending
    // The wxStyledTextCtrl can do a much better job...
    long pos          = m_textCtrl->GetInsertionPoint();
    int  num_lines    = m_textCtrl->GetNumberOfLines();
    long pos_near_end = m_textCtrl->XYToPosition(0, wxMax(0, num_lines - 5));
    bool is_near_end  = (pos >= pos_near_end);

    m_textCtrl->AppendText(msg);
    m_textCtrl->SetInsertionPoint(is_near_end ? m_textCtrl->GetLastPosition() : pos);

    m_textCtrl->Thaw();

    SetMaxLines(m_max_lines);
}
void wxLuaConsole::AppendTextWithAttr(const wxString& msg, const wxTextAttr& attr)
{
    wxTextAttr oldAttr = m_textCtrl->GetDefaultStyle();

    m_textCtrl->SetDefaultStyle(attr);
    AppendText(msg);
    m_textCtrl->SetDefaultStyle(oldAttr);

    SetMaxLines(m_max_lines);
}

bool wxLuaConsole::SetMaxLines(int max_lines)
{
    m_max_lines = max_lines;

    int num_lines = m_textCtrl->GetNumberOfLines();
    if ((m_max_lines <= 0) || (num_lines < m_max_lines))
        return false;

    long pos = m_textCtrl->GetInsertionPoint();
    long remove_pos = m_textCtrl->XYToPosition(0, num_lines - m_max_lines);

    m_textCtrl->Freeze();
    m_textCtrl->Remove(0, remove_pos);
    m_textCtrl->SetInsertionPoint(wxMax(0, pos-remove_pos));
    m_textCtrl->ShowPosition(wxMax(0, pos-remove_pos));
    m_textCtrl->Thaw();

    return true;
}

void wxLuaConsole::DisplayStack(const wxLuaState& wxlState)
{
    wxCHECK_RET(wxlState.Ok(), wxT("Invalid wxLuaState"));
    int       nIndex   = 0;
    lua_Debug luaDebug = INIT_LUA_DEBUG;
    wxString  buffer;

    lua_State* L = wxlState.GetLuaState();

    while (lua_getstack(L, nIndex, &luaDebug) != 0)
    {
        if (lua_getinfo(L, "Sln", &luaDebug))
        {
            wxString what    (luaDebug.what     ? lua2wx(luaDebug.what)     : wxString(wxT("?")));
            wxString nameWhat(luaDebug.namewhat ? lua2wx(luaDebug.namewhat) : wxString(wxT("?")));
            wxString name    (luaDebug.name     ? lua2wx(luaDebug.name)     : wxString(wxT("?")));

            buffer += wxString::Format(wxT("[%d] %s '%s' '%s' (line %d)\n    Line %d src='%s'\n"),
                                       nIndex, what.c_str(), nameWhat.c_str(), name.c_str(), luaDebug.linedefined,
                                       luaDebug.currentline, lua2wx(luaDebug.short_src).c_str());
        }
        nIndex++;
    }

    if (!buffer.empty())
    {
        AppendText(wxT("\n-----------------------------------------------------------")
                   wxT("\n- Backtrace")
                   wxT("\n-----------------------------------------------------------\n") +
                   buffer +
                   wxT("\n-----------------------------------------------------------\n\n"));
    }
}

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

#ifdef __WXMSW__

#include <iostream>

#ifndef wxDL_INIT_FUNC // not in wx < 2.9
    #define wxDL_INIT_FUNC(pfx, name, dynlib) \
        pfx ## name = (name ## _t)(dynlib).RawGetSymbol(wxT(#name))
#endif // wxDL_INIT_FUNC

// Code from http://dslweb.nwnexus.com/~ast/dload/guicon.htm
// Andrew Tucker, no license, assumed to be public domain.
void wxlua_RedirectIOToDosConsole(bool alloc_new_if_needed, short max_console_lines)
{
    int  hConHandle = 0;
    wxIntPtr lStdHandle = 0;
    CONSOLE_SCREEN_BUFFER_INFO coninfo;
    memset(&coninfo, 0, sizeof(CONSOLE_SCREEN_BUFFER_INFO));
    FILE *fp = 0; // we don't close this, let the OS close it when the app exits

    wxDynamicLibrary kernel;
    // Dynamically load kernel32 because AttachConsole() is not supported pre-XP
    BOOL attached_ok = kernel.Load(wxT("kernel32.dll"));
    
    if (attached_ok)
    {
        // Try to attach to the parent process if it's a console, i.e. we're run from a DOS prompt.
        // The code below is equivalent to calling this code:
        //   BOOL attached_ok = AttachConsole( ATTACH_PARENT_PROCESS );

        typedef BOOL (WINAPI *AttachConsole_t)(DWORD dwProcessId);
        AttachConsole_t wxDL_INIT_FUNC(pfn, AttachConsole, kernel);

        if (pfnAttachConsole)
            attached_ok = pfnAttachConsole( ATTACH_PARENT_PROCESS );
        else
            attached_ok = 0;
    }

    if (attached_ok == 0) // failed attaching
    {
        // we tried to attach, but failed don't alloc a new one
        if (!alloc_new_if_needed)
            return;

        // Unable to attach, allocate a console for this app
        AllocConsole();
    }

    // set the screen buffer to be big enough to let us scroll text
    GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &coninfo);
    coninfo.dwSize.Y = (WORD)max_console_lines;
    SetConsoleScreenBufferSize(GetStdHandle(STD_OUTPUT_HANDLE), coninfo.dwSize);
    // redirect unbuffered STDOUT to the console
    lStdHandle = (wxIntPtr)GetStdHandle(STD_OUTPUT_HANDLE);
    hConHandle = _open_osfhandle((intptr_t)lStdHandle, _O_TEXT);
    fp = _fdopen( hConHandle, "w" );
    *stdout = *fp;
    setvbuf( stdout, NULL, _IONBF, 0 );
    // redirect unbuffered STDIN to the console
    lStdHandle = (wxIntPtr)GetStdHandle(STD_INPUT_HANDLE);
    hConHandle = _open_osfhandle((intptr_t)lStdHandle, _O_TEXT);
    fp = _fdopen( hConHandle, "r" );
    *stdin = *fp;
    setvbuf( stdin, NULL, _IONBF, 0 );
    // redirect unbuffered STDERR to the console
    lStdHandle = (wxIntPtr)GetStdHandle(STD_ERROR_HANDLE);
    hConHandle = _open_osfhandle((intptr_t)lStdHandle, _O_TEXT);
    fp = _fdopen( hConHandle, "w" );
    *stderr = *fp;
    setvbuf( stderr, NULL, _IONBF, 0 );
    // make cout, wcout, cin, wcin, wcerr, cerr, wclog and clog
    // point to console as well
    std::ios::sync_with_stdio();
}

#else // !__WXMSW__

void wxlua_RedirectIOToDosConsole(bool , short )
{
    // Nothing to do since these OSes already do the right thing.
}

#endif // __WXMSW__


