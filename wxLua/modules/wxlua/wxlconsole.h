/////////////////////////////////////////////////////////////////////////////
// Purpose:     Interface to a console to help debug wxLua
// Author:      John Labenski, Francis Irving
// Created:     16/01/2002
// Copyright:   (c) 2012 John Labenski
// Copyright:   (c) 2002 Creature Labs. All rights reserved.
// Licence:     wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef WX_LUA_CONSOLE_H
#define WX_LUA_CONSOLE_H

#include <wx/frame.h>
#include <wx/filename.h>

#include "wxlua/wxlua.h"

class WXDLLIMPEXP_FWD_CORE wxSplitterWindow;
class WXDLLIMPEXP_FWD_CORE wxTextCtrl;

enum wxLuaConsole_WindowIds
{
    ID_WXLUACONSOLE                  = wxID_HIGHEST + 10,
    ID_WXLUACONSOLE_SCROLLBACK_LINES,
    ID_WXLUACONSOLE_BACKTRACE
};

// ----------------------------------------------------------------------------
// wxLuaConsole - define a console class to display print statements
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_WXLUA wxLuaConsole : public wxFrame
{
public:
    wxLuaConsole(wxWindow* parent, wxWindowID id = ID_WXLUACONSOLE,
                 const wxString& title = wxT("wxLua console"),
                 const wxPoint& pos = wxDefaultPosition,
                 const wxSize& size = wxSize(300, 400),
                 long style = wxDEFAULT_FRAME_STYLE,
                 const wxString& name = wxT("wxLuaConsole"));

    virtual ~wxLuaConsole();

    /// Override from base class.
    virtual bool Destroy();

    /// Get the first/current wxLuaConsole as a singleton object.
    /// Returns NULL if !create_on_demand and there isn't one existing.
    /// Do not keep a handle to the console past any function call since
    /// the user may close it and the handle will be invalidated.
    static wxLuaConsole* GetConsole(bool create_on_demand = false);
    /// Returns true if there is an active console.
    static bool HasConsole();

    /// Get the set wxLuaState.
    wxLuaState GetLuaState() const { return m_luaState; }
    /// Set a wxLuaState to show backtraces from.
    void SetLuaState(const wxLuaState& wxlState ) { m_luaState = wxlState; }

    /// Display a message in the console.
    void AppendText(const wxString& msg);
    /// Display a message in the console with optional wxTextCtrl attribute to display it with.
    void AppendTextWithAttr(const wxString& msg, const wxTextAttr& attr);

    /// Remove lines so there are only max_lines, returns false if nothing is changed.
    bool SetMaxLines(int max_lines = 500);
    /// Get the maximum number of lines to show in the textcontrol before removing the earliest ones.
    int  GetMaxLines() const { return m_max_lines; }

    /// Display the stack, but only if there are any items in it.
    /// This only works while Lua is running.
    void DisplayStack(const wxLuaState& wxlState);

    /// Set if wxExit() will be called with this dialog is closed to exit the app.
    /// Use this when an error has occurred so the program doesn't continue.
    void SetExitWhenClosed(bool do_exit) { m_exit_when_closed = do_exit; }
    /// Get whether the program will exit when this dialog is closed.
    bool GetExitWhenClosed() const       { return m_exit_when_closed; }

protected:
    void OnCloseWindow(wxCloseEvent& event);
    void OnMenu(wxCommandEvent& event);

    wxTextCtrl          *m_textCtrl;
    bool                 m_exit_when_closed;
    int                  m_max_lines;
    wxFileName           m_saveFilename;

    wxLuaState           m_luaState;

    static wxLuaConsole* sm_wxluaConsole;

private:
    DECLARE_EVENT_TABLE()
};

// ----------------------------------------------------------------------------
// Functions
// ----------------------------------------------------------------------------

/// Reconnect stdin, stdout and stderr to a DOS console that is optionally allocated.
/// Normally stdout/stdin/stderr goes nowhere in a MSW GUI app and this corrects that.
/// This function does nothing when called from any other OS.
void WXDLLIMPEXP_WXLUA wxlua_RedirectIOToDosConsole(bool alloc_new_if_needed,
													short max_console_lines = 500);


#endif // WX_LUA_CONSOLE_H
