/////////////////////////////////////////////////////////////////////////////
// Purpose:     Implements the client end of wxLua debugging session
// Author:      J. Winwood, John Labenski, Ray Gilbert
// Created:     May 2002
// Copyright:   (c) 2012 John Labenski, 2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef LUA_DEBUG_TARGET_H
#define LUA_DEBUG_TARGET_H

#include <wx/thread.h>
#include "wxlua/debugger/wxluadebuggerdefs.h"
#include "wxlua/wxlua.h"
#include "wxlua/debug/wxldebug.h"
#include "wxlua/debugger/wxlsock.h"

// ----------------------------------------------------------------------------
// wxLuaDebugTarget - a C++ socket target that the wxLuaDebuggerServer run in Lua
//                    communicates with. Handles the Debugger/Debuggee IO
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_WXLUADEBUGGER wxLuaDebugTarget : public wxObject
{
protected:
    // -----------------------------------------------------------------------
    // wxLuaDebugTarget::LuaThread - a wxThread for the wxLuaDebugTarget
    // -----------------------------------------------------------------------
    class LuaThread : public wxThread
    {
      public:
        LuaThread(wxLuaDebugTarget *luaDebugTarget);
        virtual ~LuaThread();

      protected:

        virtual void *Entry();   // thread execution starts here
        virtual void OnExit() {} // called when the thread exits

        wxLuaDebugTarget *m_luaDebugTarget;
    };

public:
    wxLuaDebugTarget(const wxLuaState& wxlState,
                     const wxString &serverName, int portNumber);

    virtual ~wxLuaDebugTarget();

    /// Returns true if this is currently connected to a wxLuaDebuggerServer.
    bool IsConnected(bool wait_for_connect = true) const;

    bool Run();
    void Stop();

    void ThreadFunction();
    bool HandleDebuggerCmd(int cmd);
    void DisplayError(const wxString& errorMsg) { NotifyError(errorMsg); }

protected:

    enum DebugOperations_Type
    {
        DEBUG_STEP,
        DEBUG_STEPOVER,
        DEBUG_STEPOUT,
        DEBUG_GO
    };

    wxLuaState                m_wxlState;

    LuaThread*                m_luaThread;
    wxCriticalSection         m_luaThreadCriticalSection;

    wxLuaSocket               m_clientSocket;
    int                       m_port_number;
    wxString                  m_serverName;
    bool                      m_socket_connected;

    wxArrayString             m_bufferArray;

    wxCriticalSection         m_luaCriticalSection;
    wxMutex                   m_runMutex;
    wxCondition               m_runCondition;
    wxMutex                   m_debugMutex;
    wxCondition               m_debugCondition;

    wxSortedArrayString       m_breakPointList;
    mutable wxCriticalSection m_breakPointListCriticalSection;

    DebugOperations_Type      m_nextOperation;
    bool                      m_force_break;
    bool                      m_reset_requested;
    bool                      m_is_running;
    bool                      m_is_stopped;
    bool                      m_is_exiting;
    int                       m_nframes_until_break;

    wxArrayInt                m_references;

    /// Enter critical section for accessing the lua_State from the threaded sockets.
    inline void EnterLuaCriticalSection() { m_luaCriticalSection.Enter(); }
    /// Leave critical section for accessing the lua_State from the threaded sockets.
    inline void LeaveLuaCriticalSection() { m_luaCriticalSection.Leave(); }

    /// Returns a string ("%d:%s", lineNumber, fileName) for the breakpoint, does not set it.
    wxString CreateBreakPoint(const wxString &fileName, int lineNumber) const;
    bool AtBreakPoint(const wxString &fileName, int lineNumber) const;
    bool AddBreakPoint(const wxString &fileName, int lineNumber);
    bool RemoveBreakPoint(const wxString &fileName, int lineNumber);
    bool ClearAllBreakPoints();

    bool Run(const wxString &fileName, const wxString &buffer);
    bool Step();
    bool StepOver();
    bool StepOut();
    bool Continue();
    bool Break();
    bool Reset();
    bool EnumerateStack();
    bool EnumerateStackEntry(int stackRef);
    bool EnumerateTable(int tableRef, int nIndex, long itemNode);
    bool EvaluateExpr(int exprRef, const wxString &strExpr);

    bool NotifyBreak(const wxString &fileName, int lineNumber);
    bool NotifyPrint(const wxString &errorMsg);
    bool NotifyError(const wxString &errorMsg);
    bool NotifyExit();
    bool NotifyStackEnumeration(const wxLuaDebugData& debugData);
    bool NotifyStackEntryEnumeration(int stackRef, const wxLuaDebugData& debugData);
    bool NotifyTableEnumeration(long itemNode, const wxLuaDebugData& debugData);
    bool NotifyEvaluateExpr(int exprRef, const wxString &strResult);

    /// Handle events from the static wxLuaDebugTarget::LuaDebugHook().
    bool DebugHook(int event);

    /// Get the wxLuaDebugTarget that was pushed into Lua's registry.
    static wxLuaDebugTarget* GetDebugTarget(lua_State* L);

    /// Handle the events from lua_sethook().
    static void LUACALL LuaDebugHook(lua_State *L, lua_Debug *debug);
    /// Forward the print statements to NotifyPrint().
    static int  LUACALL LuaPrint (lua_State *L);

private:
    friend class LuaThread;
};

#endif // LUA_DEBUG_TARGET_H
