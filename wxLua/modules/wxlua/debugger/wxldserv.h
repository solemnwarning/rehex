/////////////////////////////////////////////////////////////////////////////
// Purpose:     Implements the debugger end of wxLua debugging session
// Author:      J. Winwood, John Labenski, Ray Gilbert
// Created:     May 2002
// Copyright:   (c) 2012 John Labenski, 2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef WX_LUA_DEBUG_SERVER_H
#define WX_LUA_DEBUG_SERVER_H

#include <wx/process.h>
#include <wx/thread.h>
#include "wxlua/debugger/wxluadebuggerdefs.h"
#include "wxlua/debugger/wxlsock.h"
#include "wxlua/debug/wxldebug.h"
#include "wxlua/debug/wxlstack.h"

class WXDLLIMPEXP_WXLUADEBUGGER wxLuaDebuggerBase;
class WXDLLIMPEXP_WXLUADEBUGGER wxLuaDebuggerEvent;

// ----------------------------------------------------------------------------
// wxWindowIds of components used for the debugger
// ----------------------------------------------------------------------------

enum
{
    ID_WXLUA_DEBUGGEE_PROCESS = 1500 // id of the spawned debuggee wxProcess
};

// ----------------------------------------------------------------------------
// wxLuaDebuggeeEvents_Type - These are socket events sent from debuggee
//   to debugger to notify the debugger that action has been taken which was
//   probably the result of a previously received wxLuaDebuggerCommands_Type.
//   These socket events should be sent with wxLuaSocketBase::Read/WriteCmd()
// ----------------------------------------------------------------------------

enum wxLuaDebuggeeEvents_Type
{
    wxLUA_DEBUGGEE_EVENT_NONE = 0, // a socket error probably

    wxLUA_DEBUGGEE_EVENT_BREAK,
    wxLUA_DEBUGGEE_EVENT_PRINT,
    wxLUA_DEBUGGEE_EVENT_ERROR,
    wxLUA_DEBUGGEE_EVENT_EXIT,
    wxLUA_DEBUGGEE_EVENT_STACK_ENUM,
    wxLUA_DEBUGGEE_EVENT_STACK_ENTRY_ENUM,
    wxLUA_DEBUGGEE_EVENT_TABLE_ENUM,
    wxLUA_DEBUGGEE_EVENT_EVALUATE_EXPR,

    wxLUA_DEBUGGEE_EVENT__COUNT
};

// ----------------------------------------------------------------------------
// wxLuaDebuggerCommands_Type - These are socket commands sent from the
//   debugger to debuggee to direct the debuggee to take action, which will
//   then return with a wxLuaDebuggeeEvents_Type when done.
//   These socket commands should be sent with wxLuaSocketBase::Read/WriteCmd()
// ----------------------------------------------------------------------------

enum wxLuaDebuggerCommands_Type
{
    wxLUA_DEBUGGER_CMD_NONE = 0, // a socket error probably

    wxLUA_DEBUGGER_CMD_ADD_BREAKPOINT = 100, // shifted for debugging
    wxLUA_DEBUGGER_CMD_REMOVE_BREAKPOINT,
    wxLUA_DEBUGGER_CMD_DISABLE_BREAKPOINT,
    wxLUA_DEBUGGER_CMD_ENABLE_BREAKPOINT,
    wxLUA_DEBUGGER_CMD_CLEAR_ALL_BREAKPOINTS,
    wxLUA_DEBUGGER_CMD_RUN_BUFFER,
    wxLUA_DEBUGGER_CMD_DEBUG_STEP,
    wxLUA_DEBUGGER_CMD_DEBUG_STEPOVER,
    wxLUA_DEBUGGER_CMD_DEBUG_STEPOUT,
    wxLUA_DEBUGGER_CMD_DEBUG_CONTINUE,
    wxLUA_DEBUGGER_CMD_DEBUG_BREAK,
    wxLUA_DEBUGGER_CMD_RESET,
    wxLUA_DEBUGGER_CMD_ENUMERATE_STACK,
    wxLUA_DEBUGGER_CMD_ENUMERATE_STACK_ENTRY,
    wxLUA_DEBUGGER_CMD_ENUMERATE_TABLE_REF,
    wxLUA_DEBUGGER_CMD_CLEAR_DEBUG_REFERENCES,
    wxLUA_DEBUGGER_CMD_EVALUATE_EXPR,
};

// ----------------------------------------------------------------------------
// wxLuaDebuggerStackDialog - a wxLuaStackDialog for the wxLuaDebuggerBase.
//   Use the function wxLuaDebuggerBase::DisplayStackDialog() to create
//   and show one of these.
//
// Note: The wxLuaStackDialog is created by the debugger process and uses
//   the overridden EnumerateXXX functions to get the wxLuaDebugData through the
//   socket connection to the debuggee using the wxLuaDebuggerBase.
// Note: The wxLuaState of the wxLuaStackDialog is not used in this case
//   since it 'exists' in the independent debuggee process.
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_WXLUADEBUGGER wxLuaDebuggerStackDialog : public wxLuaStackDialog
{
public:
    wxLuaDebuggerStackDialog(wxLuaDebuggerBase* luaDebugger,
                             wxWindow* parent, wxWindowID id = wxID_ANY,
                             const wxString& title = wxT("wxLua Stack"),
                             const wxPoint& pos = wxDefaultPosition,
                             const wxSize& size = wxDefaultSize);

    virtual ~wxLuaDebuggerStackDialog();

    // overridden functions for the wxLuaStackDialog that forward to the
    //  wxLuaDebuggerBase, they return through a wxLuaDebuggerEvent and the
    //  wxLuaDebuggerBase::OnDebugStackEnum, OnDebugTableEnum, OnDebugStackEntryEnum
    //  functions that then call the FillXXX functions.
    virtual void EnumerateStack();
    virtual void EnumerateStackEntry(int nEntry);
    virtual void EnumerateTable(int nRef, int nEntry, long lc_item);

    // implementation

    wxLuaDebuggerBase* m_luaDebugger;

private:
    DECLARE_ABSTRACT_CLASS(wxLuaDebuggerStackDialog)
};

// ----------------------------------------------------------------------------
// wxLuaDebuggerProcess - The wxProcess from wxExecute to run a
//    wxLuaDebugTarget as a debuggee. It handles OnTerminate gracefully.
// ----------------------------------------------------------------------------

class wxLuaDebuggerProcess : public wxProcess
{
public:
    // Don't use the debugger as the event handler since we don't want
    //   problems when this may exist when the debugger is being deleted.
    wxLuaDebuggerProcess(wxLuaDebuggerBase* debugger, wxWindowID id)
        : wxProcess(NULL, id), m_debugger(debugger) {}

    // don't send event, but delete this and NULL debugger's pointer to this
    virtual void OnTerminate(int pid, int status);

    wxLuaDebuggerBase* m_debugger;
};

// ----------------------------------------------------------------------------
// wxLuaDebuggerBase - Socket debugger interface base class.
//  This base class sends wxLUA_DEBUGGER_CMD_XXX commands through the
//  socket to the debuggee. The debuggee then responds through the socket with
//  a wxLUA_DEBUGGEE_EVENT_XXX event which is turned into a
//  wxLuaDebuggerEvent of type wxEVT_WXLUA_DEBUGGER_XXX which is processed by
//  this class. Use wxEvtHandler::Connect(...) (or subclass and use an event
//  table) to intercept these events and act on them.
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_WXLUADEBUGGER wxLuaDebuggerBase : public wxEvtHandler
{
public:
    wxLuaDebuggerBase(int port_number);
    virtual ~wxLuaDebuggerBase();

    // Start the debugger server to listen for a debuggee. After creation
    //  you must call StartServer to actually start the server. returns success
    virtual bool StartServer() = 0;
    // Stop the debugger server, returns success
    virtual bool StopServer() = 0;
    // Start a debuggee client to be debugged by this, returns success
    // By default it starts a new wxLuaDebuggerProcess
    virtual long StartClient();

    // These functions all send socket commands wxLUA_DEBUGGER_CMD_XXX
    // and the appropriate data to the debuggee.

    bool AddBreakPoint(const wxString &fileName, int lineNumber);
    bool RemoveBreakPoint(const wxString &fileName, int lineNumber);
    bool DisableBreakPoint(const wxString &fileName, int lineNumber);
    bool EnableBreakPoint(const wxString &fileName, int lineNumber);
    bool ClearAllBreakPoints();
    bool Run(const wxString &fileName, const wxString &buffer);
    bool Step();
    bool StepOver();
    bool StepOut();
    bool Continue();
    bool Break();
    bool Reset();
    bool EnumerateStack();
    bool EnumerateStackEntry(int stackEntry);
    bool EnumerateTable(int tableRef, int nIndex, long nItemNode);
    bool ClearDebugReferences();
    bool EvaluateExpr(int exprRef, const wxString &strExpression);

    // Handle the wxLuaDebuggeeEvents_Type event sent by the debuggee.
    //   returns the input event_type if ok or -1 on error
    // On success a wxLuaDebuggerEvent is generated with the equivalent
    // wxEVT_WXLUA_DEBUGGER_XXX to the input wxLUA_DEBUGGEE_EVENT_XXX
    virtual int HandleDebuggeeEvent(int event_type);

    // Get the debugger socket to read/write data to the debuggee
    virtual wxLuaSocketBase* GetSocketBase() = 0;
    // Check if the socket is connected and if not send a
    //   wxEVT_WXLUA_DEBUGGER_DEBUGGEE_DISCONNECTED event with a socket error msg
    virtual bool CheckSocketConnected(bool send_event = true, const wxString& msg = wxEmptyString);
    // Check if the input is true (ie. return of a socket read) and if not send a
    //   wxEVT_WXLUA_DEBUGGER_DEBUGGEE_DISCONNECTED with a read error msg
    virtual bool CheckSocketRead(bool read_ok, const wxString& msg = wxEmptyString);
    // Check if the input is true (eg. return of a socket write) and if not send a
    //   wxEVT_WXLUA_DEBUGGER_DEBUGGEE_DISCONNECTED with a write error msg
    virtual bool CheckSocketWrite(bool write_ok, const wxString& msg = wxEmptyString);

    // Get the socket error message or ""
    virtual wxString GetSocketErrorMsg() = 0;

    // Send the event to this wxEvtHandler
    virtual void SendEvent(wxEvent& event) { AddPendingEvent(event); }

    // Get/Set the wxLuaStackDialog to show the stack of the debugged program
    wxLuaStackDialog* GetStackDialog() { return m_stackDialog; }
    void SetStackDialog(wxLuaStackDialog *stackDialog) { m_stackDialog = stackDialog; }
    // Create and display a wxLuaDebuggerStackDialog for the debuggee process
    bool DisplayStackDialog(wxWindow *parent, wxWindowID id = wxID_ANY);

    // Handle the stack dialog events using the internal wxLuaStackDialog
    void OnDebugStackEnum(wxLuaDebuggerEvent &event);
    void OnDebugTableEnum(wxLuaDebuggerEvent &event);
    void OnDebugStackEntryEnum(wxLuaDebuggerEvent &event);

    // Handle the wxProcess debuggee termination
    void OnEndDebugeeProcess(wxProcessEvent& event);

    // Get the port number the socket is using
    int GetPortNumber() const { return m_port_number; }

    // Get the wxLuaDebuggerProcess used to run the debuggee in
    wxLuaDebuggerProcess* GetDebuggeeProcess() { return m_debuggeeProcess; }
    long GetDebuggeeProcessId() const { return m_debuggeeProcessID; }
    bool KillDebuggee();

    // Set the program name to start the debuggee target with
    // Note: If the the program name is empty when this class is created, it
    //       will be initialized to wxGetApp().argv[0].
    //       If you set it to some other value it will not be changed.
    static void SetProgramName(const wxString& name) { sm_programName = name; }
    static wxString GetProgramName() { return sm_programName; }

    // Get/Set the network name to use to start the debuggee target with.
    // Note: If the the network name is empty when this class is created, it
    //       will be initialized to wxGetHostName() in MSW and 'localhost' in UNIX.
    //       If you set it to some other value it will not be changed.
    static void SetNetworkName(const wxString& name) { sm_networkName = name; }
    static wxString GetNetworkName() { return sm_networkName; }

    // implementation

    int                   m_port_number;       // the socket port to listen to
    wxLuaStackDialog     *m_stackDialog;       // the stack dialog to
    wxLuaDebuggerProcess *m_debuggeeProcess;   // wxProcess of the debuggee
    long                  m_debuggeeProcessID; // id of the debuggee wxProcess

    wxCriticalSection     m_acceptSockCritSect; // for deleting accepted socket
    wxCriticalSection     m_processCritSect;    // for deleting the client process

    static wxString sm_programName; // name of the program to run for debuggee
    static wxString sm_networkName; // name of the network to use for the debuggee

    friend class wxLuaDebuggerProcess;

private:
    DECLARE_EVENT_TABLE();
    DECLARE_ABSTRACT_CLASS(wxLuaDebuggerBase)
};

#define WXLUA_DEBUGGER_USE_C_SOCKET
#ifdef WXLUA_DEBUGGER_USE_C_SOCKET

// ----------------------------------------------------------------------------
// wxLuaDebuggerCServer - a socket server for a Lua program to communicate with a
//                        wxLuaDebugTarget run in C++.
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_WXLUADEBUGGER wxLuaDebuggerCServer : public wxLuaDebuggerBase
{
protected:
    // ----------------------------------------------------------------------------
    // wxLuaDebuggerCServer::LuaThread - a wxThread for the wxLuaDebuggerCServer
    // ----------------------------------------------------------------------------
    class LuaThread : public wxThread
    {
        public:
            LuaThread(wxLuaDebuggerCServer *pServer) : wxThread(wxTHREAD_JOINABLE),
                                                       m_pServer(pServer) {}

            virtual void *Entry();   // thread execution starts here
            virtual void OnExit();   // called when the thread exits

            wxLuaDebuggerCServer *m_pServer;
    };

public:
    wxLuaDebuggerCServer(int port_number);
    virtual ~wxLuaDebuggerCServer();

    // Start the debugger server to listen for a debuggee. After creation
    //  you must call StartServer to actually start the server. returns success
    virtual bool StartServer();
    // Stop the debugger server, returns success
    virtual bool StopServer();
    // Start a debuggee client to be debugged by this, returns process ID
    //   is > 0 on success.
    virtual long StartClient();

    virtual wxLuaSocketBase* GetSocketBase() { return m_acceptedSocket; }

    virtual wxString GetSocketErrorMsg();

    // implementation

    // The thread function for the running LuaThread, only to be called by the
    //   thread.
    void ThreadFunction();

    bool WaitForConnect(int timeOut);

    wxLuaSocket*                     m_serverSocket;
    wxLuaSocket*                     m_acceptedSocket;
    wxLuaDebuggerCServer::LuaThread* m_pThread;
    bool                             m_shutdown;

private:
    DECLARE_ABSTRACT_CLASS(wxLuaDebuggerCServer)
};

typedef wxLuaDebuggerCServer wxLuaDebuggerServer;

#else // !WXLUA_DEBUGGER_USE_C_SOCKET

// ----------------------------------------------------------------------------
// wxLuaDebuggerwxServer - a socket server for a Lua program to communicate with a
//                    wxLuaDebugTarget run in C++.
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_WXLUADEBUGGER wxLuaDebuggerwxSocketServer : public wxLuaDebuggerBase
{
public:
    wxLuaDebuggerwxSocketServer(int port_number);
    virtual ~wxLuaDebuggerwxSocketServer();

    // Start the debugger server to listen for a debuggee. After creation
    //  you must call StartServer to actually start the server. returns success
    virtual bool StartServer();
    // Stop the debugger server, returns success
    virtual bool StopServer();
    // Start a debuggee client to be debugged by this, returns success
    virtual long StartClient();

    virtual wxLuaSocketBase* GetSocketBase() { return m_acceptedSocket; }

    virtual wxString GetSocketErrorMsg();

    // implementation

    virtual void SendEvent(wxEvent& event) { ProcessEvent(event); }

    void OnServerEvent(wxSocketEvent& event);
    void OnSocketEvent(wxSocketEvent& event);

protected:
    wxSocketServer *m_serverSocket;
    wxLuawxSocket  *m_acceptedSocket;

private:
    DECLARE_EVENT_TABLE();
    DECLARE_ABSTRACT_CLASS(wxLuaDebuggerwxSocketServer)
};

typedef wxLuaDebuggerwxSocketServer wxLuaDebuggerServer;

#endif // WXLUA_DEBUGGER_USE_C_SOCKET

// ----------------------------------------------------------------------------
// wxLuaDebuggerEvent - wxEvent sent from the wxLuaDebuggerXXX to notify when
// the debuggee has taken action or status of the debugger.
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_WXLUADEBUGGER wxLuaDebuggerEvent : public wxEvent
{
public:
    wxLuaDebuggerEvent(const wxLuaDebuggerEvent& event);
    wxLuaDebuggerEvent(wxEventType eventType = wxEVT_NULL,
                       wxObject* eventObject = NULL,
                       int lineNumber = 0,
                       const wxString &fileName = wxEmptyString,
                       bool enabledFlag = false);

    void SetMessage(const wxString &message);
    void SetDebugData(long nReference, const wxLuaDebugData& pDebugData = wxNullLuaDebugData);

    int      GetLineNumber() const      { return m_line_number;}
    wxString GetFileName() const        { return m_fileName; }
    wxString GetMessage() const         { return m_strMessage; } // check HasMessage
    bool     HasMessage() const         { return m_has_message; }
    long     GetReference() const       { return m_lua_ref; }    // Lua reference
    wxLuaDebugData GetDebugData() const { return m_debugData; }
    bool     GetEnabledFlag() const     { return m_enabled_flag; }

protected:
    virtual wxEvent* Clone() const      { return new wxLuaDebuggerEvent(*this); }

    int            m_line_number;
    wxString       m_fileName;
    wxString       m_strMessage;
    bool           m_has_message;
    long           m_lua_ref;
    wxLuaDebugData m_debugData;
    bool           m_enabled_flag;

private:
    DECLARE_DYNAMIC_CLASS(wxLuaDebuggerEvent)
};

typedef void (wxEvtHandler::*wxLuaDebuggerEventFunction)(wxLuaDebuggerEvent&);

BEGIN_DECLARE_EVENT_TYPES()
    // The debuggee has connected to the debugger through the socket connection
    DECLARE_EXPORTED_EVENT_TYPE(WXDLLIMPEXP_WXLUADEBUGGER, wxEVT_WXLUA_DEBUGGER_DEBUGGEE_CONNECTED,    2510)
    // The debuggee has disconnected to the debugger through the socket connection
    //  check Has/GetMessage for a description why
    DECLARE_EXPORTED_EVENT_TYPE(WXDLLIMPEXP_WXLUADEBUGGER, wxEVT_WXLUA_DEBUGGER_DEBUGGEE_DISCONNECTED, 2510)
    // The debuggee has sent a wxLUA_DEBUGGEE_EVENT_BREAK
    DECLARE_EXPORTED_EVENT_TYPE(WXDLLIMPEXP_WXLUADEBUGGER, wxEVT_WXLUA_DEBUGGER_BREAK,                 2511)
    // The debuggee has sent a wxLUA_DEBUGGEE_EVENT_PRINT
    DECLARE_EXPORTED_EVENT_TYPE(WXDLLIMPEXP_WXLUADEBUGGER, wxEVT_WXLUA_DEBUGGER_PRINT,                 2512)
    // The debuggee has sent a wxEVT_WXLUA_DEBUGGER_ERROR
    DECLARE_EXPORTED_EVENT_TYPE(WXDLLIMPEXP_WXLUADEBUGGER, wxEVT_WXLUA_DEBUGGER_ERROR,                 2513)
    // The debuggee has sent a wxEVT_WXLUA_DEBUGGER_EXIT
    DECLARE_EXPORTED_EVENT_TYPE(WXDLLIMPEXP_WXLUADEBUGGER, wxEVT_WXLUA_DEBUGGER_EXIT,                  2514)
    // The debuggee has sent a wxLUA_DEBUGGEE_EVENT_STACK_ENUM
    DECLARE_EXPORTED_EVENT_TYPE(WXDLLIMPEXP_WXLUADEBUGGER, wxEVT_WXLUA_DEBUGGER_STACK_ENUM,            2515)
    // The debuggee has sent a wxLUA_DEBUGGEE_EVENT_STACK_ENTRY_ENUM
    DECLARE_EXPORTED_EVENT_TYPE(WXDLLIMPEXP_WXLUADEBUGGER, wxEVT_WXLUA_DEBUGGER_STACK_ENTRY_ENUM,      2516)
    // The debuggee has sent a wxLUA_DEBUGGEE_EVENT_TABLE_ENUM
    DECLARE_EXPORTED_EVENT_TYPE(WXDLLIMPEXP_WXLUADEBUGGER, wxEVT_WXLUA_DEBUGGER_TABLE_ENUM,            2517)
    // The debuggee has sent a wxLUA_DEBUGGEE_EVENT_EVALUATE_EXPR
    DECLARE_EXPORTED_EVENT_TYPE(WXDLLIMPEXP_WXLUADEBUGGER, wxEVT_WXLUA_DEBUGGER_EVALUATE_EXPR,         2518)

    //DECLARE_EXPORTED_EVENT_TYPE(WXDLLIMPEXP_WXLUADEBUGGER, wxEVT_WXLUA_DEBUGGER_STARTDEBUGGER,         2519)
    //DECLARE_EXPORTED_EVENT_TYPE(WXDLLIMPEXP_WXLUADEBUGGER, wxEVT_WXLUA_DEBUGGER_STOPDEBUGGER,          2520)
END_DECLARE_EVENT_TYPES()

#define wxLuaDebuggerEventHandler(func) \
    (wxObjectEventFunction)(wxEventFunction)wxStaticCastEvent(wxLuaDebuggerEventFunction, &func)

#define EVT_WXLUA_DEBUGGER_DEBUGGEE_CONNECTED(id, fn) DECLARE_EVENT_TABLE_ENTRY(wxEVT_WXLUA_DEBUGGER_DEBUGGEE_CONNECTED,  id, -1, wxLuaDebuggerEventHandler(fn), (wxObject *) NULL),
#define EVT_WXLUA_DEBUGGER_DEBUGGEE_DISCONNECTED(id, fn) DECLARE_EVENT_TABLE_ENTRY(wxEVT_WXLUA_DEBUGGER_DEBUGGEE_DISCONNECTED,  id, -1, wxLuaDebuggerEventHandler(fn), (wxObject *) NULL),
#define EVT_WXLUA_DEBUGGER_BREAK(id, fn)              DECLARE_EVENT_TABLE_ENTRY(wxEVT_WXLUA_DEBUGGER_BREAK,               id, -1, wxLuaDebuggerEventHandler(fn), (wxObject *) NULL),
#define EVT_WXLUA_DEBUGGER_PRINT(id, fn)              DECLARE_EVENT_TABLE_ENTRY(wxEVT_WXLUA_DEBUGGER_PRINT,               id, -1, wxLuaDebuggerEventHandler(fn), (wxObject *) NULL),
#define EVT_WXLUA_DEBUGGER_ERROR(id, fn)              DECLARE_EVENT_TABLE_ENTRY(wxEVT_WXLUA_DEBUGGER_ERROR,               id, -1, wxLuaDebuggerEventHandler(fn), (wxObject *) NULL),
#define EVT_WXLUA_DEBUGGER_EXIT(id, fn)               DECLARE_EVENT_TABLE_ENTRY(wxEVT_WXLUA_DEBUGGER_EXIT,                id, -1, wxLuaDebuggerEventHandler(fn), (wxObject *) NULL),
#define EVT_WXLUA_DEBUGGER_STACK_ENUM(id, fn)         DECLARE_EVENT_TABLE_ENTRY(wxEVT_WXLUA_DEBUGGER_STACK_ENUM,          id, -1, wxLuaDebuggerEventHandler(fn), (wxObject *) NULL),
#define EVT_WXLUA_DEBUGGER_STACK_ENTRY_ENUM(id, fn)   DECLARE_EVENT_TABLE_ENTRY(wxEVT_WXLUA_DEBUGGER_STACK_ENTRY_ENUM,    id, -1, wxLuaDebuggerEventHandler(fn), (wxObject *) NULL),
#define EVT_WXLUA_DEBUGGER_TABLE_ENUM(id, fn)         DECLARE_EVENT_TABLE_ENTRY(wxEVT_WXLUA_DEBUGGER_TABLE_ENUM,          id, -1, wxLuaDebuggerEventHandler(fn), (wxObject *) NULL),
#define EVT_WXLUA_DEBUGGER_EVALUATE_EXPR(id, fn)      DECLARE_EVENT_TABLE_ENTRY(wxEVT_WXLUA_DEBUGGER_EVALUATE_EXPR,       id, -1, wxLuaDebuggerEventHandler(fn), (wxObject *) NULL),
//#define EVT_WXLUA_DEBUGGER_STARTDEBUGGER(id, fn)      DECLARE_EVENT_TABLE_ENTRY(wxEVT_WXLUA_DEBUGGER_STARTDEBUGGER,       id, -1, wxLuaDebuggerEventHandler(fn), (wxObject *) NULL),
//#define EVT_WXLUA_DEBUGGER_STOPDEBUGGER(id, fn)       DECLARE_EVENT_TABLE_ENTRY(wxEVT_WXLUA_DEBUGGER_STOPDEBUGGER,        id, -1, wxLuaDebuggerEventHandler(fn), (wxObject *) NULL),

#endif // WX_LUA_DEBUG_SERVER_H
