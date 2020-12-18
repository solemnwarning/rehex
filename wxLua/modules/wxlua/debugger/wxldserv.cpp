/////////////////////////////////////////////////////////////////////////////
// Name:        wxldserv.cpp
// Purpose:     Provide remote debugging support for wxLua.
// Author:      J. Winwood, John Labenski, Ray Gilbert
// Created:     May 2002.
// Copyright:   (c) 2012 John Labenski, 2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include "wx/wx.h"
#endif

#include "wx/thread.h"
#include "wxlua/debugger/wxldserv.h"
#include "wxlua/debug/wxlstack.h"

#if !wxCHECK_VERSION(2, 6, 0)
    #define wxMilliSleep wxUsleep
#endif // !wxCHECK_VERSION(2, 6, 0)

// ----------------------------------------------------------------------------
// wxLuaDebuggerEvent
// ----------------------------------------------------------------------------

DEFINE_EVENT_TYPE(wxEVT_WXLUA_DEBUGGER_DEBUGGEE_CONNECTED)
DEFINE_EVENT_TYPE(wxEVT_WXLUA_DEBUGGER_DEBUGGEE_DISCONNECTED)
DEFINE_EVENT_TYPE(wxEVT_WXLUA_DEBUGGER_BREAK)
DEFINE_EVENT_TYPE(wxEVT_WXLUA_DEBUGGER_PRINT)
DEFINE_EVENT_TYPE(wxEVT_WXLUA_DEBUGGER_ERROR)
DEFINE_EVENT_TYPE(wxEVT_WXLUA_DEBUGGER_EXIT)
DEFINE_EVENT_TYPE(wxEVT_WXLUA_DEBUGGER_STACK_ENUM)
DEFINE_EVENT_TYPE(wxEVT_WXLUA_DEBUGGER_STACK_ENTRY_ENUM)
DEFINE_EVENT_TYPE(wxEVT_WXLUA_DEBUGGER_TABLE_ENUM)
DEFINE_EVENT_TYPE(wxEVT_WXLUA_DEBUGGER_EVALUATE_EXPR)
//DEFINE_EVENT_TYPE(wxEVT_WXLUA_DEBUGGER_STARTDEBUGGER)
//DEFINE_EVENT_TYPE(wxEVT_WXLUA_DEBUGGER_STOPDEBUGGER)

IMPLEMENT_DYNAMIC_CLASS(wxLuaDebuggerEvent, wxEvent)

wxLuaDebuggerEvent::wxLuaDebuggerEvent(const wxLuaDebuggerEvent& event)
                   :wxEvent(event),
                    m_line_number(event.m_line_number),
                    m_fileName(event.m_fileName),
                    m_strMessage(event.m_strMessage),
                    m_has_message(event.m_has_message),
                    m_lua_ref(event.m_lua_ref),
                    m_debugData(event.m_debugData),
                    m_enabled_flag(event.m_enabled_flag)
{
}

wxLuaDebuggerEvent::wxLuaDebuggerEvent(wxEventType eventType,
                                       wxObject* eventObject,
                                       int line_number,
                                       const wxString &file, bool enabled_flag)
                   :wxEvent(0, eventType),
                    m_line_number(line_number),
                    m_fileName(file),
                    m_has_message(false),
                    m_lua_ref(-1),
                    m_debugData(wxNullLuaDebugData),
                    m_enabled_flag(enabled_flag)
{
    SetEventObject(eventObject);
}

void wxLuaDebuggerEvent::SetMessage(const wxString& message)
{
    m_strMessage  = message;
    m_has_message = true;
}

void wxLuaDebuggerEvent::SetDebugData(long nReference, const wxLuaDebugData& debugData)
{
    m_lua_ref   = nReference;
    m_debugData = debugData;
}

// ----------------------------------------------------------------------------
// wxLuaDebuggerStackDialog
// ----------------------------------------------------------------------------
IMPLEMENT_ABSTRACT_CLASS(wxLuaDebuggerStackDialog, wxLuaStackDialog)

wxLuaDebuggerStackDialog::wxLuaDebuggerStackDialog(wxLuaDebuggerBase* luaDebugger,
                                                   wxWindow* parent, wxWindowID id,
                                                   const wxString& title,
                                                   const wxPoint& pos, const wxSize& size)
                         : m_luaDebugger(luaDebugger)
{
    wxCHECK_RET(m_luaDebugger != NULL, wxT("Invalid wxLuaDebuggerBase in wxLuaDebuggerStackDialog"));
    // use delayed creation to allow our virtual functions to work
    Create(wxNullLuaState, parent, id, title, pos, size);
}

wxLuaDebuggerStackDialog::~wxLuaDebuggerStackDialog()
{
    if (m_luaDebugger != NULL)
        m_luaDebugger->ClearDebugReferences();
}

void wxLuaDebuggerStackDialog::EnumerateStack()
{
    wxCHECK_RET(m_luaDebugger, wxT("Invalid wxLuaDebuggerServer"));
    wxBeginBusyCursor(); // ended in wxLuaDebuggerBase::OnDebugXXX
    m_luaDebugger->EnumerateStack();
}

void wxLuaDebuggerStackDialog::EnumerateStackEntry(int nEntry)
{
    wxCHECK_RET(m_luaDebugger, wxT("Invalid wxLuaDebuggerServer"));
    wxBeginBusyCursor(); // ended in wxLuaDebuggerBase::OnDebugXXX
    m_luaDebugger->EnumerateStackEntry(nEntry);
}

void wxLuaDebuggerStackDialog::EnumerateTable(int nRef, int nEntry, long lc_item)
{
    wxCHECK_RET(m_luaDebugger, wxT("Invalid wxLuaDebuggerServer"));
    wxBeginBusyCursor(); // ended in wxLuaDebuggerBase::OnDebugXXX
    m_luaDebugger->EnumerateTable(nRef, nEntry, lc_item);
}

// ----------------------------------------------------------------------------
// wxLuaDebuggerProcess
// ----------------------------------------------------------------------------

void wxLuaDebuggerProcess::OnTerminate(int pid, int status)
{
    // If this is being deleted from the destructor of wxLuaDebuggerBase
    //   it has already been NULLed so don't send event.
    if (m_debugger && m_debugger->m_debuggeeProcess)
    {
        // we don't use the event handler, but this is good enough.
        wxProcessEvent event(m_id, pid, status);
        m_debugger->OnEndDebugeeProcess(event);

        m_debugger->m_debuggeeProcess = NULL;
        m_debugger->m_debuggeeProcessID = -1;
    }

    delete this;
}

// ----------------------------------------------------------------------------
// wxLuaDebuggerBase
// ----------------------------------------------------------------------------

IMPLEMENT_ABSTRACT_CLASS(wxLuaDebuggerBase, wxEvtHandler)

wxString wxLuaDebuggerBase::sm_programName;
wxString wxLuaDebuggerBase::sm_networkName;

BEGIN_EVENT_TABLE(wxLuaDebuggerBase, wxEvtHandler)
    EVT_WXLUA_DEBUGGER_STACK_ENUM(       wxID_ANY, wxLuaDebuggerBase::OnDebugStackEnum)
    EVT_WXLUA_DEBUGGER_STACK_ENTRY_ENUM( wxID_ANY, wxLuaDebuggerBase::OnDebugStackEntryEnum)
    EVT_WXLUA_DEBUGGER_TABLE_ENUM(       wxID_ANY, wxLuaDebuggerBase::OnDebugTableEnum)

    //EVT_END_PROCESS(ID_WXLUA_DEBUGGEE_PROCESS, wxLuaDebuggerBase::OnEndDebugeeProcess)
END_EVENT_TABLE()

wxLuaDebuggerBase::wxLuaDebuggerBase(int port_number)
                  :wxEvtHandler(), m_port_number(port_number),
                   m_stackDialog(NULL),
                   m_debuggeeProcess(NULL), m_debuggeeProcessID(-1)
{
    // Initialize the debuggee program name if not already set
    if (sm_programName.IsEmpty())
        sm_programName = wxTheApp->argv[0];

    // Initialize the debuggee network name if not already set
    if (sm_networkName.IsEmpty())
    {
#ifdef __WXMSW__
        sm_networkName = wxGetHostName();
#else
        sm_networkName = wxT("localhost");
#endif // __WXMSW__
    }
}

wxLuaDebuggerBase::~wxLuaDebuggerBase()
{
    //wxPrintf(wxT("~wxLuaDebuggerBase the m_debuggeeProcess %p %d exists %d\n"), m_debuggeeProcess, m_debuggeeProcessID, wxProcess::Exists(m_debuggeeProcessID)); fflush(stdout);

    // we don't delete the the process, we kill it and its OnTerminate deletes it
    if ((m_debuggeeProcess != NULL) && (m_debuggeeProcessID > 0) &&
         wxProcess::Exists(m_debuggeeProcessID))
    {
        m_debuggeeProcess->m_debugger = NULL;
        m_debuggeeProcess = NULL;
        wxProcess::Kill(m_debuggeeProcessID, wxSIGKILL, wxKILL_CHILDREN);
    }
}

long wxLuaDebuggerBase::StartClient()
{
    if (m_debuggeeProcess == NULL)
    {
        m_debuggeeProcess = new wxLuaDebuggerProcess(this, ID_WXLUA_DEBUGGEE_PROCESS);
        wxString command = wxString::Format(wxT("%s -d%s:%u"),
                                            GetProgramName().c_str(),
                                            GetNetworkName().c_str(),
                                            m_port_number);

        m_debuggeeProcessID = wxExecute(command, wxEXEC_ASYNC|wxEXEC_MAKE_GROUP_LEADER, m_debuggeeProcess);

        if (m_debuggeeProcessID < 1)
            KillDebuggee();
    }

    return m_debuggeeProcessID;
}

bool wxLuaDebuggerBase::AddBreakPoint(const wxString &fileName, int lineNumber)
{
    return CheckSocketConnected(true, wxT("Debugger AddBreakPoint")) && CheckSocketWrite(
           GetSocketBase()->WriteCmd(wxLUA_DEBUGGER_CMD_ADD_BREAKPOINT) &&
           GetSocketBase()->WriteString(fileName) &&
           GetSocketBase()->WriteInt32(lineNumber),
           wxT("Debugger AddBreakPoint"));
}

bool wxLuaDebuggerBase::RemoveBreakPoint(const wxString &fileName, int lineNumber)
{
    return CheckSocketConnected(true, wxT("Debugger RemoveBreakPoint")) && CheckSocketWrite(
           GetSocketBase()->WriteCmd(wxLUA_DEBUGGER_CMD_REMOVE_BREAKPOINT) &&
           GetSocketBase()->WriteString(fileName) &&
           GetSocketBase()->WriteInt32(lineNumber),
           wxT("Debugger RemoveBreakPoint"));
}

bool wxLuaDebuggerBase::DisableBreakPoint(const wxString &fileName, int lineNumber)
{
    return CheckSocketConnected(true, wxT("Debugger DisableBreakPoint")) && CheckSocketWrite(
           GetSocketBase()->WriteCmd(wxLUA_DEBUGGER_CMD_DISABLE_BREAKPOINT) &&
           GetSocketBase()->WriteString(fileName) &&
           GetSocketBase()->WriteInt32(lineNumber),
           wxT("Debugger DisableBreakPoint"));
}

bool wxLuaDebuggerBase::EnableBreakPoint(const wxString &fileName, int lineNumber)
{
    return CheckSocketConnected(true, wxT("Debugger EnableBreakPoint")) && CheckSocketWrite(
           GetSocketBase()->WriteCmd(wxLUA_DEBUGGER_CMD_ENABLE_BREAKPOINT) &&
           GetSocketBase()->WriteString(fileName) &&
           GetSocketBase()->WriteInt32(lineNumber),
           wxT("Debugger EnableBreakPoint"));
}

bool wxLuaDebuggerBase::ClearAllBreakPoints()
{
    return CheckSocketConnected(true, wxT("Debugger ClearAllBreakPoints")) && CheckSocketWrite(
           GetSocketBase()->WriteCmd(wxLUA_DEBUGGER_CMD_CLEAR_ALL_BREAKPOINTS),
           wxT("Debugger ClearAllBreakPoints"));
}

bool wxLuaDebuggerBase::Run(const wxString &fileName, const wxString &buffer)
{
    return CheckSocketConnected(true, wxT("Debugger Run")) && CheckSocketWrite(
           GetSocketBase()->WriteCmd(wxLUA_DEBUGGER_CMD_RUN_BUFFER) &&
           GetSocketBase()->WriteString(fileName) &&
           GetSocketBase()->WriteString(buffer),
           wxT("Debugger Run"));
}

bool wxLuaDebuggerBase::Step()
{
    return CheckSocketConnected(true, wxT("Debugger Step")) && CheckSocketWrite(
           GetSocketBase()->WriteCmd(wxLUA_DEBUGGER_CMD_DEBUG_STEP),
           wxT("Debugger Step"));
}

bool wxLuaDebuggerBase::StepOver()
{
    return CheckSocketConnected(true, wxT("Debugger StepOver")) && CheckSocketWrite(
           GetSocketBase()->WriteCmd(wxLUA_DEBUGGER_CMD_DEBUG_STEPOVER),
           wxT("Debugger StepOver"));
}

bool wxLuaDebuggerBase::StepOut()
{
    return CheckSocketConnected(true, wxT("Debugger StepOut")) && CheckSocketWrite(
           GetSocketBase()->WriteCmd(wxLUA_DEBUGGER_CMD_DEBUG_STEPOUT),
           wxT("Debugger StepOut"));
}

bool wxLuaDebuggerBase::Continue()
{
    return CheckSocketConnected(true, wxT("Debugger Continue")) && CheckSocketWrite(
           GetSocketBase()->WriteCmd(wxLUA_DEBUGGER_CMD_DEBUG_CONTINUE),
           wxT("Debugger Continue"));
}

bool wxLuaDebuggerBase::Break()
{
    return CheckSocketConnected(true, wxT("Debugger Break")) && CheckSocketWrite(
           GetSocketBase()->WriteCmd(wxLUA_DEBUGGER_CMD_DEBUG_BREAK),
           wxT("Debugger Break"));
}

bool wxLuaDebuggerBase::Reset()
{
    return CheckSocketConnected(true, wxT("Debugger Reset")) && CheckSocketWrite(
           GetSocketBase()->WriteCmd(wxLUA_DEBUGGER_CMD_RESET),
           wxT("Debugger Reset"));
}

bool wxLuaDebuggerBase::EnumerateStack()
{
    return CheckSocketConnected(true, wxT("Debugger EnumerateStack")) && CheckSocketWrite(
           GetSocketBase()->WriteCmd(wxLUA_DEBUGGER_CMD_ENUMERATE_STACK),
           wxT("Debugger EnumerateStack"));
}

bool wxLuaDebuggerBase::EnumerateStackEntry(int stackEntry)
{
    return CheckSocketConnected(true, wxT("Debugger EnumerateStackEntry")) && CheckSocketWrite(
           GetSocketBase()->WriteCmd(wxLUA_DEBUGGER_CMD_ENUMERATE_STACK_ENTRY) &&
           GetSocketBase()->WriteInt32(stackEntry),
           wxT("Debugger EnumerateStackEntry"));
}

bool wxLuaDebuggerBase::EnumerateTable(int tableRef, int nIndex, long nItemNode)
{
    return CheckSocketConnected(true, wxT("Debugger EnumerateTable")) && CheckSocketWrite(
           GetSocketBase()->WriteCmd(wxLUA_DEBUGGER_CMD_ENUMERATE_TABLE_REF) &&
           GetSocketBase()->WriteInt32(tableRef) &&
           GetSocketBase()->WriteInt32(nIndex) &&
           GetSocketBase()->WriteLong(nItemNode),
           wxT("Debugger EnumerateTable"));
}

bool wxLuaDebuggerBase::ClearDebugReferences()
{
    return CheckSocketConnected(true, wxT("Debugger ClearDebugReferences")) && CheckSocketWrite(
           GetSocketBase()->WriteCmd(wxLUA_DEBUGGER_CMD_CLEAR_DEBUG_REFERENCES),
           wxT("Debugger ClearDebugReferences"));
}

bool wxLuaDebuggerBase::EvaluateExpr(int exprRef, const wxString &strExpression)
{
    return CheckSocketConnected(true, wxT("Debugger EvaluateExpr")) && CheckSocketWrite(
           GetSocketBase()->WriteCmd(wxLUA_DEBUGGER_CMD_EVALUATE_EXPR) &&
           GetSocketBase()->WriteInt32(exprRef) &&
           GetSocketBase()->WriteString(strExpression),
           wxT("Debugger EvaluateExpr"));
}

//extern wxString wxLuaSocketCmdEventMsg(int val);

// This function shouldn't modify any internal variables without using a
// critical section since the wxLuaDebuggerCServer calls it from the thread.
int wxLuaDebuggerBase::HandleDebuggeeEvent(int event_type)
{
    wxCHECK_MSG(GetSocketBase(), event_type, wxT("Invalid socket"));

    //wxLuaDebuggerEvent d(wxEVT_WXLUA_DEBUGGER_PRINT, this);
    //d.SetMessage(wxT("wxLuaDebugger : ") + wxLuaSocketCmdEventMsg(event_type));
    //SendEvent(d);

    switch (event_type)
    {
        case wxLUA_DEBUGGEE_EVENT_BREAK:
        {
            wxString fileName;
            wxInt32  lineNumber = 0;

            if (CheckSocketRead(
                GetSocketBase()->ReadString(fileName) &&
                GetSocketBase()->ReadInt32(lineNumber),
                wxT("Debugger wxLUA_DEBUGGEE_EVENT_BREAK")))
            {
                wxLuaDebuggerEvent debugEvent(wxEVT_WXLUA_DEBUGGER_BREAK, this, lineNumber, fileName);
                SendEvent(debugEvent);
            }
            else return -1;

            break;
        }
        case wxLUA_DEBUGGEE_EVENT_PRINT:
        {
            wxString strMessage;

            if (CheckSocketRead(
                GetSocketBase()->ReadString(strMessage),
                wxT("Debugger wxLUA_DEBUGGEE_EVENT_PRINT")))
            {
                wxLuaDebuggerEvent debugEvent(wxEVT_WXLUA_DEBUGGER_PRINT, this);
                debugEvent.SetMessage(strMessage);
                SendEvent(debugEvent);
            }
            else return -1;

            break;
        }
        case wxLUA_DEBUGGEE_EVENT_ERROR:
        {
            wxString strMessage;

            if (CheckSocketRead(
                GetSocketBase()->ReadString(strMessage),
                wxT("Debugger wxLUA_DEBUGGEE_EVENT_ERROR")))
            {
                wxLuaDebuggerEvent debugEvent(wxEVT_WXLUA_DEBUGGER_ERROR, this);
                debugEvent.SetMessage(strMessage);
                SendEvent(debugEvent);
            }
            else return -1;

            break;
        }
        case wxLUA_DEBUGGEE_EVENT_EXIT:
        {
            wxLuaDebuggerEvent debugEvent(wxEVT_WXLUA_DEBUGGER_EXIT, this);
            wxPostEvent(this, debugEvent);
            break;
        }
        case wxLUA_DEBUGGEE_EVENT_STACK_ENUM:
        {
            wxLuaDebugData debugData(true);

            if (CheckSocketRead(
                GetSocketBase()->ReadDebugData(debugData),
                wxT("Debugger wxLUA_DEBUGGEE_EVENT_STACK_ENUM")))
            {
                wxLuaDebuggerEvent debugEvent(wxEVT_WXLUA_DEBUGGER_STACK_ENUM, this);
                debugEvent.SetDebugData(-1, debugData);
                SendEvent(debugEvent);
            }
            else return -1;

            break;
        }
        case wxLUA_DEBUGGEE_EVENT_STACK_ENTRY_ENUM:
        {
            wxInt32 stackRef = 0;
            wxLuaDebugData debugData(true);

            if (CheckSocketRead(
                GetSocketBase()->ReadInt32(stackRef) &&
                GetSocketBase()->ReadDebugData(debugData),
                wxT("Debugger wxLUA_DEBUGGEE_EVENT_STACK_ENTRY_ENUM")))
            {
                wxLuaDebuggerEvent debugEvent(wxEVT_WXLUA_DEBUGGER_STACK_ENTRY_ENUM, this);
                debugEvent.SetDebugData(stackRef, debugData);
                SendEvent(debugEvent);
            }
            else return -1;

            break;
        }
        case wxLUA_DEBUGGEE_EVENT_TABLE_ENUM:
        {
            long itemNode = 0;
            wxLuaDebugData debugData(true);

            if (CheckSocketRead(
                GetSocketBase()->ReadLong(itemNode) &&
                GetSocketBase()->ReadDebugData(debugData),
                wxT("Debugger wxLUA_DEBUGGEE_EVENT_TABLE_ENUM")))
            {
                wxLuaDebuggerEvent debugEvent(wxEVT_WXLUA_DEBUGGER_TABLE_ENUM, this);
                debugEvent.SetDebugData(itemNode, debugData);
                SendEvent(debugEvent);
            }
            else return -1;

            break;
        }
        case wxLUA_DEBUGGEE_EVENT_EVALUATE_EXPR:
        {
            wxInt32 exprRef = 0;
            wxString strResult;

            if (CheckSocketRead(
                GetSocketBase()->ReadInt32(exprRef) &&
                GetSocketBase()->ReadString(strResult),
                wxT("Debugger wxLUA_DEBUGGEE_EVENT_EVALUATE_EXPR")))
            {
                wxLuaDebuggerEvent debugEvent(wxEVT_WXLUA_DEBUGGER_EVALUATE_EXPR, this);
                debugEvent.SetMessage(strResult);
                debugEvent.SetDebugData(exprRef);
                SendEvent(debugEvent);
            }
            else return -1;

            break;
        }
        default : return -1; // don't know this event?
    }

    return event_type;
}


bool wxLuaDebuggerBase::CheckSocketConnected(bool send_event, const wxString& msg)
{
    if (GetSocketBase() == NULL)
    {
        if (send_event)
        {
            wxLuaDebuggerEvent debugEvent(wxEVT_WXLUA_DEBUGGER_DEBUGGEE_DISCONNECTED, this);
            debugEvent.SetMessage(wxT("Debugger socket not created. ") + msg);
            SendEvent(debugEvent);
        }

        return false;
    }
    else if (!GetSocketBase()->IsConnected())
    {
        if (send_event)
        {
            wxLuaDebuggerEvent debugEvent(wxEVT_WXLUA_DEBUGGER_DEBUGGEE_DISCONNECTED, this);
            debugEvent.SetMessage(wxT("Debugger socket not connected. ") + msg);
            SendEvent(debugEvent);
        }

        return false;
    }

    return true;
}
bool wxLuaDebuggerBase::CheckSocketRead(bool read_ok, const wxString& msg)
{
    if (!read_ok)
    {
        wxLuaDebuggerEvent debugEvent(wxEVT_WXLUA_DEBUGGER_DEBUGGEE_DISCONNECTED, this);
        debugEvent.SetMessage(wxString::Format(wxT("Failed reading from the debugger socket. %s %s\n"), msg.c_str(), GetSocketErrorMsg().c_str()));
        SendEvent(debugEvent);
    }

    return read_ok;
}
bool wxLuaDebuggerBase::CheckSocketWrite(bool write_ok, const wxString& msg)
{
    if (!write_ok)
    {
        wxLuaDebuggerEvent debugEvent(wxEVT_WXLUA_DEBUGGER_DEBUGGEE_DISCONNECTED, this);
        debugEvent.SetMessage(wxString::Format(wxT("Failed writing to the debugger socket. %s\n%s"), msg.c_str(), GetSocketErrorMsg().c_str()));
        SendEvent(debugEvent);
    }

    return write_ok;
}

bool wxLuaDebuggerBase::DisplayStackDialog(wxWindow *parent, wxWindowID winid)
{
    wxCHECK_MSG(m_stackDialog == NULL, false, wxT("Stack dialog already shown"));

    m_stackDialog = new wxLuaDebuggerStackDialog(this, parent, winid);
    m_stackDialog->ShowModal();
    m_stackDialog->Destroy();
    m_stackDialog = NULL;
    return true;
}

void wxLuaDebuggerBase::OnDebugStackEnum(wxLuaDebuggerEvent &event)
{
    if (GetStackDialog() != NULL)
        GetStackDialog()->FillStackCombobox(event.GetDebugData());
    else
        event.Skip();

    wxEndBusyCursor();
}
void wxLuaDebuggerBase::OnDebugStackEntryEnum(wxLuaDebuggerEvent &event)
{
    if (GetStackDialog() != NULL)
        GetStackDialog()->FillStackEntry(event.GetReference(), event.GetDebugData());
    else
        event.Skip();

    wxEndBusyCursor();
}
void wxLuaDebuggerBase::OnDebugTableEnum(wxLuaDebuggerEvent &event)
{
    if (GetStackDialog() != NULL)
        GetStackDialog()->FillTableEntry(event.GetReference(), event.GetDebugData());
    else
        event.Skip();

    wxEndBusyCursor();
}

void wxLuaDebuggerBase::OnEndDebugeeProcess(wxProcessEvent& event)
{
    //wxPrintf(wxT("OnEndDebugeeProcess the m_debuggeeProcess %p %d exists %d\n"), m_debuggeeProcess, m_debuggeeProcessID, wxProcess::Exists(m_debuggeeProcessID)); fflush(stdout);

    // The process's OnTerminate will null m_debuggeeProcess,
    // but if in destructor it's already NULL and don't send event.
    if (m_debuggeeProcess != NULL)
    {
        wxLuaDebuggerEvent debugEvent(wxEVT_WXLUA_DEBUGGER_EXIT, this);
        debugEvent.SetMessage(wxString::Format(wxT("Process (%d) ended with exit code : %d"), event.GetPid(), event.GetExitCode()));
        wxPostEvent(this, debugEvent);
    }

    event.Skip();
}

bool wxLuaDebuggerBase::KillDebuggee()
{
    //wxPrintf(wxT("KillDebuggee the m_debuggeeProcess %p %d exists %d\n"), m_debuggeeProcess, m_debuggeeProcessID, wxProcess::Exists(m_debuggeeProcessID)); fflush(stdout);

    if ((m_debuggeeProcess != NULL) && (m_debuggeeProcessID > 0))
    {
        m_debuggeeProcess->m_debugger = NULL;
        m_debuggeeProcess = NULL;

        //if (p->Exists(m_debuggeeProcessID)) should exist since OnTerminate hasn't been called
            wxProcess::Kill(m_debuggeeProcessID, wxSIGKILL, wxKILL_CHILDREN);
    }
    else if (m_debuggeeProcess != NULL) // error starting process?
    {
        wxLuaDebuggerProcess* p = m_debuggeeProcess;
        m_debuggeeProcess->m_debugger = NULL;
        m_debuggeeProcess = NULL;
        delete p;
    }

    m_debuggeeProcessID = -1;

    return true;
}

#ifdef WXLUA_DEBUGGER_USE_C_SOCKET

// ----------------------------------------------------------------------------
// wxLuaDebuggerCServer::LuaThread
// ----------------------------------------------------------------------------

void *wxLuaDebuggerCServer::LuaThread::Entry()
{
    m_pServer->ThreadFunction();
    return 0;
}

void wxLuaDebuggerCServer::LuaThread::OnExit()
{
#if !wxCHECK_VERSION(2,9,0)
    wxThread::OnExit(); // in 2.9 there is OnKill() and OnDelete()
    //m_pServer->m_pThread = NULL;
#endif
}

// ----------------------------------------------------------------------------
// wxLuaDebuggerCServer
// ----------------------------------------------------------------------------
IMPLEMENT_ABSTRACT_CLASS(wxLuaDebuggerCServer, wxLuaDebuggerBase)

wxLuaDebuggerCServer::wxLuaDebuggerCServer(int port_number)
                     :wxLuaDebuggerBase(port_number),
                      m_serverSocket(NULL), m_acceptedSocket(NULL),
                      m_pThread(NULL),
                      m_shutdown(false)
{
}

wxLuaDebuggerCServer::~wxLuaDebuggerCServer()
{
    StopServer();
}

bool wxLuaDebuggerCServer::StartServer()
{
    wxCHECK_MSG(m_serverSocket == NULL, false, wxT("Debugger server socket already created"));

    m_shutdown = false;
    m_serverSocket = new wxLuaCSocket();
    m_serverSocket->m_name = wxString::Format(wxT("wxLuaDebuggerCServer::m_serverSocket (%ld)"), (long)wxGetProcessId());

    if (m_serverSocket->Listen(m_port_number))
    {
        wxCHECK_MSG(m_pThread == NULL, false, wxT("Debugger server thread already created"));

        if (!m_shutdown)
        {
            m_pThread = new wxLuaDebuggerCServer::LuaThread(this);

            return ((m_pThread != NULL) &&
                    (m_pThread->Create() == wxTHREAD_NO_ERROR) &&
                    (m_pThread->Run()    == wxTHREAD_NO_ERROR));
        }
    }
    else
    {
        wxLuaDebuggerEvent debugEvent(wxEVT_WXLUA_DEBUGGER_ERROR, this);
        debugEvent.SetMessage(m_serverSocket->GetErrorMsg(true));
        AddPendingEvent(debugEvent);

        delete m_serverSocket;
        m_serverSocket = NULL;
        m_shutdown = true;
    }

    return false;
}

long wxLuaDebuggerCServer::StartClient()
{
    wxCHECK_MSG(m_serverSocket, false, wxT("Debugger server not started"));
    wxCHECK_MSG(m_pThread, false, wxT("Debugger server thread not running"));

    if (!m_shutdown)
        return wxLuaDebuggerBase::StartClient();

    return m_debuggeeProcessID;
}

bool wxLuaDebuggerCServer::StopServer()
{
    // NO checks, can always call stop server

    // Set the shutdown flag
    m_shutdown = true;

    // try to nicely stop the socket if it exists
    if (m_acceptedSocket)
    {
        Reset();
        wxMilliSleep(500);
    }

    // close the session socket, but first NULL it so we won't try to use it
    //m_acceptSockCritSect.Enter();
    wxLuaSocket *acceptedSocket = m_acceptedSocket;
    //m_acceptedSocket = NULL;
    //m_acceptSockCritSect.Leave();

    if (acceptedSocket != NULL)
    {
        if (!acceptedSocket->Shutdown(SD_BOTH))
        {
            wxLuaDebuggerEvent debugEvent(wxEVT_WXLUA_DEBUGGER_ERROR, this);
            debugEvent.SetMessage(acceptedSocket->GetErrorMsg(true));
            AddPendingEvent(debugEvent);
        }

        wxMilliSleep(500);
        //m_acceptedSocket = NULL;
        //delete acceptedSocket;
    }

    // close the server socket, if accepted socket created it will already
    // have been deleted
    if (m_serverSocket != NULL)
    {
        wxLuaSocket *serverSocket = m_serverSocket;
        m_serverSocket = NULL;

        // close the server socket by connecting to the socket, thus
        // completing the 'accept'. If a client has not connected, this
        // code will satisfy the accept the m_shutdown flag will be set
        // so the thread will not loop and instead will just destroy the
        // session socket object and return.
        wxLuaSocket closeSocket;
        closeSocket.m_name = wxString::Format(wxT("wxLuaDebuggerCServer closeSocket (%ld)"), (long)wxGetProcessId());

        if (!closeSocket.Connect(GetNetworkName(),  m_port_number) ||
            !closeSocket.Shutdown(SD_BOTH))
        {
            wxLuaDebuggerEvent debugEvent(wxEVT_WXLUA_DEBUGGER_ERROR, this);
            debugEvent.SetMessage(serverSocket->GetErrorMsg(true));
            AddPendingEvent(debugEvent);
        }

        wxMilliSleep(100);

        delete serverSocket;
    }

    // One of the above two operations terminates the thread. Wait for it to stop.
    if ((m_pThread != NULL) && m_pThread->IsRunning())
        m_pThread->Wait();

    delete m_pThread;
    m_pThread = NULL;

    return true;
}

void wxLuaDebuggerCServer::ThreadFunction()
{
    wxCHECK_RET(m_serverSocket, wxT("Invalid server socket"));
    wxCHECK_RET(m_acceptedSocket == NULL, wxT("The debugger server has already accepted a socket connection"));

    m_acceptedSocket = m_serverSocket->Accept();
    if (!m_acceptedSocket)
    {
        wxLuaDebuggerEvent debugEvent(wxEVT_WXLUA_DEBUGGER_ERROR, this);
        debugEvent.SetMessage(m_serverSocket->GetErrorMsg(true));
        AddPendingEvent(debugEvent);
    }
    else
    {
        m_acceptedSocket->m_name = wxString::Format(wxT("wxLuaDebuggerCServer::m_acceptedSocket (%ld)"), (long)wxGetProcessId());

        wxLuaSocket *serverSocket = m_serverSocket;
        m_serverSocket = NULL;
        delete serverSocket;

        wxThread::Sleep(500);  // why ??

        // Notify that a client has connected and we are ready to debug
        wxLuaDebuggerEvent debugEvent(wxEVT_WXLUA_DEBUGGER_DEBUGGEE_CONNECTED, this);
        AddPendingEvent(debugEvent);

        unsigned char debug_event = 0; // wxLuaDebuggeeEvents_Type

        // Enter the debug loop
        while (!m_pThread->TestDestroy() && !m_shutdown && m_acceptedSocket)
        {
            debug_event = wxLUA_DEBUGGEE_EVENT_EXIT;

            {
                // lock the critical section while we access it
                wxCriticalSectionLocker locker(m_acceptSockCritSect);
                if (m_shutdown || (m_acceptedSocket == NULL) || !m_acceptedSocket->ReadCmd(debug_event))
                {
                    m_shutdown = true;
                    break;
                }
            }

            if((debug_event == wxLUA_DEBUGGEE_EVENT_EXIT) ||
               (HandleDebuggeeEvent(debug_event) != -1))
            {
                // don't send exit event until we've closed the socket
                if (debug_event == wxLUA_DEBUGGEE_EVENT_EXIT)
                {
                    m_shutdown = true;
                    break;
                }
            }
        }

        wxCriticalSectionLocker locker(m_acceptSockCritSect);
        // delete the accepted socket
        if (m_acceptedSocket != NULL)
        {
            wxLuaSocket *acceptedSocket = m_acceptedSocket;
            m_acceptedSocket = NULL;
            delete acceptedSocket;
        }
    }

    // Send the exit event, now that everything is shut down
    //if (debug_event == wxLUA_DEBUGGEE_EVENT_EXIT)
    {
        wxLuaDebuggerEvent debugEvent(wxEVT_WXLUA_DEBUGGER_EXIT, this);
        wxPostEvent(this, debugEvent);
    }
}

wxString wxLuaDebuggerCServer::GetSocketErrorMsg()
{
    wxString s;

    if (m_serverSocket)
        s += m_serverSocket->GetErrorMsg(true);
    if (m_acceptedSocket)
        s += m_acceptedSocket->GetErrorMsg(true);

    return s;
}

#else // !WXLUA_DEBUGGER_USE_C_SOCKET

// ---------------------------------------------------------------------------
// wxLuaDebuggerwxSocketServer
// ---------------------------------------------------------------------------
IMPLEMENT_ABSTRACT_CLASS(wxLuaDebuggerwxSocketServer, wxLuaDebuggerBase)

BEGIN_EVENT_TABLE(wxLuaDebuggerwxSocketServer, wxLuaDebuggerBase)
  EVT_SOCKET(ID_WXLUA_SERVER,  wxLuaDebuggerwxSocketServer::OnServerEvent)
  EVT_SOCKET(ID_WXLUA_SOCKET,  wxLuaDebuggerwxSocketServer::OnSocketEvent)
END_EVENT_TABLE()


wxLuaDebuggerwxSocketServer::wxLuaDebuggerwxSocketServer(int port_number)
                            :wxLuaDebuggerBase(port_number),
                             m_serverSocket(NULL), m_acceptedSocket(NULL)
{
}

wxLuaDebuggerwxSocketServer::~wxLuaDebuggerwxSocketServer()
{
    StopServer();
}

// Start Debugging Service
bool wxLuaDebuggerwxSocketServer::StartServer()
{
    if (!m_serverSocket)
    {
        // Create the address - defaults to localhost:0 initially
        wxIPV4address addr;
        addr.Service(m_port_number);

        // Create the server socket
        m_serverSocket = new wxSocketServer(addr, wxSOCKET_NOWAIT|wxSOCKET_BLOCK);
        m_serverSocket->SetEventHandler(*this, ID_WXLUA_SERVER);
        m_serverSocket->SetNotify(wxSOCKET_CONNECTION_FLAG);
        m_serverSocket->SetFlags(wxSOCKET_BLOCK);
        m_serverSocket->Notify(true);
    }

    return m_serverSocket->Ok();
}

bool wxLuaDebuggerwxSocketServer::StopServer()
{
    if (m_acceptedSocket)
    {
        m_acceptedSocket->GetSocket()->Notify(false);
        m_acceptedSocket->Destroy();
        delete m_acceptedSocket;
        m_acceptedSocket = NULL;
    }

    if (m_serverSocket)
    {
        m_serverSocket->Notify(false);
        m_serverSocket->Destroy(); // this deletes it too
        m_serverSocket = NULL;
    }

    return true;
}

long wxLuaDebuggerwxSocketServer::StartClient()
{
    return wxLuaDebuggerBase::StartClient();
}

wxString wxLuaDebuggerwxSocketServer::GetSocketErrorMsg()
{
    wxString s;
    if (m_acceptedSocket)
        s += m_acceptedSocket->GetErrorMsg(true);

    return s;
}

void wxLuaDebuggerwxSocketServer::OnServerEvent(wxSocketEvent& event)
{
    switch(event.GetSocketEvent())
    {
        case wxSOCKET_CONNECTION:
        {
            wxSocketBase *sock = m_serverSocket->Accept(false);
            if (!sock)
            {
                // Error
                return;
            }

            sock->SetFlags(wxSOCKET_NOWAIT);
            m_acceptedSocket = new wxLuawxSocket(sock);
            m_acceptedSocket->m_port_number = m_port_number; // can't get it from wxSocketBase
            m_acceptedSocket->m_name = wxString::Format(wxT("wxLuaDebuggerwxSocketServer::m_acceptedSocket (%ld)"), (long)wxGetProcessId());

            // Setup Handler
            sock->SetEventHandler(*this, ID_WXLUA_SOCKET);
            sock->SetNotify(wxSOCKET_INPUT_FLAG | wxSOCKET_LOST_FLAG);
            sock->Notify(true);

            wxMilliSleep(500);

            // Notify that a client has connected and we are ready to debug
            wxLuaDebuggerEvent debugEvent(wxEVT_WXLUA_DEBUGGER_DEBUGGEE_CONNECTED, this);
            AddPendingEvent(debugEvent);

            break;
        }

        default:
            // Error
            break;
    }
}

// Handle Commands from debugger (and lost connections)
void wxLuaDebuggerwxSocketServer::OnSocketEvent(wxSocketEvent& event)
{
    wxSocketBase *sock = event.GetSocket();

    // Now we process the event
    switch(event.GetSocketEvent())
    {
        case wxSOCKET_INPUT:
        {
            // We disable input events, so that the test doesn't trigger
            // wxSocketEvent again.
            sock->SetNotify(wxSOCKET_LOST_FLAG);

            unsigned char debugEvent = 0; // wxLuaDebuggeeEvents_Type
            if (m_acceptedSocket->ReadCmd(debugEvent))
                HandleDebuggeeEvent(debugEvent);

            // Enable input events again.
            sock->SetNotify(wxSOCKET_LOST_FLAG | wxSOCKET_INPUT_FLAG);
            break;
        }
        case wxSOCKET_LOST:
        {
            m_acceptedSocket->Destroy();
            delete m_acceptedSocket;
            m_acceptedSocket = NULL;
            break;
        }
        default:
            // Error
            break;
    }
}

#endif // WXLUA_DEBUGGER_USE_C_SOCKET
