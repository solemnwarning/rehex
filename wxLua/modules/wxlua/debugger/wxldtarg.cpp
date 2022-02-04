/////////////////////////////////////////////////////////////////////////////
// Purpose:     Implements the client end of wxLua debugging session
// Author:      J. Winwood, John Labenski, Ray Gilbert
// Created:     May 2002
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

#include "wxlua/debugger/wxldtarg.h"
#include "wxlua/debugger/wxldserv.h"

#if !wxCHECK_VERSION(2, 6, 0)
    #define wxMilliSleep wxUsleep
#endif // !wxCHECK_VERSION(2, 6, 0)

#define WXLUASOCKET_CONNECT_TIMEOUT 200       // 20 seconds

// ----------------------------------------------------------------------------
// wxLuaDebugTarget::LuaThread
// ----------------------------------------------------------------------------

wxLuaDebugTarget::LuaThread::LuaThread(wxLuaDebugTarget *luaDebugTarget)
                 :wxThread(wxTHREAD_JOINABLE),
                  m_luaDebugTarget(luaDebugTarget)
{
}

wxLuaDebugTarget::LuaThread::~LuaThread()
{
    wxCriticalSectionLocker locker(m_luaDebugTarget->m_luaThreadCriticalSection);
    m_luaDebugTarget->m_luaThread = NULL;
}

void *wxLuaDebugTarget::LuaThread::Entry()
{
    m_luaDebugTarget->ThreadFunction();
    return 0;
}

// ----------------------------------------------------------------------------
// wxLuaDebugTarget - Handles Debugger/Debuggee IO
// ----------------------------------------------------------------------------

wxLuaDebugTarget::wxLuaDebugTarget(const wxLuaState& wxlState,
                                   const wxString& serverName, int port_number)
                 :wxObject(),
                  m_wxlState(wxlState),
                  m_luaThread(NULL),

                  m_port_number(port_number),
                  m_serverName(serverName),
                  m_socket_connected(false),

                  m_runCondition(m_runMutex),
                  m_debugCondition(m_debugMutex),

                  m_nextOperation(DEBUG_STEP),
                  m_force_break(false),
                  m_reset_requested(false),
                  m_is_running(false),
                  m_is_stopped(false),
                  m_is_exiting(false),
                  m_nframes_until_break(0)
{
    m_clientSocket.m_name = wxString::Format(wxT("wxLuaDebugTarget::m_clientSocket (%ld)"), (long)wxGetProcessId());

    lua_State* L = m_wxlState.GetLuaState();

    // Stick us into the lua_State - push key, value
    lua_pushstring( L, "__wxLuaDebugTarget__" );
    lua_pushlightuserdata( L, (void*)this );
    // set the value
    lua_rawset( L, LUA_REGISTRYINDEX );

    // Set all the debug hooks
    lua_sethook(L, LuaDebugHook, LUA_MASKCALL | LUA_MASKLINE | LUA_MASKRET, 0);

    // Catch the print statements to send to the debugger server
    lua_pushcfunction(L, LuaPrint);
    lua_setglobal(L, "print");

    EnterLuaCriticalSection();
}

wxLuaDebugTarget::~wxLuaDebugTarget()
{
    //if (m_luaThread != NULL)
    //    delete m_luaThread;

    LeaveLuaCriticalSection();
}

bool wxLuaDebugTarget::IsConnected(bool wait_for_connect) const
{
    if (m_socket_connected || !wait_for_connect) return m_socket_connected;

    // Wait to see if we've connected
    for (int idx = 0; idx < WXLUASOCKET_CONNECT_TIMEOUT; ++idx)
    {
        if (m_socket_connected)
            break;

        wxMilliSleep(100);
    }
    return m_socket_connected;
}

bool wxLuaDebugTarget::Run()
{
    wxCHECK_MSG(m_luaThread == NULL, false, wxT("wxLuaDebugTarget::Run already called"));

    // Assume something is going to go wrong
    bool ok = false;

    m_luaThread = new LuaThread(this);
    wxCHECK_MSG(m_luaThread != NULL, false, wxT("Unable to create LuaThread"));

    if ( m_luaThread->Create() != wxTHREAD_NO_ERROR )
    {
        wxLogError(wxT("Can't Create() the LuaThread!"));
        delete m_luaThread;
        m_luaThread = NULL;
        return false;
    }

    if ( m_luaThread->Run() != wxTHREAD_NO_ERROR )
    {
        wxLogError(wxT("Can't Run() the LuaThread!"));
        delete m_luaThread;
        m_luaThread = NULL;
        return false;
    }

    // Wait for the connection to the server to complete
    if (!IsConnected(true))
    {
        wxMessageBox(wxString::Format(wxT("The wxLuaDebugTarget is unable to connect to '%s:%d'"), m_serverName.wx_str(), m_port_number),
                     wxT("wxLua debuggee"), wxOK | wxCENTRE, NULL);
        return false;
    }

    // OK, now we can start running.
    m_runCondition.Wait();

    m_is_running = true;
    ok           = true;

    size_t idx, count = m_bufferArray.GetCount();

    for (idx = 0; idx < count; ++idx)
    {
        wxString luaBuffer   = m_bufferArray.Item(idx);
        wxString bufFilename = luaBuffer.BeforeFirst(wxT('\0'));
        wxString buf         = luaBuffer.AfterFirst(wxT('\0'));

        wxLuaCharBuffer char_buf(buf);
        int rc = m_wxlState.LuaDoBuffer(char_buf, char_buf.Length(),
                                        wx2lua(bufFilename));
        ok = (rc == 0);

        if (!ok)
        {
            NotifyError(wxlua_LUA_ERR_msg(rc));
            break;
        }
    }

    m_bufferArray.Clear();

    return ok;
}

void wxLuaDebugTarget::Stop()
{
    NotifyExit();

    if (m_socket_connected)
    {
        m_clientSocket.Shutdown(SD_BOTH);
        wxMilliSleep(100);
        m_clientSocket.Close();
    }

    wxCriticalSectionLocker locker(m_luaThreadCriticalSection);

    if (m_luaThread)
        m_luaThread->Wait();
}

void wxLuaDebugTarget::ThreadFunction()
{
    bool thread_running = false;

    if (m_clientSocket.Connect(m_serverName, m_port_number))
    {
        m_socket_connected = true;
        thread_running     = true;
    }
    else
    {
        wxLogError(wxString::Format(wxT("The wxLuaDebugTarget is unable to connect to '%s:%d'"), m_serverName.wx_str(), m_port_number));
        return; // FIXME
    }

    while (thread_running && !m_reset_requested && !m_is_exiting)
    {
        {
            wxCriticalSectionLocker locker(m_luaThreadCriticalSection);
            if (!m_luaThread || m_luaThread->TestDestroy())
                break;
        }

        unsigned char debugCommand = wxLUA_DEBUGGER_CMD_NONE; // wxLuaDebuggerCommands_Type

        if (!m_clientSocket.ReadCmd(debugCommand) ||
            !HandleDebuggerCmd(debugCommand))
        {
            thread_running = false;
        }
    }
}

bool wxLuaDebugTarget::HandleDebuggerCmd(int debugCommand)
{
    bool ret = false;

    switch ((int)debugCommand)
    {
        case wxLUA_DEBUGGER_CMD_NONE :
        {
            // This is an error, but maybe we can continue?
            ret = true;
            break;
        }
        case wxLUA_DEBUGGER_CMD_ADD_BREAKPOINT:
        {
            wxString fileName;
            wxInt32  lineNumber = 0;

            if (m_clientSocket.ReadString(fileName) &&
                m_clientSocket.ReadInt32(lineNumber))
            {
                ret = AddBreakPoint(fileName, lineNumber);
            }
            break;
        }
        case wxLUA_DEBUGGER_CMD_REMOVE_BREAKPOINT:
        {
            wxString fileName;
            wxInt32  lineNumber = 0;

            if (m_clientSocket.ReadString(fileName) &&
                m_clientSocket.ReadInt32(lineNumber))
            {
                ret = RemoveBreakPoint(fileName, lineNumber);
            }
            break;
        }
        case wxLUA_DEBUGGER_CMD_CLEAR_ALL_BREAKPOINTS:
        {
            ret = ClearAllBreakPoints();
            break;
        }
        case wxLUA_DEBUGGER_CMD_RUN_BUFFER:
        {
            wxString fileName;
            wxString buffer;

            if (m_clientSocket.ReadString(fileName) &&
                m_clientSocket.ReadString(buffer))
            {
                ret = Run(fileName, buffer);
            }
            break;
        }
        case wxLUA_DEBUGGER_CMD_DEBUG_STEP:
        {
            ret = Step();
            break;
        }
        case wxLUA_DEBUGGER_CMD_DEBUG_STEPOVER:
        {
            ret = StepOver();
            break;
        }
        case wxLUA_DEBUGGER_CMD_DEBUG_STEPOUT:
        {
            ret = StepOut();
            break;
        }
        case wxLUA_DEBUGGER_CMD_DEBUG_CONTINUE:
        {
            m_force_break = false;
            ret = Continue();
            break;
        }
        case wxLUA_DEBUGGER_CMD_DEBUG_BREAK:
        {
            ret = Break();
            break;
        }
        case wxLUA_DEBUGGER_CMD_ENUMERATE_STACK:
        {
            ret = EnumerateStack();
            break;
        }
        case wxLUA_DEBUGGER_CMD_ENUMERATE_STACK_ENTRY:
        {
            wxInt32 stackRef = 0;

            if (m_clientSocket.ReadInt32(stackRef))
                ret = EnumerateStackEntry(stackRef);

            break;
        }
        case wxLUA_DEBUGGER_CMD_ENUMERATE_TABLE_REF:
        {
            wxInt32 tableRef = 0;
            wxInt32 index    = 0;
            long    itemNode = 0;

            if (m_clientSocket.ReadInt32(tableRef) &&
                m_clientSocket.ReadInt32(index) &&
                m_clientSocket.ReadLong(itemNode))
            {
                ret = EnumerateTable(tableRef, index, itemNode);
            }
            break;
        }
        case wxLUA_DEBUGGER_CMD_RESET:
        {
            ret = Reset();
            break;
        }
        case wxLUA_DEBUGGER_CMD_EVALUATE_EXPR:
        {
            wxInt32 exprRef = 0;
            wxString buffer;

            if (m_clientSocket.ReadInt32(exprRef) &&
                m_clientSocket.ReadString(buffer))
            {
                ret = EvaluateExpr(exprRef, buffer);
            }
            break;
        }
        case wxLUA_DEBUGGER_CMD_CLEAR_DEBUG_REFERENCES:
        {
            size_t idx, idxMax = m_references.GetCount();
            for (idx = 0; idx < idxMax; ++idx)
            {
                int iItem = m_references.Item(idx);
                m_wxlState.wxluaR_Unref(iItem, &wxlua_lreg_debug_refs_key);
            }
            m_references.Clear();
            ret = true;
            break;
        }
        case wxLUA_DEBUGGER_CMD_DISABLE_BREAKPOINT: // FIXME do something here
            ret = true;
            break;
        case wxLUA_DEBUGGER_CMD_ENABLE_BREAKPOINT: // FIXME do something here
            ret = true;
            break;
        default :
            wxFAIL_MSG(wxT("Invalid wxLuaDebuggerCommands_Type in wxLuaDebugTarget::ThreadFunction"));
    }

    return ret;
}

wxString wxLuaDebugTarget::CreateBreakPoint(const wxString &fileName, int lineNumber) const
{
    return wxString::Format(wxT("%d:"), lineNumber) + fileName;
}

bool wxLuaDebugTarget::AtBreakPoint(const wxString &fileName, int lineNumber) const
{
    wxCriticalSectionLocker locker(m_breakPointListCriticalSection);
    return (m_breakPointList.Index(CreateBreakPoint(fileName, lineNumber)) != wxNOT_FOUND);
}

bool wxLuaDebugTarget::AddBreakPoint(const wxString &fileName, int lineNumber)
{
    wxString breakPoint = CreateBreakPoint(fileName, lineNumber);
    wxCriticalSectionLocker locker(m_breakPointListCriticalSection);
    if (m_breakPointList.Index(breakPoint) == wxNOT_FOUND)
        m_breakPointList.Add(breakPoint);
    return true;
}

bool wxLuaDebugTarget::RemoveBreakPoint(const wxString &fileName, int lineNumber)
{
    wxCriticalSectionLocker locker(m_breakPointListCriticalSection);
    m_breakPointList.Remove(CreateBreakPoint(fileName, lineNumber));
    return true;
}

bool wxLuaDebugTarget::ClearAllBreakPoints()
{
    wxCriticalSectionLocker locker(m_breakPointListCriticalSection);
    m_breakPointList.Clear();
    return true;
}

bool wxLuaDebugTarget::Run(const wxString &fileName, const wxString &buffer)
{
    m_bufferArray.Add(fileName + wxT('\0') + buffer);
    return true;
}

bool wxLuaDebugTarget::Step()
{
    m_nextOperation = DEBUG_STEP;

    if      (!m_is_running) m_runCondition.Signal();
    else if ( m_is_stopped) m_debugCondition.Signal();

    return true;
}

bool wxLuaDebugTarget::StepOver()
{
    m_nframes_until_break = 0;
    m_nextOperation = DEBUG_STEPOVER;

    if      (!m_is_running) m_runCondition.Signal();
    else if ( m_is_stopped) m_debugCondition.Signal();

    return true;
}

bool wxLuaDebugTarget::StepOut()
{
    m_nframes_until_break = 1;
    m_nextOperation = DEBUG_STEPOVER;

    if      (!m_is_running) m_runCondition.Signal();
    else if ( m_is_stopped) m_debugCondition.Signal();

    return true;
}

bool wxLuaDebugTarget::Continue()
{
    m_nextOperation = DEBUG_GO;

    if      (!m_is_running) m_runCondition.Signal();
    else if ( m_is_stopped) m_debugCondition.Signal();

    return true;
}

bool wxLuaDebugTarget::Break()
{
    m_force_break = true;
    return true;
}

bool wxLuaDebugTarget::Reset()
{
    NotifyExit();

    m_force_break     = true;
    m_reset_requested = true;

    if      (!m_is_running) m_runCondition.Signal();
    else if ( m_is_stopped) m_debugCondition.Signal();

    return true;
}

bool wxLuaDebugTarget::EnumerateStack()
{
    wxLuaDebugData debugData(true);

    EnterLuaCriticalSection();
    debugData.EnumerateStack(m_wxlState.GetLuaState());
    LeaveLuaCriticalSection();

    return NotifyStackEnumeration(debugData);
}

bool wxLuaDebugTarget::EnumerateStackEntry(int stackRef)
{
    wxLuaDebugData debugData(true);

    EnterLuaCriticalSection();
    debugData.EnumerateStackEntry(m_wxlState.GetLuaState(), stackRef, m_references);
    LeaveLuaCriticalSection();

    return NotifyStackEntryEnumeration(stackRef, debugData);
}

bool wxLuaDebugTarget::EnumerateTable(int tableRef, int nIndex, long nItemNode)
{
    wxLuaDebugData debugData(true);

    EnterLuaCriticalSection();
    debugData.EnumerateTable(m_wxlState.GetLuaState(), tableRef, nIndex, m_references);
    LeaveLuaCriticalSection();

    return NotifyTableEnumeration(nItemNode, debugData);
}

bool wxLuaDebugTarget::EvaluateExpr(int exprRef, const wxString &strExpr) // FIXME - check this code
{
    wxString strResult(wxT("Error"));
    int      nReference = LUA_NOREF;

    EnterLuaCriticalSection();
    {
        lua_State* L = m_wxlState.GetLuaState();

        if (wxStrpbrk(strExpr.c_str(), wxT(" ~=<>+-*/%(){}[]:;,.\"'")) != NULL)
        {
            // an expression
            int nOldTop = lua_gettop(L);

            wxLuaCharBuffer charbuf(strExpr);
            int nResult = luaL_loadbuffer(L, charbuf.GetData(), charbuf.Length(), "debug");

            if (nResult == 0)
                nResult = lua_pcall(L, 0, LUA_MULTRET, 0);  // call main

            if (nResult != 0)
                wxlua_pushwxString(L, wxlua_LUA_ERR_msg(nResult));

            else if (lua_gettop(L) == nOldTop)
                lua_pushliteral(L, "OK");

            nReference = m_wxlState.wxluaR_Ref(-1, &wxlua_lreg_refs_key);
            lua_settop(L, nOldTop); // throw out all return values
        }
        else
        {
            lua_Debug ar        = INIT_LUA_DEBUG;
            int  stack_level    = 0; // 0 is the current running function
            bool variable_found = false;

            while (lua_getstack(L, stack_level++, &ar) != 0)
            {
                int stack_index = 1; // 1 is the first local stack index
                wxString name = lua2wx(lua_getlocal(L, &ar, stack_index));

                while (!name.IsEmpty())
                {
                    if (strExpr == name)
                    {
                        nReference = m_wxlState.wxluaR_Ref(-1, &wxlua_lreg_refs_key);
                        lua_pop(L, 1);
                        variable_found = true;
                        break;
                    }

                    lua_pop(L, 1);
                    name = lua2wx(lua_getlocal(L, &ar, ++stack_index));
                }

                if (variable_found)
                    break;
            }

            if (!variable_found)
            {
                  int nOldTop = lua_gettop(L);
                  lua_pushvalue(L, LUA_GLOBALSINDEX);
                  lua_pushnil(L);
                  while (lua_next(L, -2) != 0)
                  {
                      if (lua_type(L, -2) == LUA_TSTRING)
                      {
                          wxString name = lua2wx(lua_tostring(L, -2));
                          if (strExpr == name)
                          {
                              nReference = m_wxlState.wxluaR_Ref(-1, &wxlua_lreg_refs_key); // reference value
                              lua_pop(L, 2);    // pop key and value
                              variable_found = true;
                              break;
                          }
                      }

                      lua_pop(L, 1);  // removes 'value';
                  }
                  lua_settop(L, nOldTop); // the table of globals.
            }
        }

        if ((nReference != LUA_NOREF) && m_wxlState.wxluaR_GetRef(nReference, &wxlua_lreg_refs_key))
        {
            m_wxlState.wxluaR_Unref(nReference, &wxlua_lreg_refs_key);

            int wxl_type = 0;
            wxString value;
            wxLuaDebugData::GetTypeValue(L, -1, &wxl_type, value);

            strResult.Printf(wxT("%s : %s"), wxluaT_typename(L, wxl_type).c_str(), value.c_str());

            lua_pop(L, 1);
        }
    }
    LeaveLuaCriticalSection();

    return NotifyEvaluateExpr(exprRef, strResult);
}

bool wxLuaDebugTarget::NotifyBreak(const wxString &fileName, int lineNumber)
{
    return IsConnected() && !m_reset_requested &&
           m_clientSocket.WriteCmd(wxLUA_DEBUGGEE_EVENT_BREAK) &&
           m_clientSocket.WriteString(fileName) &&
           m_clientSocket.WriteInt32(lineNumber);
}

bool wxLuaDebugTarget::NotifyPrint(const wxString &errorMsg)
{
    return IsConnected() &&
           m_clientSocket.WriteCmd(wxLUA_DEBUGGEE_EVENT_PRINT) &&
           m_clientSocket.WriteString(errorMsg);
}

bool wxLuaDebugTarget::NotifyError(const wxString &errorMsg)
{
    if (IsConnected() &&
        m_clientSocket.WriteCmd(wxLUA_DEBUGGEE_EVENT_ERROR) &&
        m_clientSocket.WriteString(errorMsg))
    {
        return true;
    }
    else
        wxMessageBox(errorMsg, wxT("wxLua debug client error"), wxOK | wxCENTRE, NULL);

    return false;
}

bool wxLuaDebugTarget::NotifyExit()
{
    bool ret = IsConnected() &&
           m_clientSocket.WriteCmd(wxLUA_DEBUGGEE_EVENT_EXIT);

    return ret;
}

bool wxLuaDebugTarget::NotifyStackEnumeration(const wxLuaDebugData& debugData)
{
    return IsConnected() &&
           m_clientSocket.WriteCmd(wxLUA_DEBUGGEE_EVENT_STACK_ENUM) &&
           m_clientSocket.WriteDebugData(debugData);
}

bool wxLuaDebugTarget::NotifyStackEntryEnumeration(int entryRef,
                                                   const wxLuaDebugData& debugData)
{
    return IsConnected() &&
           m_clientSocket.WriteCmd(wxLUA_DEBUGGEE_EVENT_STACK_ENTRY_ENUM) &&
           m_clientSocket.WriteInt32(entryRef) &&
           m_clientSocket.WriteDebugData(debugData);
}

bool wxLuaDebugTarget::NotifyTableEnumeration(long itemNode,
                                              const wxLuaDebugData& debugData)
{
    return IsConnected() &&
           m_clientSocket.WriteCmd(wxLUA_DEBUGGEE_EVENT_TABLE_ENUM) &&
           m_clientSocket.WriteLong(itemNode) &&
           m_clientSocket.WriteDebugData(debugData);
}

bool wxLuaDebugTarget::NotifyEvaluateExpr(int exprRef,
                                          const wxString &strResult)
{
    return IsConnected() &&
           m_clientSocket.WriteCmd(wxLUA_DEBUGGEE_EVENT_EVALUATE_EXPR) &&
           m_clientSocket.WriteInt32(exprRef) &&
           m_clientSocket.WriteString(strResult);
}

bool wxLuaDebugTarget::DebugHook(int event)
{
    bool fWait = false;
    m_is_stopped = true;

    int      lineNumber = 0;
    wxString fileName;

    if (!(m_force_break && m_reset_requested))
    {
        lua_Debug luaDebug = INIT_LUA_DEBUG;
        lua_getstack(m_wxlState.GetLuaState(), 0, &luaDebug);
        lua_getinfo(m_wxlState.GetLuaState(), "Sln", &luaDebug);
        lineNumber = luaDebug.currentline - 1;
        fileName = lua2wx(luaDebug.source);
        if (!fileName.IsEmpty() && (fileName[0] == wxT('@')))
            fileName = fileName.Mid(1);
    }

    if (m_force_break)
    {
        if (m_reset_requested)
        {
            fWait = true;
            m_is_exiting = true;
            wxExit();
        }

        if (!m_is_exiting)
        {
            if (NotifyBreak(fileName, lineNumber))
                fWait = true;
        }
    }
    else
    {
        if (event == LUA_HOOKCALL // call
#if LUA_VERSION_NUM > 501
              || event == LUA_HOOKTAILCALL
#endif // LUA_VERSION_NUM < 501
            )
        {
            m_nframes_until_break++;
        }
        else if (event == LUA_HOOKRET // return
#if LUA_VERSION_NUM < 502
              || event == LUA_HOOKTAILRET
#endif // LUA_VERSION_NUM < 502
            )
        {
            if (m_nframes_until_break > 0)
                m_nframes_until_break--;
        }
        else if (event == LUA_HOOKLINE) // line
        {
            switch (m_nextOperation)
            {
                case DEBUG_STEP:
                {
                    if (NotifyBreak(fileName, lineNumber))
                        fWait = true;

                    break;
                }
                case DEBUG_STEPOVER:
                {
                    if ((m_nframes_until_break == 0) && NotifyBreak(fileName, lineNumber))
                        fWait = true;

                    break;
                }
                case DEBUG_GO:
                default:
                {
                    if (AtBreakPoint(fileName, lineNumber) && NotifyBreak(fileName, lineNumber))
                        fWait = true;

                    break;
                }
            }
        }
    }

    if (fWait)
    {
        // release the critical section so
        // the other thread can access LUA
        LeaveLuaCriticalSection();
        // Wait for a command
        m_debugCondition.Wait();
        // acquire the critical section again
        EnterLuaCriticalSection();
    }

    m_is_stopped = false;
    return fWait;
}

// --------------------------------------------------------------------------

wxLuaDebugTarget* wxLuaDebugTarget::GetDebugTarget(lua_State* L)
{
    wxLuaDebugTarget *luaDebugTarget = NULL;

    // try to get the state we've stored
    lua_pushstring( L, "__wxLuaDebugTarget__" );
    lua_rawget( L, LUA_REGISTRYINDEX );
    // if nothing was returned or it wasn't a ptr, abort
    if ( lua_islightuserdata(L, -1) )
        luaDebugTarget = (wxLuaDebugTarget*)lua_touserdata( L, -1 );

    lua_pop(L, 1);

    return luaDebugTarget;
}

void LUACALL wxLuaDebugTarget::LuaDebugHook(lua_State *L, lua_Debug *pLuaDebug)
{
    wxLuaDebugTarget *luaDebugTarget = GetDebugTarget(L);

    if (luaDebugTarget != NULL)
        luaDebugTarget->DebugHook(pLuaDebug->event);
}

int LUACALL wxLuaDebugTarget::LuaPrint(lua_State *L)
{
    int         idx;
    wxString stream;
    int n = lua_gettop(L);  /* number of arguments */
    lua_getglobal(L, "tostring");
    for (idx = 1; idx <= n;  idx++)
    {
        lua_pushvalue(L, -1);  /* function to be called */
        lua_pushvalue(L, idx);   /* value to print */
        lua_call(L, 1, 1);
        wxString s(lua2wx(lua_tostring(L, -1)));  /* get result */
        if (s.IsEmpty())
            return luaL_error(L, "`tostring' must return a string to `print'");
        if (idx > 1)
            stream.Append(wxT("\t"));
        stream.Append(s);
        lua_pop(L, 1);  /* pop result */
    }

    wxLuaDebugTarget *luaDebugTarget = GetDebugTarget(L);

    if (luaDebugTarget != NULL)
        luaDebugTarget->NotifyPrint(stream);

    return 0;
}
