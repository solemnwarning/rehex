/////////////////////////////////////////////////////////////////////////////
// Name:        wxlstate.cpp
// Purpose:     wxLuaState, a wxWidgets interface to Lua
// Author:      Ray Gilbert, John Labenski, J Winwood (Reuben Thomas for bitlib at bottom)
// Created:     14/11/2001
// Copyright:   (c) 2012 John Labenski, 2001-2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx/wx.h"
#include <wx/wxprec.h>

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

// for all others, include the necessary headers
#ifndef WX_PRECOMP
    #include <wx/wx.h>
#endif

#include "wxlua/wxlstate.h"
#include "wxlua/wxlcallb.h"
#include <wx/tokenzr.h>

//#include "wxluadebug/include/wxldebug.h" // for debugging only

wxLuaState wxNullLuaState(false);

extern "C"
{
    // provided by bit.c (Lua BitOp)
    int luaopen_bit(lua_State *L);

#if (LUA_VERSION_NUM < 502)
    // provided by lbitlib.c for 5.1 or we use the one in 5.2 or LuaJIT.
    int luaopen_bit32 (lua_State *L);
#endif // (LUA_VERSION_NUM < 502)
}

// ----------------------------------------------------------------------------
// C functions for Lua used in wxLuaState
// ----------------------------------------------------------------------------

// The print function that we push into Lua replacing "print(...)"
// to generate wxLuaEvent(wxEVT_LUA_PRINT, ...)
// Code copied from Lua's luaB_print() function in lbaselib.c
int LUACALL wxlua_printFunction( lua_State *L )
{
    wxLuaState wxlState(L); // doesn't have to be ok

    // If the wxLuaState is not going to print, we'll let Lua print normally
    if (!wxlState.Ok() || (wxlState.GetEventHandler() == NULL) ||
        (!wxApp::IsMainLoopRunning() && !wxlState.sm_wxAppMainLoop_will_run))
    {
        // Get our saved copy of the Lua's print function from the registry
        lua_pushlstring(L, "print_lua", 9);
        lua_rawget( L, LUA_REGISTRYINDEX ); // pop key, push print function

        // LuaJIT's print() is not a lua_CFunction and it is more flexible to
        // simply lua_call() whatever was saved when wxLua was loaded.
        //lua_CFunction lua_print = lua_tocfunction(L, -1);
        //lua_pop(L, 1);                      // pop the print function
        //return lua_print(L);
        lua_insert(L, 1);
        lua_call(L, lua_gettop(L)-1, 0);
        return 0;
    }

    // The wxLuaState can print by sending an event
    wxString msg;
    int i, n = lua_gettop(L);

    // Use the Lua tostring() function to print them as Lua would
    lua_getglobal(L, "tostring");

    if (!lua_isfunction(L, -1))
    {
        // This code is also used in wxledit.cpp, wxLuaShell::RunString()
        msg = wxT("wxLua ERROR: Unable to print() without the tostring() function. Did you remove it?");
        lua_pop(L, 1);  // pop the nil or whatever replaced tostring()
        n = 0;          // don't let for loop run
    }

    for (i = 1; i <= n; ++i)
    {
        const char *s;
        lua_pushvalue(L, -1);       /* function to be called */
        lua_pushvalue(L, i);        /* value to print */
        lua_call(L, 1, 1);
        s = lua_tostring(L, -1);    /* get result */
        if (s == NULL)
        {
            return luaL_error(L, "'tostring' must return a string to 'print'");
        }

        if (i > 1) msg.Append(wxT("\t")); // Lua uses a tab in luaB_print
        msg += lua2wx(s);

        lua_pop(L, 1);  /* pop result */
    }

    if (!msg.IsEmpty())
    {
        wxLuaEvent event(wxEVT_LUA_PRINT, wxlState.GetId(), wxlState);
        event.SetString(msg);
        wxlState.SendEvent(event);
    }
    //else if (!msg.IsEmpty())
    //    wxPrintf(wxT("%s\n"), msg.c_str()); // Lua puts a \n too

    return 0; // no items put onto stack
}

void LUACALL wxlua_debugHookFunction(lua_State *L, lua_Debug *LDebug)
{
    // NULL when shutting down.
    wxLuaStateData* wxlStateData = wxlua_getwxluastatedata(L);
    if (!wxlStateData) return;

    // FIXME - for select event types we don't want to do anything
    wxEventType evtType = wxlua_getwxeventtype(L);
    if ((evtType != wxEVT_NULL))
        //(evtType == wxEVT_IDLE) && (evtType == wxEVT_PAINT) &&
        //(evtType == wxEVT_DESTROY) && (evtType == wxEVT_CLOSE_WINDOW))
        return;

    // they want to break the program, restore old debug hook, then error out
    if (wxlStateData->m_debug_hook_break)
    {
        // It's ok that we get the wxLuaState here since we're stopping anyway.
        wxLuaState wxlState(L);

        // restore hook to previous state
        wxlState.ClearDebugHookBreak();
        wxlua_error(L, wxlStateData->m_debug_hook_break_msg.c_str());
        return;
    }

    // We use wxLuaState::SendEvent() because it sets wxEvent::SetEventObject() for us.
    if (wxlStateData->m_lua_debug_hook_send_evt && wxlStateData->m_evtHandler)
    {
        wxLuaState wxlState(L);

        lua_getinfo(L, "l", LDebug); // line (ldebug.currentline)

        wxLuaEvent event(wxEVT_LUA_DEBUG_HOOK, wxlState.GetId(), wxlState);
        event.m_lua_Debug = LDebug;
        event.SetInt(LDebug->currentline);
        wxlState.SendEvent( event );
        if (event.m_debug_hook_break)
            wxlState.wxlua_Error("Lua interpreter stopped.");
    }

    // Try to yield *after* sending event to allow C++ gui update
    if (wxlStateData->m_lua_debug_hook_yield > 0)
    {
        // yield based on number of ms passed NOT every hook event
        unsigned long last_time = wxlStateData->m_last_debug_hook_time;
        unsigned long cur_time  = wxGetLocalTimeMillis().GetLo();

        if ((cur_time > last_time + wxlStateData->m_lua_debug_hook_yield) ||
            (cur_time < last_time)) // wrapped
        {
            wxlStateData->m_last_debug_hook_time = cur_time;

            bool painting = (evtType == wxEVT_PAINT);

/*
            wxLongToLongHashMap::iterator it;
            wxLongToLongHashMap* hashMap = &wxlState.GetLuaStateRefData()->m_wxlStateData->m_trackedObjects;
            for (it = hashMap->begin(); it != hashMap->end(); ++it)
            {
                wxObject* obj = (wxObject*)it->second;
                if (obj && wxDynamicCast(obj, wxPaintDC))
                {
                    painting = true;
                    break;
                }
            }
*/

            if (!painting)
                wxYield(); //IfNeeded();
        }
    }
}

// ----------------------------------------------------------------------------
// wxFindWindowByPointer - find a window by its pointer
//     return NULL if doesn't exist, see wxFindWindowByID and wxFindWindowByLabel
// ----------------------------------------------------------------------------
static wxWindow *wxFindWindowPointerRecursively(const wxWindow *parent, const wxWindow *win)
{
    wxCHECK_MSG(win, NULL, wxT("invalid window in wxFindWindowPointerRecursively"));

    if ( parent )
    {
        // see if this is the one we're looking for
        if ( parent == win )
            return (wxWindow*)win;

        // It wasn't, so check all its children
        for ( wxWindowList::compatibility_iterator node = parent->GetChildren().GetFirst();
              node;
              node = node->GetNext() )
        {
            // recursively check each child
            wxWindow *child_win = (wxWindow *)node->GetData();
            wxWindow *retwin = wxFindWindowPointerRecursively(child_win, win);
            if (retwin)
                return retwin;
        }
    }

    return NULL; // Not found
}

// Check to see if wxWidgets still thinks "win" is a valid window
//   parent is the window to start with, if parent=NULL check all windows
static wxWindow* wxFindWindowByPointer(const wxWindow *parent, const wxWindow *win)
{
    wxCHECK_MSG(win, NULL, wxT("Invalid window in wxFindWindowByPointer"));

    if ( parent )
    {
        // just check parent and all its children
        return wxFindWindowPointerRecursively(parent, win);
    }
    // start at very top of wx's windows
    for ( wxWindowList::compatibility_iterator top_node = wxTopLevelWindows.GetFirst();
          top_node;
          top_node = top_node->GetNext() )
    {
        // recursively check each window & its children
        wxWindow *top_win = top_node->GetData();
        wxWindow *retwin = wxFindWindowPointerRecursively(top_win, win);
        if (retwin)
            return retwin;
    }

    return NULL; // Not found
}

// ----------------------------------------------------------------------------
// wxLuaCleanupWindows - given a wxWindowList of wxWindows it runs wxFindWindowByPointer
//   on it to remove dead pointers from the list if only_check=true or
//   Destroy() the windows and remove them from the list if !only_check.
// Returns true if any windows are removed, i.e. the list has changed
// ----------------------------------------------------------------------------
bool wxLuaCleanupWindows(lua_State* L, bool only_check)
{
    wxCHECK_MSG(L, false, wxT("Invalid wxLuaState"));

    bool removed = false;

    lua_pushlightuserdata(L, &wxlua_lreg_topwindows_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                     // pop key, push value (table)

    bool try_again = true;

    while (try_again)
    {
        try_again = false;

        lua_pushnil(L);
        while (lua_next(L, -2) != 0)
        {
            // value = -1, key = -2, table = -3
            wxWindow* win = (wxWindow*)lua_touserdata(L, -2);
            wxCHECK_MSG(win, false, wxT("Invalid wxWindow"));

            if (wxFindWindowByPointer(NULL, win) == NULL)
            {
                // simply remove dead window from the list
                removed = true;
                lua_pop(L, 1);        // pop value

                lua_pushvalue(L, -1); // copy key for next iteration
                lua_pushnil(L);
                lua_rawset(L, -4);    // set t[key] = nil to remove it
            }
            else if (!only_check)
            {
                removed = true;
                if (win->HasCapture())
                    win->ReleaseMouse();

                // 2.9 insists that all pushed event handlers are popped before destroying window
                // we assume (for now) that they're properly owned so we don't pop or delete them
                //while (win->GetEventHandler() != win)
                //    win->PopEventHandler(false);

                // release capture for children since we may be abruptly ending
                for ( wxWindowList::compatibility_iterator childNode = win->GetChildren().GetFirst();
                    childNode;
                    childNode = childNode->GetNext() )
                {
                    wxWindow *child = childNode->GetData();

                    lua_pushlightuserdata(L, child);
                    lua_pushnil(L);
                    lua_rawset(L, -5);

                    if (child->HasCapture())
                        child->ReleaseMouse();

                    // 2.9 insists that all pushed event handlers are popped before destroying window
                    // we assume (for now) that they're properly owned so we don't pop or delete them
                    //while (child->GetEventHandler() != child)
                    //    child->PopEventHandler(false);
                }

                if (!win->IsBeingDeleted())
                {
                    delete win;
                }

                // wxLuaWindowDestroyHandler should destroy this node
                //  and also delete all the children and their nodes
                //  it's probably best to start from the top again
                lua_pop(L, 1);        // pop value

                lua_pushnil(L);
                lua_rawset(L, -3);    // set t[key] = nil to remove it

                try_again = true;
                break;
            }
            else
                lua_pop(L, 1); // pop value, lua_next will pop key at end
        }
    }

    lua_pop(L, 1); // pop table

    return removed;
}

//----------------------------------------------------------------------------
// wxLuaStateRunLocker
//----------------------------------------------------------------------------

class wxLuaStateRunLocker
{
public:
    wxLuaStateRunLocker(int &is_running) : m_is_running(++is_running) {}
    ~wxLuaStateRunLocker() { m_is_running = wxMax(0, m_is_running-1); } // DebugHookBreak sets to 0.

    int &m_is_running;
};

//----------------------------------------------------------------------------
// wxLuaStateData
//----------------------------------------------------------------------------

wxLuaStateData::wxLuaStateData()
               :m_is_running(0),
                m_is_closing(false),
                m_lua_debug_hook_count(100), m_lua_debug_hook_yield(50),
                m_lua_debug_hook(0), m_lua_debug_hook_send_evt(false),
                m_last_debug_hook_time(0), m_debug_hook_break(false),
                m_debug_hook_break_msg(wxT("Break")),
                m_evtHandler(NULL),
                m_id(wxID_ANY)
{
}

wxLuaStateData::~wxLuaStateData()
{
    // no events here, the handler may already be gone
    m_evtHandler = NULL;
}

//----------------------------------------------------------------------------
// wxLuaStateRefData
//----------------------------------------------------------------------------

wxLuaStateRefData::wxLuaStateRefData(bool create_data)
                  :m_lua_State(NULL),
                   m_lua_State_static(false),
                   m_lua_State_coroutine(false),
                   m_wxlStateData(NULL),
                   m_own_stateData(false)
{
    if (create_data)
    {
        m_wxlStateData = new wxLuaStateData();
        m_own_stateData = true;
    }
}

wxLuaStateRefData::~wxLuaStateRefData()
{
    wxCHECK_RET((m_lua_State_static == true) || (m_lua_State == NULL),
                wxT("You must ALWAYS call wxLuaState::Destroy and not wxObject::UnRef"));

    // only close the state if it's not static,
    // as when it's static (wx is loaded as a library), it will be closed somewhere else
    if (!m_lua_State_static)
        CloseLuaState(true);

    if (m_own_stateData)
        delete m_wxlStateData;
}

bool wxLuaStateRefData::CloseLuaState(bool force, bool collectGarbage)
{
    if ((m_lua_State == NULL) || m_wxlStateData->m_is_closing || m_lua_State_coroutine)
        return true;

    if (lua_status(m_lua_State) != 0) // lua state is not LUA_OK
        return true;

    m_wxlStateData->m_is_closing = true;

    //wxCHECK_MSG(m_lua_State, false, wxT("Interpreter not created"));
    // wxCHECK_MSG(!m_is_running, false, wxT("Interpreter still running, can't destroy"));  FIXME

    // remove deleted windows first
    wxLuaCleanupWindows(m_lua_State, true);

    // are there still windows? ask to abort deleting them if !force
    bool tlwindows_open = false;
    lua_pushlightuserdata(m_lua_State, &wxlua_lreg_topwindows_key); // push key
    lua_rawget(m_lua_State, LUA_REGISTRYINDEX);                     // pop key, push value (table)

    lua_pushnil(m_lua_State);
    if (lua_next(m_lua_State, -2))
    {
        tlwindows_open = true;
        lua_pop(m_lua_State, 3); // pop key, value, table
    }
    else
        lua_pop(m_lua_State, 1); // pop table

    if (tlwindows_open)
    {
        int ret = wxOK;

        if (!force)
        {
            ret = wxMessageBox(wxT("Windows are still open, would you like to delete them?"),
                               wxT("Delete existing windows?"), wxOK|wxCANCEL|wxICON_QUESTION);
        }

        if (ret == wxCANCEL)
        {
            m_wxlStateData->m_is_closing = false;
            return false;
        }

        //wxPrintf(wxT("Deleting windows\n"));

        // delete windows and their eventhandler since they delete the wxLuaEventCallbacks
        //  which require a lua_State
        wxLuaCleanupWindows(m_lua_State, false);
        // wait for wxWindow::Destroy() to really delete the windows
        //wxYieldIfNeeded();
    }

    // clear the wxlua_lreg_wxluastatedata_key which we test for in the debug hook
    // to know if the lua_State is being closed
    lua_pushlightuserdata(m_lua_State, &wxlua_lreg_wxluastatedata_key);
    lua_pushnil(m_lua_State);
    lua_rawset( m_lua_State, LUA_REGISTRYINDEX ); // pop key, push bool

    ClearCallbacks();

    // remove refs table to try to clear memory gracefully
    wxlua_lreg_createtable(m_lua_State, &wxlua_lreg_refs_key);
    wxlua_lreg_createtable(m_lua_State, &wxlua_lreg_debug_refs_key);
    //wxlua_lreg_createtable(m_lua_State, &wxlua_lreg_derivedmethods_key); // gc will delete them

    if (collectGarbage)
        lua_gc(m_lua_State, LUA_GCCOLLECT, 0); // round up dead refs

    if (!m_lua_State_static)
        lua_close(m_lua_State);

    // Clear out the wxLuaState we hashed, note it's not refed so we have
    // NULL its ref data.
    // Note: even though the lua_State is closed the pointer value is still good.
    // The wxLuaState we pushed into the reg table is a light userdata so
    // it didn't get deleted.
    wxHashMapLuaState::iterator it = wxLuaState::s_wxHashMapLuaState.find(m_lua_State);
    if (it != wxLuaState::s_wxHashMapLuaState.end())
    {
        wxLuaState* wxlState = it->second;
        wxlState->SetRefData(NULL);
        delete wxlState;
        wxLuaState::s_wxHashMapLuaState.erase(m_lua_State);
    }

    m_lua_State = NULL;

    return true;
}

void wxLuaStateRefData::ClearCallbacks()
{
    wxCHECK_RET(m_lua_State, wxT("Invalid lua_State"));

    lua_State* L = m_lua_State;

    lua_pushlightuserdata(L, &wxlua_lreg_evtcallbacks_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                       // pop key, push value (table)

    lua_pushnil(L);
    while (lua_next(L, -2) != 0)
    {
        // value = -1, key = -2, table = -3
        wxLuaEventCallback* cb = (wxLuaEventCallback*)lua_touserdata(L, -2);
        cb->ClearwxLuaState();

        lua_pop(L, 1);               // pop value, lua_next will pop key at end
    }

    lua_pop(L, 1); // pop table

    wxlua_lreg_createtable(m_lua_State, &wxlua_lreg_evtcallbacks_key);

    // ----------------------------------------------------------------------
    // These should already be gone from wxLuaCleanupWindows, make sure...

    lua_pushlightuserdata(L, &wxlua_lreg_windestroycallbacks_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                              // pop key, push value (table)

    lua_pushnil(L);
    while (lua_next(L, -2) != 0)
    {
        // value = -1, key = -2, table = -3
        wxLuaWinDestroyCallback* cb = (wxLuaWinDestroyCallback*)lua_touserdata(L, -1);
        cb->ClearwxLuaState();

        lua_pop(L, 1);               // pop value, lua_next will pop key at end
    }

    lua_pop(L, 1); // pop table

    wxlua_lreg_createtable(m_lua_State, &wxlua_lreg_windestroycallbacks_key);
}

//----------------------------------------------------------------------------
// wxLuaState
//----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxLuaState, wxObject)

wxHashMapLuaState wxLuaState::s_wxHashMapLuaState;
bool wxLuaState::sm_wxAppMainLoop_will_run = false;


#define M_WXLSTATEDATA ((wxLuaStateRefData*)m_refData)

wxObjectRefData *wxLuaState::CreateRefData() const
{
    return new wxLuaStateRefData;
}
//wxObjectRefData *wxLuaState::CloneRefData(const wxObjectRefData *data) const
//{
//    return new wxLuaStateRefData(*(const wxLuaStateRefData *)data);
//}

void wxLuaState::Create( const wxLuaState& wxlState )
{
    Destroy();
    Ref(wxlState);
}

bool wxLuaState::Create(wxEvtHandler *handler, wxWindowID id)
{
    Destroy();

    lua_State* L = luaL_newstate();
    // load some useful libraries, loads all of them
    luaL_openlibs(L);

    bool ok = Create(L, wxLUASTATE_SETSTATE|wxLUASTATE_OPENBINDINGS);

    M_WXLSTATEDATA->m_wxlStateData->m_evtHandler = handler;
    M_WXLSTATEDATA->m_wxlStateData->m_id = id;

    // alert people that we've been created so they can finish setting us up
    wxLuaEvent event(wxEVT_LUA_CREATION, GetId(), *this);
    SendEvent( event );

    return ok;
}

bool wxLuaState::Create(lua_State* L, int state_type)
{
    wxCHECK_MSG(L != NULL, false, wxT("Invalid lua_State"));
    Destroy();

    if (WXLUA_HASBIT(state_type, wxLUASTATE_GETSTATE))
    {
        // returns an invalid, wxNullLuaState on failure
        Ref(wxLuaState::GetwxLuaState(L, WXLUA_HASBIT(state_type, wxLUASTATE_ROOTSTATE)));
    }
    else if (WXLUA_HASBIT(state_type, wxLUASTATE_SETSTATE))
    {
        m_refData = new wxLuaStateRefData();

        M_WXLSTATEDATA->m_lua_State = L;
        M_WXLSTATEDATA->m_lua_State_static = WXLUA_HASBIT(state_type, wxLUASTATE_STATICSTATE);

        // Make the GC a little more aggressive since we push void* data
        // that may be quite large. The upshot is that Lua runs faster.
        // Empirically found by timing: "for i = 1, 1E6 do local p = wx.wxPoint() end"
        lua_gc(L, LUA_GCSETPAUSE, 120);
        lua_gc(L, LUA_GCSETSTEPMUL, 400);

        // Create a new state to push into Lua, the last wxLuaStateRefData will delete it.
        // Note: we call SetRefData() so that we don't increase the ref count.
        wxLuaState* hashState = new wxLuaState(false);
        hashState->SetRefData(m_refData);
        wxLuaState::s_wxHashMapLuaState[L] = hashState;

        // Stick us into the Lua registry table - push key, value
        lua_pushlightuserdata(L, &wxlua_lreg_wxluastate_key);
        lua_pushlightuserdata( L, (void*)hashState );
        lua_rawset( L, LUA_REGISTRYINDEX ); // set the value

        // start off not in an event
        wxlua_setwxeventtype(L, wxEVT_NULL);

        // Push our wxLuaStateData
        lua_pushlightuserdata(L, &wxlua_lreg_wxluastatedata_key);
        lua_pushlightuserdata(L, M_WXLSTATEDATA->m_wxlStateData);
        lua_rawset(L, LUA_REGISTRYINDEX); // set the value

        // These tables are expected to exist no matter what.
        // They're in the registry so even if they're not used they
        // shouldn't bother anyone.

        lua_pushlightuserdata(L, &wxlua_lreg_regtable_key);
        lua_newtable(L);      // main table
          lua_newtable(L);    // metatable
          lua_pushlstring(L, "__mode", 6);
          lua_pushlstring(L, "kv", 2);
          lua_rawset(L, -3);                  // set mode of main table
          lua_setmetatable(L, -2);            // via the metatable
        lua_rawset(L, LUA_REGISTRYINDEX); // set the value

        // create the types table in registry
        wxlua_lreg_createtable(L, &wxlua_lreg_types_key);

        // create the refs table in registry
        wxlua_lreg_createtable(L, &wxlua_lreg_refs_key);

        // create the debug refs table in registry
        wxlua_lreg_createtable(L, &wxlua_lreg_debug_refs_key);

        // create the wxLuaBindClasses table in the registry
        wxlua_lreg_createtable(L, &wxlua_lreg_classes_key);

        // Create a table for overridden methods for C++ userdata objects
        wxlua_lreg_createtable(L, &wxlua_lreg_derivedmethods_key);

        // Create a table for the wxLuaBindings we've installed
        wxlua_lreg_createtable(L, &wxlua_lreg_wxluabindings_key);

        // Create a table for the userdata that we've pushed into Lua
        wxlua_lreg_createtable(L, &wxlua_lreg_weakobjects_key);

        // Create a table for objects to delete
        wxlua_lreg_createtable(L, &wxlua_lreg_gcobjects_key);

        // Create a table for wxLuaEventCallbacks
        wxlua_lreg_createtable(L, &wxlua_lreg_evtcallbacks_key);

        // Create a table for wxLuaWinDestroyCallbacks
        wxlua_lreg_createtable(L, &wxlua_lreg_windestroycallbacks_key);

        // Create a table for top level wxWindows
        wxlua_lreg_createtable(L, &wxlua_lreg_topwindows_key);

        // copy Lua's print function in case someone wants to use it
        lua_getglobal(L, "print");
#if LUA_VERSION_NUM < 502
        lua_pushlstring(L, "print_lua", 9);
        lua_pushvalue(L, -2);               // copy print function
        lua_rawset(L, LUA_GLOBALSINDEX);    // set t[key] = value, pops key and value
#else
        lua_pushglobaltable(L);
        lua_pushlstring(L, "print_lua", 9);
        lua_pushvalue(L, -3);               // copy print function
        lua_rawset(L, -3);                  // set t[key] = value, pops key and value
        lua_pop(L, 1);                      // pop the global table
#endif // LUA_VERSION_NUM < 502

        lua_pushlstring(L, "print_lua", 9); // also keep a permanent copy in registry
        lua_pushvalue(L, -2);               // copy print function
        lua_rawset(L, LUA_REGISTRYINDEX);   // set t[key] = value, pops key and value

        lua_pop(L, 1);                      // pop the print function

        // register wxLua's print handler to send events, replaces Lua's print function
        RegisterFunction(wxlua_printFunction, "print");

        // register our NULL type
        //wxluatype_NULL = wxluaT_newmetatable(L, wxluatype_NULL);
        wxLuaBinding::InstallClassMetatable(L, &wxLuaBindClass_NULL);

        // now register bindings
        if (WXLUA_HASBIT(state_type, wxLUASTATE_OPENBINDINGS))
        {
            // load the bit lib, this is the accepted way, see luaL_openlibs(L)
            lua_pushcfunction(L, luaopen_bit);
            lua_pushstring(L, "bit");
            lua_call(L, 1, 0);

#if (LUA_VERSION_NUM < 502)
            lua_pushcfunction(L, luaopen_bit32);
            lua_pushstring(L, "bit32");
            lua_call(L, 1, 0);
#endif // (LUA_VERSION_NUM < 502)

            RegisterBindings();
        }
    }
    else
        wxFAIL_MSG(wxT("Unknown state_type for wxLuaState::Create()"));

    return Ok();
}

// --------------------------------------------------------------------------

bool wxLuaState::IsOk() const
{
    return (m_refData != NULL) && (M_WXLSTATEDATA->m_lua_State != NULL);
}

// --------------------------------------------------------------------------

void wxLuaState::Destroy()
{
    if (m_refData == NULL || M_WXLSTATEDATA->m_lua_State_static) return;

    // we don't want recursion in UnRef and wxlua_garbageCollect
    if (GetRefData()->GetRefCount() == 1)
        M_WXLSTATEDATA->CloseLuaState(true);

    UnRef();
}

bool wxLuaState::CloseLuaState(bool force, bool collectGarbage)
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    if (M_WXLSTATEDATA->m_lua_State_static) return true;

    return M_WXLSTATEDATA->CloseLuaState(force, collectGarbage);
}

bool wxLuaState::IsClosing() const
{
    wxCHECK_MSG(m_refData && M_WXLSTATEDATA->m_wxlStateData, false, wxT("Invalid wxLuaState"));
    return M_WXLSTATEDATA->m_wxlStateData->m_is_closing;
}

// --------------------------------------------------------------------------

lua_State* wxLuaState::GetLuaState() const
{
    wxCHECK_MSG(Ok(), NULL, wxT("Invalid wxLuaState"));
    return M_WXLSTATEDATA->m_lua_State;
}

wxLuaStateData* wxLuaState::GetLuaStateData() const
{
    wxCHECK_MSG(m_refData != NULL, NULL, wxT("Invalid wxLuaState, missing ref data"));
    return M_WXLSTATEDATA->m_wxlStateData;
}

wxLuaState wxLuaState::GetwxLuaState(lua_State* L, bool get_root_state) // static function
{
    if (!get_root_state)
    {
        // try our hashtable for faster lookup
        wxHashMapLuaState::iterator it = s_wxHashMapLuaState.find(L);
        if (it != s_wxHashMapLuaState.end())
            return wxLuaState(*it->second);
    }

    // else it's a coroutine? look up the state data from Lua
    wxLuaState* wxlState = NULL;

    // try to get the state we've stored
    lua_pushlightuserdata(L, &wxlua_lreg_wxluastate_key);
    lua_rawget( L, LUA_REGISTRYINDEX );

    // if nothing was returned or it wasn't a ptr, abort
    if ( lua_islightuserdata(L, -1) )
        wxlState = (wxLuaState*)lua_touserdata( L, -1 );

    lua_pop(L, 1); // pop the wxLuaState or nil on failure

    if (!wxlState)
        return wxNullLuaState;

    if (get_root_state || (wxlState->GetLuaState() == L))
    {
        return wxLuaState(*wxlState); // Ref it
    }
    else
    {
        // Create a new wxLuaState for the coroutine and set the wxLuaStateData
        //  to the original wxLuaState's data
        wxLuaStateRefData* refData = new wxLuaStateRefData(false);
        refData->m_lua_State = L;
        refData->m_lua_State_static = true;
        refData->m_lua_State_coroutine = true;

        refData->m_wxlStateData = wxlState->GetLuaStateData();
        refData->m_own_stateData = false;

        wxLuaState wxlState2(false);
        wxlState2.SetRefData(refData);
        return wxlState2;
    }

    return wxNullLuaState;
}

// --------------------------------------------------------------------------

void wxLuaState::SetEventHandler(wxEvtHandler *evtHandler)
{
    wxCHECK_RET(m_refData && M_WXLSTATEDATA->m_wxlStateData, wxT("Invalid wxLuaState"));
    M_WXLSTATEDATA->m_wxlStateData->m_evtHandler = evtHandler;
}
wxEvtHandler *wxLuaState::GetEventHandler() const
{
    wxCHECK_MSG(m_refData && M_WXLSTATEDATA->m_wxlStateData, NULL, wxT("Invalid wxLuaState"));
    return M_WXLSTATEDATA->m_wxlStateData->m_evtHandler;
}

void wxLuaState::SetId(wxWindowID id)
{
    wxCHECK_RET(m_refData && M_WXLSTATEDATA->m_wxlStateData, wxT("Invalid wxLuaState"));
    M_WXLSTATEDATA->m_wxlStateData->m_id = id;
}
wxWindowID  wxLuaState::GetId() const
{
    wxCHECK_MSG(m_refData && M_WXLSTATEDATA->m_wxlStateData, wxID_ANY, wxT("Invalid wxLuaState"));
    return M_WXLSTATEDATA->m_wxlStateData->m_id;
}

bool wxLuaState::SendEvent( wxLuaEvent &event ) const
{
    wxCHECK_MSG(m_refData && M_WXLSTATEDATA->m_wxlStateData, false, wxT("Invalid wxLuaState"));

    if (M_WXLSTATEDATA->m_wxlStateData->m_evtHandler)
    {
        event.SetEventObject( (wxObject*)this );
        return M_WXLSTATEDATA->m_wxlStateData->m_evtHandler->ProcessEvent(event);
    }

    return false;
}

// ----------------------------------------------------------------------------

int wxLuaState::RunFile(const wxString &filename, int nresults)
{
    wxCHECK_MSG(Ok(), LUA_ERRRUN, wxT("Lua interpreter not created"));
    //wxCHECK_MSG(!M_WXLSTATEDATA->m_wxlStateData->m_is_running, LUA_ERRRUN, wxT("Lua interpreter is already running"));

    M_WXLSTATEDATA->m_wxlStateData->m_debug_hook_break = false;
    wxLuaStateRunLocker runLocker(M_WXLSTATEDATA->m_wxlStateData->m_is_running);

    int top = lua_GetTop();
    int status = luaL_LoadFile(wx2lua(filename));
    if (status == 0)
        status = LuaPCall(0, nresults); // no args and nresults
    else
        SendLuaErrorEvent(status, top); // compilation error

    if (nresults == 0)
        lua_SetTop(top); // restore original top (removes err msg)

    M_WXLSTATEDATA->m_wxlStateData->m_debug_hook_break = false;

    return status;
}

int wxLuaState::RunString(const wxString &script, const wxString& name, int nresults)
{
    wxLuaCharBuffer buf(script);
    return RunBuffer(buf.GetData(), buf.Length(), name, nresults);
}

int wxLuaState::RunBuffer(const char buf[], size_t size, const wxString &name, int nresults)
{
    wxCHECK_MSG(Ok(), LUA_ERRRUN, wxT("Invalid wxLuaState"));
    //wxCHECK_MSG(!M_WXLSTATEDATA->m_wxlStateData->m_is_running, LUA_ERRRUN, wxT("Lua interpreter is already running"));

    M_WXLSTATEDATA->m_wxlStateData->m_debug_hook_break = false;
    wxLuaStateRunLocker runLocker(M_WXLSTATEDATA->m_wxlStateData->m_is_running);

    int top = lua_GetTop();
    int status = luaL_LoadBuffer(buf, size, wx2lua(name));
    if (status == 0)
        status = LuaPCall(0, nresults); // no args and nresults
    else
        SendLuaErrorEvent(status, top); // compilation error

    if (nresults == 0)
        lua_SetTop(top); // restore original top (removes err msg)

    M_WXLSTATEDATA->m_wxlStateData->m_debug_hook_break = false;

    return status;
}

bool wxLuaState::IsRunning() const
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return M_WXLSTATEDATA->m_wxlStateData->m_is_running > 0;
}

// this function taken from lua.c, the lua executable
static int LUACALL wxlua_traceback (lua_State *L) {
  if (!lua_isstring(L, 1))  /* 'message' not a string? */
    return 1;  /* keep it intact */
  lua_getglobal(L, "debug");
  if (!lua_istable(L, -1)) {
    lua_pop(L, 1);
  }
  lua_getfield(L, -1, "traceback");
  if (!lua_isfunction(L, -1)) {
    lua_pop(L, 2);
    return 1;
  }
  lua_pushvalue(L, 1);      /* pass error message */
  lua_pushinteger(L, 2);    /* skip this function and traceback */
  lua_call(L, 2, 1);        /* call debug.traceback */
  return 1;
}

int wxLuaState::LuaPCall(int narg, int nresults)
{
    wxCHECK_MSG(Ok(), LUA_ERRRUN, wxT("Invalid wxLuaState"));
    lua_State* L = M_WXLSTATEDATA->m_lua_State;

    int status = 0;
    int top  = lua_gettop(L);
    int base = top - narg;                  // function index

    lua_pushcfunction(L, wxlua_traceback);  // push our traceback function

    lua_insert(L, base);                    // put it under chunk and args
    status = lua_pcall(L, narg, nresults, base);
    lua_remove(L, base);                    // remove traceback function

    if (status != 0)
    {
        SendLuaErrorEvent(status, top - (narg + 1));
        lua_settop(L, top); // restore original top (removes err msg)
    }

    return status;
}

bool wxLuaState::SendLuaErrorEvent(int status, int top)
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    wxString errorMsg;
    int line_num = -1;

    wxlua_errorinfo(GetLuaState(), status, top, &errorMsg, &line_num);

    wxLuaEvent event(wxEVT_LUA_ERROR, GetId(), *this);
    event.SetString(errorMsg);
    event.SetInt(line_num);
    return SendEvent(event);
}

wxEventType wxLuaState::GetInEventType() const
{
    wxCHECK_MSG(Ok(), wxEVT_NULL, wxT("Invalid wxLuaState"));
    return wxlua_getwxeventtype(M_WXLSTATEDATA->m_lua_State);
}

void wxLuaState::SetInEventType(wxEventType eventType)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    wxlua_setwxeventtype(M_WXLSTATEDATA->m_lua_State, eventType);
}

int wxLuaState::CompileString(const wxString &script, const wxString& name, wxString* errMsg_, int* line_num_)
{
    wxLuaCharBuffer buf(script);
    return CompileBuffer(buf.GetData(), buf.Length(), name, errMsg_, line_num_);
}
int wxLuaState::CompileBuffer(const char buf[], size_t size, const wxString &name, wxString* errMsg_, int* line_num_)
{
    // create a new lua_State so we don't mess up our own
    lua_State *L = luaL_newstate();
    luaL_openlibs(L); // load some useful libraries, loads all of them
    int top = lua_gettop(L);
    int status = luaL_loadbuffer(L, (const char*)buf, size, wx2lua(name));
    wxlua_errorinfo(L, status, top, errMsg_, line_num_);
    lua_close(L);
    return status;
}

void wxLuaState::DebugHookBreak(const wxString &msg)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    //wxCHECK_RET(M_WXLSTATEDATA->m_wxlStateData->m_is_running, wxT("Lua interpreter not running"));

    // Lua likes to be stopped within the debug hook, you get funny wxYield
    //  recursion asserts if you call wxlua_Error() within another wxYield, i.e. from a gui button

    M_WXLSTATEDATA->m_wxlStateData->m_debug_hook_break_msg = msg;
    M_WXLSTATEDATA->m_wxlStateData->m_debug_hook_break = true;
    lua_sethook(GetLuaState(), wxlua_debugHookFunction, LUA_MASKCALL|LUA_MASKRET|LUA_MASKLINE|LUA_MASKCOUNT, 1);
    M_WXLSTATEDATA->m_wxlStateData->m_is_running = 0;
}

void wxLuaState::ClearDebugHookBreak()
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));

    M_WXLSTATEDATA->m_wxlStateData->m_debug_hook_break = false;
    SetLuaDebugHook(GetLuaDebugHook(),
                    GetLuaDebugHookCount(),
                    GetLuaDebugHookYield(),
                    GetLuaDebugHookSendEvt());
}

bool wxLuaState::GetDebugHookBreak() const
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return M_WXLSTATEDATA->m_wxlStateData->m_debug_hook_break;
}
wxString wxLuaState::GetDebugHookBreakMessage() const
{
    wxCHECK_MSG(Ok(), wxEmptyString, wxT("Invalid wxLuaState"));
    return M_WXLSTATEDATA->m_wxlStateData->m_debug_hook_break_msg;
}

// ----------------------------------------------------------------------------

void wxLuaState::SetLuaDebugHook(int hook, int count, int yield_ms, bool send_debug_evt)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));

    M_WXLSTATEDATA->m_wxlStateData->m_lua_debug_hook = hook;
    M_WXLSTATEDATA->m_wxlStateData->m_lua_debug_hook_count = count;
    M_WXLSTATEDATA->m_wxlStateData->m_lua_debug_hook_yield = yield_ms;
    M_WXLSTATEDATA->m_wxlStateData->m_lua_debug_hook_send_evt = send_debug_evt;

    // These are the various hooks you can install
    //LUA_MASKCALL, LUA_MASKRET, LUA_MASKLINE, and LUA_MASKCOUNT
    lua_sethook(M_WXLSTATEDATA->m_lua_State, wxlua_debugHookFunction, hook, count);
}

int wxLuaState::GetLuaDebugHook() const
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return M_WXLSTATEDATA->m_wxlStateData->m_lua_debug_hook;
}
int wxLuaState::GetLuaDebugHookCount() const
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return M_WXLSTATEDATA->m_wxlStateData->m_lua_debug_hook_count;
}
int wxLuaState::GetLuaDebugHookYield() const
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return M_WXLSTATEDATA->m_wxlStateData->m_lua_debug_hook_yield;
}
bool wxLuaState::GetLuaDebugHookSendEvt() const
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return M_WXLSTATEDATA->m_wxlStateData->m_lua_debug_hook_send_evt;
}

unsigned long wxLuaState::GetLastLuaDebugHookTime() const
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return M_WXLSTATEDATA->m_wxlStateData->m_last_debug_hook_time;
}
void wxLuaState::SetLastLuaDebugHookTime(unsigned long t)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    M_WXLSTATEDATA->m_wxlStateData->m_last_debug_hook_time = t;
}

// ----------------------------------------------------------------------------

void wxLuaState::RegisterFunction(lua_CFunction func, const char* funcName)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_register( M_WXLSTATEDATA->m_lua_State, funcName, func );
}

bool wxLuaState::RegisterBinding(wxLuaBinding* binding)
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    wxCHECK_MSG(binding, false, wxT("Invalid wxLuaState"));

    wxLuaBinding::InitAllBindings(); // only runs the first time through

    bool ret = binding->RegisterBinding(*this);
    if (ret) lua_Pop(1);

    return ret;
}

bool wxLuaState::RegisterBindings()
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));

    return wxLuaBinding::RegisterBindings(*this);
}

wxLuaBinding* wxLuaState::GetLuaBinding(const wxString& bindingName) const
{
    wxCHECK_MSG(GetRefData() != NULL, NULL, wxT("Invalid wxLuaState"));
    return wxLuaBinding::GetLuaBinding(bindingName);
}

const wxLuaBindClass* wxLuaState::GetBindClass(int wxluatype) const
{
    wxCHECK_MSG(Ok(), NULL, wxT("Invalid wxLuaState"));

    // try to get the wxLuaBindClass from the Lua registry table first
    const wxLuaBindClass* wxlClass = wxluaT_getclass(M_WXLSTATEDATA->m_lua_State, wxluatype);

    // we shouldn't ever need this code
    if (wxlClass == NULL)
        wxlClass = wxLuaBinding::FindBindClass(wxluatype);

    return wxlClass;
}
const wxLuaBindClass* wxLuaState::GetBindClass(const char* className) const
{
    wxCHECK_MSG(Ok(), NULL, wxT("Invalid wxLuaState"));
    return wxluaT_getclass(M_WXLSTATEDATA->m_lua_State, className);
}
const wxLuaBindClass* wxLuaState::GetBindClass(const wxLuaBindMethod* wxlMethod) const
{
    wxCHECK_MSG(GetRefData() != NULL, NULL, wxT("Invalid wxLuaState"));
    return wxLuaBinding::FindBindClass(wxlMethod);
}
const wxLuaBindClass* wxLuaState::GetBindClass(const wxLuaBindCFunc* wxlClass) const
{
    wxCHECK_MSG(GetRefData() != NULL, NULL, wxT("Invalid wxLuaState"));
    return wxLuaBinding::FindBindClass(wxlClass);
}

int wxLuaState::IsDerivedType(int wxl_type, int base_wxl_type, int* baseclass_n) const
{
    wxCHECK_MSG(Ok(), -1, wxT("Invalid wxLuaState"));
    return wxluaT_isderivedtype(M_WXLSTATEDATA->m_lua_State, wxl_type, base_wxl_type, baseclass_n);
}

void wxLuaState::SetCallBaseClassFunction(bool call_base)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    wxlua_setcallbaseclassfunction(M_WXLSTATEDATA->m_lua_State, call_base);
}
bool wxLuaState::GetCallBaseClassFunction()
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return wxlua_getcallbaseclassfunction(M_WXLSTATEDATA->m_lua_State);
}

// ----------------------------------------------------------------------------
// memory tracking functions

void wxLuaState::AddGCObject(void* obj_ptr, int wxl_type)
{
    wxCHECK_RET(Ok() && obj_ptr, wxT("Invalid wxLuaState or wxObject to track"));
    wxluaO_addgcobject(M_WXLSTATEDATA->m_lua_State, obj_ptr, wxl_type);
}

bool wxLuaState::DeleteGCObject(int stack_idx, int flags)
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState or object"));
    return wxluaO_deletegcobject(M_WXLSTATEDATA->m_lua_State, stack_idx, flags);
}

bool wxLuaState::IsGCObject(void *obj_ptr) const
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return wxluaO_isgcobject(M_WXLSTATEDATA->m_lua_State, obj_ptr);
}

wxArrayString wxLuaState::GetGCObjectInfo() const
{
    wxCHECK_MSG(Ok(), wxArrayString(), wxT("Invalid wxLuaState"));
    return wxluaO_getgcobjectinfo(M_WXLSTATEDATA->m_lua_State);
}

void wxLuaState::AddTrackedWindow(wxObject *obj)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    wxluaW_addtrackedwindow(M_WXLSTATEDATA->m_lua_State, obj);
}

void wxLuaState::RemoveTrackedWindow(wxWindow *win)
{
    wxCHECK_RET(Ok() && win, wxT("Invalid wxLuaState or wxWindow"));
    wxluaW_removetrackedwindow(M_WXLSTATEDATA->m_lua_State, win);
}

bool wxLuaState::IsTrackedWindow(wxWindow *win, bool check_parents) const
{
    wxCHECK_MSG(Ok() && win, false, wxT("Invalid wxLuaState or wxWindow"));
    return wxluaW_istrackedwindow(M_WXLSTATEDATA->m_lua_State, win, check_parents);
}

wxArrayString wxLuaState::GetTrackedWindowInfo() const
{
    wxCHECK_MSG(Ok(), wxArrayString(), wxT("Invalid wxLuaState"));
    return wxluaW_gettrackedwindowinfo(M_WXLSTATEDATA->m_lua_State);
}

void wxLuaState::GarbageCollectWindows(bool closeWindows)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    // remove deleted windows
    wxLuaCleanupWindows(M_WXLSTATEDATA->m_lua_State, !closeWindows);
}

void wxLuaState::AddTrackedEventCallback(wxLuaEventCallback* callback)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_State* L = M_WXLSTATEDATA->m_lua_State;

    lua_pushlightuserdata(L, &wxlua_lreg_evtcallbacks_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                       // pop key, push value (table)

    lua_pushlightuserdata(L, callback);                  // push key
    lua_pushlightuserdata(L, callback->GetEvtHandler()); // push value
    lua_rawset(L, -3); // set t[key] = value; pops key and value

    lua_pop(L, 1);     // pop table
}
bool wxLuaState::RemoveTrackedEventCallback(wxLuaEventCallback* callback)
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    lua_State* L = M_WXLSTATEDATA->m_lua_State;

    lua_pushlightuserdata(L, &wxlua_lreg_evtcallbacks_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                       // pop key, push value (table)

    lua_pushlightuserdata(L, callback); // push key
    lua_pushnil(L);                     // push value
    lua_rawset(L, -3); // set t[key] = value; pops key and value

    lua_pop(L, 1);     // pop table

    return true; // FIXME return a real value
}

wxArrayString wxLuaState::GetTrackedEventCallbackInfo() const
{
    wxArrayString names;

    wxCHECK_MSG(Ok(), names, wxT("Invalid wxLuaState"));
    lua_State* L = M_WXLSTATEDATA->m_lua_State;

    lua_pushlightuserdata(L, &wxlua_lreg_evtcallbacks_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                       // pop key, push value (table)

    lua_pushnil(L);
    while (lua_next(L, -2) != 0)
    {
        // value = -1, key = -2, table = -3
        wxLuaEventCallback* wxlCallback = (wxLuaEventCallback*)lua_touserdata(L, -2);
        wxCHECK_MSG(wxlCallback, names, wxT("Invalid wxLuaEventCallback"));

        names.Add(wxlCallback->GetInfo());

        lua_pop(L, 1); // pop value, lua_next will pop key at end
    }

    lua_pop(L, 1); // pop table

    names.Sort();
    return names;
}

void wxLuaState::AddTrackedWinDestroyCallback(wxLuaWinDestroyCallback* callback)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_State* L = M_WXLSTATEDATA->m_lua_State;

    lua_pushlightuserdata(L, &wxlua_lreg_windestroycallbacks_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                              // pop key, push value (table)

    lua_pushlightuserdata(L, callback->GetWindow()); // push key
    lua_pushlightuserdata(L, callback);              // push value
    lua_rawset(L, -3); // set t[key] = value; pops key and value

    lua_pop(L, 1);     // pop table
}
bool wxLuaState::RemoveTrackedWinDestroyCallback(wxLuaWinDestroyCallback* callback)
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    lua_State* L = M_WXLSTATEDATA->m_lua_State;

    lua_pushlightuserdata(L, &wxlua_lreg_windestroycallbacks_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                              // pop key, push value (table)

    lua_pushlightuserdata(L, callback->GetWindow()); // push key
    lua_pushnil(L);                                  // push value
    lua_rawset(L, -3); // set t[key] = value; pops key and value

    lua_pop(L, 1);     // pop table

    return true; // FIXME return if it was here or not
}

wxArrayString wxLuaState::GetTrackedWinDestroyCallbackInfo() const
{
    wxArrayString names;

    wxCHECK_MSG(Ok(), names, wxT("Invalid wxLuaState"));
    lua_State* L = M_WXLSTATEDATA->m_lua_State;

    lua_pushlightuserdata(L, &wxlua_lreg_windestroycallbacks_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                              // pop key, push value (table)

    lua_pushnil(L);
    while (lua_next(L, -2) != 0)
    {
        // value = -1, key = -2, table = -3
        wxLuaWinDestroyCallback* wxlDestroyCallBack = (wxLuaWinDestroyCallback*)lua_touserdata(L, -1);
        wxCHECK_MSG(wxlDestroyCallBack, names, wxT("Invalid wxLuaWinDestroyCallback"));

        names.Add(wxlDestroyCallBack->GetInfo());

        lua_pop(L, 1); // pop value, lua_next will pop key at end
    }

    names.Sort();
    return names;
}

// ----------------------------------------------------------------------------

void wxLuaState::wxlua_Error(const char *errorMsg) const
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    wxlua_error(M_WXLSTATEDATA->m_lua_State, errorMsg);
}

void* wxLuaState::wxlua_ToUserdata(int stack_idx, bool reset /* = false*/) const
{
    wxCHECK_MSG(Ok(), NULL, wxT("Invalid wxLuaState"));
    return wxlua_touserdata(M_WXLSTATEDATA->m_lua_State, stack_idx, reset);
}

// ----------------------------------------------------------------------------
// wxLua Lua Registry Table Functions

int wxLuaState::wxluaR_Ref(int stack_idx, void* lightuserdata_reg_key)
{
    wxCHECK_MSG(Ok(), LUA_REFNIL, wxT("Invalid wxLuaState"));
    return wxluaR_ref(M_WXLSTATEDATA->m_lua_State, stack_idx, lightuserdata_reg_key);
}

bool wxLuaState::wxluaR_Unref(int wxlref_index, void* lightuserdata_reg_key)
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return wxluaR_unref(M_WXLSTATEDATA->m_lua_State, wxlref_index, lightuserdata_reg_key);
}

bool wxLuaState::wxluaR_GetRef(int wxlref_index, void* lightuserdata_reg_key)
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return wxluaR_getref(M_WXLSTATEDATA->m_lua_State, wxlref_index, lightuserdata_reg_key);
}

// ----------------------------------------------------------------------------

int wxLuaState::wxluaT_NewMetatable(int wxl_type)
{
    wxCHECK_MSG(Ok(), WXLUA_TUNKNOWN, wxT("Invalid wxLuaState"));
    return wxluaT_newmetatable(M_WXLSTATEDATA->m_lua_State, wxl_type);
}

bool wxLuaState::wxluaT_SetMetatable(int wxl_type)
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return wxluaT_setmetatable(M_WXLSTATEDATA->m_lua_State, wxl_type);
}

int wxLuaState::wxluaT_Type(int stack_idx) const
{
    wxCHECK_MSG(Ok(), WXLUA_TUNKNOWN, wxT("Invalid wxLuaState"));
    return wxluaT_type(M_WXLSTATEDATA->m_lua_State, stack_idx);
}

bool wxLuaState::wxluaT_PushUserDataType(const void *obj_ptr, int wxl_type, bool track)
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return wxluaT_pushuserdatatype(M_WXLSTATEDATA->m_lua_State, obj_ptr, wxl_type, track);
}

// ----------------------------------------------------------------------------
// wxLua get data type

int wxLuaState::IswxLuaType(int luatype, int wxl_type) const
{
    wxCHECK_MSG(Ok(), -1, wxT("Invalid wxLuaState"));
    return wxlua_iswxluatype(luatype, wxl_type, M_WXLSTATEDATA->m_lua_State);
}

bool wxLuaState::IsUserDataType(int stack_idx, int wxl_type) const
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return wxluaT_isuserdatatype(M_WXLSTATEDATA->m_lua_State, stack_idx, wxl_type);
}

void* wxLuaState::GetUserDataType(int stack_idx, int wxl_type) const
{
    wxCHECK_MSG(Ok(), NULL, wxT("Invalid wxLuaState"));
    return wxluaT_getuserdatatype(M_WXLSTATEDATA->m_lua_State, stack_idx, wxl_type);
}

const char* wxLuaState::GetStringType(int stack_idx)
{
    wxCHECK_MSG(Ok(), NULL, wxT("Invalid wxLuaState"));
    return wxlua_getstringtype(M_WXLSTATEDATA->m_lua_State, stack_idx);
}
wxString wxLuaState::GetwxStringType(int stack_idx)
{
    wxCHECK_MSG(Ok(), wxEmptyString, wxT("Invalid wxLuaState"));
    return wxlua_getwxStringtype(M_WXLSTATEDATA->m_lua_State, stack_idx);
}
bool wxLuaState::GetBooleanType(int stack_idx)
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return wxlua_getbooleantype(M_WXLSTATEDATA->m_lua_State, stack_idx);
}
long wxLuaState::GetIntegerType(int stack_idx)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return wxlua_getintegertype(M_WXLSTATEDATA->m_lua_State, stack_idx);
}
double wxLuaState::GetNumberType(int stack_idx)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return wxlua_getnumbertype(M_WXLSTATEDATA->m_lua_State, stack_idx);
}

bool wxLuaState::IsStringType(int stack_idx) const
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return wxlua_isstringtype(M_WXLSTATEDATA->m_lua_State, stack_idx);
}

bool wxLuaState::IswxStringType(int stack_idx) const
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return wxlua_iswxstringtype(M_WXLSTATEDATA->m_lua_State, stack_idx);
}

bool wxLuaState::IsBooleanType(int stack_idx) const
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return wxlua_isbooleantype(M_WXLSTATEDATA->m_lua_State, stack_idx);
}
bool wxLuaState::IsIntegerType(int stack_idx) const
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return wxlua_isintegertype(M_WXLSTATEDATA->m_lua_State, stack_idx);
}
bool wxLuaState::IsNumberType(int stack_idx) const
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return wxlua_isnumbertype(M_WXLSTATEDATA->m_lua_State, stack_idx);
}

wxString* wxLuaState::GetwxStringArray(int stack_idx, int &count)
{
    wxCHECK_MSG(Ok(), NULL, wxT("Invalid wxLuaState"));
    return wxlua_getwxStringarray(M_WXLSTATEDATA->m_lua_State, stack_idx, count);
}

wxLuaSmartwxArrayString wxLuaState::GetwxArrayString(int stack_idx)
{
    wxCHECK_MSG(Ok(), wxLuaSmartwxArrayString(NULL, true), wxT("Invalid wxLuaState"));
    return wxlua_getwxArrayString(M_WXLSTATEDATA->m_lua_State, stack_idx);
}

const char** wxLuaState::GetCharArray(int stack_idx, int &count)
{
    wxCHECK_MSG(Ok(), NULL, wxT("Invalid wxLuaState"));
    return wxlua_getchararray(M_WXLSTATEDATA->m_lua_State, stack_idx, count);
}

int wxLuaState::PushwxArrayStringTable(const wxArrayString &strArray)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return wxlua_pushwxArrayStringtable(M_WXLSTATEDATA->m_lua_State, strArray);
}

int wxLuaState::PushwxArrayIntTable(const wxArrayInt &intArray)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return wxlua_pushwxArrayInttable(M_WXLSTATEDATA->m_lua_State, intArray);
}

int* wxLuaState::GetIntArray(int stack_idx, int &count)
{
    wxCHECK_MSG(Ok(), NULL, wxT("Invalid wxLuaState"));
    return wxlua_getintarray(M_WXLSTATEDATA->m_lua_State, stack_idx, count);
}

wxLuaSmartwxArrayInt wxLuaState::GetwxArrayInt(int stack_idx)
{
    wxCHECK_MSG(Ok(), wxLuaSmartwxArrayInt(NULL, true), wxT("Invalid wxLuaState"));
    return wxlua_getwxArrayInt(M_WXLSTATEDATA->m_lua_State, stack_idx);
}

wxString wxLuaState::GetwxLuaTypeName(int wxl_type) const
{
    wxCHECK_MSG(Ok(), wxEmptyString, wxT("Invalid wxLuaState"));
    return wxluaT_typename(M_WXLSTATEDATA->m_lua_State, wxl_type);
}

bool wxLuaState::SetDerivedMethod(void *obj_ptr, const char *method_name, wxLuaObject* wxlObj)
{
    wxCHECK_MSG(Ok() && obj_ptr, false, wxT("Invalid wxLuaState or object to set derived method for."));
    return wxlua_setderivedmethod(M_WXLSTATEDATA->m_lua_State, obj_ptr, method_name, wxlObj);
}

bool wxLuaState::HasDerivedMethod(const void *obj_ptr, const char *method_name, bool push_method) const
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return wxlua_hasderivedmethod(M_WXLSTATEDATA->m_lua_State, obj_ptr, method_name, push_method);
}

bool wxLuaState::RemoveDerivedMethods(void *obj_ptr) const
{
    wxCHECK_MSG(Ok() && obj_ptr, false, wxT("Invalid wxLuaState or object to remove."));
    return wxlua_removederivedmethods(M_WXLSTATEDATA->m_lua_State, obj_ptr);
}

wxLuaState wxLuaState::GetDerivedMethodState(void *obj_ptr, const char *method_name)
{
    wxCHECK_MSG(obj_ptr, wxNullLuaState, wxT("Invalid object to wxLuaState::GetDerivedMethod"));

    wxHashMapLuaState::iterator it;
    for (it = wxLuaState::s_wxHashMapLuaState.begin();
         it != wxLuaState::s_wxHashMapLuaState.end(); ++it)
    {
        wxLuaState wxlState(*(wxLuaState*)it->second);
        if (wxlState.HasDerivedMethod(obj_ptr, method_name, false))
            return wxlState;
    }

    return wxNullLuaState;
}

// ----------------------------------------------------------------------------
// Raw basic Lua stack functions.

int wxLuaState::lua_GetTop() const
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_gettop(M_WXLSTATEDATA->m_lua_State);
}
void wxLuaState::lua_SetTop(int index)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_settop(M_WXLSTATEDATA->m_lua_State, index);
}
void wxLuaState::lua_PushValue(int index)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_pushvalue(M_WXLSTATEDATA->m_lua_State, index);
}
void wxLuaState::lua_Remove(int index)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_remove(M_WXLSTATEDATA->m_lua_State, index);
}
void wxLuaState::lua_Pop(int count) const
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_pop(M_WXLSTATEDATA->m_lua_State, count);
}
void wxLuaState::lua_Insert(int index)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_insert(M_WXLSTATEDATA->m_lua_State, index);
}
void wxLuaState::lua_Replace(int index)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_replace(M_WXLSTATEDATA->m_lua_State, index);
}
int wxLuaState::lua_CheckStack(int size)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_checkstack(M_WXLSTATEDATA->m_lua_State, size);
}
void wxLuaState::lua_XMove(const wxLuaState& to, int n)
{
    wxCHECK_RET(Ok() && to.Ok(), wxT("Invalid wxLuaState"));
    lua_xmove(M_WXLSTATEDATA->m_lua_State, to.GetLuaState(), n);
}

// ----------------------------------------------------------------------------
// access functions (stack -> C)

bool wxLuaState::lua_IsNumber(int index) const
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return lua_isnumber(M_WXLSTATEDATA->m_lua_State, index) != 0;
}
bool wxLuaState::lua_IsString(int index) const
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return lua_isstring(M_WXLSTATEDATA->m_lua_State, index) != 0;
}
bool wxLuaState::lua_IsCFunction(int index) const
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return lua_iscfunction(M_WXLSTATEDATA->m_lua_State, index) != 0;
}
bool wxLuaState::lua_IsUserdata(int index) const
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return lua_isuserdata(M_WXLSTATEDATA->m_lua_State, index) != 0;
}
int wxLuaState::lua_Type(int index) const
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_type(M_WXLSTATEDATA->m_lua_State, index);
}
wxString wxLuaState::lua_TypeName(int type) const
{
    wxCHECK_MSG(Ok(), wxEmptyString, wxT("Invalid wxLuaState"));
    return lua2wx(lua_typename(M_WXLSTATEDATA->m_lua_State, type));
}

int wxLuaState::lua_Equal(int index1, int index2) const
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_equal(M_WXLSTATEDATA->m_lua_State, index1, index2);
}
int wxLuaState::lua_RawEqual(int index1, int index2) const
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_rawequal(M_WXLSTATEDATA->m_lua_State, index1, index2);
}
int wxLuaState::lua_LessThan(int index1, int index2) const
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_lessthan(M_WXLSTATEDATA->m_lua_State, index1, index2);
}

double wxLuaState::lua_ToNumber(int index) const
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_tonumber(M_WXLSTATEDATA->m_lua_State, index);
}
int wxLuaState::lua_ToInteger(int index) const
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_tointeger(M_WXLSTATEDATA->m_lua_State, index);
}
int wxLuaState::lua_ToBoolean(int index) const
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_toboolean(M_WXLSTATEDATA->m_lua_State, index);
}
const char* wxLuaState::lua_ToString(int index) const
{
    wxCHECK_MSG(Ok(), NULL, wxT("Invalid wxLuaState"));
    return lua_tostring(M_WXLSTATEDATA->m_lua_State, index);
}
wxString wxLuaState::lua_TowxString(int index) const
{
    wxCHECK_MSG(Ok(), wxEmptyString, wxT("Invalid wxLuaState"));
    return lua2wx(lua_tostring(M_WXLSTATEDATA->m_lua_State, index));
}
size_t wxLuaState::lua_StrLen(int index) const
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_strlen(M_WXLSTATEDATA->m_lua_State, index);
}
size_t wxLuaState::luaL_ObjLen(int t) const
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_objlen(M_WXLSTATEDATA->m_lua_State, t);
}
lua_CFunction wxLuaState::lua_ToCFunction(int index) const
{
    wxCHECK_MSG(Ok(), NULL, wxT("Invalid wxLuaState"));
    return lua_tocfunction(M_WXLSTATEDATA->m_lua_State, index);
}
void *wxLuaState::lua_ToUserdata(int index) const
{
    wxCHECK_MSG(Ok(), NULL, wxT("Invalid wxLuaState"));
    return lua_touserdata(M_WXLSTATEDATA->m_lua_State, index);
}
wxLuaState wxLuaState::lua_ToThread(int index) const
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return wxLuaState(lua_tothread(M_WXLSTATEDATA->m_lua_State, index));
}
const void* wxLuaState::lua_ToPointer(int index) const
{
    wxCHECK_MSG(Ok(), NULL, wxT("Invalid wxLuaState"));
    return lua_topointer(M_WXLSTATEDATA->m_lua_State, index);
}

// ----------------------------------------------------------------------------
// Raw Lua push functions (C -> stack)

void wxLuaState::lua_PushNil()
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_pushnil(M_WXLSTATEDATA->m_lua_State);
}
void wxLuaState::lua_PushNumber(lua_Number n)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_pushnumber(M_WXLSTATEDATA->m_lua_State, n);
}
void wxLuaState::lua_PushInteger(lua_Integer n)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_pushinteger(M_WXLSTATEDATA->m_lua_State, n);
}
void wxLuaState::lua_PushLString(const char* s, size_t len)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_pushlstring(M_WXLSTATEDATA->m_lua_State, s, len);
}
void wxLuaState::lua_PushString(const char* s)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_pushstring(M_WXLSTATEDATA->m_lua_State, s);
}
void wxLuaState::lua_PushCClosure(lua_CFunction fn, int n)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_pushcclosure(M_WXLSTATEDATA->m_lua_State, fn, n);
}
void wxLuaState::lua_PushBoolean(bool b)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_pushboolean(M_WXLSTATEDATA->m_lua_State, b ? 1 : 0);
}
void wxLuaState::lua_PushLightUserdata(void* p)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_pushlightuserdata(M_WXLSTATEDATA->m_lua_State, p);
}

// ----------------------------------------------------------------------------
// Raw Lua get functions (Lua -> stack)

void wxLuaState::lua_GetTable(int idx)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_gettable(M_WXLSTATEDATA->m_lua_State, idx);
}
void wxLuaState::lua_GetField(int idx, const char* k)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_getfield(M_WXLSTATEDATA->m_lua_State, idx, k);
}
void wxLuaState::lua_RawGet(int idx)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_rawget(M_WXLSTATEDATA->m_lua_State, idx);
}
void wxLuaState::lua_RawGeti(int idx, int n)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_rawgeti(M_WXLSTATEDATA->m_lua_State, idx, n);
}
void wxLuaState::lua_CreateTable(int narr, int nrec)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_createtable(M_WXLSTATEDATA->m_lua_State, narr, nrec);
}
void wxLuaState::lua_NewTable()
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_newtable(M_WXLSTATEDATA->m_lua_State);
}
void* wxLuaState::lua_NewUserdata(size_t sz)
{
    wxCHECK_MSG(Ok(), NULL, wxT("Invalid wxLuaState"));
    return lua_newuserdata(M_WXLSTATEDATA->m_lua_State, sz);
}
int wxLuaState::lua_GetMetatable(int objindex)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_getmetatable(M_WXLSTATEDATA->m_lua_State, objindex);
}

#if LUA_VERSION_NUM < 502
void wxLuaState::lua_GetFenv(int idx)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_getfenv(M_WXLSTATEDATA->m_lua_State, idx);
}
#endif // LUA_VERSION_NUM < 502

// -----------------------------------------------------------------------
// Raw Lua set functions (stack -> Lua)

void wxLuaState::lua_SetTable(int idx)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_settable(M_WXLSTATEDATA->m_lua_State, idx);
}
void wxLuaState::lua_SetField(int idx, const char* k)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_setfield(M_WXLSTATEDATA->m_lua_State, idx, k);
}
void wxLuaState::lua_RawSet(int idx)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_rawset(M_WXLSTATEDATA->m_lua_State, idx);
}
void wxLuaState::lua_RawSeti(int idx, int n)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_rawseti(M_WXLSTATEDATA->m_lua_State, idx, n);
}
int wxLuaState::lua_SetMetatable(int objindex)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_setmetatable(M_WXLSTATEDATA->m_lua_State, objindex);
}

#if LUA_VERSION_NUM < 502
int wxLuaState::lua_SetFenv(int idx)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_setfenv(M_WXLSTATEDATA->m_lua_State, idx);
}
#endif // LUA_VERSION_NUM < 502

// ----------------------------------------------------------------------------
// Raw Lua `load' and `call' functions (load and run Lua code)

void wxLuaState::lua_Call(int nargs, int nresults)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_call(M_WXLSTATEDATA->m_lua_State, nargs, nresults);
}
int wxLuaState::lua_PCall(int nargs, int nresults, int errfunc)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_pcall(M_WXLSTATEDATA->m_lua_State, nargs, nresults, errfunc);
}
int wxLuaState::lua_CPCall(lua_CFunction func, void *ud)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
#if LUA_VERSION_NUM >= 503
    lua_pushcfunction(M_WXLSTATEDATA->m_lua_State, func);
    lua_pushlightuserdata(M_WXLSTATEDATA->m_lua_State, ud);
    return lua_pcall(M_WXLSTATEDATA->m_lua_State, 1, 0, 0);
#else
    return lua_cpcall(M_WXLSTATEDATA->m_lua_State, func, ud);
#endif
}
#if LUA_VERSION_NUM < 502
int  wxLuaState::lua_Load(lua_Reader reader, void *dt, const char* chunkname)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_load(M_WXLSTATEDATA->m_lua_State, reader, dt, chunkname);
}
#else
int  wxLuaState::lua_Load(lua_Reader reader, void *dt, const char* chunkname, const char* mode)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_load(M_WXLSTATEDATA->m_lua_State, reader, dt, chunkname, mode);
}
#endif // LUA_VERSION_NUM < 502
int wxLuaState::lua_Dump(lua_Writer writer, void *data)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_dump(M_WXLSTATEDATA->m_lua_State, writer, data
    // Lua 5.3+ requires additional parameter `int strip`
#if LUA_VERSION_NUM >= 503
      , 0
#endif
    );
}

// ----------------------------------------------------------------------------
// Raw Lua coroutine functions

int wxLuaState::lua_Yield(int nresults)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_yield(M_WXLSTATEDATA->m_lua_State, nresults);
}

#if LUA_VERSION_NUM < 502
int wxLuaState::lua_Resume(int narg)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_resume(M_WXLSTATEDATA->m_lua_State, narg);
}
#endif // LUA_VERSION_NUM < 502

int wxLuaState::lua_Status()
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_status(M_WXLSTATEDATA->m_lua_State);
}

// ----------------------------------------------------------------------------
// Raw Lua garbage-collection functions

int wxLuaState::lua_GC(int what, int data)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_gc(M_WXLSTATEDATA->m_lua_State, what, data);
}

// ----------------------------------------------------------------------------
// Raw Lua miscellaneous functions

wxString wxLuaState::lua_Version() const
{
    return lua2wx(LUA_VERSION);
}
int wxLuaState::lua_Error()
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_error(M_WXLSTATEDATA->m_lua_State);
}
int wxLuaState::lua_Next(int idx)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_next(M_WXLSTATEDATA->m_lua_State, idx);
}
void wxLuaState::lua_Concat(int n)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_concat(M_WXLSTATEDATA->m_lua_State, n);
}

// -----------------------------------------------------------------------
// Raw Lua some useful "macros", lua.h

void wxLuaState::lua_Register(const char* funcName, lua_CFunction f)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_register(M_WXLSTATEDATA->m_lua_State, funcName, f);
}
void wxLuaState::lua_PushCFunction(lua_CFunction f)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_pushcfunction(M_WXLSTATEDATA->m_lua_State, f);
}

bool wxLuaState::lua_IsFunction(int idx) const
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return lua_isfunction(M_WXLSTATEDATA->m_lua_State, idx);
}
bool wxLuaState::lua_IsTable(int idx) const
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return lua_istable(M_WXLSTATEDATA->m_lua_State, idx);
}
bool wxLuaState::lua_IsLightUserdata(int idx) const
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return lua_islightuserdata(M_WXLSTATEDATA->m_lua_State, idx);
}
bool wxLuaState::lua_IsNil(int idx) const
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return lua_isnil(M_WXLSTATEDATA->m_lua_State, idx);
}
bool wxLuaState::lua_IsBoolean(int idx) const
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return lua_isboolean(M_WXLSTATEDATA->m_lua_State, idx);
}
bool wxLuaState::lua_IsThread(int idx) const
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return lua_isthread(M_WXLSTATEDATA->m_lua_State, idx);
}
bool wxLuaState::lua_IsNone(int idx) const
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return lua_isnone(M_WXLSTATEDATA->m_lua_State, idx);
}
bool wxLuaState::lua_IsNoneOrNil(int idx) const
{
    wxCHECK_MSG(Ok(), false, wxT("Invalid wxLuaState"));
    return lua_isnoneornil(M_WXLSTATEDATA->m_lua_State, idx);
}

void wxLuaState::lua_SetGlobal(const char* s)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_setglobal(M_WXLSTATEDATA->m_lua_State, s);
}
void wxLuaState::lua_GetGlobal(const char* s)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_getglobal(M_WXLSTATEDATA->m_lua_State, s);
}

// ----------------------------------------------------------------------------
// Raw Lua Debug functions, lua.h

int wxLuaState::lua_GetStack(int level, lua_Debug* ar)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_getstack(M_WXLSTATEDATA->m_lua_State, level, ar);
}
int wxLuaState::lua_GetInfo(const char* what, lua_Debug* ar)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_getinfo(M_WXLSTATEDATA->m_lua_State, what, ar);
}
const char* wxLuaState::lua_GetLocal(const lua_Debug* ar, int n)
{
    wxCHECK_MSG(Ok(), NULL, wxT("Invalid wxLuaState"));
    return lua_getlocal(M_WXLSTATEDATA->m_lua_State, ar, n);
}
const char* wxLuaState::lua_SetLocal(const lua_Debug* ar, int n)
{
    wxCHECK_MSG(Ok(), NULL, wxT("Invalid wxLuaState"));
    return lua_setlocal(M_WXLSTATEDATA->m_lua_State, ar, n);
}
const char* wxLuaState::lua_GetUpvalue(int funcindex, int n)
{
    wxCHECK_MSG(Ok(), NULL, wxT("Invalid wxLuaState"));
    return lua_getupvalue(M_WXLSTATEDATA->m_lua_State, funcindex, n);
}
const char* wxLuaState::lua_SetUpvalue(int funcindex, int n)
{
    wxCHECK_MSG(Ok(), NULL, wxT("Invalid wxLuaState"));
    return lua_setupvalue(M_WXLSTATEDATA->m_lua_State, funcindex, n);
}

void wxLuaState::lua_SetHook(lua_Hook func, int mask, int count)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_sethook(M_WXLSTATEDATA->m_lua_State, func, mask, count);
    // lua_sethook returns 1 for lua 5.1 & 5.2
    // lua_sethook is void in 5.3+
}

lua_Hook wxLuaState::lua_GetHook()
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_gethook(M_WXLSTATEDATA->m_lua_State);
}
int wxLuaState::lua_GetHookMask()
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_gethookmask(M_WXLSTATEDATA->m_lua_State);
}
int wxLuaState::lua_GetHookCount()
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return lua_gethookcount(M_WXLSTATEDATA->m_lua_State);
}

// ----------------------------------------------------------------------------
// Raw Lua auxlib functions, lauxlib.h

#if LUA_VERSION_NUM >= 503
extern "C" {
    static int create_table(lua_State *L) {
        lua_newtable(L);
        return 1;    
    }
}
#endif
void wxLuaState::luaL_Register(lua_State *L, const char *libname, const luaL_Reg *l)
{
#if LUA_VERSION_NUM >= 503
    // Do NOT use luaL_requiref with lua5.2, because with lua5.2 luaL_requiref always creates new module!
    // lua5.3 luaL_requiref creates new modul only if modname is not already present in package.loaded
    // call luaL_requiref with glb=true -> stores the module into global modname for backwards compatibility.
    luaL_requiref(L, libname, create_table, 1);
    luaL_setfuncs(L, l, 0);
#else
    luaL_register(L, libname, l);
#endif
}
void wxLuaState::luaL_Register(const char *libname, const luaL_Reg *l)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));

    wxLuaState::luaL_Register(M_WXLSTATEDATA->m_lua_State, libname, l);
}
int wxLuaState::luaL_GetMetafield(int obj, const char *e)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return luaL_getmetafield(M_WXLSTATEDATA->m_lua_State, obj, e);
}
int wxLuaState::luaL_CallMeta(int obj, const char *e)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return luaL_callmeta(M_WXLSTATEDATA->m_lua_State, obj, e);
}
#if LUA_VERSION_NUM < 502
int wxLuaState::luaL_TypeError(int narg, const char *tname)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return luaL_typerror(M_WXLSTATEDATA->m_lua_State, narg, tname);
}
#endif // LUA_VERSION_NUM < 502
int wxLuaState::luaL_ArgError(int numarg, const char *extramsg)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return luaL_argerror(M_WXLSTATEDATA->m_lua_State, numarg, extramsg);
}
const char* wxLuaState::luaL_CheckLString(int numArg, size_t *l)
{
    wxCHECK_MSG(Ok(), NULL, wxT("Invalid wxLuaState"));
    return luaL_checklstring(M_WXLSTATEDATA->m_lua_State, numArg, l);
}
const char* wxLuaState::luaL_OptLString(int numArg, const char *def, size_t *l)
{
    wxCHECK_MSG(Ok(), NULL, wxT("Invalid wxLuaState"));
    return luaL_optlstring(M_WXLSTATEDATA->m_lua_State, numArg, def, l);
}
lua_Number wxLuaState::luaL_CheckNumber(int numArg)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return luaL_checknumber(M_WXLSTATEDATA->m_lua_State, numArg);
}
lua_Number wxLuaState::luaL_OptNumber(int nArg, lua_Number def)
{
    wxCHECK_MSG(Ok(), def, wxT("Invalid wxLuaState"));
    return luaL_optnumber(M_WXLSTATEDATA->m_lua_State, nArg, def);
}
lua_Integer wxLuaState::luaL_CheckInteger(int numArg)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return luaL_checkinteger(M_WXLSTATEDATA->m_lua_State, numArg);
}
lua_Integer wxLuaState::luaL_OptInteger(int nArg, lua_Integer def)
{
    wxCHECK_MSG(Ok(), def, wxT("Invalid wxLuaState"));
    return luaL_optinteger(M_WXLSTATEDATA->m_lua_State, nArg, def);
}

void wxLuaState::luaL_CheckStack(int sz, const char *msg)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    luaL_checkstack(M_WXLSTATEDATA->m_lua_State, sz, msg);
}
void wxLuaState::luaL_CheckType(int narg, int t)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    luaL_checktype(M_WXLSTATEDATA->m_lua_State, narg, t);
}
void wxLuaState::luaL_CheckAny(int narg)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    luaL_checkany(M_WXLSTATEDATA->m_lua_State, narg);
}

int   wxLuaState::luaL_NewMetatable(const char *tname)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return luaL_newmetatable(M_WXLSTATEDATA->m_lua_State, tname);
}
void  wxLuaState::luaL_GetMetatable(const char *tname)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    luaL_getmetatable(M_WXLSTATEDATA->m_lua_State, tname);
}
void* wxLuaState::luaL_CheckUdata(int ud, const char *tname)
{
    wxCHECK_MSG(Ok(), NULL, wxT("Invalid wxLuaState"));
    return luaL_checkudata(M_WXLSTATEDATA->m_lua_State, ud, tname);
}

void wxLuaState::luaL_Where(int lvl)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    luaL_where(M_WXLSTATEDATA->m_lua_State, lvl);
}
int wxLuaState::luaL_Error(const char *fmt, ...)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return luaL_error(M_WXLSTATEDATA->m_lua_State, fmt);
}

int wxLuaState::luaL_CheckOption(int narg, const char *def, const char *const lst[])
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return luaL_checkoption(M_WXLSTATEDATA->m_lua_State, narg, def, lst);
}

int wxLuaState::luaL_Ref(int t)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return luaL_ref(M_WXLSTATEDATA->m_lua_State, t);
}
void wxLuaState::luaL_Unref(int t, int ref)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    luaL_unref(M_WXLSTATEDATA->m_lua_State, t, ref);
}

int wxLuaState::luaL_LoadFile(const char *filename)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return luaL_loadfile(M_WXLSTATEDATA->m_lua_State, filename);
}
int wxLuaState::luaL_LoadBuffer(const char *buff, size_t sz, const char *name)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return luaL_loadbuffer(M_WXLSTATEDATA->m_lua_State, buff, sz, name);
}
int wxLuaState::luaL_LoadString(const char *s)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
    return luaL_loadstring(M_WXLSTATEDATA->m_lua_State, s);
}

void wxLuaState::luaL_ArgCheck(bool condition, int numarg, const char* extramsg)
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    luaL_argcheck(M_WXLSTATEDATA->m_lua_State, condition, numarg, extramsg);
}
const char* wxLuaState::luaL_CheckString(int numArg)
{
    wxCHECK_MSG(Ok(), NULL, wxT("Invalid wxLuaState"));
    return luaL_checkstring(M_WXLSTATEDATA->m_lua_State, numArg);
}
const char* wxLuaState::luaL_OptString(int numArg, const char* def)
{
    wxCHECK_MSG(Ok(), NULL, wxT("Invalid wxLuaState"));
    return luaL_optstring(M_WXLSTATEDATA->m_lua_State, numArg, def);
}
int wxLuaState::luaL_CheckInt(int numArg)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
#if LUA_VERSION_NUM >= 502
    return (int)luaL_checkinteger(M_WXLSTATEDATA->m_lua_State, numArg);
#else
    return (int)luaL_checkint(M_WXLSTATEDATA->m_lua_State, numArg);
#endif
}
int wxLuaState::luaL_OptInt(int numArg, int def)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
#if LUA_VERSION_NUM >= 502
    return (int)luaL_optinteger(M_WXLSTATEDATA->m_lua_State, numArg, def);
#else
    return (int)luaL_optint(M_WXLSTATEDATA->m_lua_State, numArg, def);
#endif
}
long wxLuaState::luaL_CheckLong(int numArg)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
#if LUA_VERSION_NUM >= 502
    return (long)luaL_checkinteger(M_WXLSTATEDATA->m_lua_State, numArg);
#else
    return (long)luaL_checklong(M_WXLSTATEDATA->m_lua_State, numArg);
#endif
}
long wxLuaState::luaL_OptLong(int numArg, int def)
{
    wxCHECK_MSG(Ok(), 0, wxT("Invalid wxLuaState"));
#if LUA_VERSION_NUM >= 502
    return (long)luaL_optinteger(M_WXLSTATEDATA->m_lua_State, numArg, def);
#else
    return (long)luaL_optlong(M_WXLSTATEDATA->m_lua_State, numArg, def);
#endif
}

// ----------------------------------------------------------------------------
// others

void wxLuaState::GetGlobals()
{
    wxCHECK_RET(Ok(), wxT("Invalid wxLuaState"));
    lua_pushglobaltable(M_WXLSTATEDATA->m_lua_State);
}

#define LUA_PATH "LUA_PATH"

// get LUA_PATH
wxString wxLuaState::GetLuaPath()
{
    wxCHECK_MSG(Ok(), wxEmptyString, wxT("Invalid wxLuaState"));
    lua_GetGlobal(LUA_PATH);
    wxString path = lua_TowxString(-1);
    lua_Pop(1);

    return path;
}

// add path list to LUA_PATH
void wxLuaState::AddLuaPath(const wxPathList& pathlist)
{
    size_t i, count = pathlist.GetCount();
    for (i = 0; i < count; ++i)
    {
        wxFileName fname(pathlist[i]);
        AddLuaPath(fname);
    }
}

// add filename path to LUA_PATH
void wxLuaState::AddLuaPath(const wxFileName& filename)
{
    wxFileName fname = filename;
    fname.SetName(wxT("?"));
    fname.SetExt(wxT("lua"));

    wxString path    = fname.GetFullPath();
    wxString luapath = GetLuaPath();

    // check if path
    wxStringTokenizer tkz(luapath, wxT(";"));
    while (tkz.HasMoreTokens())
    {
        wxString token = tkz.GetNextToken();

        if ((token == path) || (!wxFileName::IsCaseSensitive() && token.CmpNoCase(path) == 0))
            return;
    }

    // append separator
    if (!luapath.IsEmpty() && (luapath.Last() != wxT(';')))
        luapath += wxT(';');

    // append path
    luapath += path + wxT(';');

    lua_PushString(luapath.c_str());
    lua_SetGlobal(LUA_PATH);
}

//-----------------------------------------------------------------------------
// wxLuaEvent
//-----------------------------------------------------------------------------

#if wxCHECK_VERSION(3,0,0)
wxDEFINE_EVENT(wxEVT_LUA_CREATION, wxLuaEvent);
wxDEFINE_EVENT(wxEVT_LUA_PRINT, wxLuaEvent);
wxDEFINE_EVENT(wxEVT_LUA_ERROR, wxLuaEvent);
wxDEFINE_EVENT(wxEVT_LUA_DEBUG_HOOK, wxLuaEvent);
#else
DEFINE_LOCAL_EVENT_TYPE(wxEVT_LUA_CREATION)
DEFINE_LOCAL_EVENT_TYPE(wxEVT_LUA_PRINT)
DEFINE_LOCAL_EVENT_TYPE(wxEVT_LUA_ERROR)
DEFINE_LOCAL_EVENT_TYPE(wxEVT_LUA_DEBUG_HOOK)
//DEFINE_LOCAL_EVENT_TYPE(wxEVT_LUA_INIT)
//DEFINE_LOCAL_EVENT_TYPE(wxEVT_LUA_DEBUGGERATTACHED)
#endif

wxLuaEvent::wxLuaEvent(wxEventType commandType, wxWindowID id, const wxLuaState& wxlState)
           :wxNotifyEvent(commandType, id),  m_wxlState(wxlState),
            m_debug_hook_break(false),
            m_lua_Debug(NULL)
{
}

wxLuaEvent::wxLuaEvent( const wxLuaEvent &event )
           :wxNotifyEvent(event), m_wxlState(event.m_wxlState),
            m_debug_hook_break(event.m_debug_hook_break),
            m_lua_Debug(event.m_lua_Debug)
{
}
