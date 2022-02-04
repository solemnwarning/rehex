/////////////////////////////////////////////////////////////////////////////
// Name:        wxlcallb.h
// Purpose:     wxLuaEventCallback and wxLuaWinDestroyCallback
// Author:      Francis Irving, John Labenski
// Created:     21/01/2002
// Copyright:   (c) 2012 John Labenski, 2002 Creature Labs. All rights reserved.
// Licence:     wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WXLCALLB_H_
#define _WXLCALLB_H_

#include "wxlua/wxldefs.h"
#include "wxlua/wxlstate.h"


#if wxCHECK_VERSION(2,9,0)
    #define wxLuaCallbackBaseClass wxEvtHandler
#else
    #define wxLuaCallbackBaseClass wxObject
#endif


// ----------------------------------------------------------------------------
// wxLuaEventCallback - Forward events from wxEvtHandlers to Lua functions.
//
// The wxLuaEventCallback is created with the wxLuaState, the stack index of a
// Lua function to call when a wxEvent is received, the window id ranges, and
// the wxEventType used with wxEvtHandler::Connect() with "this" as the
// callback user data for event.
//
// Do NOT delete wxLuaEventCallbacks since the wxEvtHandler deletes the
// callback user data itself.
//
// The function wxLuaEventCallback::OnAllEvents() generically handles all wxEvents
// by retrieving the wxLuaEventCallback instance from the wxEvent userdata
// to call wxLuaEventCallback::OnEvent() on the correct instance.
// ----------------------------------------------------------------------------

#define WXLUAEVENTCALLBACK_NOROUTINE 1000000 // use this for the lua_func_stack_idx
                                             // param of the constructor for no Lua routine

class WXDLLIMPEXP_WXLUA wxLuaEventCallback : public wxLuaCallbackBaseClass
{
public:
    // default constructor, call Connect() to actually connect the event
    wxLuaEventCallback();

    virtual ~wxLuaEventCallback();

    // Verifies the inputs and calls evtHandler->Connect() with "this" as
    //   the callback userdata.
    // lua_func_stack_idx is the Lua stack index of a function to call with
    //   the wxEvent as the single parameter.
    // win_id and last_id follow the same notation as wxEvtHandler::Connect().
    //   If only one event Id is needed set last_id = wxID_ANY
    // Returns an empty string on success and the wxEvtHandler takes ownership of this,
    //   otherwise an error message is returned and you must delete this since nobody else will.
    virtual wxString Connect( const wxLuaState& wxlState, int lua_func_stack_idx,
                              wxWindowID win_id, wxWindowID last_id,
                              wxEventType eventType, wxEvtHandler *evtHandler );

    void ClearwxLuaState(); // m_wxlState.UnRef()

    wxLuaState    GetwxLuaState() const { return m_wxlState; }
    wxWindowID    GetId() const         { return m_id; }
    wxWindowID    GetLastId() const     { return m_last_id; }
    wxEventType   GetEventType() const  { return m_wxlBindEvent ? *m_wxlBindEvent->eventType : wxEVT_NULL; }
    wxEvtHandler* GetEvtHandler() const { return m_evtHandler; }
    int           GetLuaFuncRef() const { return m_luafunc_ref; }

    const wxLuaBindEvent* GetwxLuaBindEvent() const { return m_wxlBindEvent; }

    // Get a human readable string about this callback.
    // "wxEVT_XXX(evt#) -> wxLuaEventCallback(&callback, ids %d %d)|wxEvtHandler(&evthandler) -> wxEvtHandlerClassName"
    wxString GetInfo() const;

    // Central event handler that calls OnEvent() for the actual
    //   wxLuaEventCallback callback userdata.
    // This function is treated like a static function that all handlers of
    //   this class will call.
    void OnAllEvents(wxEvent& event);

    // Handle the wxEvent by calling the Lua function to handle the event.
    // The Lua function will receive a single parameter, the wxEvent.
    virtual void OnEvent(wxEvent *event);

protected:
    int           m_luafunc_ref; // ref of the Lua routine to call in the wxlua_lreg_refs_key registry table
    wxLuaState    m_wxlState;    // stored to verify that that lua_State is still active
    wxEvtHandler* m_evtHandler;
    wxWindowID    m_id;
    wxWindowID    m_last_id;
    const wxLuaBindEvent* m_wxlBindEvent; // data for this wxEventType

private:
    DECLARE_ABSTRACT_CLASS(wxLuaEventCallback)
};

// ----------------------------------------------------------------------------
// wxLuaWinDestroyCallback - Handle the wxEVT_DESTROY event from wxWindows.
//
// Clears the metatable for the wxWindow userdata so that after a call to
// win:Destroy() calling a function on win won't crash wxLua, but will generate
// an error message in Lua.
//
// Do NOT delete this, the wxEvtHandler deletes the callback user data itself
// unless it is !Ok() since that means it wasn't attached to the window.
//
// The function OnAllDestroyEvents() generically handles the events and forwards them
// to the wxEvent's wxLuaWinDestroyCallback callback user data function OnDestroy().
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_WXLUA wxLuaWinDestroyCallback : public wxLuaCallbackBaseClass
{
public:
    wxLuaWinDestroyCallback(const wxLuaState& state, wxWindow *win);

    virtual ~wxLuaWinDestroyCallback();

    void ClearwxLuaState(); // m_wxlState.UnRef()

    wxLuaState GetwxLuaState() const { return m_wxlState; }
    wxWindow*  GetWindow() const     { return m_window; }

    // If Ok then this should be attached to a wxEVT_DESTROY callback
    // else you should delete this since nobody else will.
    bool Ok() const { return m_wxlState.Ok() && (m_window != NULL); }

    // Get a human readable string
    // "wxWindowClassName(&win, id=%d)|wxLuaDestroyCallback(&callback)"
    wxString GetInfo() const;

    // Central event handler that calls OnDestroy() for the actual
    //   wxLuaWinDestroyCallback callback user data.
    // This function is treated like a static function that all handlers of
    //   this class will call.
    void OnAllDestroyEvents(wxWindowDestroyEvent& event);

    // Handle the event by clearing the metatable for the window.
    virtual void OnDestroy(wxWindowDestroyEvent& event);

protected:
    wxLuaState m_wxlState; // store it since we're added to a list of its callbacks.
    wxWindow*  m_window;

private:
    DECLARE_ABSTRACT_CLASS(wxLuaWinDestroyCallback)
};

#endif //_WXLCALLB_H_
