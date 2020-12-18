/////////////////////////////////////////////////////////////////////////////
// Name:        wxlcallb.cpp
// Purpose:     wxLuaEventCallback and wxLuaWinDestroyCallback
// Author:      Francis Irving, John Labenski
// Created:     11/05/2002
// Copyright:   (c) 2012 John Labenski, 2002 Creature Labs. All rights reserved.
// Licence:     wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx/wx.h".
#include <wx/wxprec.h>

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include <wx/wx.h>
#endif // WX_PRECOMP

#include "wxlua/wxlcallb.h"

//-----------------------------------------------------------------------------
// wxLuaEventCallback
//-----------------------------------------------------------------------------
IMPLEMENT_ABSTRACT_CLASS(wxLuaEventCallback, wxLuaCallbackBaseClass)

wxLuaEventCallback::wxLuaEventCallback()
                   :wxLuaCallbackBaseClass(),
                    m_luafunc_ref(0), //m_wxlState(wxNullLuaState),
                    m_evtHandler(NULL), m_id(wxID_ANY), m_last_id(wxID_ANY),
                    m_wxlBindEvent(NULL)
{
}

wxLuaEventCallback::~wxLuaEventCallback()
{
    // Remove the reference to the Lua function that we call
    if (m_wxlState.Ok())
    {
        m_wxlState.wxluaR_Unref(m_luafunc_ref, &wxlua_lreg_refs_key);
        // delete the reference to this handler
        m_wxlState.RemoveTrackedEventCallback(this);
    }
}

wxString wxLuaEventCallback::Connect(const wxLuaState& wxlState, int lua_func_stack_idx,
                                     wxWindowID win_id, wxWindowID last_id,
                                     wxEventType eventType, wxEvtHandler *evtHandler)
{
    // Assert too since these errors are serious and not just bad Lua code.
    wxCHECK_MSG(evtHandler != NULL, wxT("Invalid wxEvtHandler in wxLuaEventCallback::Connect()"), wxT("Invalid wxEvtHandler in wxLuaEventCallback::Connect()"));
    wxCHECK_MSG((m_evtHandler == NULL) && (m_luafunc_ref == 0), wxT("Attempting to reconnect a wxLuaEventCallback"), wxT("Attempting to reconnect a wxLuaEventCallback"));
    wxCHECK_MSG(wxlState.Ok(), wxT("Invalid wxLuaState"), wxT("Invalid wxLuaState"));

    m_wxlState   = wxlState;
    m_evtHandler = evtHandler;
    m_id         = win_id;
    m_last_id    = last_id;

    // NOTE: FIXME? We look for the wxLuaBindEvent in all of the bindings, but it
    // may not have actually been installed if someone had modified the bindings.
    // It should be ok since it will error out soon enough without crashing.
    m_wxlBindEvent = wxLuaBinding::FindBindEvent(eventType);

    // Do not install this invalid or unknown event type since we won't know
    // what wxEvent type class to use and someone probably made a mistake.
    if (m_wxlBindEvent == NULL)
    {
        return wxString::Format(wxT("wxLua: Invalid or unknown wxEventType %d for wxEvtHandler::Connect(). winIds %d, %d."),
                                  (int)eventType, win_id, last_id);
    }

    m_wxlState.AddTrackedEventCallback(this);

    // create a reference to the Lua event handler function
    if (lua_func_stack_idx != WXLUAEVENTCALLBACK_NOROUTINE)
        m_luafunc_ref = m_wxlState.wxluaR_Ref(lua_func_stack_idx, &wxlua_lreg_refs_key);

    // Note: We use the callback userdata and not the event sink since the event sink
    // requires a wxEvtHandler object which is a fairly large class.
    // The userdata (i.e. this) is also deleted for us which makes our life easier.
    m_evtHandler->Connect(win_id, last_id, eventType,
                          (wxObjectEventFunction)&wxLuaEventCallback::OnAllEvents,
                          this);

    return wxEmptyString;
}

void wxLuaEventCallback::ClearwxLuaState()
{
    m_wxlState.UnRef(); // ok if it's not Ok()
}

wxString wxLuaEventCallback::GetInfo() const
{
    return wxString::Format(wxT("%s(%d) -> wxLuaEventCallback(%p, ids %d, %d)|wxEvtHandler(%p) -> %s : %s"),
                lua2wx(m_wxlBindEvent ? m_wxlBindEvent->name : "?NULL?").c_str(),
                (int)GetEventType(),
                this, m_id, m_last_id,
                m_evtHandler,
                m_evtHandler ? m_evtHandler->GetClassInfo()->GetClassName() : wxT("?NULL?"),
                m_wxlState.GetwxLuaTypeName(m_wxlBindEvent ? *m_wxlBindEvent->wxluatype : WXLUA_TUNKNOWN).c_str());
}

void wxLuaEventCallback::OnAllEvents(wxEvent& event)
{
    wxEventType evtType = event.GetEventType();

    // Get the wxLuaEventCallback instance to use which is NOT "this" since
    // "this" is a central event handler function. i.e. this != theCallback
    wxLuaEventCallback *theCallback = (wxLuaEventCallback *)event.m_callbackUserData;
    wxCHECK_RET(theCallback != NULL, wxT("Invalid wxLuaEventCallback in wxEvent user data"));

    if (theCallback != NULL)
    {
        // Not an error if !Ok(), the wxLuaState is cleared during shutdown or after a destroy event.
        wxLuaState wxlState(theCallback->GetwxLuaState());
        if (wxlState.Ok())
        {
            wxlState.SetInEventType(evtType);
            theCallback->OnEvent(&event);
            wxlState.SetInEventType(wxEVT_NULL);
        }
    }

    // we want the wxLuaWinDestroyCallback to get this too
    if (evtType == wxEVT_DESTROY)
        event.Skip(true);
}

void wxLuaEventCallback::OnEvent(wxEvent *event)
{
    static wxClassInfo* wxSpinEvent_ClassInfo   = wxClassInfo::FindClass(wxT("wxSpinEvent"));
    static wxClassInfo* wxScrollEvent_ClassInfo = wxClassInfo::FindClass(wxT("wxScrollEvent"));

    // Cannot call it if Lua is gone or the interpreter has been destroyed
    // This can happen when the program exits since windows may be destroyed
    // after Lua has been deleted.
    if (!m_wxlState.Ok())
        return;

    // ref the state in case this generates a wxEVT_DESTROY which clears us
    wxLuaState wxlState(m_wxlState);

    // initialize to the generic wxluatype_wxEvent
    int event_wxl_type = *p_wxluatype_wxEvent; // inits to wxluatype_TUNKNOWN == WXLUA_TUNKNOWN

    // If !m_wxlBindEvent, we would have errored in Connect(), but don't crash...
    if (m_wxlBindEvent != NULL)
    {
        event_wxl_type = *m_wxlBindEvent->wxluatype;

        // These wxEventTypes can be wxScrollEvents or wxSpinEvents - FIXME could this be cleaner?
        // wxEVT_SCROLL_LINEUP, wxEVT_SCROLL_LINEDOWN, wxEVT_SCROLL_THUMBTRACK

        if ((*m_wxlBindEvent->wxluatype == *p_wxluatype_wxScrollEvent) &&
            event->GetClassInfo()->IsKindOf(wxSpinEvent_ClassInfo))
        {
            if (*p_wxluatype_wxSpinEvent != WXLUA_TUNKNOWN)
                event_wxl_type = *p_wxluatype_wxSpinEvent;
            else
                event_wxl_type = *p_wxluatype_wxEvent; // get the generic wxluatype_wxEvent
        }
        else if ((*m_wxlBindEvent->wxluatype == *p_wxluatype_wxSpinEvent) &&
                 event->GetClassInfo()->IsKindOf(wxScrollEvent_ClassInfo))
        {
            if (*p_wxluatype_wxScrollEvent != WXLUA_TUNKNOWN)
                event_wxl_type = *p_wxluatype_wxScrollEvent;
            else
                event_wxl_type = *p_wxluatype_wxEvent; // get the generic wxluatype_wxEvent
        }
    }

    // Should know our event type, but error out in case we don't
    wxCHECK_RET(event_wxl_type != WXLUA_TUNKNOWN, wxT("Unknown wxEvent wxLua tag for : ") + wxString(event->GetClassInfo()->GetClassName()));

    wxlState.lua_CheckStack(LUA_MINSTACK);
    int oldTop = wxlState.lua_GetTop();
    if (wxlState.wxluaR_GetRef(m_luafunc_ref, &wxlua_lreg_refs_key))
    {
#if LUA_VERSION_NUM < 502
        // lua_setfenv() is not in Lua 5.2 nor can you set an env for a function anymore
        wxlState.GetGlobals();
        if (wxlState.lua_SetFenv(-2) != 0)
#endif // LUA_VERSION_NUM < 502
        {
            // Don't track the wxEvent since we don't own it and tracking it
            // causes clashes in the object registry table since many can be
            // created and deleted and the mem address is resused by C++.
            wxlState.wxluaT_PushUserDataType(event, event_wxl_type, false);
            wxlState.LuaPCall(1, 0); // one input no returns
        }
#if LUA_VERSION_NUM < 502
        else
            wxlState.wxlua_Error("wxLua: wxEvtHandler::Connect() in wxLuaEventCallback::OnEvent(), callback function is not a Lua function.");
#endif // LUA_VERSION_NUM < 502
    }
    else
        wxlState.wxlua_Error("wxLua: wxEvtHandler::Connect() in wxLuaEventCallback::OnEvent(), callback function to call is not refed.");

    wxlState.lua_SetTop(oldTop); // pop function and error message from the stack (if they're there)
}

// ----------------------------------------------------------------------------
// wxLuaWinDestroyCallback
// ----------------------------------------------------------------------------
IMPLEMENT_ABSTRACT_CLASS(wxLuaWinDestroyCallback, wxLuaCallbackBaseClass)

wxLuaWinDestroyCallback::wxLuaWinDestroyCallback(const wxLuaState& wxlState,
                                                 wxWindow* win)
                        :wxLuaCallbackBaseClass(), m_wxlState(wxlState), m_window(win)
{
    wxCHECK_RET(m_wxlState.Ok(), wxT("Invalid wxLuaState"));
    wxCHECK_RET(m_window != NULL, wxT("Invalid wxWindow"));

    m_wxlState.AddTrackedWinDestroyCallback(this);

    // connect the event handler and set this as the callback user data
    m_window->Connect(m_window->GetId(), wxEVT_DESTROY,
                      (wxObjectEventFunction)&wxLuaWinDestroyCallback::OnAllDestroyEvents,
                      this);
}

wxLuaWinDestroyCallback::~wxLuaWinDestroyCallback()
{
    if (m_wxlState.Ok())
    {
        m_wxlState.RemoveTrackedWinDestroyCallback(this);
        m_wxlState.RemoveTrackedWindow(m_window);
    }
}

void wxLuaWinDestroyCallback::ClearwxLuaState()
{
    m_wxlState.UnRef(); // ok if it's not Ok()
}

wxString wxLuaWinDestroyCallback::GetInfo() const
{
    wxString winName(wxT("wxWindow?"));
    if (m_window && m_window->GetClassInfo())
        winName = m_window->GetClassInfo()->GetClassName();

    return wxString::Format(wxT("%s(%p, id=%d)|wxLuaDestroyCallback(%p)"),
                winName.c_str(), m_window, m_window ? m_window->GetId() : -1,
                this);
}

void wxLuaWinDestroyCallback::OnAllDestroyEvents(wxWindowDestroyEvent& event)
{
    // Central handler for events, forward to the specific instance
    wxLuaWinDestroyCallback *theCallback = (wxLuaWinDestroyCallback *)event.m_callbackUserData;
    if (theCallback && (((wxWindow*)event.GetEventObject()) == theCallback->m_window))
    {
        theCallback->OnDestroy(event);
    }
    else
        event.Skip();
}

void wxLuaWinDestroyCallback::OnDestroy(wxWindowDestroyEvent& event)
{
    event.Skip();

    // FIXME - Is it an error to receive an event after you've deleted Lua?
    //  probably not if Lua is getting shutdown

    // Note: do not remove from wxLuaState's destroyHandlerList here, wait 'till destructor
    if (m_wxlState.Ok())
    {
        lua_State* L = m_wxlState.GetLuaState();

        // clear the metatable for all userdata we're tracking.
        wxluaO_untrackweakobject(L, NULL, m_window);
        wxlua_removederivedmethods(L, m_window);

        // Clear our own pointer to this window
        wxluaW_removetrackedwindow(L, m_window);

        wxEvtHandler* evtHandler = m_window->GetEventHandler();

        // Finally, clear out the wxLuaEventCallbacks for the very odd cases where
        // (activation) events can be sent during destruction. These can happen
        // if you pop up a modal dialog (asking if they want to save perhaps)
        // and when the dialog is closed the frame below sends an activation event,
        // but we're right in the middle of being destroyed and we crash.

        lua_pushlightuserdata(L, &wxlua_lreg_evtcallbacks_key); // push key
        lua_rawget(L, LUA_REGISTRYINDEX);                       // pop key, push value (table)

        lua_pushnil(L);
        while (lua_next(L, -2) != 0)
        {
            // value = -1, key = -2, table = -3
            wxLuaEventCallback* wxlCallback = (wxLuaEventCallback*)lua_touserdata(L, -2);
            wxCHECK_RET(wxlCallback, wxT("Invalid wxLuaEventCallback"));

            if ((wxlCallback->GetEvtHandler() == evtHandler) ||
                (wxlCallback->GetEvtHandler() == (wxEvtHandler*)m_window))
            {
                // remove the ref to the routine since we're clearing the wxLuaState
                // See ~wxLuaEventCallback
                wxluaR_unref(L, wxlCallback->GetLuaFuncRef(), &wxlua_lreg_refs_key);
                wxlCallback->ClearwxLuaState();

                lua_pop(L, 1);        // pop value

                // The code below is the equivalent of this, but works while iterating
                //   "m_wxlState.RemoveTrackedEventCallback(wxlCallback);"

                lua_pushvalue(L, -1); // copy key for next iteration
                lua_pushnil(L);
                lua_rawset(L, -4);    // set t[key] = nil to remove it
            }
            else
                lua_pop(L, 1);        // pop value, lua_next will pop key at end
        }

        lua_pop(L, 1); // pop table
    }
}
