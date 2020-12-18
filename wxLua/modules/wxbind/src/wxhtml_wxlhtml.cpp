/////////////////////////////////////////////////////////////////////////////
// Name:        wxLuaHtmlWindow.cpp
// Purpose:     Provide an interface to wxHtmlWindow for wxLua.
// Author:      J. Winwood.
// Created:     June 2002.
// Copyright:   (c) 2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/wxprec.h>

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include <wx/wx.h>
#endif

#include <wx/datetime.h>

#include "wxbind/include/wxhtml_wxlhtml.h"
#include "wxbind/include/wxhtml_bind.h"

//#include "wxlua/wxlcallb.h"

#if wxLUA_USE_wxHTML

DEFINE_EVENT_TYPE(wxEVT_HTML_TAG_HANDLER)

// ----------------------------------------------------------------------------
// wxLuaHtmlWindow
// ----------------------------------------------------------------------------
IMPLEMENT_ABSTRACT_CLASS(wxLuaHtmlWindow, wxHtmlWindow)

wxLuaHtmlWindow::wxLuaHtmlWindow(const wxLuaState& wxlState,
                                 wxWindow *parent, wxWindowID id,
                                 const wxPoint& pos, const wxSize& size,
                                 long  style, const wxString& name)
                :wxHtmlWindow(parent, id, pos, size, style, name)
{
    m_wxlState = wxlState;
}

#if wxCHECK_VERSION(2,7,0)
bool
#else
void
#endif
    wxLuaHtmlWindow::OnCellClicked(wxHtmlCell *cell, wxCoord x, wxCoord y, const wxMouseEvent& event)
{
    bool fResult = false;
#if wxCHECK_VERSION(2,7,0)
    bool ret = false;
#endif

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "OnCellClicked", true))
    {
        lua_State *L = m_wxlState.GetLuaState();
        int nOldTop = lua_gettop(L);
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaHtmlWindow, true);
        m_wxlState.wxluaT_PushUserDataType(cell, wxluatype_wxHtmlCell, true);
        lua_pushnumber(L, x);
        lua_pushnumber(L, y);
        m_wxlState.wxluaT_PushUserDataType((void *) &event, wxluatype_wxMouseEvent, true);

        if (m_wxlState.LuaPCall(5, 1) == 0)
            fResult = (lua_tonumber(L, -1) != 0);

        lua_settop(L, nOldTop-1); // -1 to remove pushed derived method func too

        if (fResult)
        {
#if wxCHECK_VERSION(2,7,0)
            ret =
#endif
                wxHtmlWindow::OnCellClicked(cell, x, y, event);
        }
    }
    else
    {
#if wxCHECK_VERSION(2,7,0)
        ret =
#endif
            wxHtmlWindow::OnCellClicked(cell, x, y, event);
    }

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always
#if wxCHECK_VERSION(2,7,0)
    return ret;
#endif
}

void wxLuaHtmlWindow::OnCellMouseHover(wxHtmlCell *cell, wxCoord x, wxCoord y)
{
    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "OnCellMouseHover", true))
    {
        lua_State *L = m_wxlState.GetLuaState();
        int nOldTop = lua_gettop(L);
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaHtmlWindow, true);
        m_wxlState.wxluaT_PushUserDataType(cell, wxluatype_wxHtmlCell, true);
        lua_pushnumber(L, x);
        lua_pushnumber(L, y);

        m_wxlState.LuaPCall(4, 0);
        lua_settop(L, nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        wxHtmlWindow::OnCellMouseHover(cell, x, y);

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always
}

void wxLuaHtmlWindow::OnLinkClicked(const wxHtmlLinkInfo& link)
{
    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "OnLinkClicked", true))
    {
        lua_State *L = m_wxlState.GetLuaState();
        int nOldTop = lua_gettop(L);
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaHtmlWindow, true);
        m_wxlState.wxluaT_PushUserDataType((void *) &link, wxluatype_wxHtmlLinkInfo, true);

        m_wxlState.LuaPCall(2, 0);
        lua_settop(L, nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        wxHtmlWindow::OnLinkClicked(link);

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always
}

void wxLuaHtmlWindow::OnSetTitle(const wxString& title)
{
    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "OnSetTitle", true))
    {
        lua_State *L = m_wxlState.GetLuaState();
        int nOldTop = lua_gettop(L);
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaHtmlWindow, true);
        m_wxlState.lua_PushString(title.c_str());

        m_wxlState.LuaPCall(2, 0);
        lua_settop(L, nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        wxHtmlWindow::OnSetTitle(title);

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always
}

// ----------------------------------------------------------------------------
// wxLuaHtmlWinTagHandler
// ----------------------------------------------------------------------------

class wxLuaHtmlWinTagHandler : public wxHtmlWinTagHandler
{
public:
    wxLuaHtmlWinTagHandler() {}

    virtual wxString GetSupportedTags() { return wxT("LUA"); }

    virtual bool HandleTag(const wxHtmlTag& tag)
    {
        wxLuaHtmlWinTagEvent htmlEvent(wxEVT_HTML_TAG_HANDLER);
        htmlEvent.SetTagInfo(&tag, m_WParser);

        if (wxTheApp->ProcessEvent(htmlEvent))
            return htmlEvent.GetParseInnerCalled();

        return false;
    }
};

class wxLuaHtmlTagsModule : public wxHtmlTagsModule
{
    DECLARE_DYNAMIC_CLASS(wxLuaHtmlTagsModule)
public:
    virtual void FillHandlersTable(wxHtmlWinParser *parser)
    {
        parser->AddTagHandler(new wxLuaHtmlWinTagHandler);
    }
};

IMPLEMENT_DYNAMIC_CLASS(wxLuaHtmlTagsModule, wxHtmlTagsModule)

// ----------------------------------------------------------------------------
// wxLuaHtmlWinTagEvent
// ----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxLuaHtmlWinTagEvent, wxEvent)

wxLuaHtmlWinTagEvent::wxLuaHtmlWinTagEvent(wxEventType eventType)
                     :wxEvent(wxID_ANY, eventType), m_pHtmlTag(NULL),
                      m_pHtmlParser(NULL), m_fParseInnerCalled(false)
{
}

wxLuaHtmlWinTagEvent::wxLuaHtmlWinTagEvent(const wxLuaHtmlWinTagEvent& event)
                     :wxEvent(event), m_pHtmlTag(event.m_pHtmlTag),
                      m_pHtmlParser(event.m_pHtmlParser),
                      m_fParseInnerCalled(event.m_fParseInnerCalled)
{
}

void wxLuaHtmlWinTagEvent::SetTagInfo(const wxHtmlTag *pHtmlTag,
                                      wxHtmlWinParser *pParser)
{
    m_pHtmlTag    = pHtmlTag;
    m_pHtmlParser = pParser;
}

#endif //wxLUA_USE_wxHTML
