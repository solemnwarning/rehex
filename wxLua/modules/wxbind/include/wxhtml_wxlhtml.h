/////////////////////////////////////////////////////////////////////////////
// Purpose:     Wrappers for wxHTML classes for wxLua
// Author:      J. Winwood
// Created:     June 2002
// Copyright:   (c) 2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef WX_LUA_WXLHTML_H
#define WX_LUA_WXLHTML_H

#include "wx/html/htmlwin.h"
#include "wx/html/htmlcell.h"

#include "wxbind/include/wxbinddefs.h"
#include "wxluasetup.h"

#if wxLUA_USE_wxHTML

// ----------------------------------------------------------------------------
// wxLuaHtmlWindow
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_BINDWXHTML wxLuaHtmlWindow : public wxHtmlWindow
{
public:
    wxLuaHtmlWindow(const wxLuaState& wxlState,
                    wxWindow *parent, wxWindowID id = wxID_ANY,
                    const wxPoint& pos = wxDefaultPosition,
                    const wxSize& size = wxDefaultSize,
                    long style = wxHW_SCROLLBAR_AUTO,
                    const wxString& name = wxT("wxLuaHtmlWindow"));

    virtual ~wxLuaHtmlWindow() {}

#if wxCHECK_VERSION(2, 7, 0)
    virtual bool
#else
    virtual void
#endif
        OnCellClicked(wxHtmlCell *cell, wxCoord x, wxCoord y, const wxMouseEvent& event);
    virtual void OnCellMouseHover(wxHtmlCell *cell, wxCoord x, wxCoord y);
    virtual void OnLinkClicked(const wxHtmlLinkInfo& link);
    virtual void OnSetTitle(const wxString& title);

private:
    wxLuaState m_wxlState;

    DECLARE_ABSTRACT_CLASS(wxLuaHtmlWindow)
};

// ----------------------------------------------------------------------------
// wxLuaHtmlWinTagEvent
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_BINDWXHTML wxLuaHtmlWinTagEvent : public wxEvent
{
public:
    wxLuaHtmlWinTagEvent(wxEventType eventType = wxEVT_NULL);
    wxLuaHtmlWinTagEvent(const wxLuaHtmlWinTagEvent& event);

    virtual ~wxLuaHtmlWinTagEvent() {}

    void SetTagInfo(const wxHtmlTag *pHtmlTag, wxHtmlWinParser *pParser);

    const wxHtmlTag* GetHtmlTag() const { return m_pHtmlTag; }
    wxHtmlWinParser* GetHtmlParser() const { return m_pHtmlParser; }

    bool GetParseInnerCalled() const { return m_fParseInnerCalled; }
    void SetParseInnerCalled(bool fParseInnerCalled) { m_fParseInnerCalled = fParseInnerCalled; }

protected:
    virtual wxEvent* Clone() const { return new wxLuaHtmlWinTagEvent(*this); }

private:
    const wxHtmlTag *m_pHtmlTag;
    wxHtmlWinParser *m_pHtmlParser;
    bool             m_fParseInnerCalled;
    DECLARE_DYNAMIC_CLASS(wxLuaHtmlWinTagEvent)
};

typedef void (wxEvtHandler::*wxLuaHtmlWinTagEventFunction)(wxLuaHtmlWinTagEvent&);

BEGIN_DECLARE_EVENT_TYPES()
    DECLARE_EXPORTED_EVENT_TYPE(WXDLLIMPEXP_BINDWXHTML, wxEVT_HTML_TAG_HANDLER, 0)
END_DECLARE_EVENT_TYPES()

#define EVT_HTML_TAG_HANDLER(id, fn) DECLARE_EVENT_TABLE_ENTRY(wxEVT_HTML_TAG_HANDLER, id, wxID_ANY, (wxObjectEventFunction) (wxEventFunction) (wxLuaHtmlWinTagEventFunction) & fn, (wxObject *) NULL),

#endif // wxLUA_USE_wxHTML

#endif //WX_LUA_WXLHTML_H
