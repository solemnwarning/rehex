/////////////////////////////////////////////////////////////////////////////
// Purpose:     Wrappers around wxCore classes for wxLua
// Author:      J. Winwood
// Created:     July 2002
// Copyright:   (c) 2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef WX_LUA_WXLCORE_H
#define WX_LUA_WXLCORE_H

#include "wxbind/include/wxbinddefs.h"
#include "wxluasetup.h"

class WXDLLIMPEXP_FWD_WXLUA wxLuaObject;


#if (wxVERSION_NUMBER < 2900)
    typedef int wxPenCap;
    typedef int wxPenJoin;
    typedef int wxPenStyle;

    typedef int wxRasterOperationMode;
    typedef int wxPolygonFillMode;
    typedef int wxFloodFillStyle;
    typedef int wxMappingMode;
    typedef int wxImageResizeQuality;
#endif

// ----------------------------------------------------------------------------
// wxLuaDataObjectSimple
// ----------------------------------------------------------------------------
#if wxLUA_USE_wxDataObject && wxUSE_DATAOBJ

#include <wx/dataobj.h>

class WXDLLIMPEXP_BINDWXCORE wxLuaDataObjectSimple : public wxDataObjectSimple
{
public:
    wxLuaDataObjectSimple(const wxLuaState& wxlState,
                          const wxDataFormat& format = wxFormatInvalid);

    virtual size_t GetDataSize() const;
    virtual bool GetDataHere(void* buf) const;
    virtual bool SetData(size_t len, const void* buf);

private:
    mutable wxLuaState m_wxlState;
};

#endif // wxLUA_USE_wxDataObject && wxUSE_DATAOBJ

// ----------------------------------------------------------------------------
// wxLuaFileDropTarget
// ----------------------------------------------------------------------------
#if wxLUA_USE_wxDataObject && wxUSE_DRAG_AND_DROP

#include <wx/dnd.h>

class WXDLLIMPEXP_BINDWXCORE wxLuaFileDropTarget : public wxFileDropTarget
{
public:
    wxLuaFileDropTarget(const wxLuaState& wxlState);

    virtual bool OnDropFiles(wxCoord x, wxCoord y, const wxArrayString& filenames);
    virtual wxDragResult OnData(wxCoord x, wxCoord y, wxDragResult def);

private:
    mutable wxLuaState m_wxlState;
};

#endif // wxLUA_USE_wxDataObject && wxUSE_DRAG_AND_DROP

// ----------------------------------------------------------------------------
// wxLuaTextDropTarget
// ----------------------------------------------------------------------------
#if wxLUA_USE_wxDataObject && wxUSE_DRAG_AND_DROP

#include <wx/dnd.h>

class WXDLLIMPEXP_BINDWXCORE wxLuaTextDropTarget : public wxTextDropTarget
{
public:
    wxLuaTextDropTarget(const wxLuaState& wxlState);

    virtual bool OnDropText(wxCoord x, wxCoord y, const wxString& text);
    virtual wxDragResult OnData(wxCoord x, wxCoord y, wxDragResult def);
    virtual wxDragResult OnEnter(wxCoord x, wxCoord y, wxDragResult def);
    virtual void OnLeave();
    virtual wxDragResult OnDragOver(wxCoord x, wxCoord y, wxDragResult def);

private:
    mutable wxLuaState m_wxlState;
};

#endif // wxLUA_USE_wxDataObject && wxUSE_DRAG_AND_DROP

// ----------------------------------------------------------------------------
// wxLuaURLDropTarget - Copied from wxWidgets/samples/dnd/dnd.cpp
// Unfortunately the wxURLDataObject does not derive from a wxTextDataObject
// in MSW so we need to create this class.
// ----------------------------------------------------------------------------
#if wxLUA_USE_wxDataObject && wxUSE_DRAG_AND_DROP

#include <wx/dnd.h>

class WXDLLIMPEXP_BINDWXCORE wxLuaURLDropTarget : public wxDropTarget
{
public:
    wxLuaURLDropTarget(const wxLuaState& wxlState);

    virtual bool OnDropURL(wxCoord x, wxCoord y, const wxString& text);
    virtual wxDragResult OnData(wxCoord x, wxCoord y, wxDragResult def);


    // URLs can't be moved, only copied
    virtual wxDragResult OnDragOver(wxCoord WXUNUSED(x), wxCoord WXUNUSED(y),
                                    wxDragResult WXUNUSED(def))
    {
        return wxDragLink; // At least IE 5.x needs wxDragLink, the
                           // other browsers on MSW seem okay with it too.
    }

private:
    mutable wxLuaState m_wxlState;
};

#endif // wxLUA_USE_wxDataObject && wxUSE_DRAG_AND_DROP

// ----------------------------------------------------------------------------
// wxLuaPrintout
// ----------------------------------------------------------------------------
#if wxLUA_USE_wxLuaPrintout

#include "wx/print.h"

class WXDLLIMPEXP_BINDWXCORE wxLuaPrintout : public wxPrintout
{
public:
    wxLuaPrintout(const wxLuaState& wxlState,
                  const wxString& title = wxT("Printout"),
                  wxLuaObject *pObject = NULL);

    // added function so you don't have to override GetPageInfo
    void SetPageInfo(int minPage, int maxPage, int pageFrom, int pageTo);

    // overrides
    virtual void GetPageInfo(int *minPage, int *maxPage, int *pageFrom, int *pageTo);
    virtual bool HasPage(int pageNum);
    virtual bool OnBeginDocument(int startPage, int endPage);
    virtual void OnEndDocument();
    virtual void OnBeginPrinting();
    virtual void OnEndPrinting();
    virtual void OnPreparePrinting();
    virtual bool OnPrintPage(int pageNumber);

    wxLuaObject *GetID() const { return m_pObject; }

    // Dummy test function to directly verify that the binding virtual functions really work.
    virtual wxString TestVirtualFunctionBinding(const wxString& val);
    static int ms_test_int;

private:
    wxLuaState   m_wxlState;
    wxLuaObject *m_pObject;
    int          m_minPage;
    int          m_maxPage;
    int          m_pageFrom;
    int          m_pageTo;
    DECLARE_ABSTRACT_CLASS(wxLuaPrintout)
};

#endif //wxLUA_USE_wxLuaPrintout

// ----------------------------------------------------------------------------
// wxLuaArtProvider
// ----------------------------------------------------------------------------
#if wxLUA_USE_wxArtProvider

#include "wx/artprov.h"

class WXDLLIMPEXP_BINDWXCORE wxLuaArtProvider : public wxArtProvider
{
public:
    wxLuaArtProvider(const wxLuaState& wxlState);

    // Get the default size of an icon for a specific client
    virtual wxSize DoGetSizeHint(const wxArtClient& client);

    // Derived classes must override this method to create requested
    // art resource. This method is called only once per instance's
    // lifetime for each requested wxArtID.
    virtual wxBitmap CreateBitmap(const wxArtID& id, const wxArtClient& client, const wxSize& size);

private:
    wxLuaState m_wxlState;

    DECLARE_ABSTRACT_CLASS(wxLuaArtProvider)
};

#endif // wxLUA_USE_wxArtProvider


// ----------------------------------------------------------------------------
// wxLuaTreeItemData - our treeitem data that allows us to get/set an index
// ----------------------------------------------------------------------------
#if wxLUA_USE_wxTreeCtrl && wxUSE_TREECTRL

#include "wx/treectrl.h"

class WXDLLIMPEXP_BINDWXCORE wxLuaTreeItemData : public wxTreeItemData
{
public:
    wxLuaTreeItemData() : m_data(NULL) {}
    wxLuaTreeItemData(wxLuaObject* obj) : m_data(obj) {}

    virtual ~wxLuaTreeItemData() { if (m_data) delete m_data; }

    wxLuaObject* GetData() const { return m_data; }
    void         SetData(wxLuaObject* obj) { if (m_data) delete m_data; m_data = obj; }

private:
    wxLuaObject* m_data;
};

#endif //wxLUA_USE_wxTreeCtrl && wxUSE_TREECTRL


// ----------------------------------------------------------------------------
// wxLuaListCtrl - Allows wxLC_VIRTUAL style
// ----------------------------------------------------------------------------
#if wxLUA_USE_wxListCtrl && wxUSE_LISTCTRL

#include "wx/listctrl.h"

class WXDLLIMPEXP_BINDWXCORE wxLuaListCtrl : public wxListCtrl
{
public:
    // Constructors
    wxLuaListCtrl(const wxLuaState& wxlState);
    wxLuaListCtrl(const wxLuaState& wxlState,
                  wxWindow *parent, wxWindowID id,
                  const wxPoint &pos=wxDefaultPosition,
                  const wxSize &size=wxDefaultSize, long style=wxLC_ICON,
                  const wxValidator &validator=wxDefaultValidator,
                  const wxString &name=wxListCtrlNameStr);


    // Virtual functions used with wxLC_VIRTUAL
    virtual wxListItemAttr * OnGetItemAttr(long item) const;

#if wxCHECK_VERSION(3,0,0) && defined(__WXMSW__)
    virtual wxListItemAttr * OnGetItemColumnAttr(long item, long column) const;
#endif // wxCHECK_VERSION(3,0,0) && defined(__WXMSW__)

    virtual int OnGetItemColumnImage(long item, long column) const;
    virtual int OnGetItemImage (long item) const;
    virtual wxString OnGetItemText (long item, long column) const;

private:
    mutable wxLuaState m_wxlState;

    DECLARE_ABSTRACT_CLASS(wxLuaListCtrl)
};

#endif //wxLUA_USE_wxListCtrl && wxUSE_LISTCTRL


// ----------------------------------------------------------------------------
// wxLuaProcess - Allows overriding onTerminate event
// ----------------------------------------------------------------------------
#if wxLUA_USE_wxProcess

#include "wx/process.h"

class WXDLLIMPEXP_BINDWXCORE wxLuaProcess : public wxProcess
{
public:
    wxLuaProcess(wxEvtHandler *parent = NULL, int nId = wxID_ANY);
    wxLuaProcess(int flags);
    static bool Exists(int pid);
    static wxKillError Kill(int pid, wxSignal sig = wxSIGTERM, int flags = wxKILL_NOCHILDREN);
    static wxLuaProcess *Open(const wxString& cmd, int flags = wxEXEC_ASYNC);
    virtual void OnTerminate(int pid, int status);
private:
    DECLARE_ABSTRACT_CLASS(wxLuaProcess)
};

#endif //wxLUA_USE_wxProcess

#endif //WX_LUA_WXLCORE_H
