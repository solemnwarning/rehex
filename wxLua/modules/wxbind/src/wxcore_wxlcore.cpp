/////////////////////////////////////////////////////////////////////////////
// Name:        wxLuaPrinting.cpp
// Purpose:     Provide an interface to wxPrintout for wxLua.
// Author:      J. Winwood.
// Created:     July 2002.
// Copyright:   (c) 2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include "wx/wx.h"
#endif

#include "wx/datetime.h"

#include "wxbind/include/wxcore_wxlcore.h"
#include "wxbind/include/wxcore_bind.h" // for wxLua_wxObject_wxSize

// ----------------------------------------------------------------------------
// wxLuaDataObjectSimple
// ----------------------------------------------------------------------------

#if wxLUA_USE_wxDataObject && wxUSE_DATAOBJ

// This lua tag is defined in bindings
extern WXDLLIMPEXP_DATA_BINDWXCORE(int) wxluatype_wxLuaDataObjectSimple;

wxLuaDataObjectSimple::wxLuaDataObjectSimple(const wxLuaState& wxlState,
                                             const wxDataFormat& format)
                      :wxDataObjectSimple(format)
{
    m_wxlState = wxlState;
}

size_t wxLuaDataObjectSimple::GetDataSize() const
{
    size_t result = 0;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "GetDataSize", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaDataObjectSimple, true);

        if (m_wxlState.LuaPCall(1, 1) == 0)
            result = m_wxlState.GetNumberType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        result = wxDataObjectSimple::GetDataSize();

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return result;
}

bool wxLuaDataObjectSimple::GetDataHere(void* buf) const
{
    bool result = false;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "GetDataHere", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaDataObjectSimple, true);

        if (m_wxlState.LuaPCall(1, 2) == 0)
        {
            result = m_wxlState.GetBooleanType(-2);

            size_t len;
            const void *lua_buf = (const void *)wxlua_getstringtypelen(m_wxlState.GetLuaState(), -1, &len);

            memcpy(buf, lua_buf, len);
        }

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        result = wxDataObjectSimple::GetDataHere(buf);

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return result;
}

bool wxLuaDataObjectSimple::SetData(size_t len, const void* buf)
{
    bool result = false;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "SetData", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaDataObjectSimple, true);
        m_wxlState.lua_PushLString((const char*)buf, len);

        if (m_wxlState.LuaPCall(2, 1) == 0)
            result = m_wxlState.GetBooleanType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        result = wxDataObjectSimple::SetData(len, buf);

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return result;
}

#endif //wxLUA_USE_wxDataObject && wxUSE_DATAOBJ

// ----------------------------------------------------------------------------
// wxLuaFileDropTarget
// ----------------------------------------------------------------------------

#if wxLUA_USE_wxDataObject && wxUSE_DRAG_AND_DROP

// This lua tag is defined in bindings
extern WXDLLIMPEXP_DATA_BINDWXCORE(int) wxluatype_wxLuaFileDropTarget;

wxLuaFileDropTarget::wxLuaFileDropTarget(const wxLuaState& wxlState)
                    :wxFileDropTarget()
{
    m_wxlState = wxlState;
}

bool wxLuaFileDropTarget::OnDropFiles(wxCoord x, wxCoord y,
                                      const wxArrayString& filenames)
{
    bool result = false;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "OnDropFiles", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaFileDropTarget, true);
        m_wxlState.lua_PushInteger(x);
        m_wxlState.lua_PushInteger(y);
        m_wxlState.PushwxArrayStringTable(filenames);

        if (m_wxlState.LuaPCall(4, 1) == 0)
            result = m_wxlState.GetBooleanType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    //else - do nothing, the base class function is pure virtual
    //    result = wxFileDropTarget::OnDropFiles(x, y, filenames);

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return result;
}

wxDragResult wxLuaFileDropTarget::OnData(wxCoord x, wxCoord y, wxDragResult def)
{
    wxDragResult result = wxDragNone;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "OnData", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaFileDropTarget, true);
        m_wxlState.lua_PushInteger(x);
        m_wxlState.lua_PushInteger(y);
        m_wxlState.lua_PushInteger(def);

        if (m_wxlState.LuaPCall(4, 1) == 0)
            result = (wxDragResult)m_wxlState.GetIntegerType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        result = wxFileDropTarget::OnData(x, y, def);

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return result;
}

#endif //wxLUA_USE_wxDataObject && wxUSE_DRAG_AND_DROP

// ----------------------------------------------------------------------------
// wxLuaFileDropTarget
// ----------------------------------------------------------------------------

#if wxLUA_USE_wxDataObject && wxUSE_DRAG_AND_DROP

// This lua tag is defined in bindings
extern WXDLLIMPEXP_DATA_BINDWXCORE(int) wxluatype_wxLuaTextDropTarget;

wxLuaTextDropTarget::wxLuaTextDropTarget(const wxLuaState& wxlState)
                    :wxTextDropTarget()
{
    m_wxlState = wxlState;
}

bool wxLuaTextDropTarget::OnDropText(wxCoord x, wxCoord y, const wxString& text)
{
    bool result = false;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "OnDropText", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaTextDropTarget, true);
        m_wxlState.lua_PushInteger(x);
        m_wxlState.lua_PushInteger(y);
        m_wxlState.lua_PushString(wx2lua(text));

        if (m_wxlState.LuaPCall(4, 1) == 0)
            result = m_wxlState.GetBooleanType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    //else - do nothing, the base class function is pure virtual
    //    result = wxTextDropTarget::OnDropText(x, y, text);

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return result;
}

wxDragResult wxLuaTextDropTarget::OnData(wxCoord x, wxCoord y, wxDragResult def)
{
    wxDragResult result = wxDragNone;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "OnData", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaTextDropTarget, true);
        m_wxlState.lua_PushInteger(x);
        m_wxlState.lua_PushInteger(y);
        m_wxlState.lua_PushInteger(def);

        if (m_wxlState.LuaPCall(4, 1) == 0)
            result = (wxDragResult)m_wxlState.GetIntegerType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        result = wxTextDropTarget::OnData(x, y, def);

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return result;
}

wxDragResult wxLuaTextDropTarget::OnEnter(wxCoord x, wxCoord y, wxDragResult def)
{
    wxDragResult result = wxDragNone;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "OnEnter", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaTextDropTarget, true);
        m_wxlState.lua_PushInteger(x);
        m_wxlState.lua_PushInteger(y);
        m_wxlState.lua_PushInteger(def);

        if (m_wxlState.LuaPCall(4, 1) == 0)
            result = (wxDragResult)m_wxlState.GetIntegerType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
    {
        // do nothing if function is not set in Lua
    }

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return result;
}

void wxLuaTextDropTarget::OnLeave()
{
    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "OnLeave", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaTextDropTarget, true);

        if (m_wxlState.LuaPCall(1, 0) == 0)
        {
            // All is OK, do nothing
        }

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
    {
        // do nothing if function is not set in Lua
    }

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always
}

wxDragResult wxLuaTextDropTarget::OnDragOver(wxCoord x, wxCoord y, wxDragResult def)
{
    wxDragResult result = wxDragNone;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "OnDragOver", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaTextDropTarget, true);
        m_wxlState.lua_PushInteger(x);
        m_wxlState.lua_PushInteger(y);
        m_wxlState.lua_PushInteger(def);

        if (m_wxlState.LuaPCall(4, 1) == 0)
            result = (wxDragResult)m_wxlState.GetIntegerType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        result = wxTextDropTarget::OnDragOver(x, y, def);

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return result;
}

#endif //wxLUA_USE_wxDataObject && wxUSE_DRAG_AND_DROP


// ----------------------------------------------------------------------------
// wxLuaURLDropTarget
// ----------------------------------------------------------------------------

#if wxLUA_USE_wxDataObject && wxUSE_DRAG_AND_DROP

// This lua tag is defined in bindings
extern WXDLLIMPEXP_DATA_BINDWXCORE(int) wxluatype_wxLuaURLDropTarget;

wxLuaURLDropTarget::wxLuaURLDropTarget(const wxLuaState& wxlState)
                   :wxDropTarget()
{
    SetDataObject(new wxURLDataObject);
    m_wxlState = wxlState;
}

bool wxLuaURLDropTarget::OnDropURL(wxCoord x, wxCoord y, const wxString& text)
{
    bool result = false;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "OnDropURL", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaURLDropTarget, true);
        m_wxlState.lua_PushInteger(x);
        m_wxlState.lua_PushInteger(y);
        m_wxlState.lua_PushString(wx2lua(text));

        if (m_wxlState.LuaPCall(4, 1) == 0)
            result = m_wxlState.GetBooleanType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    //else - do nothing, there is no base class function

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return result;
}

wxDragResult wxLuaURLDropTarget::OnData(wxCoord x, wxCoord y, wxDragResult def)
{
    wxDragResult result = wxDragNone;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "OnData", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaURLDropTarget, true);
        m_wxlState.lua_PushInteger(x);
        m_wxlState.lua_PushInteger(y);
        m_wxlState.lua_PushInteger(def);

        if (m_wxlState.LuaPCall(4, 1) == 0)
            result = (wxDragResult)m_wxlState.GetIntegerType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
    {
        // result = wxDropTarget::OnData(x, y, def); this is pure virtual

        if ( !GetData() )
            return wxDragNone;

        m_wxlState.SetCallBaseClassFunction(false); // clear flag before next virtual call

        wxURLDataObject *dobj = (wxURLDataObject *)m_dataObject;
        return OnDropURL( x, y, dobj->GetURL() ) ? def : wxDragNone;
    }

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return result;
}

#endif //wxLUA_USE_wxDataObject && wxUSE_DRAG_AND_DROP

// ----------------------------------------------------------------------------
// wxLuaPrintout
// ----------------------------------------------------------------------------

#if wxLUA_USE_wxLuaPrintout

// This lua tag is defined in bindings
extern WXDLLIMPEXP_DATA_BINDWXCORE(int) wxluatype_wxLuaPrintout;

int wxLuaPrintout::ms_test_int = -1;

IMPLEMENT_ABSTRACT_CLASS(wxLuaPrintout, wxPrintout)

wxLuaPrintout::wxLuaPrintout(const wxLuaState& wxlState,
                             const wxString& title, wxLuaObject *pObject)
              :wxPrintout(title), m_wxlState(wxlState), m_pObject(pObject),
                m_minPage(0), m_maxPage(0), m_pageFrom(0), m_pageTo(0)
{
}

void wxLuaPrintout::SetPageInfo(int minPage, int maxPage, int pageFrom, int pageTo)
{
    m_minPage  = minPage;
    m_maxPage  = maxPage;
    m_pageFrom = pageFrom;
    m_pageTo   = pageTo;
}

void wxLuaPrintout::GetPageInfo(int *minPage, int *maxPage, int *pageFrom, int *pageTo)
{
    *minPage = *maxPage = *pageFrom = *pageTo = 0;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "GetPageInfo", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaPrintout, true);

        if (m_wxlState.LuaPCall(1, 4) == 0)
        {
            *minPage  = (int)m_wxlState.GetNumberType(-4);
            *maxPage  = (int)m_wxlState.GetNumberType(-3);
            *pageFrom = (int)m_wxlState.GetNumberType(-2);
            *pageTo   = (int)m_wxlState.GetNumberType(-1);
        }

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
    {
        *minPage  = m_minPage;
        *maxPage  = m_maxPage;
        *pageFrom = m_pageFrom;
        *pageTo   = m_pageTo;
    }

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always
}

bool wxLuaPrintout::HasPage(int pageNum)
{
    bool fResult = false;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "HasPage", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaPrintout, true);
        m_wxlState.lua_PushNumber(pageNum);

        if (m_wxlState.LuaPCall(2, 1) == 0)
            fResult = m_wxlState.GetBooleanType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        fResult = wxPrintout::HasPage(pageNum);

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return fResult;
}

// Notes about virtual functions:
//
// This is the call list using the wxPrintf statements in wxLuaPrintout::OnBeginDocument
//    for the wxLua code (see printing.wx.lua sample for complete listing)
//
//    previewPrintout = wxLuaPrintout("Test print")
//    ...
//    previewPrintout.OnBeginDocument = function(self, startPage, endPage)
//                                   return self:base_OnBeginDocument(startPage, endPage)
//                               end
//    ...
//    local preview = wx.wxPrintPreview(printerPrintout, previewPrintout, printDialogData)
//
// wxLuaPrintout::OnBeginDocument 1 call base 0
// wxlua_getTableFunc func 'base_OnBeginDocument' pClass -1220355700 'wxLuaPrintout', userdata 1, lightuserdata 0, ttag 207, class_tag 207 lua_State 139252808 wxLuaStateRefData 139155808 call base 1
// wxLua_wxPrintout_OnBeginDocument 1 (this is the wxLua binding function for wxPrintout::OnBeginDocument)
// wxLuaPrintout::OnBeginDocument 1 call base 1
// wxLuaPrintout::OnBeginDocument 3 call base 1
// wxPrintout::OnBeginDocument (this is the call to the wxWidgets function in its library)
// wxLuaPrintout::OnBeginDocument 4 call base 1
// wxLuaPrintout::OnBeginDocument 2 call base 0
// wxLuaPrintout::OnBeginDocument 4 call base 0

bool wxLuaPrintout::OnBeginDocument(int startPage, int endPage)
{
    // NOTE: The wxLua program MUST call the base class, see printing.wx.lua
    bool fResult = true;

    //wxPrintf(wxT("wxLuaPrintout::OnBeginDocument 1 call base %d\n"), m_wxlState.GetCallBaseClassFunction());

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "OnBeginDocument", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaPrintout, true);
        m_wxlState.lua_PushNumber(startPage);
        m_wxlState.lua_PushNumber(endPage);

        if (m_wxlState.LuaPCall(3, 1) == 0)
            fResult = m_wxlState.GetBooleanType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
        //wxPrintf(wxT("wxLuaPrintout::OnBeginDocument 2 call base %d\n"), m_wxlState.GetCallBaseClassFunction());
    }
    else
    {
        //wxPrintf(wxT("wxLuaPrintout::OnBeginDocument 3 call base %d\n"), m_wxlState.GetCallBaseClassFunction());
        fResult = wxPrintout::OnBeginDocument(startPage, endPage);
    }

    //wxPrintf(wxT("wxLuaPrintout::OnBeginDocument 4 call base %d\n"), m_wxlState.GetCallBaseClassFunction());

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return fResult;
}

void wxLuaPrintout::OnEndDocument()
{
    // NOTE: The wxLua program MUST call the base class, see printing.wx.lua
    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "OnEndDocument", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaPrintout, true);
        m_wxlState.LuaPCall(1, 0);
        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        wxPrintout::OnEndDocument();

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always
}

void wxLuaPrintout::OnBeginPrinting()
{
    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "OnBeginPrinting", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaPrintout, true);
        m_wxlState.LuaPCall(1, 0);
        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        wxPrintout::OnBeginPrinting();

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always
}

void wxLuaPrintout::OnEndPrinting()
{
    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "OnEndPrinting", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaPrintout, true);
        m_wxlState.LuaPCall(1, 0);
        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        wxPrintout::OnEndPrinting();

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always
}

void wxLuaPrintout::OnPreparePrinting()
{
    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "OnPreparePrinting", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaPrintout, true);
        m_wxlState.LuaPCall(1, 0);
        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        wxPrintout::OnPreparePrinting();

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always
}

bool wxLuaPrintout::OnPrintPage(int pageNum)
{
    bool fResult = false;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "OnPrintPage", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaPrintout, true);
        m_wxlState.lua_PushNumber(pageNum);

        if (m_wxlState.LuaPCall(2, 1) == 0)
            fResult = m_wxlState.GetBooleanType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    // no else since this is pure virtual

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return fResult;
}

wxString wxLuaPrintout::TestVirtualFunctionBinding(const wxString& val)
{
    wxString result(val + wxT("-Base"));

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "TestVirtualFunctionBinding", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaPrintout, true);
        m_wxlState.lua_PushString(val.c_str());

        if (m_wxlState.LuaPCall(2, 1) == 0)
            result = m_wxlState.GetwxStringType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    // no else since wxPrintout doesn't have this function

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return result;
}

#endif // wxLUA_USE_wxLuaPrintout

// ----------------------------------------------------------------------------
// wxLuaArtProvider
// ----------------------------------------------------------------------------

IMPLEMENT_ABSTRACT_CLASS(wxLuaArtProvider, wxArtProvider)

extern WXDLLIMPEXP_DATA_BINDWXCORE(int) wxluatype_wxLuaArtProvider;
extern WXDLLIMPEXP_DATA_BINDWXCORE(int) wxluatype_wxSize;
extern WXDLLIMPEXP_DATA_BINDWXCORE(int) wxluatype_wxBitmap;

wxLuaArtProvider::wxLuaArtProvider(const wxLuaState& wxlState) : m_wxlState(wxlState)
{
}

wxSize wxLuaArtProvider::DoGetSizeHint(const wxArtClient& client)
{
    wxSize size;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "DoGetSizeHint", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaArtProvider, true);
        m_wxlState.lua_PushString(client.c_str());

        if (m_wxlState.LuaPCall(2, 1) == 0)
        {
            wxSize *s = (wxSize*)m_wxlState.GetUserDataType(-1, wxluatype_wxSize);
            if (s) size = *s;
        }

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        size = wxArtProvider::DoGetSizeHint(client);

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return size;
}

wxBitmap wxLuaArtProvider::CreateBitmap(const wxArtID& id, const wxArtClient& client, const wxSize& size)
{
    wxBitmap bitmap;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "CreateBitmap", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaArtProvider, true);
        m_wxlState.lua_PushString(id.c_str());
        m_wxlState.lua_PushString(client.c_str());

        // allocate a new object using the copy constructor
        wxSize* s = new wxSize(size);
        // add the new object to the tracked memory list
        m_wxlState.AddGCObject((void*)s, wxluatype_wxSize);
        m_wxlState.wxluaT_PushUserDataType(s, wxluatype_wxSize, true);

        if (m_wxlState.LuaPCall(4, 1) == 0)
        {
            wxBitmap *b = (wxBitmap*)m_wxlState.GetUserDataType(-1, wxluatype_wxBitmap);
            if (b) bitmap = *b;
        }

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    // no else since this is pure virtual

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return bitmap;
}


// ----------------------------------------------------------------------------
// wxLuaListCtrl
// ----------------------------------------------------------------------------

#if wxLUA_USE_wxListCtrl && wxUSE_LISTCTRL

IMPLEMENT_ABSTRACT_CLASS(wxLuaListCtrl, wxListCtrl)

extern WXDLLIMPEXP_DATA_BINDWXCORE(int) wxluatype_wxLuaListCtrl;
extern WXDLLIMPEXP_DATA_BINDWXCORE(int) wxluatype_wxListItemAttr;

wxLuaListCtrl::wxLuaListCtrl(const wxLuaState& wxlState)
              :m_wxlState(wxlState)
{
}

wxLuaListCtrl::wxLuaListCtrl(const wxLuaState& wxlState, wxWindow *parent, wxWindowID id,
                             const wxPoint &pos, const wxSize &size, long style,
                             const wxValidator &validator, const wxString &name)
              :wxListCtrl(parent, id, pos, size, style, validator, name), m_wxlState(wxlState)
{
}

wxListItemAttr * wxLuaListCtrl::OnGetItemAttr(long item) const
{
    wxListItemAttr * attr = NULL;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "OnGetItemAttr", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaListCtrl, true);
        m_wxlState.lua_PushNumber(item);

        if (m_wxlState.LuaPCall(2, 1) == 0)
            attr = (wxListItemAttr*)m_wxlState.GetUserDataType(-1, wxluatype_wxListItemAttr);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        attr = wxListCtrl::OnGetItemAttr(item);

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return attr;
}

#if wxCHECK_VERSION(3,0,0) && defined(__WXMSW__)
wxListItemAttr * wxLuaListCtrl::OnGetItemColumnAttr(long item, long column) const
{
    wxListItemAttr * attr = NULL;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "OnGetItemColumnAttr", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaListCtrl, true);
        m_wxlState.lua_PushNumber(item);
        m_wxlState.lua_PushNumber(column);

        if (m_wxlState.LuaPCall(3, 1) == 0)
            attr = (wxListItemAttr*)m_wxlState.GetUserDataType(-1, wxluatype_wxListItemAttr);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        attr = wxListCtrl::OnGetItemColumnAttr(item, column);

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return attr;
}
#endif //wxCHECK_VERSION(3,0,0) && defined(__WXMSW__)

int wxLuaListCtrl::OnGetItemColumnImage(long item, long column) const
{
    int image = 0;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "OnGetItemColumnImage", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaListCtrl, true);
        m_wxlState.lua_PushNumber(item);
        m_wxlState.lua_PushNumber(column);

        if (m_wxlState.LuaPCall(3, 1) == 0)
            image = m_wxlState.GetIntegerType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        image = wxListCtrl::OnGetItemColumnImage(item, column);

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return image;
}

int wxLuaListCtrl::OnGetItemImage(long item) const
{
    int image = 0;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "OnGetItemImage", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaListCtrl, true);
        m_wxlState.lua_PushNumber(item);

        if (m_wxlState.LuaPCall(2, 1) == 0)
            image = m_wxlState.GetIntegerType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    // no else since the class must override this function

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return image;
}

wxString wxLuaListCtrl::OnGetItemText(long item, long column) const
{
    wxString str;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "OnGetItemText", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaListCtrl, true);
        m_wxlState.lua_PushNumber(item);
        m_wxlState.lua_PushNumber(column);

        if (m_wxlState.LuaPCall(3, 1) == 0)
            str = m_wxlState.GetwxStringType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        str = wxListCtrl::OnGetItemText(item, column);

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return str;
}

#endif //wxLUA_USE_wxListCtrl && wxUSE_LISTCTRL

// ----------------------------------------------------------------------------
// wxLuaProcess - Allows overriding onTerminate event
// ----------------------------------------------------------------------------
#if wxLUA_USE_wxProcess

IMPLEMENT_ABSTRACT_CLASS(wxLuaProcess, wxProcess)

extern WXDLLIMPEXP_DATA_BINDWXCORE(int) wxluatype_wxLuaProcess;

wxLuaProcess::wxLuaProcess(int flags)
    : wxProcess(flags)
{
}

wxLuaProcess::wxLuaProcess(wxEvtHandler *parent, int nId)
    : wxProcess(parent, nId)
{
}

void wxLuaProcess::OnTerminate(int pid, int status)
{
    wxProcessEvent event(m_id, pid, status);
    ProcessEvent(event);
}

#endif //WX_LUA_WXLCORE_H
