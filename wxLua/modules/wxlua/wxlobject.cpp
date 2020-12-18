/////////////////////////////////////////////////////////////////////////////
// Name:          wxlobject.cpp
// Purpose:       wxLuaObject and other binding helper classes
// Author:        Ray Gilbert, John Labenski, J Winwood
// Created:       14/11/2001
// Copyright:     (c) 2012 John Labenski
// Licence:       wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/wxprec.h>

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include <wx/wx.h>
#endif

#include "wxlua/wxlobject.h"
#include "wxlua/wxlstate.h"

//-----------------------------------------------------------------------------
// wxLuaObject
//-----------------------------------------------------------------------------
IMPLEMENT_ABSTRACT_CLASS(wxLuaObject, wxObject)

wxLuaObject::wxLuaObject(const wxLuaState& wxlState, int stack_idx)
            : m_wxlState(new wxLuaState(wxlState.GetLuaState(), wxLUASTATE_GETSTATE|wxLUASTATE_ROOTSTATE)),
              m_alloc_flag(wxLUAOBJECT_NONE),
              m_int(0) // GCC only wants one initializer
{
    // set up the reference to the item on the stack
    m_reference = m_wxlState->wxluaR_Ref(stack_idx, &wxlua_lreg_refs_key);
}
wxLuaObject::wxLuaObject(lua_State* L, int stack_idx)
            : m_alloc_flag(wxLUAOBJECT_NONE),
              m_int(0) // GCC only wants one initializer
{
    m_wxlState = new wxLuaState(L, wxLUASTATE_GETSTATE|wxLUASTATE_ROOTSTATE);

    // set up the reference to the item on the stack
    m_reference = m_wxlState->wxluaR_Ref(stack_idx, &wxlua_lreg_refs_key);
}

wxLuaObject::~wxLuaObject()
{
    if ((m_reference != LUA_NOREF) && m_wxlState->Ok() && !m_wxlState->IsClosing())
    {
        m_wxlState->wxluaR_Unref(m_reference, &wxlua_lreg_refs_key);
        m_reference = LUA_NOREF;
    }
    //else if (!m_wxlState->IsClosing())
    //    wxPrintf(wxT("~wxLuaObject %d %d %d\n"), (int)m_reference, (int)m_wxlState->Ok(), (int)m_wxlState->IsClosing());

    if (m_alloc_flag == wxLUAOBJECT_STRING)
        delete m_string;
    else if (m_alloc_flag == wxLUAOBJECT_ARRAYINT)
        delete m_arrayInt;

    delete m_wxlState;
}

void wxLuaObject::RemoveReference(lua_State* L)
{
    // If a reference exists, remove it, but don't bother if Lua is being closed
    if ((m_reference != LUA_NOREF) && m_wxlState->Ok() && !m_wxlState->IsClosing())
        wxluaR_unref(L, m_reference, &wxlua_lreg_refs_key);

    m_reference = LUA_NOREF;
}

bool wxLuaObject::GetObject(lua_State* L)
{
    if (m_alloc_flag == wxLUAOBJECT_BOOL)
    {
        lua_pushboolean(L, m_bool);
        return true;
    }
    else if (m_alloc_flag == wxLUAOBJECT_INT)
    {
        lua_pushnumber(L, m_int);
        return true;
    }
    else if (m_alloc_flag == wxLUAOBJECT_STRING)
    {
        lua_pushstring(L, wx2lua(*m_string));
        return true;
    }
    else if (m_alloc_flag == wxLUAOBJECT_ARRAYINT)
    {
        wxlua_pushwxArrayInttable(L, *m_arrayInt);
        return true;
    }
    else if ((m_reference != LUA_NOREF) && wxluaR_getref(L, m_reference, &wxlua_lreg_refs_key))
        return true;

    return false; // nothing on the stack
}

void wxLuaObject::SetObject(lua_State* L, int stack_idx)
{
    wxCHECK_RET(m_alloc_flag == wxLUAOBJECT_NONE, wxT("wxLuaObject already initialized by wxLuaObject::GetXXXPtr"));

    if (m_reference != LUA_NOREF) // FIXME should this error out?
        wxluaR_unref(L, m_reference, &wxlua_lreg_refs_key);

    m_reference = wxluaR_ref(L, stack_idx, &wxlua_lreg_refs_key);
}

bool *wxLuaObject::GetBoolPtr(lua_State* L)
{
    wxCHECK_MSG((m_alloc_flag == wxLUAOBJECT_NONE) || (m_alloc_flag == wxLUAOBJECT_BOOL),
                0, wxT("wxLuaObject already initialized in wxLuaObject::GetBoolPtr"));

    if (m_alloc_flag == wxLUAOBJECT_NONE)
    {
        if ((m_reference != LUA_NOREF) && GetObject(L))
        {
            m_bool = (lua_toboolean(L, -1) != 0);
            m_alloc_flag = wxLUAOBJECT_BOOL;
            lua_pop(L, 1);
        }
    }

    return &m_bool;
}

int *wxLuaObject::GetIntPtr(lua_State* L)
{
    wxCHECK_MSG((m_alloc_flag == wxLUAOBJECT_NONE) || (m_alloc_flag == wxLUAOBJECT_INT),
                0, wxT("wxLuaObject already initialized in wxLuaObject::GetIntPtr"));

    if (m_alloc_flag == wxLUAOBJECT_NONE)
    {
        if ((m_reference != LUA_NOREF) && GetObject(L))
        {
            m_int = (int)lua_tonumber(L, -1);
            m_alloc_flag = wxLUAOBJECT_INT;
            lua_pop(L, 1);
        }
    }

    return &m_int;
}

wxString *wxLuaObject::GetStringPtr(lua_State* L)
{
    wxCHECK_MSG((m_alloc_flag == wxLUAOBJECT_NONE) || (m_alloc_flag == wxLUAOBJECT_STRING),
                0, wxT("wxLuaObject already initialized in wxLuaObject::GetStringPtr"));

    if (m_alloc_flag == wxLUAOBJECT_NONE)
    {
        m_string = new wxString(); // create valid string for return

        if ((m_reference != LUA_NOREF) && GetObject(L))
        {
            *m_string = lua2wx(lua_tostring(L, -1));
            m_alloc_flag = wxLUAOBJECT_STRING;
            lua_pop(L, 1);
        }
    }

    return m_string;
}

wxArrayInt *wxLuaObject::GetArrayPtr(lua_State* L)
{
    wxCHECK_MSG((m_alloc_flag == wxLUAOBJECT_NONE) || (m_alloc_flag == wxLUAOBJECT_ARRAYINT),
                0, wxT("wxLuaObject already initialized in wxLuaObject::GetArrayPtr"));

    if (m_alloc_flag == wxLUAOBJECT_NONE)
    {
        m_arrayInt = new wxArrayInt(); // create valid array for return

        if ((m_reference != LUA_NOREF) && GetObject(L))
        {
            *m_arrayInt = (wxArrayInt&)wxlua_getwxArrayInt(L, -1); // coerce wxLuaSmartwxArrayInt
            m_alloc_flag = wxLUAOBJECT_ARRAYINT;
            lua_pop(L, 1);
        }
    }

    return m_arrayInt;
}

// ----------------------------------------------------------------------------
// wxLuaSmartwxArrayString
// ----------------------------------------------------------------------------

const wxLuaSmartwxArrayString wxLuaNullSmartwxArrayString(NULL, true);

class wxLuaSmartwxArrayStringRefData : public wxObjectRefData
{
public:
    wxLuaSmartwxArrayStringRefData(wxArrayString* arr, bool del) : m_arr(arr), m_delete(del)
    {
        if (m_arr == NULL) { m_arr = new wxArrayString; m_delete = true; } // always exists
    }

    virtual ~wxLuaSmartwxArrayStringRefData() { if (m_delete) delete m_arr; }

    wxArrayString *m_arr;
    bool           m_delete;
};

wxLuaSmartwxArrayString::wxLuaSmartwxArrayString(wxArrayString *arr, bool del)
{
    m_refData = new wxLuaSmartwxArrayStringRefData(arr, del);
}
wxArrayString* wxLuaSmartwxArrayString::GetArray() const
{
    return ((wxLuaSmartwxArrayStringRefData*)m_refData)->m_arr;
}

// ----------------------------------------------------------------------------
// wxLuaSmartwxSortedArrayString
// ----------------------------------------------------------------------------

class wxLuaSmartwxSortedArrayStringRefData : public wxObjectRefData
{
public:
    wxLuaSmartwxSortedArrayStringRefData(wxSortedArrayString* arr, bool del) : m_arr(arr), m_delete(del)
    {
        if (m_arr == NULL) { m_arr = new wxSortedArrayString; m_delete = true; } // always exists
    }

    virtual ~wxLuaSmartwxSortedArrayStringRefData() { if (m_delete) delete m_arr; }

    wxSortedArrayString *m_arr;
    bool                 m_delete;
};

wxLuaSmartwxSortedArrayString::wxLuaSmartwxSortedArrayString(wxSortedArrayString *arr, bool del)
{
    m_refData = new wxLuaSmartwxSortedArrayStringRefData(arr, del);
}
wxSortedArrayString* wxLuaSmartwxSortedArrayString::GetArray() const
{
    return ((wxLuaSmartwxSortedArrayStringRefData*)m_refData)->m_arr;
}

// ----------------------------------------------------------------------------
// wxLuaSmartwxArrayInt
// ----------------------------------------------------------------------------

class wxLuaSmartwxArrayIntRefData : public wxObjectRefData
{
public:
    wxLuaSmartwxArrayIntRefData(wxArrayInt* arr, bool del) : m_arr(arr), m_delete(del)
    {
        if (m_arr == NULL) { m_arr = new wxArrayInt; m_delete = true; } // always exists
    }

    virtual ~wxLuaSmartwxArrayIntRefData() { if (m_delete) delete m_arr; }

    wxArrayInt *m_arr;
    bool        m_delete;
};

wxLuaSmartwxArrayInt::wxLuaSmartwxArrayInt(wxArrayInt *arr, bool del)
{
    m_refData = new wxLuaSmartwxArrayIntRefData(arr, del);
}

wxArrayInt* wxLuaSmartwxArrayInt::GetArray() const
{
    return ((wxLuaSmartwxArrayIntRefData*)m_refData)->m_arr;
}

// ----------------------------------------------------------------------------
// wxLuaSmartwxArrayDouble
// ----------------------------------------------------------------------------

class wxLuaSmartwxArrayDoubleRefData : public wxObjectRefData
{
public:
    wxLuaSmartwxArrayDoubleRefData(wxArrayDouble* arr, bool del) : m_arr(arr), m_delete(del)
    {
        if (m_arr == NULL) { m_arr = new wxArrayDouble; m_delete = true; } // always exists
    }

    virtual ~wxLuaSmartwxArrayDoubleRefData() { if (m_delete) delete m_arr; }

    wxArrayDouble *m_arr;
    bool        m_delete;
};

wxLuaSmartwxArrayDouble::wxLuaSmartwxArrayDouble(wxArrayDouble *arr, bool del)
{
    m_refData = new wxLuaSmartwxArrayDoubleRefData(arr, del);
}

wxArrayDouble* wxLuaSmartwxArrayDouble::GetArray() const
{
    return ((wxLuaSmartwxArrayDoubleRefData*)m_refData)->m_arr;
}
