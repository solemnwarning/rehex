/////////////////////////////////////////////////////////////////////////////
// Name:        wxadv_wxladv.cpp
// Purpose:     Wrappers around wxAdv classes for wxLua
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

#include "wxbind/include/wxadv_wxladv.h"

#if wxUSE_GRID && wxLUA_USE_wxGrid

// ----------------------------------------------------------------------------
// wxLuaGridTableBase
// ----------------------------------------------------------------------------

// This lua tag is defined in bindings
extern WXDLLIMPEXP_DATA_BINDWXADV(int) wxluatype_wxGridCellAttr;
extern WXDLLIMPEXP_DATA_BINDWXADV(int) wxluatype_wxLuaGridTableBase;

IMPLEMENT_ABSTRACT_CLASS(wxLuaGridTableBase, wxGridTableBase)

wxLuaGridTableBase::wxLuaGridTableBase(const wxLuaState& wxlState)
                   :m_wxlState(wxlState)
{
}

wxLuaGridTableBase::~wxLuaGridTableBase()
{
    SetView(NULL);
}

int wxLuaGridTableBase::GetNumberRows()
{
    int numrows = 0;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "GetNumberRows", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);

        if (m_wxlState.LuaPCall(1, 1) == 0)
            numrows = (int)m_wxlState.GetNumberType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    // no else since this is pure virtual

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return numrows;
}

int wxLuaGridTableBase::GetNumberCols()
{
    int numcols = 0;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "GetNumberCols", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);

        if (m_wxlState.LuaPCall(1, 1) == 0)
            numcols = (int)m_wxlState.GetNumberType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    // no else since this is pure virtual

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return numcols;
}

bool wxLuaGridTableBase::IsEmptyCell( int row, int col )
{
    bool fResult = false;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "IsEmptyCell", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);
        m_wxlState.lua_PushNumber(row);
        m_wxlState.lua_PushNumber(col);

        if (m_wxlState.LuaPCall(3, 1) == 0)
            fResult = m_wxlState.GetBooleanType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    // no else since this is pure virtual

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return fResult;
}

wxString wxLuaGridTableBase::GetValue( int row, int col )
{
    wxString val;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "GetValue", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);
        m_wxlState.lua_PushNumber(row);
        m_wxlState.lua_PushNumber(col);

        if (m_wxlState.LuaPCall(3, 1) == 0)
            val = m_wxlState.GetwxStringType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    // no else since this is pure virtual

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return val;
}

void wxLuaGridTableBase::SetValue( int row, int col, const wxString& value )
{
    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "SetValue", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);
        m_wxlState.lua_PushNumber(row);
        m_wxlState.lua_PushNumber(col);
        m_wxlState.lua_PushString(value.c_str());

        m_wxlState.LuaPCall(4, 0);
        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    // no else since this is pure virtual

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always
}

// Data type determination and value access
//virtual wxString GetTypeName( int row, int col );
wxString wxLuaGridTableBase::GetTypeName( int row, int col )
{
    wxString val;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "GetTypeName", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);
        m_wxlState.lua_PushNumber(row);
        m_wxlState.lua_PushNumber(col);

        if (m_wxlState.LuaPCall(3, 1) == 0)
            val = m_wxlState.GetwxStringType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        val = wxGridTableBase::GetTypeName( row, col );

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return val;
}

//virtual bool CanGetValueAs( int row, int col, const wxString& typeName );
bool wxLuaGridTableBase::CanGetValueAs( int row, int col, const wxString& typeName )
{
    bool fResult = false;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "CanGetValueAs", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);
        m_wxlState.lua_PushNumber(row);
        m_wxlState.lua_PushNumber(col);
        m_wxlState.lua_PushString(typeName.c_str());

        if (m_wxlState.LuaPCall(4, 1) == 0)
            fResult = m_wxlState.GetBooleanType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        fResult = wxGridTableBase::CanGetValueAs( row, col, typeName );

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return fResult;
}

//virtual bool CanSetValueAs( int row, int col, const wxString& typeName );
bool wxLuaGridTableBase::CanSetValueAs( int row, int col, const wxString& typeName )
{
    bool fResult = false;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "CanSetValueAs", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);
        m_wxlState.lua_PushNumber(row);
        m_wxlState.lua_PushNumber(col);
        m_wxlState.lua_PushString(typeName.c_str());

        if (m_wxlState.LuaPCall(4, 1) == 0)
            fResult = m_wxlState.GetBooleanType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        fResult = wxGridTableBase::CanSetValueAs( row, col, typeName );

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return fResult;
}

//
//virtual long GetValueAsLong( int row, int col );
long wxLuaGridTableBase::GetValueAsLong( int row, int col )
{
    long lResult = 0;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "GetValueAsLong", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);
        m_wxlState.lua_PushNumber(row);
        m_wxlState.lua_PushNumber(col);

        if (m_wxlState.LuaPCall(3, 1) == 0)
            lResult = m_wxlState.GetIntegerType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        lResult = wxGridTableBase::GetValueAsLong( row, col );

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return lResult;
}

//virtual double GetValueAsDouble( int row, int col );
double wxLuaGridTableBase::GetValueAsDouble( int row, int col )
{
    double dResult = 0;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "GetValueAsDouble", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);
        m_wxlState.lua_PushNumber(row);
        m_wxlState.lua_PushNumber(col);

        if (m_wxlState.LuaPCall(3, 1) == 0)
            dResult = m_wxlState.GetNumberType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        dResult = wxGridTableBase::GetValueAsDouble( row, col );

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return dResult;
}

//virtual bool GetValueAsBool( int row, int col );
bool wxLuaGridTableBase::GetValueAsBool( int row, int col )
{
    bool fResult = false;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "GetValueAsBool", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);
        m_wxlState.lua_PushNumber(row);
        m_wxlState.lua_PushNumber(col);

        if (m_wxlState.LuaPCall(3, 1) == 0)
            fResult = m_wxlState.GetBooleanType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        fResult = wxGridTableBase::GetValueAsBool( row, col );

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return fResult;
}

//virtual void SetValueAsLong( int row, int col, long value );
void wxLuaGridTableBase::SetValueAsLong( int row, int col, long value )
{
    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "SetValueAsLong", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);
        m_wxlState.lua_PushNumber(row);
        m_wxlState.lua_PushNumber(col);
        m_wxlState.lua_PushNumber(value);

        m_wxlState.LuaPCall(4, 0);
        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        wxGridTableBase::SetValueAsLong( row, col, value );

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always
}

//virtual void SetValueAsDouble( int row, int col, double value );
void wxLuaGridTableBase::SetValueAsDouble( int row, int col, double value )
{
    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "SetValueAsDouble", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);
        m_wxlState.lua_PushNumber(row);
        m_wxlState.lua_PushNumber(col);
        m_wxlState.lua_PushNumber(value);

        m_wxlState.LuaPCall(4, 0);
        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        wxGridTableBase::SetValueAsDouble( row, col, value );

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always
}

//virtual void SetValueAsBool( int row, int col, bool value );
void wxLuaGridTableBase::SetValueAsBool( int row, int col, bool value )
{
    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "SetValueAsBool", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);
        m_wxlState.lua_PushNumber(row);
        m_wxlState.lua_PushNumber(col);
        m_wxlState.lua_PushBoolean(value);

        m_wxlState.LuaPCall(4, 0);
        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        wxGridTableBase::SetValueAsBool( row, col, value );

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always
}

// For user defined types
//virtual void* GetValueAsCustom( int row, int col, const wxString& typeName );
//void* wxLuaGridTableBase::GetValueAsCustom( int row, int col, const wxString& typeName )
//{
//}

//virtual void  SetValueAsCustom( int row, int col, const wxString& typeName, void* value );
//void  wxLuaGridTableBase::SetValueAsCustom( int row, int col, const wxString& typeName, void* value )
//{
//}

// Overriding these is optional
//virtual void SetView( wxGrid *grid ) { m_view = grid; }
//virtual wxGrid * GetView() const { return m_view; }

//virtual void Clear() {}
void wxLuaGridTableBase::Clear()
{
    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "Clear", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);

        m_wxlState.LuaPCall(1, 0);
        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        wxGridTableBase::Clear( );

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always
}

//virtual bool InsertRows( size_t pos = 0, size_t numRows = 1 );
bool wxLuaGridTableBase::InsertRows( size_t pos, size_t numRows )
{
    bool fResult = false;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "InsertRows", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);
        m_wxlState.lua_PushNumber(pos);
        m_wxlState.lua_PushNumber(numRows);

        if (m_wxlState.LuaPCall(3, 1) == 0)
            fResult = m_wxlState.GetBooleanType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        fResult = wxGridTableBase::InsertRows( pos, numRows );

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return fResult;
}

//virtual bool AppendRows( size_t numRows = 1 );
bool wxLuaGridTableBase::AppendRows( size_t numRows )
{
    bool fResult = false;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "AppendRows", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);
        m_wxlState.lua_PushNumber(numRows);

        if (m_wxlState.LuaPCall(2, 1) == 0)
            fResult = m_wxlState.GetBooleanType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        fResult = wxGridTableBase::AppendRows( numRows );

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return fResult;
}

//virtual bool DeleteRows( size_t pos = 0, size_t numRows = 1 );
bool wxLuaGridTableBase::DeleteRows( size_t pos, size_t numRows )
{
    bool fResult = false;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "DeleteRows", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);
        m_wxlState.lua_PushNumber(pos);
        m_wxlState.lua_PushNumber(numRows);

        if (m_wxlState.LuaPCall(3, 1) == 0)
            fResult = m_wxlState.GetBooleanType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        fResult = wxGridTableBase::DeleteRows( pos, numRows );

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return fResult;
}

//virtual bool InsertCols( size_t pos = 0, size_t numCols = 1 );
bool wxLuaGridTableBase::InsertCols( size_t pos, size_t numCols )
{
    bool fResult = false;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "InsertCols", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);
        m_wxlState.lua_PushNumber(pos);
        m_wxlState.lua_PushNumber(numCols);

        if (m_wxlState.LuaPCall(3, 1) == 0)
            fResult = m_wxlState.GetBooleanType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        fResult = wxGridTableBase::InsertCols( pos, numCols );

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return fResult;
}

//virtual bool AppendCols( size_t numCols = 1 );
bool wxLuaGridTableBase::AppendCols( size_t numCols )
{
    bool fResult = false;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "AppendCols", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);
        m_wxlState.lua_PushNumber(numCols);

        if (m_wxlState.LuaPCall(2, 1) == 0)
            fResult = m_wxlState.GetBooleanType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        fResult = wxGridTableBase::AppendCols( numCols );

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return fResult;
}

//virtual bool DeleteCols( size_t pos = 0, size_t numCols = 1 );
bool wxLuaGridTableBase::DeleteCols( size_t pos, size_t numCols )
{
    bool fResult = false;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "DeleteCols", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);
        m_wxlState.lua_PushNumber(pos);
        m_wxlState.lua_PushNumber(numCols);

        if (m_wxlState.LuaPCall(3, 1) == 0)
            fResult = m_wxlState.GetBooleanType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        fResult = wxGridTableBase::DeleteCols( pos, numCols );

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return fResult;
}

//virtual wxString GetRowLabelValue( int row );
wxString wxLuaGridTableBase::GetRowLabelValue( int row )
{
    wxString val;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "GetRowLabelValue", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);
        m_wxlState.lua_PushNumber(row);

        if (m_wxlState.LuaPCall(2, 1) == 0)
            val = m_wxlState.GetwxStringType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        val = wxGridTableBase::GetRowLabelValue( row );

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return val;
}

//virtual wxString GetColLabelValue( int col );
wxString wxLuaGridTableBase::GetColLabelValue( int col )
{
    wxString val;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "GetColLabelValue", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);
        m_wxlState.lua_PushNumber(col);

        if (m_wxlState.LuaPCall(2, 1) == 0)
            val = m_wxlState.GetwxStringType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        val = wxGridTableBase::GetColLabelValue( col );

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return val;
}

//virtual void SetRowLabelValue( int WXUNUSED(row), const wxString& ) {}
void wxLuaGridTableBase::SetRowLabelValue( int row, const wxString& val )
{
    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "SetRowLabelValue", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);
        m_wxlState.lua_PushNumber(row);
        m_wxlState.lua_PushString(val.c_str());

        m_wxlState.LuaPCall(3, 0);
        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        wxGridTableBase::SetRowLabelValue( row, val );

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always
}

//virtual void SetColLabelValue( int WXUNUSED(col), const wxString& ) {}
void wxLuaGridTableBase::SetColLabelValue( int col, const wxString& val )
{
    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "SetColLabelValue", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);
        m_wxlState.lua_PushNumber(col);
        m_wxlState.lua_PushString(val.c_str());

        m_wxlState.LuaPCall(3, 0);
        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        wxGridTableBase::SetColLabelValue( col, val );

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always
}

// Attribute handling
// give us the attr provider to use - we take ownership of the pointer
//void SetAttrProvider(wxGridCellAttrProvider *attrProvider);
// get the currently used attr provider (may be NULL)
//wxGridCellAttrProvider *GetAttrProvider() const { return m_attrProvider; }
//
// Does this table allow attributes?  Default implementation creates
// a wxGridCellAttrProvider if necessary.
//virtual bool CanHaveAttributes();
bool wxLuaGridTableBase::CanHaveAttributes()
{
    bool fResult = false;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "CanHaveAttributes", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);

        if (m_wxlState.LuaPCall(1, 1) == 0)
            fResult = m_wxlState.GetBooleanType(-1);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        fResult = wxGridTableBase::CanHaveAttributes( );

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return fResult;
}

// by default forwarded to wxGridCellAttrProvider if any. May be
// overridden to handle attributes directly in the table.
//virtual wxGridCellAttr *GetAttr( int row, int col,
//                                 wxGridCellAttr::wxAttrKind  kind );
wxGridCellAttr *wxLuaGridTableBase::GetAttr( int row, int col,
                                 wxGridCellAttr::wxAttrKind  kind )
{
    wxGridCellAttr *attr = NULL;

    if (m_wxlState.Ok() && !m_wxlState.GetCallBaseClassFunction() &&
        m_wxlState.HasDerivedMethod(this, "GetAttr", true))
    {
        int nOldTop = m_wxlState.lua_GetTop();
        m_wxlState.wxluaT_PushUserDataType(this, wxluatype_wxLuaGridTableBase, true);
        m_wxlState.lua_PushNumber(row);
        m_wxlState.lua_PushNumber(col);
        m_wxlState.lua_PushInteger(kind);

        if (m_wxlState.LuaPCall(4, 1) == 0)
            attr = (wxGridCellAttr*)m_wxlState.GetUserDataType(-1, wxluatype_wxGridCellAttr);

        m_wxlState.lua_SetTop(nOldTop-1); // -1 to remove pushed derived method func too
    }
    else
        attr = wxGridTableBase::GetAttr( row, col, kind );

    m_wxlState.SetCallBaseClassFunction(false); // clear flag always

    return attr;
}

// these functions take ownership of the pointer
//virtual void SetAttr(wxGridCellAttr* attr, int row, int col);
//void wxLuaGridTableBase::SetAttr(wxGridCellAttr* attr, int row, int col)
//{
//}

//virtual void SetRowAttr(wxGridCellAttr *attr, int row);
//void wxLuaGridTableBase::SetRowAttr(wxGridCellAttr *attr, int row)
//{
//}

//virtual void SetColAttr(wxGridCellAttr *attr, int col);
//void wxLuaGridTableBase::SetColAttr(wxGridCellAttr *attr, int col)
//{
//}

#endif // wxUSE_GRID && wxLUA_USE_wxGrid
