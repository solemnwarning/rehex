/////////////////////////////////////////////////////////////////////////////
// Purpose:     Wrappers around wxAdv classes for wxLua
// Author:      J. Winwood
// Created:     July 2002
// Copyright:   (c) 2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef WX_LUA_WXLADV_H
#define WX_LUA_WXLADV_H

#include "wxbind/include/wxbinddefs.h"
#include "wxluasetup.h"

#if wxUSE_GRID && wxLUA_USE_wxGrid

#include "wx/grid.h"

class WXDLLIMPEXP_BINDWXADV wxLuaGridTableBase : public wxGridTableBase
{
public:
    wxLuaGridTableBase(const wxLuaState& wxlState);
    virtual ~wxLuaGridTableBase();

    // You must override these functions in a derived table class
    //
    virtual int GetNumberRows();
    virtual int GetNumberCols();
    virtual bool IsEmptyCell( int row, int col );
    virtual wxString GetValue( int row, int col );
    virtual void SetValue( int row, int col, const wxString& value );

    // Data type determination and value access
    virtual wxString GetTypeName( int row, int col );
    virtual bool CanGetValueAs( int row, int col, const wxString& typeName );
    virtual bool CanSetValueAs( int row, int col, const wxString& typeName );

    virtual long GetValueAsLong( int row, int col );
    virtual double GetValueAsDouble( int row, int col );
    virtual bool GetValueAsBool( int row, int col );

    virtual void SetValueAsLong( int row, int col, long value );
    virtual void SetValueAsDouble( int row, int col, double value );
    virtual void SetValueAsBool( int row, int col, bool value );

    // For user defined types
    //virtual void* GetValueAsCustom( int row, int col, const wxString& typeName );
    //virtual void  SetValueAsCustom( int row, int col, const wxString& typeName, void* value );

    // Overriding these is optional
    //
    //virtual void SetView( wxGrid *grid ) { m_view = grid; }
    //virtual wxGrid * GetView() const { return m_view; }

    virtual void Clear();
    virtual bool InsertRows( size_t pos = 0, size_t numRows = 1 );
    virtual bool AppendRows( size_t numRows = 1 );
    virtual bool DeleteRows( size_t pos = 0, size_t numRows = 1 );
    virtual bool InsertCols( size_t pos = 0, size_t numCols = 1 );
    virtual bool AppendCols( size_t numCols = 1 );
    virtual bool DeleteCols( size_t pos = 0, size_t numCols = 1 );

    virtual wxString GetRowLabelValue( int row );
    virtual wxString GetColLabelValue( int col );
    virtual void SetRowLabelValue( int WXUNUSED(row), const wxString& );
    virtual void SetColLabelValue( int WXUNUSED(col), const wxString& );

    // Attribute handling
    //

    // give us the attr provider to use - we take ownership of the pointer
    //void SetAttrProvider(wxGridCellAttrProvider *attrProvider);

    // get the currently used attr provider (may be NULL)
    //wxGridCellAttrProvider *GetAttrProvider() const { return m_attrProvider; }

    // Does this table allow attributes?  Default implementation creates
    // a wxGridCellAttrProvider if necessary.
    virtual bool CanHaveAttributes();

    // by default forwarded to wxGridCellAttrProvider if any. May be
    // overridden to handle attributes directly in the table.
    virtual wxGridCellAttr *GetAttr( int row, int col,
                                     wxGridCellAttr::wxAttrKind  kind );


    // these functions take ownership of the pointer
    //virtual void SetAttr(wxGridCellAttr* attr, int row, int col);
    //virtual void SetRowAttr(wxGridCellAttr *attr, int row);
    //virtual void SetColAttr(wxGridCellAttr *attr, int col);

private:
    wxLuaState   m_wxlState;
    DECLARE_ABSTRACT_CLASS(wxLuaGridTableBase)
};

#endif // wxUSE_GRID && wxLUA_USE_wxGrid

// Template function to "delete" wxRecCounter-based classes (wxGridCellWorker and wxGridCellAttr etc.)
// since DecRef() should be called to delete them.
template <class T> void wxLua_wxRefCounter_DecRef_delete_function(void** p)
{
    T* o = (T*)(*p);
    o->DecRef();
}



#endif // WX_LUA_WXLADV_H
