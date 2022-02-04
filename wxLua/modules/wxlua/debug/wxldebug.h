/////////////////////////////////////////////////////////////////////////////
// Purpose:     Lua and wxLua debugging code
// Author:      J. Winwood, John Labenski
// Created:     June 2003
// Copyright:   (c) 2012 John Labenski, 2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef WX_LUA_DEBUG_H
#define WX_LUA_DEBUG_H

#include <wx/dynarray.h>
#include <wx/treectrl.h> // for wxTreeItemData

#include "wxlua/debug/wxluadebugdefs.h"
#include "wxlua/wxlstate.h"

class WXDLLIMPEXP_WXLUADEBUG wxLuaDebugData;

// ----------------------------------------------------------------------------
// wxLuaDebugItem - A class to store an item from Lua for wxLuaDebugData
//
// It is typically used to store table[key] = value pair info. However it may
// be used to store stack information as well.
// ----------------------------------------------------------------------------

enum wxLuaDebugItem_Type
{
    WXLUA_DEBUGITEM_LOCALS    = 0x0100, // This wxLuaDebugItem is the parent for local variables

    WXLUA_DEBUGITEM_EXPANDED  = 0x0200, // for wxLuaStackDialog

    WXLUA_DEBUGITEM_IS_REFED  = 0x1000, // This item was created with a new
                                        // wxluaR_ref() rather than using an existing one.
    WXLUA_DEBUGITEM_KEY_REF   = 0x2000, // The ref is for the key
    WXLUA_DEBUGITEM_VALUE_REF = 0x4000, // The ref is for the value
};

class WXDLLIMPEXP_WXLUADEBUG wxLuaDebugItem
{
public:
    wxLuaDebugItem(const wxLuaDebugItem &debugDataItem);
    wxLuaDebugItem(const wxString &itemKey,   int itemKeyType,
                   const wxString &itemValue, int itemValueType,
                   const wxString &itemSource,
                   int lua_ref, int idx = 0, int flag = 0);

    // The key has the typical meaning of the key in a Lua table
    wxString GetKey() const             { return m_itemKey; }
    int      GetKeyType() const         { return m_itemKeyType; }
    wxString GetKeyTypeString() const   { return wxluaT_typename(NULL, m_itemKeyType); }

    // The value has the typical meaning of the value for the key in a Lua table
    wxString GetValue() const           { return m_itemValue; }
    int      GetValueType() const       { return m_itemValueType; }
    wxString GetValueTypeString() const { return wxluaT_typename(NULL, m_itemValueType); }

    // The lua_Debug.source value when enumerating the stack or a stack item
    wxString GetSource() const          { return m_itemSource; }

    int      GetRef() const             { return m_lua_ref; }  // wxluaR_ref() reference
    int      GetIndex() const           { return m_index; }    // stack index or table level index
    int      GetFlag() const            { return m_flag; }     // see wxLuaDebugItem_Type
    bool     GetFlagBit(int mask) const { return WXLUA_HASBIT(m_flag, mask); }

    // If GetFlagBit(WXLUA_DEBUGITEM_KEY_REFED) try to convert GetKey() to a number
    // else if GetFlagBit(WXLUA_DEBUGITEM_VALUE_REFED) try to convert GetValue() to a number
    // Asserts if neither or both of the bits are set.
    bool     GetRefPtr(wxUIntPtr& ptr) const;

    void     SetFlag(int flag)             { m_flag = flag; }
    void     SetFlagBit(int bit, bool set) { m_flag = WXLUA_SETBIT(m_flag, bit, set); }
    void     SetRef(int lua_ref)           { m_lua_ref = lua_ref; } // only if you've wxluaR_unref()ed it

    // Get a human readable string for debugging
    wxString ToString() const
    {
        return wxString::Format(wxT("Key: '%s' KeyType: %d '%s' Value: '%s' ValueType: %d '%s' Ref: %d Idx: %d Flag: %x HasSrc: %d"),
            m_itemKey.c_str(), m_itemKeyType, GetKeyTypeString().c_str(),
            m_itemValue.c_str(), m_itemValueType, GetValueTypeString().c_str(),
            m_lua_ref, m_index, m_flag, (int)!m_itemSource.IsEmpty());
    }

    // implementation

    wxString   m_itemKey;
    int        m_itemKeyType;
    wxString   m_itemValue;
    int        m_itemValueType;
    wxString   m_itemSource;
    int        m_lua_ref;
    int        m_index;
    int        m_flag;
};

#if defined(WXMAKINGDLL_WXLUADEBUG) || defined(WXUSINGDLL)
    WX_DEFINE_SORTED_USER_EXPORTED_ARRAY(wxLuaDebugItem *, wxLuaDebugItemArray, WXDLLIMPEXP_WXLUADEBUG);
#else
    WX_DEFINE_SORTED_ARRAY(wxLuaDebugItem *, wxLuaDebugItemArray);
#endif

// ----------------------------------------------------------------------------
// wxLuaDebugData - a wxObject ref counted container for a wxLuaDebugItemArray
// The destructor deletes the array items.
// ----------------------------------------------------------------------------

// an invalid wxLuaDebugData for comparison (like wxNullBitmap)
extern WXDLLIMPEXP_DATA_WXLUADEBUG(wxLuaDebugData) wxNullLuaDebugData;

class WXDLLIMPEXP_WXLUADEBUG wxLuaDebugData : public wxObject
{
public:
    wxLuaDebugData(bool create);
    wxLuaDebugData(const wxLuaDebugData &debugData) { Ref(debugData); }

    virtual ~wxLuaDebugData() {} // make gcc happy even though it's not used

    // Has this been created with its ref data?
    bool Ok() const { return (m_refData != NULL); }

    // Get the data array, please use safe array access functions if possible
    wxLuaDebugItemArray* GetArray();
    const wxLuaDebugItemArray* GetArray() const;

    // wxArray functions mapped to the internal array w/ error checking
    //   The wxLuaDebugItem items added must be created with 'new' and
    //   will be deleted when this class is destroyed.
    size_t GetCount() const;
    wxLuaDebugItem* Item(size_t index) const;
    void Add(wxLuaDebugItem* item);

    //-------------------------------------------------------------------------

    // fill this with the stack entries for the wxLuaState
    //   returns the number of stack entries added
    int EnumerateStack(lua_State* L);
    // fill this with the locals from a particular stack frame, if an item on the stack is a
    //   table then add a reference to it in the references array
    int EnumerateStackEntry(lua_State* L, int stack_frame, wxArrayInt& references);
    // Fill this with the name and value of items in a table at the given reference
    // in the wxlua_lreg_debug_refs_key in the LUA_REGISTRYINDEX.
    // nRef may also be LUA_GLOBALSINDEX and LUA_REGISTRYINDEX.
    // If the table has a sub table then add a reference to it to the references array.
    int EnumerateTable(lua_State* L, int nRef, int nEntry, wxArrayInt& references);

    //-------------------------------------------------------------------------
    // These functions are static to allow them to be used in other places to
    //    give a consistent feel to the display of Lua values.

    // Get information about the item at the 'stack_idx'. Returns the lua_type(L, stack_idx),
    //   fills 'wxl_type' with the WXLUA_TXXX type and 'value' with a human readable value.
    static int GetTypeValue(lua_State *L, int stack_idx, int* wxl_type, wxString& value);
    // Get a wxString description about the table at the stack_idx in the Lua stack
    static wxString GetTableInfo(lua_State *L, int stack_idx);
    // Get a wxString description about user data at the stack_idx in the Lua stack
    //  if full then try to look up the name of the user data from the bindings
    static wxString GetUserDataInfo(lua_State *L, int stack_idx, bool full_userdata);

    //-------------------------------------------------------------------------

    // Make a full copy of the array and return it.
    wxLuaDebugData Copy() const;

    // Ref this table if it hasn't been refed already, returns ref # or LUA_NOREF if not refed
    int RefTable(lua_State* L, int stack_idx, int* flag_type, int extra_flag, wxArrayInt& references);

    // Sorting function for the wxLuaDebugItemArray, sorts by name
    static int SortFunction(wxLuaDebugItem *elem1, wxLuaDebugItem *elem2 );

    // operators
    bool operator == (const wxLuaDebugData& debugData) const
        { return m_refData == debugData.m_refData; }
    bool operator != (const wxLuaDebugData& debugData) const
        { return m_refData != debugData.m_refData; }

    wxLuaDebugData& operator = (const wxLuaDebugData& debugData)
    {
        if ( (*this) != debugData )
            Ref(debugData);
        return *this;
    }
};

// ----------------------------------------------------------------------------
// wxLuaCheckStack - Dump the contents of the lua_State for debugging
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_WXLUADEBUG wxLuaCheckStack
{
public:
    // Create a instance, remembers lua_gettop(), 'msg' can be used to add
    // information about where or why this was created.
    // If 'print_to_console' then all functions below that return a string will also
    // print to the console as well.
    wxLuaCheckStack(lua_State* L, const wxString &msg = wxEmptyString, bool print_to_console = true);
    // Prints out the starting top and ending top if 'print_to_console' in constructor
    ~wxLuaCheckStack();

    // Returns a string comparing the starting and current lua_gettop() with additional msg
    wxString TestStack(const wxString &msg = wxEmptyString);

    // Returns a string of the current items on the stack with their types.
    wxString DumpStack(const wxString& msg = wxEmptyString);

    // Returns a string of all of the global variables and subtables with additional msg.
    wxString DumpGlobals(const wxString& msg = wxEmptyString);
    // Dump the table and its subtables from the globals index with additional msg.
    // The name may be of the form "table1.subtable2.subtable3..."
    wxString DumpTable(const wxString& tableName, const wxString& msg = wxEmptyString);
    // Dump the table and its subtables at the stack_idx with additional msg.
    wxString DumpTable(int stack_idx, const wxString& msg = wxEmptyString);

    // Dump the contents of the table at the stack_idx to a string. 'tablename' and 'msg' are
    // for informational messages, 'tableArray' is used to avoid recursion and should be empty
    // for the initial call, and 'indent' is used to track indentation level for each subtable.
    wxString DumpTable(int stack_idx, const wxString& tablename, const wxString& msg, wxSortedArrayString& tableArray, int indent);

    // Print a message to the console if 'print_to_console' in constructor.
    void OutputMsg(const wxString& msg) const;

    // implementation

    lua_State* m_luaState;
    wxString   m_msg;
    int        m_top;
    bool       m_print_to_console;
};

#endif // WX_LUA_DEBUG_H
