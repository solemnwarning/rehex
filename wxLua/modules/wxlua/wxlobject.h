/////////////////////////////////////////////////////////////////////////////
// Name:        wxlobject.h
// Purpose:     wxLuaObject and other binding helper classes
// Author:      Ray Gilbert, John Labenski, J Winwood
// Created:     14/11/2001
// Copyright:   (c) 2012 John Labenski, Ray Gilbert
// Licence:     wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WXLOBJECT_H_
#define _WXLOBJECT_H_

#include "wxlua/wxldefs.h"

#ifdef GetObject
    #undef GetObject // MSVC defines this
#endif

#include <wx/object.h>
#include <wx/clntdata.h>

class WXDLLIMPEXP_FWD_WXLUA wxLuaState;

// ----------------------------------------------------------------------------
// wxLuaObject - Wraps a reference to a Lua object reference inside a
//   wxObject-derived class so that a Lua object can be used for userdata.
// Also with a simple extension by a proxy member value it can be used
//   to provide pointers to the wxValidator classes.
// Note that all functions take a lua_State since we may be called from a
//   coroutine with a different lua_State pointer and we want to make sure
//   that we push/pull our object from the right lua_State. The registry
//   where we store our object is shared by coroutine states.
// ----------------------------------------------------------------------------

enum wxLuaObject_Type
{
    wxLUAOBJECT_NONE     = 0, // nothing is allocated
    wxLUAOBJECT_BOOL     = 1, // bool allocated
    wxLUAOBJECT_INT      = 2, // int allocated
    wxLUAOBJECT_STRING   = 4, // wxString allocated
    wxLUAOBJECT_ARRAYINT = 8  // wxArrayInt allocated
};

class WXDLLIMPEXP_WXLUA wxLuaObject : public wxObject, wxClientData
{
public:
    // Wrap the item at the lua_State's stack index and create a reference to it
    // in the wxlua_lreg_refs_key registy table
    wxLuaObject(const wxLuaState& wxlState, int stack_idx);
    wxLuaObject(lua_State* L, int stack_idx);

    virtual ~wxLuaObject();

    // YOU MUST ALWAYS CALL THIS before deleting this object!
    // This is because we do not store a pointer to the lua_State in the
    // constructor since we may be used in coroutines and we need to
    // make sure that we push the data into the correct lua_State.
    void RemoveReference(lua_State* L);

    // Get the value of the reference object and push it onto the stack.
    // (or a proxy if the object has been aliased for a wxValidator class.)
    // returns true if the object is valid and has a reference, returns false
    // on failure and nothing is pushed on the stack.
    bool GetObject(lua_State* L);
    // Remove any existing reference and allocate another.
    // You cannot call this after calling GetXXXPtr(), but only if this wraps a
    // stack item.
    void SetObject(lua_State* L, int stack_idx);

    // The following methods are used by the wxValidator interface
    // Call GetObject() so that it's on the stack then try to get the value of
    // the object as the specified type and set the member variable equal to it
    // and return a pointer to member variable to a function that wants
    // a pointer to read/write from/to.
    // You may only call only one of these per instance of a wxLuaObject class.
    bool       *GetBoolPtr(lua_State* L);
    int        *GetIntPtr(lua_State* L);
    wxString   *GetStringPtr(lua_State* L);
    wxArrayInt *GetArrayPtr(lua_State* L);

    // Return a flag value that indicated which GetXXXPrt() function was called
    // else wxLUAOBJECT_NONE. This is for using this object with a wxValidator class
    wxLuaObject_Type GetAllocationFlag() const { return m_alloc_flag; }
    // Returns the reference number in the wxlua_lreg_refs_key Lua Registry table
    // or LUA_NOREF if not setup.
    int GetReference() const { return m_reference; }

protected:
    wxLuaState* m_wxlState;   // a pointer due to #include recursion.
    int         m_reference;  // reference in wxlua_lreg_refs_key registry table

    wxLuaObject_Type m_alloc_flag; // type of object for wxValidator interface

    union                          // object stored for wxValidator interface
    {
        bool        m_bool;
        int         m_int;
        wxString*   m_string;
        wxArrayInt* m_arrayInt;
    };

private:
    DECLARE_ABSTRACT_CLASS(wxLuaObject)
};

// ----------------------------------------------------------------------------
// wxLuaSmartStringArray - Wraps a "new" array of wxStrings with an automatic
//                         destructor that deletes them to make binding easier.
// ----------------------------------------------------------------------------
class WXDLLIMPEXP_WXLUA wxLuaSmartStringArray
{
public:
    wxLuaSmartStringArray(wxString *strArr = NULL) : m_strArr(strArr) { }
    ~wxLuaSmartStringArray() { delete[] m_strArr; }

    void operator = (wxString *strArr) { m_strArr = strArr; }
    operator const wxString *() const { return m_strArr; }

private:
    wxString *m_strArr;
};

// ----------------------------------------------------------------------------
// wxLuaSmartIntArray - Wraps a "new" array of ints with an automatic
//                      destructor that deletes them to make binding easier.
// ----------------------------------------------------------------------------
class WXDLLIMPEXP_WXLUA wxLuaSmartIntArray
{
public:
    wxLuaSmartIntArray(int* intArr = NULL) : m_intArr(intArr) { }
    ~wxLuaSmartIntArray() { delete[] m_intArr; }

    void operator = (int *intArr) { m_intArr = intArr; }
    operator       int *()       { return m_intArr; } // Note: not const for wxGLCanvas
    operator const int *() const { return m_intArr; }

private:
    int *m_intArr;
};

// ----------------------------------------------------------------------------
// wxLuaSmartwxArrayString - Wraps a "new" wxArrayString with an automatic
//                           destructor that deletes them to make binding easier.
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_WXLUA wxLuaSmartwxArrayString : public wxObject
{
public:
    wxLuaSmartwxArrayString(const wxLuaSmartwxArrayString& arr) { Ref(arr); }
    wxLuaSmartwxArrayString(wxArrayString *arr, bool del);

    wxArrayString* GetArray() const;

    operator const wxArrayString *() const { return  GetArray(); }
    operator const wxArrayString &() const { return *GetArray(); }
    operator       wxArrayString &()       { return *GetArray(); }

    // You may have to cast the wxLuaSmartwxArrayString with (wxArrayString&)
    // e.g. wxLuaSmartwxArrayString arr; ((wxArrayString&)arr).Add(wxT("hello"));
    wxLuaSmartwxArrayString& operator = (const wxLuaSmartwxArrayString& arr)
    {
        Ref(arr);
        return *this;
    }
    wxLuaSmartwxArrayString& operator = (const wxArrayString& arr)
    {
        *GetArray() = arr;
        return *this;
    }
};

extern const WXDLLIMPEXP_DATA_WXLUA(wxLuaSmartwxArrayString) wxLuaNullSmartwxArrayString;

// ----------------------------------------------------------------------------
// wxLuaSmartwxSortedArrayString - Wraps a "new" wxSortedArrayString with an automatic
//                                 destructor that deletes them to make binding easier.
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_WXLUA wxLuaSmartwxSortedArrayString : public wxObject
{
public:
    wxLuaSmartwxSortedArrayString(const wxLuaSmartwxArrayString& arr) { Ref(arr); }
    wxLuaSmartwxSortedArrayString(wxSortedArrayString *arr, bool del);

    wxSortedArrayString* GetArray() const;

    operator const wxSortedArrayString *() const { return  GetArray(); }
    operator const wxSortedArrayString &() const { return *GetArray(); }
    operator       wxSortedArrayString &()       { return *GetArray(); }

    // You may have to cast the wxLuaSmartwxSortedArrayString with (wxSortedArrayString&)
    // e.g. wxLuaSmartwxSortedArrayString arr; ((wxSortedArrayString&)arr).Add(wxT("hello"));
    wxLuaSmartwxSortedArrayString& operator = (const wxLuaSmartwxSortedArrayString& arr)
    {
        Ref(arr);
        return *this;
    }
};

// ----------------------------------------------------------------------------
// wxLuaSmartwxArrayInt - Wraps a "new" wxArrayInt with an automatic
//                        destructor to delete them to make binding easier
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_WXLUA wxLuaSmartwxArrayInt : public wxObject
{
public:
    wxLuaSmartwxArrayInt(const wxLuaSmartwxArrayInt& arr) { Ref(arr); }
    wxLuaSmartwxArrayInt(wxArrayInt *arr = NULL, bool del = true);

    wxArrayInt* GetArray() const;

    operator const wxArrayInt *() const { return  GetArray(); }
    operator const wxArrayInt &() const { return *GetArray(); }
    operator       wxArrayInt &()       { return *GetArray(); }

    // You may have to cast the wxLuaSmartwxArrayInt with (wxArrayInt&)
    // e.g. wxLuaSmartwxArrayInt arr; ((wxArrayInt&)arr).Add(5);
    wxLuaSmartwxArrayInt& operator = (const wxLuaSmartwxArrayInt& arr)
    {
        Ref(arr);
        return *this;
    }
};

// ----------------------------------------------------------------------------
// wxLuaSmartwxArrayDouble - Wraps a "new" wxArrayDouble with an automatic
//                        destructor to delete them to make binding easier
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_WXLUA wxLuaSmartwxArrayDouble : public wxObject
{
public:
    wxLuaSmartwxArrayDouble(const wxLuaSmartwxArrayDouble& arr) { Ref(arr); }
    wxLuaSmartwxArrayDouble(wxArrayDouble *arr = NULL, bool del = true);

    wxArrayDouble* GetArray() const;

    operator const wxArrayDouble *() const { return  GetArray(); }
    operator const wxArrayDouble &() const { return *GetArray(); }
    operator       wxArrayDouble &()       { return *GetArray(); }

    // You may have to cast the wxLuaSmartwxArrayDouble with (wxArrayDouble&)
    // e.g. wxLuaSmartwxArrayDouble arr; ((wxArrayDouble&)arr).Add(5);
    wxLuaSmartwxArrayDouble& operator = (const wxLuaSmartwxArrayDouble& arr)
    {
        Ref(arr);
        return *this;
    }
};

#endif // _WXLOBJECT_H_
