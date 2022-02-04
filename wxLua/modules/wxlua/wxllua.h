/////////////////////////////////////////////////////////////////////////////
// Name:        wxllua.h
// Purpose:     wxLua C style functions to interface with Lua
// Author:      Ray Gilbert, John Labenski, J Winwood
// Created:     14/11/2001
// Copyright:   (c) 2012 John Labenski, 2001-2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WXLLUA_H_
#define _WXLLUA_H_

#include "wxlua/wxldefs.h"
#include "wxlua/wxlbind.h"
#include "wxlua/wxlobject.h"
#include "wxlua/sharedptr.h"

#if wxUSE_GEOMETRY
#include <wx/geometry.h>
#endif

#include <vector>

class WXDLLIMPEXP_FWD_WXLUA wxLuaEvent;
class WXDLLIMPEXP_FWD_WXLUA wxLuaState;
class WXDLLIMPEXP_FWD_WXLUA wxLuaStateData;
class WXDLLIMPEXP_FWD_WXLUA wxLuaStateRefData;
class WXDLLIMPEXP_FWD_WXLUA wxLuaEventCallback;
class WXDLLIMPEXP_FWD_WXLUA wxLuaWinDestroyCallback;

// ----------------------------------------------------------------------------
// String functions - convert between Lua (ansi string) and wxString (encoded)
// ----------------------------------------------------------------------------

#define WXLUA_USE_WXSTR_CONVUTF8    1
#define WXLUA_USE_WXSTR_CONVCURRENT 0

// Convert a 8-bit ANSI C Lua String into a wxString
inline WXDLLIMPEXP_WXLUA wxString lua2wx(const char* luastr)
{
    if (luastr == NULL) return wxEmptyString; // check for NULL

#if WXLUA_USE_WXSTR_CONVUTF8

    return wxString(luastr, wxConvUTF8);

#elif WXLUA_USE_WXSTR_CONVCURRENT

    return wxString(luastr, *wxConvCurrent);

#else //!WXLUA_USE_WXSTR_CONVCURRENT
    #if wxUSE_UNICODE
        wxString str(luastr, wxConvUTF8);
    #else
        wxString str(wxConvUTF8.cMB2WC(luastr), *wxConvCurrent);
    #endif // wxUSE_UNICODE

        if (str.IsEmpty())
            str = wxConvertMB2WX(luastr); // old way that mostly works

        return str;
#endif //WXLUA_USE_WXSTR_CONVCURRENT
}

// Convert a wxString to 8-bit ANSI C Lua String
inline const WXDLLIMPEXP_WXLUA wxCharBuffer wx2lua(const wxString& wxstr)
{
#if WXLUA_USE_WXSTR_CONVUTF8

    wxCharBuffer buffer(wxstr.mb_str(wxConvUTF8));
    return buffer;

#elif WXLUA_USE_WXSTR_CONVCURRENT

    wxCharBuffer buffer(wxstr.mb_str(*wxConvCurrent));
    return buffer;

#else //!WXLUA_USE_WXSTR_CONVCURRENT
    wxCharBuffer buffer(wxConvUTF8.cWC2MB(wxstr.wc_str(*wxConvCurrent))); // skieu

    if ((buffer.data() == NULL) && !wxstr.IsEmpty())
        buffer = wxConvertWX2MB(wxstr.c_str()); // old way that mostly works

    return buffer;
#endif //WXLUA_USE_WXSTR_CONVCURRENT
}


// Convert a wxString to 8-bit ANSI C Lua Buffer and store it
class WXDLLIMPEXP_WXLUA wxLuaCharBuffer
{
public:
    wxLuaCharBuffer(const wxString &wxstr) : m_buffer(wx2lua(wxstr)) {}

    size_t Length() const { return strlen((const char*)m_buffer); }
    const char *GetData() const { return (const char*)m_buffer; }

    operator const char *() const { return m_buffer; }

    wxCharBuffer m_buffer; // member since non virtual destructor in wxCharBuffer
};

// ----------------------------------------------------------------------------
// Special keys used by wxLua in the LUA_REGISTRYINDEX table.
//
// Note: We do not push a human readable string for these because Lua always
// makes a copy and hashes the string, this takes a considerable amount of
// time when benchmarked using valgrind.
// ----------------------------------------------------------------------------

// Light userdata used as keys in the Lua LUA_REGISTRYINDEX table for wxLua.
// Note that even though these keys have human readable names as values,
// they're not used, just the memory address.

// The key in the LUA_REGISTRYINDEX table that is a weak keyed table of
//   the tables wxLua pushed into the registry with their keys as values.
// This is used by the wxLuaDebugData to know if the table is one of the wxLua
//   registry tables for better wxLuaStackDialog performance.
// LUA_REGISTRYINDEX[&wxlua_lreg_regtable_key][weak {wxlua_lreg_XXX_key table}] =
//    lightuserdata(&wxlua_lreg_XXX_key)
extern WXDLLIMPEXP_DATA_WXLUA(const char*) wxlua_lreg_regtable_key;

// The key in the LUA_REGISTRYINDEX table whose value is a lightuserdata
//   of a wxLuaState for this lua_State.
// LUA_REGISTRYINDEX[&wxlua_lreg_wxluastate_key] = lightuserdata(&wxLuaState)
extern WXDLLIMPEXP_DATA_WXLUA(const char*) wxlua_lreg_wxluastate_key;
// The key in the LUA_REGISTRYINDEX table that has a wxLuaStateData class
//   lightuserdata value for the wxLuaState.
// LUA_REGISTRYINDEX[&wxlua_lreg_wxluastatedata_key] = lightuserdata(&wxLuaStateData)
extern WXDLLIMPEXP_DATA_WXLUA(const char*) wxlua_lreg_wxluastatedata_key;

// The key in the LUA_REGISTRYINDEX table that is a table of lightuserdata
//   wxLuaBindings and the ref to the Lua table they were installed into.
// LUA_REGISTRYINDEX[&wxlua_lreg_wxluabindings_key] = {lightuserdata(&wxLuaBinding) = wxlua_lreg_refs_key ref#, ...}
extern WXDLLIMPEXP_DATA_WXLUA(const char*) wxlua_lreg_wxluabindings_key;
// The key in the LUA_REGISTRYINDEX table that is a lookup table of string
//   C++ classname keys and lightuserdata pointers to the associated wxLuaBindClass struct.
// LUA_REGISTRYINDEX[&wxlua_lreg_debug_refs_key][wxLuaBindClass.name] = lightuserdata(&wxLuaBindClass)
extern WXDLLIMPEXP_DATA_WXLUA(const char*) wxlua_lreg_classes_key;
// The key in the LUA_REGISTRYINDEX table that is a numerically keyed table indexed
//   on the wxLua types where each item is a userdata metatable for a C++ class.
// Note: The wxLua types WXLUA_TXXX that correspond to the Lua LUA_TXXX types
//   are not stored in this table since they do not use our metatables.
//   The keys in this table are all > 1. They values are either tables or 0
//   if the wxLuaBinding containing the wxLua type was not registered.
// LUA_REGISTRYINDEX[&wxlua_lreg_types_key][wxLua type number] = { metatable for a C++ class }
extern WXDLLIMPEXP_DATA_WXLUA(const char*) wxlua_lreg_types_key;

// The key in the LUA_REGISTRYINDEX table that is a table of all
//   objects that we've pushed into Lua using wxluaT_pushuserdatatype().
// Note: A single object like a wxWindow may be pushed with multiple wxLua types.
//   e.g. wxWindow* w = wx.wxWindow() retrieve the window later from wxObject* wxEvent:GetEventObject()
// LUA_REGISTRYINDEX[&wxlua_lreg_weakobjects_key][lightuserdata(obj_ptr)] =
//     { wxLua type1 = weak fulluserdata, wxLua type2 = weak fulluserdata... }
extern WXDLLIMPEXP_DATA_WXLUA(const char*) wxlua_lreg_weakobjects_key;
// The key in the LUA_REGISTRYINDEX table that is a table of all
//   objects to delete that were added using wxluaO_addgcobject().
// LUA_REGISTRYINDEX[&wxlua_lreg_gcobjects_key][lightuserdata(obj_ptr)] =
//     integer wxLua type
extern WXDLLIMPEXP_DATA_WXLUA(const char*) wxlua_lreg_gcobjects_key;

// The key in the LUA_REGISTRYINDEX table that is a table
//   of Lua objects/functions assigned to wxLua userdata programatically in Lua.
// LUA_REGISTRYINDEX[&wxlua_lreg_derivedmethods_key][lightuserdata(obj_ptr)] =
//    {["derived func/value name"] = wxLuaObject(Lua function/value), ...}
extern WXDLLIMPEXP_DATA_WXLUA(const char*) wxlua_lreg_derivedmethods_key;
// The key in the LUA_REGISTRYINDEX table that is a table of all
//   wxLuaEventCallbacks that we've created.
// LUA_REGISTRYINDEX[&wxlua_lreg_evtcallbacks_key][lightuserdata(&wxLuaEventCallback)] =
//     lightuserdata(&wxEvtHandler)
extern WXDLLIMPEXP_DATA_WXLUA(const char*) wxlua_lreg_evtcallbacks_key;
// The key in the LUA_REGISTRYINDEX table that is a table of wxWindow keys and
//   wxLuaWinDestroyCallback values that we've created.
// LUA_REGISTRYINDEX[&wxlua_lreg_windestroycallbacks_key][lightuserdata(&wxWindow)] =
//    lightuserdata(wxLuaWinDestroyCallback)
extern WXDLLIMPEXP_DATA_WXLUA(const char*) wxlua_lreg_windestroycallbacks_key;
// The key in the LUA_REGISTRYINDEX table that is a table of all
//   top level wxWindows that we've created and need to destroy when closed.
// LUA_REGISTRYINDEX[&wxlua_lreg_topwindows_key][lightuserdata(&wxWindow)] = 1
extern WXDLLIMPEXP_DATA_WXLUA(const char*) wxlua_lreg_topwindows_key;
// The key in the LUA_REGISTRYINDEX table that has a boolean value
//   of whether the Lua code has prepended a '_' to function name to indicate
//   that they want the base class function called.
// LUA_REGISTRYINDEX[&wxlua_lreg_callbaseclassfunc_key] = true/false
extern WXDLLIMPEXP_DATA_WXLUA(const char*) wxlua_lreg_callbaseclassfunc_key;
// The key in the LUA_REGISTRYINDEX table that has a wxEventType (integer) value
//   of the current wxEvent is that is being run or wxEVT_NULL if not in an event.
// LUA_REGISTRYINDEX[&wxlua_lreg_wxeventtype_key] = wxEventType (wxEVT_NULL)
extern WXDLLIMPEXP_DATA_WXLUA(const char*) wxlua_lreg_wxeventtype_key;

// The key in the LUA_REGISTRYINDEX table that is a numerically keyed table
//   with references to Lua objects we want to keep a handle to. The object could be
//   anything, a table, function, number, string, userdata...
// LUA_REGISTRYINDEX[&wxlua_lreg_refs_key][ref number] = Lua object
extern WXDLLIMPEXP_DATA_WXLUA(const char*) wxlua_lreg_refs_key;
// The key in the LUA_REGISTRYINDEX table that is a numerically keyed table
//   with references to objects the wxLuaDebugData wants to keep a handle to by
//   storing their value for lookup. It is used only for the wxLuaDebugData.
// LUA_REGISTRYINDEX[&wxlua_lreg_debug_refs_key][ref number] = Lua object
extern WXDLLIMPEXP_DATA_WXLUA(const char*) wxlua_lreg_debug_refs_key;

// ----------------------------------------------------------------------------
// wxLua userdata metatable structure:
// {
//    lightuserdata(&wxlua_metatable_type_key) = wxLua type number in wxlua_lreg_types_key table
//    lightuserdata(&wxlua_metatable_wxluabindclass_key) = lightuserdata(&wxLuaBindClass)
//    __gc       = function(wxlua_wxLuaBindClass__gc)
//    __index    = function(wxlua_wxLuaBindClass__index)
//    __newindex = function(wxlua_wxLuaBindClass__newindex)
//    __tostring = function(wxlua_wxLuaBindClass__tostring)
// }

// Light userdata used as keys in the metatables created for the class userdata objects.
// Note that even though these keys have values, they're not used, just the memory address.

// The key of a metatable used for wxLua userdata that is the wxLua type number in the
//   wxlua_lreg_types_key table this metatable is for.
extern WXDLLIMPEXP_DATA_WXLUA(const char*) wxlua_metatable_type_key;
// The key of a metatable used for wxLua userdata that stores a lightuserdata
//   of the wxLuaBindClass struct for this class.
extern WXDLLIMPEXP_DATA_WXLUA(const char*) wxlua_metatable_wxluabindclass_key;

// ----------------------------------------------------------------------------
// Create one of the wxlua_lreg_XXX_key tables in the LUA_REGISTRYINDEX and
//   properly set the wxlua_lreg_regtablekey_key too.
WXDLLIMPEXP_WXLUA void wxlua_lreg_createtable(lua_State* L, void* lightuserdata_reg_key, int narr = 0, int nrec = 0);

// ----------------------------------------------------------------------------
// The functions below are Lua C helper functions, some are also part of the wxLuaState
// and you are recommended to use those if the wxLuaState is required. However
// in some cases it may not be necessary to create a wxLuaState and just
// calling these functions will suffice. Only the functions that do not
// require the internal data from the wxLuaState are separated here.
// ----------------------------------------------------------------------------

// Translate the LUA_ERRXXX integers into a human readable string.
//   returns an empty string for an input of 0.
WXDLLIMPEXP_WXLUA wxString wxlua_LUA_ERR_msg(int LUA_ERRx);

// Get information from the return value of lua_pcall(), luaL_loadbuffer(), etc
//   The errMsg input is filled with wxlua_LUA_ERR_msg() and if the current top
//   is > than top it tries to get Lua's error string from the top of the stack.
// Returns true if the input status != 0 and the errMsg and line_num are filled.
// If errMsg and line_num aren't NULL then fill them with the msg and line.
// status is the return from lua_pcall(), luaL_loadbuffer(), etc, LUA_ERRxxx
// top is the lua_gettop from before the call that may have generated the error.
WXDLLIMPEXP_WXLUA bool wxlua_errorinfo(lua_State* L, int status, int top, wxString* errMsg = NULL, int* line_num = NULL);


// Push the errorMsg on the stack and call luaL_error()
WXDLLIMPEXP_WXLUA void LUACALL wxlua_error(lua_State* L, const char* errorMsg);
wxLUA_UNICODE_ONLY(WXDLLIMPEXP_WXLUA inline void LUACALL wxlua_error(lua_State* L, const wxString& errorMsg) { wxlua_error(L, wx2lua(errorMsg)); })

// Create an error message that the item at the stack_idx is not correct for a
//   function call and call wxlua_argerrormsg().
// The expectedType string should tell the user what is valid input and is a
//   string to be flexible for multiple valid types.
// The error message format is:
// "wxLua: Expected %s for parameter %d, but got a '%s'.", expectedType.c_str(), stack_idx, argType.c_str()
// Typical expectedType strings would be wxT("a 'number'")
WXDLLIMPEXP_WXLUA void LUACALL wxlua_argerror(lua_State *L, int stack_idx, const wxString& expectedType);
// Create an error message for an incorrect function call and call wxlua_error().
// The message created has this format:
//    msg
//    "functionNameCalled(argName1, argName2, ...)"         <-- from wxlua_getLuaArgsMsg()
//    "01. functionName(validArgName1, validArgName2, ...)" <-- from wxlua_getBindMethodArgsMsg()
//    "02. ..."
WXDLLIMPEXP_WXLUA void LUACALL wxlua_argerrormsg(lua_State *L, const wxString& msg);

// Get the userdata at the stack index, if null_ptr then set the pointer wrapped
//   by Lua's userdata to NULL to clear it.
WXDLLIMPEXP_WXLUA void* LUACALL wxlua_touserdata(lua_State* L, int stack_idx, bool null_ptr = false);

//----------------------------------------------------------------------------
// wxluaR_XXX - functions operate on the tables in Lua's LUA_REGISTRYINDEX which
// are keyed on lightuserdata that use the luaL_ref() integer reference mechanism
// to store objects. The 'R' stands for Registry or Reference.
//
// Possible values for the "void* lightuserdata_reg_key" are
//   &wxlua_lreg_types_key, &wxlua_lreg_refs_key, &wxlua_lreg_debug_refs_key
//   unless you are using these functions for your own table in the LUA_REGISTRYINDEX.
//----------------------------------------------------------------------------

// Create a reference to the object at stack index in a table with the key
//   lightuserdata_reg_key in the LUA_REGISTRYINDEX table. Does not pop the object.
// Returns the table index or LUA_REFNIL if the item on the stack is none or nil (an error).
WXDLLIMPEXP_WXLUA int LUACALL wxluaR_ref(lua_State* L, int stack_idx, void* lightuserdata_reg_key);
// Remove a reference to the object at the index in a table with the key
//   lightuserdata_reg_key in the LUA_REGISTRYINDEX table, returns success.
WXDLLIMPEXP_WXLUA bool LUACALL wxluaR_unref(lua_State* L, int wxlref_idx, void* lightuserdata_reg_key);
// Push onto the top of the stack the object at the index in a table with the key
//   lightuserdata_reg_key in the LUA_REGISTRYINDEX table, if the index is LUA_REFNIL or the
//   value is nil it returns false and doesn't leave anything on the stack.
WXDLLIMPEXP_WXLUA bool LUACALL wxluaR_getref(lua_State* L, int wxlref_idx, void* lightuserdata_reg_key);
// Is the item at the stack_idx in the table with the key lightuserdata_reg_key
//   in the LUA_REGISTRYINDEX table. Returns the ref index or LUA_NOREF if it's not.
WXDLLIMPEXP_WXLUA int LUACALL wxluaR_isrefed(lua_State* L, int stack_idx, void* lightuserdata_reg_key);

//----------------------------------------------------------------------------
// wxluaO_XXX - functions operate on wxLua "Objects" which are userdata wrapping
// C++ class objects and are stored in the wxlua_lreg_weakobjects_key
// and the wxlua_lreg_gcobjects_key table in the LUA_REGISTRYINDEX.
//----------------------------------------------------------------------------

enum wxLuaGCObject_Flags
{
    WXLUA_DELETE_OBJECT_LAST = 0x0000, // Delete the object only if this is the
                                       // last userdata referece to it.

    WXLUA_DELETE_OBJECT_ALL  = 0x0001, // Delete the object and clear all
                                       // userdata references to it.
};

// Track this object and delete it when Lua calls the __gc method for it.
// The object is stored in the wxlua_lreg_gcobjects_key of the LUA_REGISTRYINDEX.
//   Note that the Lua userdata internal pointer is to the obj_ptr.
WXDLLIMPEXP_WXLUA bool LUACALL wxluaO_addgcobject(lua_State* L, void* obj_ptr, int wxl_type);
// Remove the wxLua object wrapped in a Lua userdata at the stack index from the
//   wxlua_lreg_gcobjects_key table of the LUA_REGISTRYINDEX.
// It is deleted depending on the flags enum wxLuaGCObject_Flags.
// If flags = WXLUA_DELETE_OBJECT_ALL or if this is the last userdata it will also remove all
//   wxlua_lreg_weakobjects_key and wxlua_lreg_derivedmethods_key since the object is gone.
WXDLLIMPEXP_WXLUA bool LUACALL wxluaO_deletegcobject(lua_State *L, int stack_idx, int flags);
// Remove this obj_ptr from the wxlua_lreg_gcobjects_key table of the
//   LUA_REGISTRYINDEX. The Lua userdata for the object stays in Lua and it's
//   assumed that someone else will delete the object (took ownership of it).
WXDLLIMPEXP_WXLUA bool LUACALL wxluaO_undeletegcobject(lua_State *L, void *obj_ptr);
// Check if this obj_ptr is in the wxlua_lreg_gcobjects_key table of the
//   LUA_REGISTRYINDEX.
WXDLLIMPEXP_WXLUA bool LUACALL wxluaO_isgcobject(lua_State *L, void *obj_ptr);
// Get a wxArrayString of the info in the wxlua_lreg_gcobjects_key LUA_REGISTRYINDEX table.
// Strings are of the form "ClassName(&obj)"
WXDLLIMPEXP_WXLUA wxArrayString LUACALL wxluaO_getgcobjectinfo(lua_State *L);

// Track the obj_ptr and its Lua userdata at udata_stack_idx which is of the
//   wxLua type in the wxlua_lreg_weakobjects_key table of the
//   LUA_REGISTRYINDEX so we can push it again if needed.
WXDLLIMPEXP_WXLUA void LUACALL wxluaO_trackweakobject(lua_State *L, int udata_stack_idx, void *obj_ptr, int wxl_type);
// Remove the obj_ptr key from the wxlua_lreg_weakobjects_key table of
//   the LUA_REGISTRYINDEX. It removes the metatable for the single Lua userdata,
//   "udata", since this function is called before the object is deleted.
//   e.g. p1 = wx.wxPoint(); p2 = p1; p2:delete(); p1:SetX(5) errors, but doesn't segfault.
// If udata == NULL it removes ALL tracked userdata for this obj_ptr and clears
//   all of their metatables.
WXDLLIMPEXP_WXLUA int LUACALL wxluaO_untrackweakobject(lua_State *L, void* udata, void *obj_ptr);
// Check if this object with the given wxLua type is in the wxlua_lreg_weakobjects_key
//   table of the LUA_REGISTRYINDEX.
// If the object is found with the right wxLua type and push_on_stack is true
//   the Lua userdata for the object is pushed on top of the stack. If it's not
//   found then it returns false and nothing is left on the stack.
WXDLLIMPEXP_WXLUA bool LUACALL wxluaO_istrackedweakobject(lua_State *L, void *obj_ptr, int wxl_type, bool push_on_stack);
// Get a wxArrayString of the info in the wxlua_lreg_weakobjects_key LUA_REGISTRYINDEX table.
// Strings are of the form "&obj_ptr = wxLuaTypeName1(&udata, type=wxLuaType), ..."
// If the object is casted to multiple types there will be wxLuaTypeName2(...) and so on.
WXDLLIMPEXP_WXLUA wxArrayString LUACALL wxluaO_gettrackedweakobjectinfo(lua_State *L);

//----------------------------------------------------------------------------
// wxluaW_XXX - functions operate on tracked wxWindows stored in the
// wxlua_lreg_topwindows_key in Lua's LUA_REGISTRYINDEX.
//----------------------------------------------------------------------------

// Add the wxObject which is presumably a wxWindow (this function checks)
//   to the wxlua_lreg_topwindows_key table of the LUA_REGISTRYINDEX table if
//   it has not already been added.
WXDLLIMPEXP_WXLUA void LUACALL wxluaW_addtrackedwindow(lua_State *L, wxObject* wxobj);
// Remove the wxWindow from the wxlua_lreg_topwindows_key table of the
//   LUA_REGISTRYINDEX table.
WXDLLIMPEXP_WXLUA void LUACALL wxluaW_removetrackedwindow(lua_State *L, wxWindow* win);
// Is this wxWindow or one of its parents already added to the
//   wxlua_lreg_topwindows_key table of the LUA_REGISTRYINDEX table?
WXDLLIMPEXP_WXLUA bool LUACALL wxluaW_istrackedwindow(lua_State *L, wxWindow* win, bool check_parents);
// Get a wxArrayString of the info in the wxlua_lreg_topwindows_key LUA_REGISTRYINDEX table.
// Strings are of the form "ClassName(&win id=wxWindowID)"
WXDLLIMPEXP_WXLUA wxArrayString LUACALL wxluaW_gettrackedwindowinfo(lua_State *L);

//----------------------------------------------------------------------------
// wxluaT_XXX - functions operate on wxLua types which are integers.
// wxLua types for C++ classes are positive and the userdata metatables are
// stored in the wxlua_lreg_types_key table in Lua's LUA_REGISTRYINDEX.
// wxLua types matching LUA_TXXX types are negative, see WXLUA_TXXX.
//----------------------------------------------------------------------------

// Allocate a new table (a metatable for a userdata) with a
//   wxlua_metatable_type_key key equal to the input wxl_type and
//   store it in the wxlua_lreg_types_key LUA_REGISTRYINDEX table.
// Returns the index into the wxLua types table which is a new wxLua type.
// Leaves the new table on the top of the stack.
WXDLLIMPEXP_WXLUA int LUACALL wxluaT_newmetatable(lua_State* L, int wxl_type);
// Get the metatable for the wxLua type stored in the
//   wxlua_lreg_types_key LUA_REGISTRYINDEX table.
// Returns true if the type's metatable was found and is on the stack, nothing
//   is left on the stack on failure.
WXDLLIMPEXP_WXLUA bool LUACALL wxluaT_getmetatable(lua_State* L, int wxl_type);
// Set the metatable of the userdata at top of stack to the table stored in the
//   wxlua_lreg_types_key LUA_REGISTRYINDEX table.
WXDLLIMPEXP_WXLUA bool LUACALL wxluaT_setmetatable(lua_State* L, int wxl_type);

// Get the numeric wxLua type of the item at the stack index.
// This is the wxLua equivalent of lua_type() but instead of returning
//   LUA_TXXX it returns WXLUA_TXXX for standard types.
// If the object is a userdata it checks the metatable for the
//   wxlua_metatable_type_key to get the wxLua type where the type is
//   presumedly the index into the wxlua_lreg_types_key of the LUA_REGISTRYINDEX
//   table and denotes what type of C++ object this is.
// Returns WXLUA_TUNKNOWN on failure.
WXDLLIMPEXP_WXLUA int LUACALL wxluaT_type(lua_State* L, int stack_idx);

// Get a human readable name for the predefined WXLUA_TXXX or binding
//   wxluatype_XXX wxLua types stored in the wxlua_lreg_types_key
//   of the LUA_REGISTRYINDEX table.
// This is the wxLua equivalent of lua_typename(L, luatype).
// If the lua_State is not NULL then if the type is a wxLua type for classes
//   return the C++ class/struct name.
// Returns empty string if the type is unknown.
WXDLLIMPEXP_WXLUA wxString LUACALL wxluaT_typename(lua_State* L, int wxl_type);
// Get a human readable name for the item at the stack index.
// This is the wxLua equivalent of luaL_typename(L, stack_idx).
// This function calls wxluaT_typename(L, wxluaT_type(L, stack_idx)) and is a
//   convenience function.
WXDLLIMPEXP_WXLUA wxString LUACALL wxluaT_gettypename(lua_State* L, int stack_idx);
// Get the luaL_typename(L, stack_idx) == lua_typename(lua_type(L, stack_idx)) as a wxString.
// Returns one of the LUA_TXXX values.
WXDLLIMPEXP_WXLUA wxString LUACALL wxlua_luaL_typename(lua_State* L, int stack_idx);

// Get the wxLua type for the class or struct with the given name
WXDLLIMPEXP_WXLUA int LUACALL wxluaT_gettype(lua_State* L, const char* name);
// Get the wxLuaBindClass* for this wxLua type or NULL if the type is invalid.
// Gets the wxLuaBindClass from the metatable stored in the wxlua_lreg_types_key registry table
//   for the classes that have been installed into Lua.
WXDLLIMPEXP_WXLUA const wxLuaBindClass* LUACALL wxluaT_getclass(lua_State* L, int wxl_type);
// Get the wxLuaBindClass* for this class_name or NULL if the name is invalid.
// Gets the wxLuaBindClass from the wxlua_lreg_classes_key table in the LUA_REGISTRYINDEX.
WXDLLIMPEXP_WXLUA const wxLuaBindClass* LUACALL wxluaT_getclass(lua_State* L, const char* class_name);

// Is the item at stack_idx of the userdata type or derived from the the given wxLua type.
WXDLLIMPEXP_WXLUA bool wxluaT_isuserdatatype(lua_State* L, int stack_idx, int wxl_type);
// Get the userdata object at the stack_idx that is of the wxLua class type or a
//   class derived from the wxLua type. If the userdata does not have the correct type,
//   or if the parameter isn't a userdata then wxlua_error() is called and NULL is returned.
WXDLLIMPEXP_WXLUA void* LUACALL wxluaT_getuserdatatype(lua_State* L, int stack_idx, int wxl_type);
// Push the obj_ptr onto the top of the stack wrapped in a newuserdata
//   with its metatable set to the table from wxluaR_getref(L, wxl_type, &wxlua_lreg_types_key).
// Returns true if the wxLua type is known, the metatable set, and it's on the stack, nothing
//   is pushed on the stack if this returns false.
// If the wxLua type is derived from the wxWindow type it will be added to the
//   wxlua_lreg_windestroycallbacks_key table.
// If track=true then push the obj_ptr as a lightuser data key into the
//   wxlua_lreg_weakobjects_key table of the Lua LUA_REGISTRYINDEX table so
//   that if we need to push it again we just push the already created full userdata value.
WXDLLIMPEXP_WXLUA bool LUACALL wxluaT_pushuserdatatype(lua_State* L, const void *obj_ptr, 
                                                       int wxl_type, bool track = true, bool allow_NULL = false);

// ----------------------------------------------------------------------------
// Functions to get info about the wxLua types.
// Used to determine what to expect for a function call in the bindings.
// ----------------------------------------------------------------------------

// Is a class with the wxl_type equal to or derived from a class with the base_wxl_type.
//   Optional input baseclass_n is set to the highest multiple baseclass level, where
//     0 means that inheritance from wxl_type to base_wxl_type is always the first
//     base class, a 1 or higher means that wxl_type is derived from the second or higher
//     base class somewhere along the inheritance chain.
//   return of 0 means same class, +1 means base is parent, +2 base is grandparent, ...
//   returns -1 if the wxLua type is not derived from the base type.
WXDLLIMPEXP_WXLUA int LUACALL wxluaT_isderivedtype(lua_State* L, int wxl_type, 
                                                   int base_wxl_type, int* baseclass_n = NULL);
// Same as above, but works directly with the wxLuaBindClasses.
WXDLLIMPEXP_WXLUA int LUACALL wxluaT_isderivedclass(const wxLuaBindClass* wxlClass, 
                                                    const wxLuaBindClass* base_wxlClass, 
                                                    int* baseclass_n = NULL);
// Verify if the luatype = lua_type(L, stack_idx) is valid for the
//   wxl_type which is one of the predefined WXLUA_TXXX or s_wxluaarg_XXX types.
// Returns 1 if it matches, 0 if it doesn't, -1 if the wxl_type is not known.
// Note that this function does not do a direct mapping between wxlua_luatowxluatype()
//   and wxlua_wxluatoluatype() since it allows a small amount of coersion between types.
// If the input lua_State is not NULL it will account for the automatic conversion of
//   (wxString, wxArrayString, wxArrayInt) from the Lua type to wxLua type.
WXDLLIMPEXP_WXLUA int LUACALL wxlua_iswxluatype(int luatype, int wxl_type, lua_State* L = NULL);
// Get the wxLua type for the lua_type() = LUA_TXXX, returns -1 if unknown.
WXDLLIMPEXP_WXLUA int wxlua_luatowxluatype(int luatype);
// Get the lua_type() = LUA_TXXX for the predefined WXLUA_TXXX types.
//   returns -1 (LUA_TNONE) if the type was not one of the predefined types.
WXDLLIMPEXP_WXLUA int wxlua_wxluatoluatype(int wxluatype);

// Is the object at the stack_idx a userdata object that wxLua has pushed into Lua?
//   This should be the same as
//   (lua_isuserdata(L, stack_idx) && !lua_islightuserdata(L, stack_idx))
#define wxlua_iswxuserdata(L, stack_idx) (lua_type((L), (stack_idx)) == LUA_TUSERDATA)

// Helper functions to get numbers, booleans and strings safer.
// These validate that the object at the stack index specified is a string, bool,
//   int, or double number object or that the object can be converted to it.
// Note: wxLua has a stricter sense of type than Lua and we don't want to
//       always allow coersion between types since oftentimes there's an error.
WXDLLIMPEXP_WXLUA bool wxlua_iswxstringtype(lua_State* L, int stack_idx);
#define wxlua_isstringtype(L, stack_idx)  (wxlua_iswxluatype(lua_type(L, stack_idx), WXLUA_TSTRING) == 1)
#define wxlua_isbooleantype(L, stack_idx) (wxlua_iswxluatype(lua_type(L, stack_idx), WXLUA_TBOOLEAN) == 1)
#define wxlua_isintegertype(L, stack_idx) (wxlua_iswxluatype(lua_type(L, stack_idx), WXLUA_TINTEGER) == 1)
#define wxlua_isnumbertype(L, stack_idx)  (wxlua_iswxluatype(lua_type(L, stack_idx), WXLUA_TNUMBER) == 1)
#define wxlua_ispointertype(L, stack_idx) (wxlua_iswxluatype(lua_type(L, stack_idx), WXLUA_TPOINTER) == 1)

// After verifying using wxlua_isXXXtype return the value, else call
//   wxlua_error() with a message that is appropriate for stack_idx to be a
//   parameter to a function call. (These are used in the bindings)
// Note: The function wxLuaState::GetwxStringType does automatic conversion
//       of both a Lua string and a userdata wxString to a wxString.
WXDLLIMPEXP_WXLUA const char* LUACALL wxlua_getstringtypelen(lua_State* L, int stack_idx, size_t *len);
WXDLLIMPEXP_WXLUA const char* LUACALL wxlua_getstringtype(lua_State* L, int stack_idx);
WXDLLIMPEXP_WXLUA wxString LUACALL    wxlua_getwxStringtype(lua_State* L, int stack_idx);
WXDLLIMPEXP_WXLUA bool LUACALL        wxlua_getbooleantype(lua_State* L, int stack_idx);
WXDLLIMPEXP_WXLUA long LUACALL        wxlua_getenumtype(lua_State* L, int stack_idx);
WXDLLIMPEXP_WXLUA long LUACALL        wxlua_getintegertype(lua_State* L, int stack_idx);
WXDLLIMPEXP_WXLUA unsigned long LUACALL wxlua_getuintegertype(lua_State* L, int stack_idx);
WXDLLIMPEXP_WXLUA double LUACALL      wxlua_getnumbertype(lua_State* L, int stack_idx);
WXDLLIMPEXP_WXLUA void* LUACALL       wxlua_getpointertype(lua_State* L, int stack_idx);


// Helper functions to get/set tables of strings and ints
// Validate that the object at the stack index specified is a table object.
// This assumes that each table array entry is a string/number
//   or can be converted to a string/number using the
//   wxlua_isstring/numbertype definitions of what is a string/number.

// Convert the table at stack index to a "new" array of const char* strings.
// Return a pointer to the array of strings. You need to delete the array, but not
//   the individual strings since Lua should still have them during the life of the
//   returned array, if not you will need to copy them.
// Returns the number of character strings in the array in count.
// See usage in the wxBitmap constructor for XPMs.
WXDLLIMPEXP_WXLUA const char** LUACALL wxlua_getchararray(lua_State* L, int stack_idx, int& count);

// Convert a table array or a wxArrayString at the stack_idx to an array of wxStrings.
// If it's a table, it must have integer keys and string or wxString values.
// Returns a pointer to a new array of wxStrings and set the size in count.
// You must delete the return value if not NULL.
WXDLLIMPEXP_WXLUA wxString* LUACALL wxlua_getwxStringarray(lua_State* L, int stack_idx, int& count);
// Convert a table array or a wxArrayInt at the stack_idx to an array of integers.
// If it's a table, it must have integer keys and values.
// Returns a pointer to a new array of ints and set the size in count
// You must delete the return value if not NULL.
WXDLLIMPEXP_WXLUA int* LUACALL wxlua_getintarray(lua_State* L, int stack_idx, int& count);

// Convert a table array or a wxArrayString object at the stack_idx to a wxArrayString.
// If it's a table, it must have integer keys and string or wxString values.
WXDLLIMPEXP_WXLUA wxLuaSmartwxArrayString LUACALL wxlua_getwxArrayString(lua_State* L, int stack_idx);
// Convert a table array or a wxSortedArrayString object at the stack_idx to a wxSortedArrayString.
// If it's a table, it must have integer keys and string or wxString values.
WXDLLIMPEXP_WXLUA wxLuaSmartwxSortedArrayString LUACALL wxlua_getwxSortedArrayString(lua_State* L, int stack_idx);
// Convert a table array or a wxArrayInt object at the stack_idx to a wxArrayInt.
// If it's a table, it must have integer keys and values.
WXDLLIMPEXP_WXLUA wxLuaSmartwxArrayInt LUACALL wxlua_getwxArrayInt(lua_State* L, int stack_idx);
// Convert a table array or a wxArrayDouble object at the stack_idx to a wxArrayDouble.
// If it's a table, it must have integer keys and double values.
WXDLLIMPEXP_WXLUA wxLuaSmartwxArrayDouble LUACALL wxlua_getwxArrayDouble(lua_State* L, int stack_idx);
// Convert a table array at the stack_idx to a vector of wxPoints.
// Valid tables are : {{1,2},...}, {{x=1,y=2},...}, or {wx.wxPoint(1,2),,...}
WXDLLIMPEXP_WXLUA wxLuaSharedPtr<std::vector<wxPoint> > LUACALL wxlua_getwxPointArray(lua_State* L, int stack_idx);
// Convert a table array at the stack_idx to a vector of wxPoint2DDoubles.
// Valid tables are : {{1,2},...}, {{x=1,y=2},...}, or {wx.wxPoint2DDouble(1,2),,...}
WXDLLIMPEXP_WXLUA wxLuaSharedPtr<std::vector<wxPoint2DDouble> > LUACALL wxlua_getwxPoint2DDoubleArray(lua_State* L, int stack_idx);
// Creates a Lua table array and pushes Lua strings into it, returns the number of items added.
//   The table is left on the stack.
WXDLLIMPEXP_WXLUA int LUACALL wxlua_pushwxArrayStringtable(lua_State* L, const wxArrayString& strArray);
// Creates a Lua table array and pushes the integers into it, returns the number of items added.
//   The table is left on the stack.
WXDLLIMPEXP_WXLUA int LUACALL wxlua_pushwxArrayInttable(lua_State* L, const wxArrayInt& intArray);
// Creates a Lua table array and pushes the doubles into it, returns the number of items added.
//   The table is left on the stack.
WXDLLIMPEXP_WXLUA int LUACALL wxlua_pushwxArrayDoubletable(lua_State* L, const wxArrayDouble& doubleArray);
// Push the wxString into Lua after converting it.
WXDLLIMPEXP_WXLUA void LUACALL wxlua_pushwxString(lua_State* L, const wxString& str);

// Helper function to concatenate a wxArrayString into a wxString.
WXDLLIMPEXP_WXLUA wxString wxlua_concatwxArrayString(const wxArrayString& arr, const wxString& sep = wxT("\n"));


// Push the program args into a global table called "args" as the Lua executable does.
//   start_n is the arg to start pushing until max args "argc".
//   returns the number of args pushed.
WXDLLIMPEXP_WXLUA int wxlua_pushargs(lua_State* L, wxChar **argv, int argc, int start_n);

//----------------------------------------------------------------------------
// Derived class member functions for classes in wxLua. The data is stored
// in the wxlua_lreg_derivedmethods_key table in the LUA_REGISTRYINDEX.
//----------------------------------------------------------------------------

// Add this derived method, a Lua function or value the user has set to a
//   wxLua userdata object that we will push onto the stack when they access
//   the __index of the object with the "method_name". The obj_ptr is the
//   object the Lua userdata stores and the new wxLuaObject wraps the Lua
//   function or value which will be deleted by wxLua when the userdata is deleted.
WXDLLIMPEXP_WXLUA bool LUACALL wxlua_setderivedmethod(lua_State* L, void *obj_ptr, 
                                                      const char *method_name, wxLuaObject* wxlObj);
// Is there a derived method for the given obj_ptr with the method_name that was
//   added by calling wxlua_setderivedmethod()?
// If push_method then push the method onto the stack.
WXDLLIMPEXP_WXLUA bool LUACALL wxlua_hasderivedmethod(lua_State* L, const void *obj_ptr, 
                                                      const char *method_name, bool push_method);
// Remove any derived functions or values for the obj_ptr that have been added with
//   wxlua_setderivedmethod().
// This is called when an object is being garbage collected by wxluaO_deletegcobject()
//   and probably shouldn't be called otherwise.
WXDLLIMPEXP_WXLUA bool LUACALL wxlua_removederivedmethods(lua_State* L, void *obj_ptr);

//----------------------------------------------------------------------------
// Other functions for wxLua's keys in the LUA_REGISTRYINDEX
//----------------------------------------------------------------------------

// Get the wxlua_lreg_callbaseclassfunc_key value of the LUA_REGISTRYINDEX table
//   to determines whether a virtual C++ class member function should call its own
//   base class function or a wxLua derived method if it exists.
WXDLLIMPEXP_WXLUA bool LUACALL wxlua_getcallbaseclassfunction(lua_State* L);
// Set if the class member function call in Lua has a prepended '_' to imply that
//   the user wants the base class function and not the derived method in the
//   wxlua_lreg_derivedmethods_key table.
// Sets the wxlua_lreg_callbaseclassfunc_key value of the LUA_REGISTRYINDEX table.
WXDLLIMPEXP_WXLUA void LUACALL wxlua_setcallbaseclassfunction(lua_State* L, bool call_base);

// Get the wxlua_lreg_wxeventtype_key value of the LUA_REGISTRYINDEX table
//   to see if we're currently in a wxEvent callback.
// Returns wxEVT_NULL if not in an event handler.
// Be careful about destroying Lua when in an event handler.
WXDLLIMPEXP_WXLUA wxEventType LUACALL wxlua_getwxeventtype(lua_State* L);
// Set the wxlua_lreg_wxeventtype_key value of the LUA_REGISTRYINDEX table
//   with the current wxEventType we're in or wxEVT_NULL if none.
WXDLLIMPEXP_WXLUA void LUACALL wxlua_setwxeventtype(lua_State* L, wxEventType evt_type);

// Get the wxlua_lreg_wxluastatedata_key wxLuaStateData value from
//   the LUA_REGISTRYINDEX table for the owner wxLuaState.
// Note: It returns NULL if the lua_State is about to be closed.
WXDLLIMPEXP_WXLUA wxLuaStateData* LUACALL wxlua_getwxluastatedata(lua_State* L);


#endif // _WXLLUA_H_
