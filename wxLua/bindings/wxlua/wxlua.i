// ===========================================================================
// Purpose:     wxLua specific wrappers
// Author:      J Winwood, John Labenski
// Created:     14/11/2001
// Copyright:   (c) 2001-2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 2.8.4
// ===========================================================================

// ---------------------------------------------------------------------------
// wxLua version defines

#define wxLUA_MAJOR_VERSION
#define wxLUA_MINOR_VERSION
#define wxLUA_RELEASE_NUMBER
#define wxLUA_SUBRELEASE_NUMBER
#define_wxstring wxLUA_VERSION_STRING

bool wxLUA_CHECK_VERSION(int major, int minor, int release); // actually a define
bool wxLUA_CHECK_VERSION_FULL(int major, int minor, int release, int subrel); // actually a define

// ---------------------------------------------------------------------------
// Compile the luaScript of the given name and return the lua error code, a message
// and the line number (or -1) of the error.
// %override [int return, lua_string err_msg, int line_number] CompileLuaScript(const wxString& luaScript, const wxString& fileName );
int CompileLuaScript(const wxString& luaScript, const wxString& fileName );

// ---------------------------------------------------------------------------
// Get information about the status of wxLua.

// Get a table or string of all tracked top level windows that wxLua will
// Destroy() when lua is closed.
// Example output : { "ClassName(&win id=wxWindowID)", ...}
LuaTable GetTrackedWindowInfo(bool as_string = false );

// Get a table or string of all tracked userdata wxLua will delete when lua
// is closed or lua will eventually garbage collect.
// Example output : { "ClassName(&obj)", ... }
LuaTable GetGCUserdataInfo(bool as_string = false );

// Get a table or string of all tracked userdata wxLua has pushed.
// A single object may have multiple types if it has been casted.
// Example output : { "&obj wxLuaTypeName(type#), ...", ... }
LuaTable GetTrackedObjectInfo(bool as_string = false );

// Get a table or string of all tracked wxEvent callbacks that have been
// installed using wxEvtHandler::Connect(... );
// "wxEVT_XXX(evt#) -> wxLuaEventCallback(&callback, ids %d %d)|wxEvtHandler(&evthandler) -> wxEvtHandlerClassName"
LuaTable GetTrackedEventCallbackInfo(bool as_string = false );

// Get a table or string of all wxWindow derived classes that have been created in wxLua.
// "wxWindowClassName(&win, id=%d)|wxLuaDestroyCallback(&callback)"
LuaTable GetTrackedWinDestroyCallbackInfo(bool as_string = false );

// Is the wxLua userdata object on the list to be garbage collected by Lua?
bool isgcobject(void* object );

// Is the wxLua userdata object on the list of tracked objects?
bool istrackedobject(void* object );

// Is the wxLua object refed by wxLua
bool isrefed(void* object );

// ---------------------------------------------------------------------------
// Force the Lua garbage collector to act or ignore object *DANGEROUS*
//
// These are *only* meant for very special cases and should NOT be used unless
// you have an initmate knowledge about the object and how it will be treated
// by wxWidgets, wxLua, and Lua.

// Add the userdata object to the list of objects that will be deleted when
// it goes out of scope and the Lua garbage collector runs.
// bool gcobject(void* object );

// Remove the userdata object from the list of objects that will be deleted when
// it goes out of scope and the Lua garbage collector runs.
bool ungcobject(void* object );

// ---------------------------------------------------------------------------
// Type information about the bindings or current userdata

enum wxLuaMethod_Type      // The type of a Lua method
{
    WXLUAMETHOD_CONSTRUCTOR, // constructor
    WXLUAMETHOD_METHOD,      // class member function
    WXLUAMETHOD_CFUNCTION,   // global C function (not part of a class)
    WXLUAMETHOD_GETPROP,     // Get %property funcName, read
    WXLUAMETHOD_SETPROP,     // Set %property funcName, write

    WXLUAMETHOD_STATIC,      // Class member function is static

    WXLUAMETHOD_DELETE       // This is the delete function that wxLua has generated
                             // to delete this class and is not part of the
                             // original class.
};

#define WXLUA_TNONE
#define WXLUA_TNIL
#define WXLUA_TBOOLEAN
#define WXLUA_TLIGHTUSERDATA
#define WXLUA_TNUMBER
#define WXLUA_TSTRING
#define WXLUA_TTABLE
#define WXLUA_TFUNCTION
#define WXLUA_TUSERDATA
#define WXLUA_TTHREAD
#define WXLUA_TINTEGER
#define WXLUA_TCFUNCTION

#define WXLUA_T_MAX

#define LUA_TNONE              // (-1 );
#define LUA_TNIL               // 0
#define LUA_TBOOLEAN           // 1
#define LUA_TLIGHTUSERDATA     // 2
#define LUA_TNUMBER            // 3
#define LUA_TSTRING            // 4
#define LUA_TTABLE             // 5
#define LUA_TFUNCTION          // 6
#define LUA_TUSERDATA          // 7
#define LUA_TTHREAD            // 8

// Is this lua_type() (or in lua the type() function) considered equivalent
%rename iswxluatype int wxlua_iswxluatype(int luatype, int wxluaarg_tag );

// %override [wxlua_typename, wxlua_type#, lua_typename, lua_type#] type(any object );
// Given any type of object, returns four values:
//    wxlua name of the type    - wxluaT_gettypename(L, stack_idx );
//    wxlua number of the type  - wxluaT_type(L, stack_idx );
//    lua name of the type      - lua_typename(L, lua_type(L, stack_idx) );
//    lua number of the type    - lua_type(L, stack_idx );
wxString type(void* object );

// %override wxString typename(int wxluaarg_tag );
// Returns the wxLua name binding wxLua class type numbers.
wxString typename(int wxluaarg_tag );

// ---------------------------------------------------------------------------
// wxLuaBinding - These are not wrapped in the standard way, but coded by hand
//                for size.

// These items follow the structure below and ALL items are called as if they
// were table members.
// Example : print(wxlua.GetBindings()[1].GetClassCount );
// Example : print(wxlua.GetBindings()[1].GetClassArray[1].methods[1].name );
// Note: Use only '.' and NO () to make it a function call, also check to see
//       if the item exists first (unlike the example above)!
// Also, you probably want to store the returned tables and get the values from
//   them instead of getting the whole table every time from wxlua.GetBindings()...
// Please see the bindings.wx.lua sample program for usage.

// Entry point to get the objects below.
// returns a table array of each installed binding { wxLuaBinding* }
LuaTable GetBindings( );

/*

class wxLuaBinding
{
    // No constructor as this is read only

    string GetBindingName
    string GetLuaNamespace

    int GetClassCount
    int GetFunctionCount
    int GetNumberCount
    int GetStringCount
    int GetEventCount
    int GetObjectCount

    {wxLuaBindClass*}                              GetClassArray
    {wxLuaBindMethod*}                             GetFunctionArray
    {name, value}                                  GetNumberArray
    {name, value}                                  GetStringArray
    {name, wxEventType, wxluatype, wxLuaBindClass} GetEventArray
    {name, object, wxluatype, wxLuaBindClass}      GetObjectArray
};

struct wxLuaBindClass
{
    // No constructor as this is read only

    string              name
    {wxLuaBindMethod*}  wxluamethods
    int                 wxluamethods_n
    wxClassInfo*        classInfo
    int                 wxluatype
    {string}            baseclassNames
    {wxLuaBindClass*}   baseBindClasses
    {name, value}       enums
    int                 enums_n

    {string}            fields // array of member field names
};

struct wxLuaBindMethod
{
    // No constructor as this is read only

    string              name
    int                 method_type
    {wxLuaBindCFunc*}   wxluacfuncs
    int                 wxluacfuncs_n
    wxLuaBindMethod*    basemethod

    wxLuaBindClass*     class      // class this is part of (not in struct );
    string              class_name // class name this is part of (not in struct );

    {string}            fields // array of member field names
};

struct wxLuaBindCFunc
{
    // No constructor as this is read only

    cfunction           lua_cfunc
    int                 method_type
    int                 minargs
    int                 maxargs
    {int}               argtypes

    string              class_name // added, not in struct

    {string}            fields // array of member field names
};

*/


// ---------------------------------------------------------------------------
// wxLuaState

#include "wxlua/wxlstate.h"

class %delete wxLuaState : public wxObject
{
/*
    wxLuaState(bool create = false );
    wxLuaState(wxEvtHandler *handler, wxWindowID id = wxID_ANY );

    bool Ok() const;
    void Destroy( );
    bool CloseLuaState(bool force );
    bool IsClosing() const;
    wxEventType GetInEventType() const;
    void SetEventHandler(wxEvtHandler *evtHandler );
    wxEvtHandler *GetEventHandler() const;
    void SetId(wxWindowID id );
    wxWindowID GetId() const;
    void SendEvent( wxLuaEvent &event ) const;

    int RunFile(const wxString &fileName );
    int RunString(const wxString &script, const wxString& name = "" );
    bool IsRunning() const;
*/
};

// ---------------------------------------------------------------------------
// wxLuaObject - Allows Lua data items to be used for wxClientData.

enum wxLuaObject_Type
{
    wxLUAOBJECT_NONE,
    wxLUAOBJECT_BOOL,
    wxLUAOBJECT_INT,
    wxLUAOBJECT_STRING,
    wxLUAOBJECT_ARRAYINT
};

class %delete wxLuaObject : public wxObject // ALSO! wxClientData use it anywhere that takes that
{
    // %override wxLuaObject(any value type );
    // C++ Func: wxLuaObject(const wxLuaState& wxlState, int stack_idx = 1 );
    // Wrap the single value passed in with a wxLuaObject
    wxLuaObject( );

    // %override void wxLuaObject::SetObject(any value type );
    // C++ Func: void SetObject(int stack_idx = 1 );
    // Discard the old reference and create a new one for the item passed in
    void SetObject( );

    // %override [any value type] wxLuaObject::GetObject( );
    // C++ Func: bool GetObject( );
    // get the object, note C++ returns bool, in lua it "returns" the referenced object
    void GetObject() const;

    // These are not useful in lua
    //bool       *GetBoolPtr();
    //int        *GetIntPtr();
    //wxString   *GetStringPtr();
    //wxArrayInt *GetArrayPtr();

    int  GetAllocationFlag() const;
};

class %delete wxLuaEvent : public wxNotifyEvent
{
    %wxEventType wxEVT_LUA_CREATION    // EVT_LUA_CREATION(winid, func );
    %wxEventType wxEVT_LUA_PRINT       // EVT_LUA_PRINT(winid, func );
    %wxEventType wxEVT_LUA_ERROR       // EVT_LUA_ERROR(winid, func );
    %wxEventType wxEVT_LUA_DEBUG_HOOK  // EVT_LUA_DEBUG_HOOK(winid, func );


    wxLuaEvent(wxEventType commandType = wxEVT_NULL, wxWindowID id = wxID_ANY); // , const wxLuaState& wxlState = wxNullLuaState);
    wxLuaEvent(const wxLuaEvent& event);

    // use GetString method to retrieve info

    // Get the line number in the code, -1 if unknown
    int GetLineNum() const;

    wxLuaState GetwxLuaState() const;
    void SetwxLuaState(const wxLuaState& wxlState);

    //lua_State *GetLuaState() const;
    // non null only for wxEVT_LUA_DEBUG_HOOK
    //lua_Debug *GetLuaDebug() const;

    // If called from a wxEVT_LUA_DEBUG_HOOK the interpreter will stop
    void DebugHookBreak(bool stop);
};

