/////////////////////////////////////////////////////////////////////////////
// Name:        wxlstate.h
// Purpose:     wxLuaState - a wxWidgets interface to Lua
// Author:      Ray Gilbert, John Labenski, J Winwood
// Created:     14/11/2001
// Copyright:   (c) 2012 John Labenski, 2001-2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WXLSTATE_H_
#define _WXLSTATE_H_

#include "wxlua/wxldefs.h"
#include "wxlua/wxllua.h"
#include "wxlua/wxlbind.h"
#include "wxlua/wxlobject.h"
#include "wxlua/sharedptr.h"

#include <wx/filefn.h>
#include <wx/filename.h>
#include <wx/hashmap.h>
#include <wx/event.h>

#include <vector>

class WXDLLIMPEXP_FWD_WXLUA wxLuaEvent;
class WXDLLIMPEXP_FWD_WXLUA wxLuaState;
class WXDLLIMPEXP_FWD_WXLUA wxLuaStateData;
class WXDLLIMPEXP_FWD_WXLUA wxLuaStateRefData;
class WXDLLIMPEXP_FWD_WXLUA wxLuaEventCallback;
class WXDLLIMPEXP_FWD_WXLUA wxLuaWinDestroyCallback;


//----------------------------------------------------------------------------
// wxLuaStateData - the internal data for the wxLuaState.
//   All members of this class should be accessed through the wxLuaState.
//   It is public only for people who need to get at the internals, there are
//   absolutely no guarantees that things won't change.
//----------------------------------------------------------------------------

class WXDLLIMPEXP_WXLUA wxLuaStateData
{
public:
    wxLuaStateData();
    ~wxLuaStateData();

    int  m_is_running;                    // is the lua_State running a script
    bool m_is_closing;                    // are we currently being closed

    int  m_lua_debug_hook_count;          // values from wxLuaState::SetLuaDebugHook()
    int  m_lua_debug_hook_yield;
    int  m_lua_debug_hook;
    bool m_lua_debug_hook_send_evt;

    unsigned long m_last_debug_hook_time; // last time the debug hook was called

    bool     m_debug_hook_break;          // should the lua_State break for next debug_hook
    wxString m_debug_hook_break_msg;      // message when breaking in the debug_hook

    wxEvtHandler *m_evtHandler;           // event handler to send wxLuaEvents to
    wxWindowID    m_id;                   // event id to send the events with
};

//----------------------------------------------------------------------------
// wxLuaStateRefData - the internal data for the wxLuaState.
//                     please use the wxLuaState accessor functions
//----------------------------------------------------------------------------

#include <wx/hashmap.h>
WX_DECLARE_VOIDPTR_HASH_MAP_WITH_DECL(wxLuaState *, wxHashMapLuaState, class WXDLLIMPEXP_WXLUA);

class WXDLLIMPEXP_WXLUA wxLuaStateRefData : public wxObjectRefData
{
public:
    wxLuaStateRefData(bool create_data = true);
    virtual ~wxLuaStateRefData();

    // destroy and cleanup the lua_State, returns success
    // if 'force' = true then make sure all wxWindows are destroyed.
    bool CloseLuaState(bool force, bool collectGarbage = true);
    // clear all wxLuaEventCallbacks and wxLuaWinDestroyCallbacks on destruction
    void ClearCallbacks();

    // ------------------------------------------------------------------------

    lua_State* m_lua_State;           // the lua_State that "is" Lua
    bool       m_lua_State_static;    // lua_close() the lua_State if !static
    bool       m_lua_State_coroutine; // this is a coroutine, don't close it

    wxLuaStateData* m_wxlStateData;   // the data shared for this state
    bool            m_own_stateData;  // not a coroutine when true, so delete it when done
};

//----------------------------------------------------------------------------
// wxLuaState - a ref counted class to interface between C++ and Lua's C lua_State
//----------------------------------------------------------------------------

// enum wxLuaState_Type is for the functions
//  wxLuaState(lua_State* L, int state_type = wxLUASTATE_GETSTATE)
//  wxLuaState::Create(lua_State* L, int state_type = wxLUASTATE_GETSTATE);
enum wxLuaState_Type
{
    wxLUASTATE_GETSTATE = 1, // Attach to a previously created wxLuaState's
                             //   lua_State refing the existing wxLuaStateRefData

    wxLUASTATE_SETSTATE = 2, // Set the lua_State for the wxLuaState.
                             // Does not call lua_openlibs() so you should have
                             //   called before setting it to the wxLuaState.

    // The values below are to be ored with wxLUASTATE_GETSTATE only.
    wxLUASTATE_ROOTSTATE    = 0x10, // Get the root lua_State, the owner of a
                                    //   coroutine state, uses given lua_State
                                    //   if not coroutine.

    // The values below are to be ored with wxLUASTATE_SETSTATE only.
    wxLUASTATE_STATICSTATE  = 0x20, // The lua_State is static and the wxLuaState
                                    //   will not lua_close() it when Destroy()ed.
    wxLUASTATE_OPENBINDINGS = 0x40  // Install all the bindings in
                                    //   wxLuaBinding::GetBindingList() into the
                                    //   lua_State. You may install the bindings
                                    //   one at a time using
                                    //   wxLuaState::RegisterBinding(wxLuaBinding*)
};

// an invalid wxLuaState for comparison (like wxNullBitmap)
extern WXDLLIMPEXP_DATA_WXLUA(wxLuaState) wxNullLuaState;

class WXDLLIMPEXP_WXLUA wxLuaState : public wxObject
{
public:
    // Default constructor or if create=true then
    //   call the function Create(wxEvtHandler=NULL, id=wxID_ANY).
    wxLuaState(bool create = false) { if (create) Create(); }
    // Create a new lua_State and add the bindings.
    //   Calls the function Create(wxEvtHandler, id).
    wxLuaState(wxEvtHandler *handler, wxWindowID id = wxID_ANY) { Create(handler, id); }
    // Create a wxLuaState from an existing lua_State.
    //   Calls the function Create(lua_State, state_type), state_type is enum wxLuaState_Type.
    inline wxLuaState(lua_State* L, int state_type = wxLUASTATE_GETSTATE) { Create(L, state_type); }
    // Copy constructor, refs existing wxLuaState
    inline wxLuaState(const wxLuaState& wxlState) { Ref(wxlState); }

    // ALWAYS Destroy() the wxLuaState instead of calling UnRef(), else circular
    //  destruction since ref count goes to 0 before actually destroying the lua_State
    virtual ~wxLuaState() { Destroy(); }

    // -----------------------------------------------------------------------

    // Ref the given wxLuaState
    void Create(const wxLuaState& wxlState);
    // Create a new lua_State and send wxLuaEvents to this handler.
    //   The handler may be NULL to not send events to anyone.
    //   Calls the function Create(lua_State, wxLUASTATE_USESTATE).
    bool Create(wxEvtHandler *handler = NULL, wxWindowID id = wxID_ANY);
    // Create a wxLuaState from an existing lua_State.
    //   See enum wxLuaState_Type for infomation about state_type.
    bool Create(lua_State* L, int state_type = wxLUASTATE_GETSTATE);

    // -----------------------------------------------------------------------

    // Is this wxLuaState valid, has refed data and its lua_State is created
    bool IsOk() const;
    inline bool Ok() const { return IsOk(); }

    // -----------------------------------------------------------------------

    // Destroy the refed data, use this instead of wxObject::UnRef().
    //  Only calls lua_close(L) if this is the last refed state and this was
    //  created without the wxLUASTATE_STATICSTATE flag.
    //  Note: if you have a top level window (wxFrame) open in Lua and exit the
    //  C++ program your program will seem to "hang" because wxApp doesn't
    //  exit with a top level window open. Call CloseLuaState(true) to ensure
    //  all non parented (top level) windows are destroyed.
    //  You must always call CloseLuaState() when you want to close Lua instead
    //  of hoping that when you call Destroy() you have the last refed instance.
    void Destroy();
    // Close the lua_State and if 'force' close all attached wxWindows
    //   if !force then popup a dialog to ask if all wxWindows should be destroyed.
    // Only calls lua_close(L) if this is the last refed state and this was
    //  created without the wxLUASTATE_STATICSTATE flag.
    bool CloseLuaState(bool force, bool collectGarbage = true);
    // Are we currently being closed? Used when the garbage collector is running when
    //  we don't care about cleaning Lua up so just delete the data. (internal use)
    bool IsClosing() const;

    // -----------------------------------------------------------------------

    // Get the lua_State
    lua_State* GetLuaState() const;
    // Get the ref data (internal use)
    wxLuaStateRefData* GetLuaStateRefData() const { return (wxLuaStateRefData*)GetRefData(); }
    // Get the data for the lua_State in the ref data (internal use)
    wxLuaStateData* GetLuaStateData() const;

    // -----------------------------------------------------------------------

    // Get the wxLuaState from the corresponding lua_State
    // If get_root_state and L is a coroutine then return the wxLuaState
    // for the parent lua_State of the coroutine, else just return the wxLuaState for L.
    //  returns wxNullLuaState if none found.
    static wxLuaState GetwxLuaState(lua_State* L, bool get_root_state);
    // A mapping between hashmap[lua_State* L] = wxLuaState*
    // Note: The hashed new wxLuaState is not Refed since we want to know when
    //       the ref count goes to 1 for cleanup and it is deleted when
    //       its wxLuaStateRefData is finally deleted.
    // Note: The coroutine lua_States are not hashed since we cannot know when
    //       they are created or deleted. We must create wxLuaStates for them on the fly.
    static wxHashMapLuaState s_wxHashMapLuaState;

    // -----------------------------------------------------------------------

    // In order for wxLua scripts to work from a C++ program's wxApp::OnInit()
    //   and the Lua module you may have to set this variable to force the wxLua
    //   code "wx.wxGetApp:MainLoop()" to not call wxApp::MainLoop().
    // The issue is that within the function wxApp::OnInit() wxApp::IsMainLoopRunning()
    //   returns false, but it will be running after OnInit() returns so we should
    //   silently ignore the Lua code wanting to prematurely start the MainLoop.
    // Initialized to false, meaning not set.
    // Set to true for the Lua code "wx.wxGetApp:MainLoop()" to not call
    //   the app's MainLoop() function.
    //
    // See the wxLua apps for usage.
    static bool sm_wxAppMainLoop_will_run;

    // -----------------------------------------------------------------------

    // Get/Set the event handler that the wxLuaEvents from this will be sent to, can be NULL.
    //  See wxEVT_LUA_XXX for a list of possible events that may be sent.
    void SetEventHandler(wxEvtHandler *evtHandler);
    wxEvtHandler *GetEventHandler() const;
    // Get/Set the wxWindowID that the wxLuaEvents will be sent with.
    void SetId(wxWindowID id);
    wxWindowID GetId() const;

    // Sends the input wxLuaEvent, after checking that this is valid, to the
    //  set wxEventHandler (may be NULL), see constructor or SetEventHandler().
    //  returns wxEvtHandler::ProcessEvent(event)
    bool SendEvent( wxLuaEvent &event ) const;

    // -----------------------------------------------------------------------

    // Run a Lua file from disk using lua_loadfile() then LuaPCall().
    //   Leaves nresults on the stack, use LUA_MULTRET to leave them all.
    //   Returns 0 on success or Lua's error code.
    //   Sends a wxEVT_LUA_ERROR wxLuaEvent on error.
    int RunFile(const wxString &fileName, int nresults = 0);
    // Run a string that contains Lua code using luaL_loadbuffer() then LuaPCall().
    //   Leaves nresults on the stack, use LUA_MULTRET to leave them all.
    //   Returns 0 on success or Lua's error code.
    //   Sends a wxEVT_LUA_ERROR wxLuaEvent on error.
    int RunString(const wxString &script, const wxString& name = wxEmptyString, int nresults = 0);
    // Run a char array #included from bin2c compilation or something else
    //   using luaL_loadbuffer() then LuaPCall().
    //   Leaves nresults on the stack, use LUA_MULTRET to leave them all.
    //   Returns 0 on success or Lua's error code.
    //   Sends a wxEVT_LUA_ERROR wxLuaEvent on error.
    int RunBuffer(const char buf[], size_t size, const wxString &name = wxT("= lua"), int nresults = 0);

    int LuaDoString(const wxString &script, const wxString& name = wxEmptyString, int nresults = 0) { return RunString(script, name, nresults); }
    int LuaDoFile(const wxString &filename, int nresults = 0) { return RunFile(filename, nresults); }
    int LuaDoBuffer(const char *buffer, size_t len, const char *name, int nresults = 0) { return RunBuffer(buffer, len, lua2wx(name), nresults); }

    // Is a program running now, running state is set for Run/File/String/Buffer
    bool IsRunning() const;

    // Replacement for lua_pcall()
    //   Returns 0 on success or Lua's error code.
    //   Sends a wxEVT_LUA_ERROR wxLuaEvent on error.
    //   narg is the number of args to the function to call.
    //   nresults is the number of values expected to be returned and Lua
    //     will adjust the stack to match.
    //     Use LUA_MULTRET for a variable number of returns.
    int LuaPCall(int narg, int nresults);

    //
    bool SendLuaErrorEvent(int status, int top);

    // Get the wxEventType that Lua may currently be in, wxEVT_NULL if not in an
    //   event handler. Be careful about destroying Lua when in an event handler.
    //   See wxlua_getwxeventtype()
    wxEventType GetInEventType() const;
    // Set the wxEventType that the Lua code is currently running (internal use).
    //   See wxlua_setwxeventtype()
    void SetInEventType(wxEventType eventType);

    // -----------------------------------------------------------------------

    // Try to compile the Lua program. Creates new lua_State to test for syntax
    //   errors and sends error events. See wxlua_errorinfo() for errMsg and line_num.
    int CompileString(const wxString &script, const wxString& name = wxEmptyString,
                      wxString* errMsg = NULL, int* line_num = NULL);
    int CompileBuffer(const char buf[], size_t size, const wxString &name = wxEmptyString,
                      wxString* errMsg = NULL, int* line_num = NULL);

    // -----------------------------------------------------------------------

    // Break a currently running Lua program by setting the Lua debug hook to
    //  be called for anything and breaking as soon as possible by calling
    //  wxlua_error() with the message
    void DebugHookBreak(const wxString &message = wxT("Lua interpreter stopped"));
    // Clear a previously set DebugHookBreak(), resetting the debug hook
    //  to the previous values
    void ClearDebugHookBreak();
    // Has DebugHookBreak() been called and we're waiting for the next hook call?
    bool GetDebugHookBreak() const;
    // Get the message that will be sent when from a DebugHookBreak() call
    wxString GetDebugHookBreakMessage() const;

    // Have Lua run an internal hook function with this mask
    //   hook = LUA_MASKCALL | LUA_MASKRET | LUA_MASKLINE | LUA_MASKCOUNT
    // Every count hook mask a wxEVT_LUA_DEBUG_HOOK event is sent if send_debug_evt.
    // If yield_ms > 0 then wxYield is called every yield milliseconds.
    // Turn the hook off with count < 1
    // see lua_sethook() function
    void SetLuaDebugHook(int hook = LUA_MASKCALL|LUA_MASKRET|LUA_MASKLINE|LUA_MASKCOUNT,
                         int count = 1000, int yield_ms = 100,
                         bool send_debug_evt = false);
    int  GetLuaDebugHook() const;
    int  GetLuaDebugHookCount() const;
    int  GetLuaDebugHookYield() const;
    bool GetLuaDebugHookSendEvt() const;

    // Internally updated time that the debug hook was last called when running
    //  Lua code and SetLuaDebugHook is turned on
    unsigned long GetLastLuaDebugHookTime() const;
    // Set to an specific time to control debug timing
    void SetLastLuaDebugHookTime(unsigned long t);

    // -----------------------------------------------------------------------
    // Binding functions

    // Registers a new C function for Lua, see usage in wxlstate.cpp
    void RegisterFunction(lua_CFunction func, const char* funcName);
    wxLUA_UNICODE_ONLY(void RegisterFunction(lua_CFunction func, const wxString &funcName) { RegisterFunction(func, wx2lua(funcName)); })

    // Register a single wxLuaBinding, returns true on success. Nothing is
    //   left on the stack.
    bool RegisterBinding(wxLuaBinding* binding);
    // Register all the bindings in the wxLuaBinding::GetBindingList(), this is done
    //   automatically if the wxLuaState is created with wxLUASTATE_OPENBINDINGS.
    bool RegisterBindings();

    // Get the installed wxLuaBinding with the given
    //   wxLuaBinding::GetBindingName() or NULL for no match.
    // See wxLuaBinding::GetLuaBinding().
    wxLuaBinding* GetLuaBinding(const wxString& bindingName) const;

    // Get wxLuaBindClass for given Lua Tag using wxLuaBindClass::wxluatype,
    //   returns NULL on failure. See wxluaT_getclass().
    const wxLuaBindClass* GetBindClass(int iClassTag) const;
    // Get wxLuaBindClass for given class name using wxLuaBindClass::name,
    //   returns NULL on failure. See wxluaT_getclass().
    const wxLuaBindClass* GetBindClass(const char* className) const;
    // Get the first wxLuaBindClass that has this particular wxLuaBindMethod
    //   returns NULL on failure. See wxLuaBinding::GetBindClass().
    const wxLuaBindClass* GetBindClass(const wxLuaBindMethod* wxlMethod) const;
    // Get the first wxLuaBindClass that has this particular wxLuaBindCFunc in its methods
    //   returns NULL on failure. See wxLuaBinding::GetBindClass().
    const wxLuaBindClass* GetBindClass(const wxLuaBindCFunc* wxlCFunc) const;
    // See wxluaT_isderivedtype().
    int IsDerivedType(int wxl_type, int base_wxl_type, int* baseclass_n) const;

    // See wxlua_setcallbaseclassfunction() and wxlua_getcallbaseclassfunction().
    void SetCallBaseClassFunction(bool call_base);
    bool GetCallBaseClassFunction();

    // -----------------------------------------------------------------------
    // memory tracking functions (internal use)

    // See wxluaO_addgcobject().
    void AddGCObject(void* obj_ptr, int wxl_type);
    // See wxluaO_deletegcobject().
    bool DeleteGCObject(int stack_idx, int flags);
    // See wxluaO_isgcobject().
    bool IsGCObject(void *obj_ptr) const;
    // See wxluaO_getgcobjectinfo().
    wxArrayString GetGCObjectInfo() const;

    // Add a wxWindow to track and delete when we're closed, only track
    //   the parent window, not its children. returns true if it was added.
    // Note: wxObject is used as the base class since we blindly call this
    // function for all objects with classinfo in the bindings and we
    // want to minimize the code in the bindings.
    void AddTrackedWindow(wxObject *win);
    // Don't track this window anymore and don't delete it.
    void RemoveTrackedWindow(wxWindow *win);
    // Is this window tracked, if check_parents see if a parent of it is.
    bool IsTrackedWindow(wxWindow *win, bool check_parents = true) const;
    // Get an array of strings "wxWindow_classname(&win id=wxWindowID)"
    wxArrayString GetTrackedWindowInfo() const;

    // delete all stray wxWindow derived classes that have been destroyed
    //   by wxWidgets (eg. a child window)
    // This function does not need to be called ever, for debugging perhaps?
    void GarbageCollectWindows(bool closeWindows);

    // Add or remove a tracked wxLuaEventCallback connected to a wxEvtHandler
    void AddTrackedEventCallback(wxLuaEventCallback* callback);
    bool RemoveTrackedEventCallback(wxLuaEventCallback* callback);
    // Get an array of strings "wxEVT_XXX (wxEventType #) count#"
    wxArrayString GetTrackedEventCallbackInfo() const;

    // Add or remove a tracked wxLuaWinDestroyCallback connected to wxEVT_DESTROY.
    void AddTrackedWinDestroyCallback(wxLuaWinDestroyCallback* callback);
    bool RemoveTrackedWinDestroyCallback(wxLuaWinDestroyCallback* callback);
    // Get an array of strings "wxWindow_classname count#"
    wxArrayString GetTrackedWinDestroyCallbackInfo() const;

    // -----------------------------------------------------------------------

    // Push the errorMsg on the stack and call wxlua_error()
    void wxlua_Error(const char *errorMsg) const;
    wxLUA_UNICODE_ONLY(void wxlua_Error(const wxString& errorMsg) const { wxlua_Error(wx2lua(errorMsg)); })

    void* wxlua_ToUserdata(int stack_idx, bool null_ptr = false) const;

    // -----------------------------------------------------------------------
    // wxLua Lua Registry Table Functions

    int   wxluaR_Ref(int stack_idx, void* lightuserdata_reg_key);
    bool  wxluaR_Unref(int wxlref_index, void* lightuserdata_reg_key);
    bool  wxluaR_GetRef(int wxlref_index, void* lightuserdata_reg_key);

    int   wxluaT_NewMetatable(int wxl_type);
    bool  wxluaT_SetMetatable(int wxl_type);
    int   wxluaT_Type(int stack_idx) const;

    bool  wxluaT_PushUserDataType(const void *obj_ptr, int wxl_type, bool track);

    // -----------------------------------------------------------------------
    // wxLua get data type

    // See wxlua_iswxluatype().
    int IswxLuaType(int luatype, int wxl_type) const;
    // See wxluaT_isuserdatatype().
    bool IsUserDataType(int stack_idx, int wxl_type) const;
    // See wxluaT_getuserdatatype().
    void* GetUserDataType(int stack_idx, int iTag) const;

    // helper functions to get numbers, booleans and strings safer

    // See wxlua_getstringtype().
    const char* GetStringType(int stack_idx);
    // See wxlua_getwxStringtype().
    wxString GetwxStringType(int stack_idx);
    // See wxlua_getbooleantype().
    bool GetBooleanType(int stack_idx);
    // See wxlua_getintegertype().
    long GetIntegerType(int stack_idx);
    // See wxlua_getnumbertype().
    double GetNumberType(int stack_idx);

    // See wxlua_isXXXtype().
    bool IsStringType(int stack_idx) const;
    bool IswxStringType(int stack_idx) const;
    bool IsBooleanType(int stack_idx) const;
    bool IsIntegerType(int stack_idx) const;
    bool IsNumberType(int stack_idx) const;

    // See wxlua_getwxStringarray().
    wxString* GetwxStringArray(int stack_idx, int &count);
    // See wxlua_getwxArrayString().
    wxLuaSmartwxArrayString GetwxArrayString(int stack_idx);
    // See wxlua_getchararray().
    const char** GetCharArray(int stack_idx, int &count);

    // See wxlua_getintarray().
    int* GetIntArray(int stack_idx, int &count);
    // See wxlua_getwxArrayInt().
    wxLuaSmartwxArrayInt GetwxArrayInt(int stack_idx);

    // See wxlua_pushwxArrayStringtable().
    int PushwxArrayStringTable(const wxArrayString &strArray);
    // See wxlua_pushwxArrayInttable().
    int PushwxArrayIntTable(const wxArrayInt &intArray);

    // -----------------------------------------------------------------------

    // See wxluaT_typename().
    wxString GetwxLuaTypeName(int wxl_type) const;

    // -----------------------------------------------------------------------

    // See wxlua_setderivedmethod
    bool SetDerivedMethod(void *obj_ptr, const char *method_name, wxLuaObject* wxlObj);
    // See wxlua_hasderivedmethod().
    bool HasDerivedMethod(const void *obj_ptr, const char *method_name, bool push_method) const;
    // See wxlua_removederivedmethods()
    bool RemoveDerivedMethods(void *obj_ptr) const;
    // Find a derived method given an object and and a method name.
    // If the method can be found, return the valid wxLuaState it belongs to.
    // This function can be used for classes that implement virtual functions to
    // try to find a wxLuaState that may have overridden the function to call it.
    // It is probably easier to merely make a wxLuaState a class member for
    // faster lookup though.
    static wxLuaState GetDerivedMethodState(void *obj_ptr, const char *method_name);

    // -----------------------------------------------------------------------
    // C++ interface for the lua_State functions
    //   functions prepended by lua_XXX directly call the 'C' lua_XXX function
    //   The function names have been capitalized to allow case sensitive searching
    // -----------------------------------------------------------------------
    // Raw basic Lua stack functions, lua.h

    int  lua_GetTop() const;
    void lua_SetTop(int index);
    void lua_PushValue(int index);
    void lua_Remove(int index);
    void lua_Pop(int count) const;
    void lua_Insert(int index);
    void lua_Replace(int index);
    int  lua_CheckStack(int size);
    void lua_XMove(const wxLuaState& to, int n);

    // -----------------------------------------------------------------------
    // Raw Lua accesses functions (stack -> C), lua.h

    bool lua_IsNumber(int index) const;
    bool lua_IsString(int index) const;
    bool lua_IsCFunction(int index) const;
    bool lua_IsUserdata(int index) const;
    int  lua_Type(int index) const;
    wxString lua_TypeName(int type) const;

    int  lua_Equal(int index1, int index2) const;
    int  lua_RawEqual(int index1, int index2) const;
    int  lua_LessThan(int index1, int index2) const;

    double        lua_ToNumber(int index) const;
    int           lua_ToInteger(int index) const;
    int           lua_ToBoolean(int index) const;
    const char*   lua_ToString(int index) const;
    wxString      lua_TowxString(int index) const; // wxLua added
    size_t        lua_StrLen(int index) const;
    size_t        luaL_ObjLen(int index) const;
    lua_CFunction lua_ToCFunction(int index) const;
    void*         lua_ToUserdata(int index) const;
    wxLuaState    lua_ToThread(int index) const;
    const void*   lua_ToPointer(int index) const;

    // -----------------------------------------------------------------------
    // Raw Lua push functions (C -> stack), lua.h

    void lua_PushNil();
    void lua_PushNumber(lua_Number n);
    void lua_PushInteger(lua_Integer n);
    void lua_PushLString(const char* s, size_t len);
    void lua_PushString(const char* s);
    wxLUA_UNICODE_ONLY(void lua_PushString(const wxString& s) { lua_PushString(wx2lua(s)); })
    //wxString lua_PushVfString();
    //wxString lua_PushFString();
    void lua_PushCClosure(lua_CFunction fn, int n);
    void lua_PushBoolean(bool b);
    void lua_PushLightUserdata(void* p);
    //void lua_PushThread(lua_State* L);

    // -----------------------------------------------------------------------
    // Raw Lua get functions (Lua -> stack), lua.h

    void  lua_GetTable(int idx);
    void  lua_GetField(int idx, const char* k);
    wxLUA_UNICODE_ONLY(void lua_GetField(int idx, const wxString& k) { lua_GetField(idx, wx2lua(k)); })
    void  lua_RawGet(int idx);
    void  lua_RawGeti(int idx, int n);
    void  lua_CreateTable(int narr, int nrec);
    void  lua_NewTable();
    void* lua_NewUserdata(size_t sz);
    int   lua_GetMetatable(int objindex);

#if LUA_VERSION_NUM < 502
    void  lua_GetFenv(int idx);
#endif // LUA_VERSION_NUM < 502

    // -----------------------------------------------------------------------
    // Raw Lua set functions (stack -> Lua), lua.h

    void  lua_SetTable(int idx);
    void  lua_SetField(int idx, const char* k);
    wxLUA_UNICODE_ONLY(void lua_SetField(int idx, const wxString& k) { lua_SetField(idx, wx2lua(k)); })
    void  lua_RawSet(int idx);
    void  lua_RawSeti(int idx, int n);
    int   lua_SetMetatable(int objindex);

#if LUA_VERSION_NUM < 502
    int   lua_SetFenv(int idx);
#endif // LUA_VERSION_NUM < 502

    // -----------------------------------------------------------------------
    // Raw Lua `load' and `call' functions (load and run Lua code), lua.h

    void lua_Call(int nargs, int nresults);
    int  lua_PCall(int nargs, int nresults, int errfunc);
    int  lua_CPCall(lua_CFunction func, void *ud);

#if LUA_VERSION_NUM < 502
    int  lua_Load(lua_Reader reader, void *dt, const char* chunkname);
    wxLUA_UNICODE_ONLY(int lua_Load(lua_Reader reader, void *dt, const wxString& chunkname) { return lua_Load(reader, dt, wx2lua(chunkname)); })
#else
    int  lua_Load(lua_Reader reader, void *dt, const char* chunkname, const char* mode);
    wxLUA_UNICODE_ONLY(int lua_Load(lua_Reader reader, void *dt, const wxString& chunkname, const wxString& mode) { return lua_Load(reader, dt, wx2lua(chunkname), wx2lua(mode)); })
#endif // LUA_VERSION_NUM < 502

    int lua_Dump(lua_Writer writer, void *data);

    // -----------------------------------------------------------------------
    // Raw Lua coroutine functions, lua.h

    int lua_Yield(int nresults);
#if LUA_VERSION_NUM < 502
    int lua_Resume(int narg);
#endif // LUA_VERSION_NUM < 502
    int lua_Status();

    // -----------------------------------------------------------------------
    // Raw Lua garbage-collection functions, lua.h

    int lua_GC(int what, int data);

    // -----------------------------------------------------------------------
    // Raw Lua miscellaneous functions, lua.h

    wxString lua_Version() const;
    int   lua_Error();
    int   lua_Next(int idx);
    void  lua_Concat(int n);

    //LUA_API lua_Alloc (lua_getallocf) (lua_State *L, void **ud);
    //LUA_API void lua_setallocf (lua_State *L, lua_Alloc f, void *ud);

    // -----------------------------------------------------------------------
    // Raw Lua some useful "macros", lua.h

    //lua_boxpointer(L,u)
    //lua_unboxpointer(L,i)
    //lua_pop(L,n)            lua_settop(L, -(n)-1)

    static void luaL_Register(lua_State *L, const char *libname, const luaL_Reg *l);
    void lua_Register(const char* funcName, lua_CFunction f);
    wxLUA_UNICODE_ONLY(void lua_Register(const wxString& funcName, lua_CFunction f) { lua_Register(wx2lua(funcName), f); })
    void lua_PushCFunction(lua_CFunction f);

    bool lua_IsFunction(int idx) const;
    bool lua_IsTable(int idx) const;
    bool lua_IsLightUserdata(int idx) const;
    bool lua_IsNil(int idx) const;
    bool lua_IsBoolean(int idx) const;
    bool lua_IsThread(int idx) const;
    bool lua_IsNone(int idx) const;
    bool lua_IsNoneOrNil(int idx) const;

    //lua_pushliteral(L, s)   lua_pushlstring(L, "" s, (sizeof(s)/sizeof(char))-1)

    void lua_SetGlobal(const char* s);
    void lua_GetGlobal(const char* s);

    // -----------------------------------------------------------------------
    // Raw Lua Debug functions, lua.h

    int lua_GetStack(int level, lua_Debug* ar);
    int lua_GetInfo(const char* what, lua_Debug* ar);
    wxLUA_UNICODE_ONLY(int lua_GetInfo(const wxString& what, lua_Debug* ar) { return lua_GetInfo(wx2lua(what), ar); })
    const char* lua_GetLocal(const lua_Debug* ar, int n);
    const char* lua_SetLocal(const lua_Debug* ar, int n);
    const char* lua_GetUpvalue(int funcindex, int n);
    const char* lua_SetUpvalue(int funcindex, int n);

    void lua_SetHook(lua_Hook func, int mask, int count);
    lua_Hook lua_GetHook();
    int lua_GetHookMask();
    int lua_GetHookCount();

    // -----------------------------------------------------------------------
    // Raw Lua auxlib functions, lauxlib.h

    void luaL_Register(const char *libname, const luaL_Reg *l);
    int luaL_GetMetafield(int obj, const char *e);
    int luaL_CallMeta(int obj, const char *e);
#if LUA_VERSION_NUM < 502
    int luaL_TypeError(int narg, const char *tname);
#endif // LUA_VERSION_NUM < 502
    int luaL_ArgError(int numarg, const char *extramsg);
    const char *luaL_CheckLString(int numArg, size_t *l);
    const char *luaL_OptLString(int numArg, const char *def, size_t *len);
    lua_Number luaL_CheckNumber(int numArg);
    lua_Number luaL_OptNumber(int nArg, lua_Number def);
    lua_Integer luaL_CheckInteger(int numArg);
    lua_Integer luaL_OptInteger(int nArg, lua_Integer def);

    void luaL_CheckStack(int sz, const char *msg);
    void luaL_CheckType(int narg, int t);
    void luaL_CheckAny(int narg);

    int   luaL_NewMetatable(const char *tname);
    void  luaL_GetMetatable(const char *tname);
    void *luaL_CheckUdata(int ud, const char *tname);

    void luaL_Where(int lvl);
    int luaL_Error(const char *fmt, ...);

    int luaL_CheckOption(int narg, const char *def, const char *const lst[]);

    int luaL_Ref(int t);
    void luaL_Unref(int t, int ref);

    int luaL_LoadFile(const char *filename);
    int luaL_LoadBuffer(const char *buff, size_t sz, const char *name);
    int luaL_LoadString(const char *s);

    //LUALIB_API lua_State *(luaL_newstate) (void);
    //LUALIB_API const char *(luaL_gsub) (lua_State *L, const char *s, const char *p, const char *r);
    //LUALIB_API const char *(luaL_findtable) (lua_State *L, int idx, const char *fname, int szhint);

    // -----------------------------------------------------------------------
    // Raw Lua some useful macros, lauxlib.h

    void luaL_ArgCheck(bool condition, int numarg, const char* extramsg);
    const char* luaL_CheckString(int numArg);
    const char* luaL_OptString(int numArg, const char* def);
    int  luaL_CheckInt(int numArg);
    int  luaL_OptInt(int numArg, int def);
    long luaL_CheckLong(int numArg);
    long luaL_OptLong(int numArg, int def);

    // -----------------------------------------------------------------------
    // others

    void GetGlobals();

    // -----------------------------------------------------------------------
    // LUA_PATH

    wxString GetLuaPath();
    void AddLuaPath(const wxPathList& pathlist);
    void AddLuaPath(const wxFileName& filename);

    // -----------------------------------------------------------------------
    // operators

    bool operator == (const wxLuaState& wxlState) const
        { return m_refData == wxlState.m_refData; }
    bool operator != (const wxLuaState& wxlState) const
        { return m_refData != wxlState.m_refData; }

    wxLuaState& operator = (const wxLuaState& wxlState)
    {
        if ( (*this) != wxlState )
            Create(wxlState);
        return *this;
    }

private:
    // ref counting code
    virtual wxObjectRefData *CreateRefData() const;
    //virtual wxObjectRefData *CloneRefData(const wxObjectRefData *data) const;

    DECLARE_DYNAMIC_CLASS(wxLuaState)
};

//-----------------------------------------------------------------------------
// wxLuaEvent - An event sent from the wxLuaState to the set wxEvtHandler
//              to alert the handler of print,
//-----------------------------------------------------------------------------

class WXDLLIMPEXP_WXLUA wxLuaEvent: public wxNotifyEvent
{
public:
    wxLuaEvent(wxEventType commandType = wxEVT_NULL, wxWindowID id = wxID_ANY,
               const wxLuaState& wxlState = wxNullLuaState);

    wxLuaEvent(const wxLuaEvent &event);

    // use GetString method to retrieve info

    // Get the line number in the code, -1 if unknown
    int GetLineNum() const { return m_commandInt; }

    wxLuaState GetwxLuaState() const { return m_wxlState; }
    void SetwxLuaState(const wxLuaState& wxlState) { m_wxlState = wxlState; }

    lua_State *GetLuaState() const { return m_wxlState.GetLuaState(); }
    // non null only for wxEVT_LUA_DEBUG_HOOK
    lua_Debug *GetLuaDebug() const { return m_lua_Debug; }

    // If called from a wxEVT_LUA_DEBUG_HOOK the interpreter will stop
    void DebugHookBreak(bool stop) { m_debug_hook_break = stop; }

    // implementation
    virtual wxEvent *Clone() const { return new wxLuaEvent(*this); }

    wxLuaState m_wxlState;
    bool m_debug_hook_break;
    lua_Debug *m_lua_Debug;
};

#if wxCHECK_VERSION(3,0,0)
// A wxLuaState is being created, sent at the end of
//   wxLuaState(wxEvtHandler, win id) or Create(wxEvtHandler, win id)
wxDECLARE_EVENT(wxEVT_LUA_CREATION, wxLuaEvent);
// Lua's print(...) statements and such, check GetString()
wxDECLARE_EVENT(wxEVT_LUA_PRINT, wxLuaEvent);
// an error in Lua has occurred, check GetString() for message
wxDECLARE_EVENT(wxEVT_LUA_ERROR, wxLuaEvent);
// see LuaDebugHook function
wxDECLARE_EVENT(wxEVT_LUA_DEBUG_HOOK, wxLuaEvent);
#else
BEGIN_DECLARE_EVENT_TYPES()
    // A wxLuaState is being created, sent at the end of
    //   wxLuaState(wxEvtHandler, win id) or Create(wxEvtHandler, win id)
    DECLARE_EXPORTED_EVENT_TYPE(WXDLLIMPEXP_WXLUA, wxEVT_LUA_CREATION,   0)
    // Lua's print(...) statements and such, check GetString()
    DECLARE_EXPORTED_EVENT_TYPE(WXDLLIMPEXP_WXLUA, wxEVT_LUA_PRINT,      0)
    // an error in Lua has occurred, check GetString() for message
    DECLARE_EXPORTED_EVENT_TYPE(WXDLLIMPEXP_WXLUA, wxEVT_LUA_ERROR,      0)
    // see LuaDebugHook function
    DECLARE_EXPORTED_EVENT_TYPE(WXDLLIMPEXP_WXLUA, wxEVT_LUA_DEBUG_HOOK, 0)
    // after app starts, first idle
    //DECLARE_EXPORTED_EVENT_TYPE(WXDLLIMPEXP_WXLUA, wxEVT_LUA_INIT,       0)
    //DECLARE_EXPORTED_EVENT_TYPE(WXDLLIMPEXP_WXLUA, wxEVT_LUA_DEBUGGERATTACHED,   0)
END_DECLARE_EVENT_TYPES()
#endif

typedef void (wxEvtHandler::*wxLuaEventFunction)(wxLuaEvent&);

#define wxLuaEventHandler(func) \
    (wxObjectEventFunction)(wxEventFunction)(wxCommandEventFunction)(wxNotifyEventFunction)wxStaticCastEvent(wxLuaEventFunction, &func)

#define wx__DECLARE_WXLUAEVT(evt, id, fn) wx__DECLARE_EVT1(evt, id, wxLuaEventHandler(fn))

#define EVT_LUA_CREATION(id, fn)   wx__DECLARE_WXLUAEVT(wxEVT_LUA_CREATION,   id, fn)
#define EVT_LUA_PRINT(id, fn)      wx__DECLARE_WXLUAEVT(wxEVT_LUA_PRINT,      id, fn)
#define EVT_LUA_ERROR(id, fn)      wx__DECLARE_WXLUAEVT(wxEVT_LUA_ERROR,      id, fn)
#define EVT_LUA_DEBUG_HOOK(id, fn) wx__DECLARE_WXLUAEVT(wxEVT_LUA_DEBUG_HOOK, id, fn)

#endif // _WXLSTATE_H_
