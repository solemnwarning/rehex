/////////////////////////////////////////////////////////////////////////////
// Name:        wxlbind.h
// Purpose:     wxLuaBinding
// Author:      Ray Gilbert, John Labenski, J Winwood
// Created:     14/11/2001
// Copyright:   (c) 2012 John Labenski, Ray Gilbert
// Licence:     wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WXLBIND_H_
#define _WXLBIND_H_

#include "wxlua/wxldefs.h"

#include <wx/event.h>

#ifdef GetObject
    #undef GetObject // MSVC defines this
#endif

class  WXDLLIMPEXP_FWD_WXLUA wxLuaBinding;
class  WXDLLIMPEXP_FWD_WXLUA wxLuaState;
struct WXDLLIMPEXP_FWD_WXLUA wxLuaBindClass;

// ----------------------------------------------------------------------------
// wxLua binding defines, enums, and structs
// ----------------------------------------------------------------------------

// The inbuilt wxLua types (WXLUA_TXXX) corresponding to Lua types (LUA_TXXX)
//   are shifted to be positive values.
// The Binding wxLua types are positive integers generated automatically when
//   wxLua is initialized and start at WXLUA_T_MAX+1.
// *Use the function bool wxlua_iswxuserdatatype(wxl_type) if you want to
//   differentiate between the two.
//
// Note that WXLUA_TUNKNOWN is used as an initialiser for class types
//   and is used as an end marker for the wxLuaArgType array that
//   represents function prototype argument types in the wxLuaBindCFunc struct
//   and it must always be 0. The Lua type LUA_TNONE starts at 1 since
//   Lua arrays start at 1.

// wxLua types for Lua types
#define WXLUA_TUNKNOWN         0  // unset and invalid, not a LUA_TXXX
#define WXLUA_TNONE            1  // LUA_TNONE -1
#define WXLUA_TNIL             2  // LUA_TNIL 0
#define WXLUA_TBOOLEAN         3  // LUA_TBOOLEAN 1
#define WXLUA_TLIGHTUSERDATA   4  // LUA_TLIGHTUSERDATA 2
#define WXLUA_TNUMBER          5  // LUA_TNUMBER 3
#define WXLUA_TSTRING          6  // LUA_TSTRING 4
#define WXLUA_TTABLE           7  // LUA_TTABLE 5
#define WXLUA_TFUNCTION        8  // LUA_TFUNCTION 6
#define WXLUA_TUSERDATA        9  // LUA_TUSERDATA 7
#define WXLUA_TTHREAD          10 // LUA_TTHREAD 8
#define WXLUA_TINTEGER         11 // LUA_TNUMBER but integer only, not a LUA_TXXX
#define WXLUA_TCFUNCTION       12 // LUA_TFUNCTION & lua_iscfunction(), not a LUA_TXXX
#define WXLUA_TPOINTER         13 // LUA_TLIGHTUSERDATA || LUA_TUSERDATA ||
                                  // LUA_TFUNCTION || LUA_TTABLE || LUA_TTHREAD
                                  // any valid type for lua_topointer(), not a LUA_TXXX
#define WXLUA_TANY             14 // Any data type is valid, not a LUA_TXXX

#define WXLUA_T_MAX            14 // Max of the Lua WXLUA_TXXX values
#define WXLUA_T_MIN            0  // Min of the Lua WXLUA_TXXX values

#define WXLUATYPE_NULL         15 // C++ NULL, is full wxLua type with metatable

// Check that the Lua LUA_TXXX types are what they used to be
#if (LUA_TNONE     != -1) || (LUA_TNIL           != 0) || \
    (LUA_TBOOLEAN  != 1)  || (LUA_TLIGHTUSERDATA != 2) || \
    (LUA_TNUMBER   != 3)  || (LUA_TSTRING        != 4) || \
    (LUA_TTABLE    != 5)  || (LUA_TFUNCTION      != 6) || \
    (LUA_TUSERDATA != 7)  || (LUA_TTHREAD        != 8)
#   error "Lua has changed its LUA_TXXX defines."
#endif

// Is this wxLua type one of the basic Lua types
#define WXLUAT_IS_LUAT(wxl_type) (((wxl_type) >= WXLUA_T_MIN) && ((wxl_type) <= WXLUA_T_MAX))

// Blindly convert the lua_type to the wxlua_type. Note: WXLUA_TXXX = LUA_TXXX + 2
// *** See wxlua_luatowxluatype() for a better function ***
#define LUAT_TO_WXLUAT(luatype) ((luatype) + 2)

// Returns true if the wxLua type is for a wxLua binding type and not a
//   generic WXLUA_TXXX type. This means that there might be a metatable for
//   this type in the wxlua_lreg_types_key of the LUA_REGISTRYINDEX table.
#define wxlua_iswxuserdatatype(wxl_type) ((wxl_type) > WXLUA_T_MAX)

// Variables used in the wxLuaArgType member of the wxLuaBindCFunc for
// Lua types. The binding generator uses these and generates new ones for
// classes and structs as specified in the bindings.
extern WXDLLIMPEXP_DATA_WXLUA(int) wxluatype_TUNKNOWN;
extern WXDLLIMPEXP_DATA_WXLUA(int) wxluatype_TNONE;
extern WXDLLIMPEXP_DATA_WXLUA(int) wxluatype_TNIL;
extern WXDLLIMPEXP_DATA_WXLUA(int) wxluatype_TBOOLEAN;
extern WXDLLIMPEXP_DATA_WXLUA(int) wxluatype_TLIGHTUSERDATA;
extern WXDLLIMPEXP_DATA_WXLUA(int) wxluatype_TNUMBER;
extern WXDLLIMPEXP_DATA_WXLUA(int) wxluatype_TSTRING;
extern WXDLLIMPEXP_DATA_WXLUA(int) wxluatype_TTABLE;
extern WXDLLIMPEXP_DATA_WXLUA(int) wxluatype_TFUNCTION;
extern WXDLLIMPEXP_DATA_WXLUA(int) wxluatype_TUSERDATA;
extern WXDLLIMPEXP_DATA_WXLUA(int) wxluatype_TTHREAD;
extern WXDLLIMPEXP_DATA_WXLUA(int) wxluatype_TINTEGER;
extern WXDLLIMPEXP_DATA_WXLUA(int) wxluatype_TCFUNCTION;
extern WXDLLIMPEXP_DATA_WXLUA(int) wxluatype_TPOINTER;
extern WXDLLIMPEXP_DATA_WXLUA(int) wxluatype_TANY;

// The NULL wxLua type is not part of the bindings, but is installed
// by the wxLuaState since it may be used by various bindings and does not
// rely on wxWidgets.
extern WXDLLIMPEXP_DATA_WXLUA(int) wxluatype_NULL;                 // wxLua type for NULL pointer
extern WXDLLIMPEXP_DATA_WXLUA(wxLuaBindClass) wxLuaBindClass_NULL; // for NULL pointer

// Copies of wxLua types that are used very often, point to wxluatype_TUNKNOWN if unset.
// Note that we do not use the original since we may not be linked
// to the binding library that defines them.
// Their values are set at compile time if linked to library,
//   see wxbase_rules.lua and wxcore_rules.lua
extern WXDLLIMPEXP_DATA_WXLUA(int*) p_wxluatype_wxEvent;       // wxLua type for wxEvent
extern WXDLLIMPEXP_DATA_WXLUA(int*) p_wxluatype_wxWindow;      // wxLua type for wxWindow
extern WXDLLIMPEXP_DATA_WXLUA(int*) p_wxluatype_wxScrollEvent; // wxLua type for wxScrollEvent - see wxLuaEventCallback::OnEvent
extern WXDLLIMPEXP_DATA_WXLUA(int*) p_wxluatype_wxSpinEvent;   // wxLua type for wxSpinEvent   - see wxLuaEventCallback::OnEvent
extern WXDLLIMPEXP_DATA_WXLUA(int*) p_wxluatype_wxString;      // wxLua type for wxString
extern WXDLLIMPEXP_DATA_WXLUA(int*) p_wxluatype_wxArrayString; // wxLua type for wxArrayString
extern WXDLLIMPEXP_DATA_WXLUA(int*) p_wxluatype_wxSortedArrayString; // wxLua type for wxSortedArrayString
extern WXDLLIMPEXP_DATA_WXLUA(int*) p_wxluatype_wxArrayInt;    // wxLua type for wxArrayInt
extern WXDLLIMPEXP_DATA_WXLUA(int*) p_wxluatype_wxArrayDouble; // wxLua type for wxArrayDouble
extern WXDLLIMPEXP_DATA_WXLUA(int*) p_wxluatype_wxMemoryBuffer; // wxLua type for wxMemoryBuffer
extern WXDLLIMPEXP_DATA_WXLUA(int*) p_wxluatype_wxPoint;       // wxLua type for wxPoint
extern WXDLLIMPEXP_DATA_WXLUA(int*) p_wxluatype_wxPoint2DDouble;       // wxLua type for wxPoint2DDouble

// ----------------------------------------------------------------------------
// wxLuaArgType a pointer to a declared wxLua type, see wxLuaBindCFunc::argtypes
// ----------------------------------------------------------------------------

typedef int* wxLuaArgType;      // address of wxLua class type (a pointer to it)
extern WXDLLIMPEXP_DATA_WXLUA(wxLuaArgType) g_wxluaargtypeArray_None[1]; // = {0}

// ----------------------------------------------------------------------------
// wxLuaMethod_Type: Values for the wxLuaBindMethod::method_type and wxLuaBindCFunc::method_type
// ----------------------------------------------------------------------------
enum wxLuaMethod_Type
{
    WXLUAMETHOD_CONSTRUCTOR = 0x0001, // class constructor
    WXLUAMETHOD_METHOD      = 0x0002, // class member function
    WXLUAMETHOD_CFUNCTION   = 0x0004, // global C function (not part of a class)
    WXLUAMETHOD_GETPROP     = 0x0008, // Get %property funcName, read
    WXLUAMETHOD_SETPROP     = 0x0010, // Set %property funcName, write

    WXLUAMETHOD_STATIC      = 0x1000, // Class member function is static

    WXLUAMETHOD_DELETE      = 0x2000, // This is the delete function that wxLua has generated
                                      // to delete this class and is not part of the
                                      // original class.

    WXLUAMETHOD_MASK        = 0xFFFF  // Match any type for searching
};

// ----------------------------------------------------------------------------
// wxLuaBindCFunc - Defines a single function for wxLua
// ----------------------------------------------------------------------------

struct WXDLLIMPEXP_WXLUA wxLuaBindCFunc
{
    lua_CFunction lua_cfunc;   // C function that implements the method or property
    int           method_type; // enum wxLuaMethod_Type flags for this function
    int           minargs;     // Min number of required args
    int           maxargs;     // Max number of args allowed, equal to length of argtypes array
    wxLuaArgType* argtypes;    // Array of wxLua types representing each argument, NULL terminated.
};

// ----------------------------------------------------------------------------
// wxLuaBindMethod - Defines a method or property (a function) for wxLua
// ----------------------------------------------------------------------------

struct WXDLLIMPEXP_WXLUA wxLuaBindMethod
{
    const char*      name;          // Name of the method or property
    int              method_type;   // enum wxLuaMethod_Type flags for this method.
                                    //   Note that each func has own type, this is ored values of them.
    wxLuaBindCFunc*  wxluacfuncs;   // Array of C functions for this method
    int              wxluacfuncs_n; // Number of C functions (overloaded > 1) for this method
    wxLuaBindMethod* basemethod;    // Overloaded method from the base class, else NULL.
};

// ----------------------------------------------------------------------------
// wxLuaBindNumber - Defines a numeric value for wxLua
// ----------------------------------------------------------------------------

struct WXDLLIMPEXP_WXLUA wxLuaBindNumber
{
    const char* name;          // name
    double      value;         // numeric value
};

// ----------------------------------------------------------------------------
// wxLuaBindString - Defines a wxWidgets wxChar* string for wxLua
// ----------------------------------------------------------------------------

struct WXDLLIMPEXP_WXLUA wxLuaBindString
{
    const char*   name;          // name
    const char*   c_string;      // string value
    const wxChar* wxchar_string; // string value
};

// ----------------------------------------------------------------------------
// wxLuaBindEvent - Defines a wxWidgets wxEventType for wxLua
// ----------------------------------------------------------------------------

#if (wxVERSION_NUMBER >= 2900)
    // In 2.9 wxEVT_XXX are declared as wxEventTypeTag<E.G. wxCommandEvent> wxEVT_XXX;
    // The operator const wxEventType& is used to get the int wxEventType.
    #define WXLUA_GET_wxEventType_ptr(wxEVT_XXX) &((const wxEventType&)(wxEVT_XXX))
#else
    #define WXLUA_GET_wxEventType_ptr(wxEVT_XXX) &(wxEVT_XXX)
#endif

struct WXDLLIMPEXP_WXLUA wxLuaBindEvent
{
    const char*        name;      // Name of the wxEventType, e.g. "wxEVT_COMMAND_MENU_SELECTED"
    const wxEventType* eventType; // wxWidgets event type, e.g. &wxEVT_COMMAND_MENU_SELECTED
    int*               wxluatype; // wxLua class type that wxWidgets uses for this wxEventType,
                                  //   e.g. &wxluatype_wxCommandEvent
};

// ----------------------------------------------------------------------------
// wxLuaBindEvent - Defines an object or pointer for wxLua
// ----------------------------------------------------------------------------

struct WXDLLIMPEXP_WXLUA wxLuaBindObject
{
    const char*  name;      // Name of the object or pointer
    int*         wxluatype; // wxLua class type of the object or pointer.
    const void*  objPtr;    // Pointer to the object, e.g. &wxDefaultPosition
    const void** pObjPtr;   // Pointer to the object pointer, e.g. (const void **)&wxThePenList
                            // This is done since the object may not be created at compile time.
};

// ----------------------------------------------------------------------------
// wxLuaBindClass - Defines a C++ class or struct for wxLua
// ----------------------------------------------------------------------------

typedef void (*wxlua_delete_function) (void** o);

struct WXDLLIMPEXP_WXLUA wxLuaBindClass
{
    const char*      name;           // Name of the class or struct
    wxLuaBindMethod* wxluamethods;   // Pointer to array of methods for this class
    int              wxluamethods_n; // Number of methods
    wxClassInfo*     classInfo;      // Pointer to the wxClassInfo associated with this class or NULL.
    int*             wxluatype;      // wxLua class type for userdata
    const char**     baseclassNames; // Names of base classes, or NULL if no base classes.
                                     // This is a NULL terminated array of strings.
    wxLuaBindClass** baseBindClasses;// Pointers to the base classes or NULL for no base classes.
                                     // This member is set after all the bindings are
                                     // registered since the base class may be from
                                     // a different module and so it can't be set at compile time.
                                     // This array is one shorter than the baseclassNames array
                                     // and you should use it rather than this to check the length
                                     // since any one of these may be NULL if the
                                     // library or module with the base class is not loaded.

    wxLuaArgType*    baseclass_wxluatypes;     // NULL terminated array of wxLua types for the base classes
                                               // that are from second or higher base classes
    wxIntPtr*        baseclass_vtable_offsets; // Array of pointer offsets of the second or higher
                                               // base classes from the root class.
                                               // See note above wxluaT_getuserdatatype()

    wxLuaBindNumber* enums;          // Class member enums or NULL if none
    int              enums_n;        // number of enums

    wxlua_delete_function delete_fn; // Function that will cast the void* pointer
                                     // to the class type and then call delete on it.
};

// ----------------------------------------------------------------------------
// C functions for the metatable for wxLua userdata installed by the wxLuaBinding
// ----------------------------------------------------------------------------

// Generic delete function for userdata binding objects
WXDLLIMPEXP_WXLUA int LUACALL wxlua_userdata_delete(lua_State *L);

// memory deallocation function for created wxLuaBindClass defined objects, Lua's __gc metatable index
WXDLLIMPEXP_WXLUA int LUACALL wxlua_wxLuaBindClass__gc(lua_State *L);
// Lua 'set table' function for created wxLuaBindClass defined objects, Lua's __newindex metatable index
WXDLLIMPEXP_WXLUA int LUACALL wxlua_wxLuaBindClass__newindex(lua_State *L);
// Lua 'get table' function for created wxLuaBindClass defined objects, Lua's __index metatable index
WXDLLIMPEXP_WXLUA int LUACALL wxlua_wxLuaBindClass__index(lua_State *L);
// Lua 'tostring' function for created wxLuaBindClass defined objects, Lua's __tostring metatable index
WXDLLIMPEXP_WXLUA int LUACALL wxlua_wxLuaBindClass__tostring(lua_State *L);

// ----------------------------------------------------------------------------
// Overloaded binding function call helper functions.
// ----------------------------------------------------------------------------

// Redirect a Lua function call to one wxLuaBindCFunc from a list of overloaded functions.
// The 1st upvalue must be a wxLuaBindMethod.
WXDLLIMPEXP_WXLUA int LUACALL wxlua_callOverloadedFunction(lua_State* L);
// Redirect a Lua function call to one wxLuaBindCFunc from a list of overloaded functions
// declared in the wxLuaBindMethod.
WXDLLIMPEXP_WXLUA int LUACALL wxlua_callOverloadedFunction(lua_State* L, struct wxLuaBindMethod* wxlMethod);
// Get a human readable string of the Lua args (items on the stack) for a function call
WXDLLIMPEXP_WXLUA wxString wxlua_getLuaArgsMsg(lua_State* L, int start_stack_idx, int end_stack_idx);
// Get a human readable wxString of the wxLuaArgType arrays for the functions in the method
WXDLLIMPEXP_WXLUA wxString wxlua_getBindMethodArgsMsg(lua_State* L, struct wxLuaBindMethod* wxlMethod);

// ----------------------------------------------------------------------------
// wxLuaBinding - binds classes, functions, objects, and event callbacks to
//                the wxLuaState.
// ----------------------------------------------------------------------------

// wxArray of wxLua Bindings
WX_DEFINE_USER_EXPORTED_ARRAY_PTR(wxLuaBinding*, wxLuaBindingArray, class WXDLLIMPEXP_WXLUA);

class WXDLLIMPEXP_WXLUA wxLuaBinding : public wxObject
{
public:
    wxLuaBinding();
    virtual ~wxLuaBinding() {}

    // Register all the bindings added to the static member wxLuaBindingArray.
    // Leaves nothing on the stack.
    static bool RegisterBindings(const wxLuaState& wxlState);

    // Binds C Functions/Defines/Object/Events to a Lua table with binding's namespace.
    // The Lua table that the bindings were installed into is left on the top
    //   of the stack and you must pop it when done.
    virtual bool RegisterBinding(const wxLuaState& wxlState);

    // Create the metatable for the class and install it into the Lua registry.
    static bool InstallClassMetatable(lua_State* L, const wxLuaBindClass* wxlClass);
    // Install a single wxLuaBindClass struct into the table at the top
    // of the stack.
    static bool InstallClass(lua_State* L, const wxLuaBindClass* wxlClass);

    // -----------------------------------------------------------------------

    // Get/Set the binding name, a unique name of the binding.
    //   By default it is the "hook_cpp_namespace" used in the binding
    //   generator which needs to be a unique name.
    wxString GetBindingName() const           { return m_bindingName; }
    void SetBindingName(const wxString& name) { m_bindingName = name; }

    // Get/Set the namespace table in Lua that this binding will be installed to
    wxString GetLuaNamespace() const                { return m_nameSpace; }
    void SetLuaNamespace(const wxString& nameSpace) { m_nameSpace = nameSpace; }

    size_t GetClassCount() const        { return m_classCount; }
    wxLuaBindClass* GetClassArray()     { return m_classArray; }

    size_t GetNumberCount() const       { return m_numberCount; }
    wxLuaBindNumber* GetNumberArray()   { return m_numberArray; }

    size_t GetStringCount() const       { return m_stringCount; }
    wxLuaBindString* GetStringArray()   { return m_stringArray; }

    size_t GetEventCount() const        { return m_eventCount; }
    wxLuaBindEvent* GetEventArray()     { return m_eventArray; }

    size_t GetObjectCount() const       { return m_objectCount; }
    wxLuaBindObject* GetObjectArray()   { return m_objectArray; }

    size_t GetFunctionCount() const     { return m_functionCount; }
    wxLuaBindMethod* GetFunctionArray() { return m_functionArray; }

    // Is this wxLua type defined in this binding?
    bool HaswxLuaType(int wxl_type) const { return (wxl_type >= m_first_wxluatype) && (wxl_type <= m_last_wxluatype); }

    // -----------------------------------------------------------------------
    // These functions only look through the binding data of this wxLuaBinding

    // Find the wxLuaBindEvent with the wxEventType, returns NULL if not found.
    const wxLuaBindEvent* GetBindEvent(wxEventType eventType) const;
    // Look up the wxEventType name as a string, from the wxEventType number
    //  in the wxLuaBindEvent* struct list of this binding.
    wxString GetEventTypeName(wxEventType eventType) const;
    // Get the wxLuaBindClass that has this wxLua type, or NULL if none
    const wxLuaBindClass* GetBindClass(int wxl_type) const;
    // Get the wxLuaBindClass that has this name, or NULL if none
    const wxLuaBindClass* GetBindClass(const char* className) const;
    // Get the first wxLuaBindClass that has this wxLuaBindMethod
    const wxLuaBindClass* GetBindClass(const wxLuaBindMethod* wxlMethod) const;
    // Get the first wxLuaBindClass that has this wxLuaBindCFunc
    const wxLuaBindClass* GetBindClass(const wxLuaBindCFunc* wxlCFunc) const;

    // -----------------------------------------------------------------------
    // These functions search through the static wxLuaBinding::GetBindingArray()
    // for the items.

    // Get the installed wxLuaBinding with the given
    //   wxLuaBinding::GetBindingName() or NULL for no match.
    static wxLuaBinding* GetLuaBinding(const wxString& bindingName);

    // Get wxLuaBindClass for given wxLua type using wxLuaBindClass::wxluatype,
    //   returns NULL on failure.
    static const wxLuaBindClass* FindBindClass(int wxl_type);
    // Get wxLuaBindClass that has this class name using wxLuaBindClass::name,
    //   returns NULL on failure.
    static const wxLuaBindClass* FindBindClass(const char* className);
    // Get the first wxLuaBindClass that has this particular wxLuaBindMethod
    //   returns NULL on failure.
    static const wxLuaBindClass* FindBindClass(const wxLuaBindMethod* wxlMethod);
    // Get the first wxLuaBindClass that has this particular wxLuaBindCFunc in its methods
    //   returns NULL on failure.
    static const wxLuaBindClass* FindBindClass(const wxLuaBindCFunc* wxlCFunc);

    // Get wxLuaBindEvent for given wxEventType (wxEvent::GetEventType()) by finding
    //   the matching wxLuaBindEvent::eventType.
    //   returns NULL on failure.
    static const wxLuaBindEvent* FindBindEvent(wxEventType eventType);

    // Get the wxLuaBinding that has this wxLuaBindMethod in its wxLuaBinding::GetFunctionArray().
    //   returns NULL on failure.
    static wxLuaBinding* FindMethodBinding(const wxLuaBindMethod* wxlMethod);

    // -----------------------------------------------------------------------
    // These functions search through the input struct

    // Lookup a wxLuaBindMethod function or property called methodName in the wxLuaBindClass
    // that is also of the wxLuaMethod_Type method_type. The method_type may be
    // ored values and the first match found is returned or NULL if not found.
    // If the wxLuaBindMethod cannot be found on the current class recurse through base classes
    //   if search_baseclasses.
    static wxLuaBindMethod* GetClassMethod(const wxLuaBindClass *wxlClass, const char *methodName,
                                           int method_type, bool search_baseclasses);

    // -----------------------------------------------------------------------

    // Get all the bindings that were initialized using the generated binding
    //   function wxLuaBinding_[binding name]_init().
    //   You can adjust the array *only* if you do not have any wxLuaStates
    //   created, otherwise the wxLua types will be out of sync.
    static wxLuaBindingArray& GetBindingArray() { return sm_bindingArray; }

    // -----------------------------------------------------------------------

    // Initialize all of the bindings by iterating the GetBindingArray() and
    // setting the base classes and base class functions. This function
    // is automatically run by the wxLuaState and should not need to be called
    // unless you later add a new binding to the array, in which case force it to be rerun.
    static void InitAllBindings(bool force_update = false);

protected:

    // Call only once after subclassed version is created to sort the bindings appropriately
    void InitBinding();

    // Register the classes, defines, strings, events, objects, and functions
    // stored in the binding arrays. The Lua table to install them into
    // must be at the top of the stack.
    virtual void DoRegisterBinding(const wxLuaState& wxlState) const;

    // binding objects
    size_t           m_classCount;
    wxLuaBindClass*  m_classArray;
    size_t           m_numberCount;
    wxLuaBindNumber* m_numberArray;
    size_t           m_stringCount;
    wxLuaBindString* m_stringArray;
    size_t           m_eventCount;
    wxLuaBindEvent*  m_eventArray;
    size_t           m_objectCount;
    wxLuaBindObject* m_objectArray;
    size_t           m_functionCount;
    wxLuaBindMethod* m_functionArray;

    wxString m_bindingName;     // A unique name of the binding
    wxString m_nameSpace;       // Lua table namespace e.g. "wx"
    int m_first_wxluatype;      // The first wxLua type allocated for a class
    int m_last_wxluatype;       // The last wxLua type of registered classes

    static wxLuaBindingArray sm_bindingArray;
    static int               sm_bindingArray_initialized;
    static int               sm_wxluatype_max;

    DECLARE_ABSTRACT_CLASS(wxLuaBinding)
};

#endif // _WXLBIND_H_
