/////////////////////////////////////////////////////////////////////////////
// Name:          wxlbind.cpp
// Purpose:       wxLuaBinding
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

#include "wxlua/wxlbind.h"
#include "wxlua/wxlstate.h"

//#include "wxluadebug/include/wxldebug.h" // for debugging only


wxLuaArgType g_wxluaargtypeArray_None[1] = {0};

int wxluatype_TUNKNOWN       = WXLUA_TUNKNOWN;
int wxluatype_TNONE          = WXLUA_TNONE;
int wxluatype_TNIL           = WXLUA_TNIL;
int wxluatype_TBOOLEAN       = WXLUA_TBOOLEAN;
int wxluatype_TLIGHTUSERDATA = WXLUA_TLIGHTUSERDATA; // raw data
int wxluatype_TNUMBER        = WXLUA_TNUMBER;
int wxluatype_TSTRING        = WXLUA_TSTRING;
int wxluatype_TTABLE         = WXLUA_TTABLE;
int wxluatype_TFUNCTION      = WXLUA_TFUNCTION;
int wxluatype_TUSERDATA      = WXLUA_TUSERDATA;      // raw data
int wxluatype_TTHREAD        = WXLUA_TTHREAD;
int wxluatype_TINTEGER       = WXLUA_TINTEGER;
int wxluatype_TCFUNCTION     = WXLUA_TCFUNCTION;
int wxluatype_TPOINTER       = WXLUA_TPOINTER;
int wxluatype_TANY           = WXLUA_TANY;

int wxluatype_NULL           = WXLUATYPE_NULL;

wxLuaBindClass wxLuaBindClass_NULL =
    { "NULL", NULL, 0, NULL, &wxluatype_NULL, NULL, NULL, NULL, NULL, NULL, 0, };

int* p_wxluatype_wxEvent             = &wxluatype_TUNKNOWN;
int* p_wxluatype_wxWindow            = &wxluatype_TUNKNOWN;
int* p_wxluatype_wxScrollEvent       = &wxluatype_TUNKNOWN;
int* p_wxluatype_wxSpinEvent         = &wxluatype_TUNKNOWN;
int* p_wxluatype_wxString            = &wxluatype_TUNKNOWN;
int* p_wxluatype_wxArrayString       = &wxluatype_TUNKNOWN;
int* p_wxluatype_wxSortedArrayString = &wxluatype_TUNKNOWN;
int* p_wxluatype_wxArrayInt          = &wxluatype_TUNKNOWN;
int* p_wxluatype_wxArrayDouble       = &wxluatype_TUNKNOWN;
int* p_wxluatype_wxMemoryBuffer      = &wxluatype_TUNKNOWN;
int* p_wxluatype_wxPoint             = &wxluatype_TUNKNOWN;
int* p_wxluatype_wxPoint2DDouble     = &wxluatype_TUNKNOWN;

// ----------------------------------------------------------------------------
// wxlua_tableErrorHandler
// ----------------------------------------------------------------------------

/*
static int LUACALL wxlua_tableErrorHandler(lua_State *L)
{
    wxlua_error(L, "Cannot modify read-only wxLua table");
    return 0;
}
*/

// ----------------------------------------------------------------------------
// Generic delete function for bindings
// ----------------------------------------------------------------------------

int LUACALL wxlua_userdata_delete(lua_State *L)
{
    // if removed from tracked mem list, remove the metatable so that __gc is not called on this object.
    if (wxluaO_deletegcobject(L, 1, WXLUA_DELETE_OBJECT_ALL))
    {
        lua_pushnil(L);
        lua_setmetatable(L, -2);
    }
    else
    {
        wxString msg;
        msg.Printf(wxT("wxLua: Unable to call wxuserdata:delete() on object!"));

        // leave this printf since we really want to know if this happens
        wxPrintf(wxString(msg + wxT("\n")).c_str());
        wxlua_argerrormsg(L, msg);
    }

    return 0;
}

// ----------------------------------------------------------------------------
// If the class defines a gc function, then call it.
// ----------------------------------------------------------------------------

int LUACALL wxlua_wxLuaBindClass__gc(lua_State *L)
{
    wxLuaBindClass *wxlClass = (wxLuaBindClass *)lua_touserdata(L, lua_upvalueindex(1));

    if ((wxlClass != NULL) && wxlua_iswxuserdata(L, 1) && (wxluaT_type(L, 1) == *wxlClass->wxluatype))
    {
        // clean up the rest of this, this won't error if the key doesn't exist
        wxluaO_deletegcobject(L, 1, WXLUA_DELETE_OBJECT_LAST);
    }

    return 0;
}

// ----------------------------------------------------------------------------
// Called by LUA to find the method that corresponds to a __index method name.
// ----------------------------------------------------------------------------

int LUACALL wxlua_wxLuaBindClass__index(lua_State *L)
{
    // This function is called for the __index metatable of the wxLua userdata
    // for class instances.

    // Lua stack : 1 = userdata, 2 = key; userdata:key()
    // You cannot seem to get the calling convention (. or :) or if it was
    // called as a function() or a .member?

    // See below, if _XXX is called then we set this flag so that
    //  the called function knows to call the base class instead of recalling
    //  the Lua function and recursing.
    wxlua_setcallbaseclassfunction(L, false);

    bool found    = false;
    int  result   = 0;
    wxLuaBindClass *wxlClass = (wxLuaBindClass *)lua_touserdata(L, lua_upvalueindex(1));
    wxCHECK_MSG(wxlClass, 0, wxT("Invalid wxLuaBindClass")); // fail hard

    void *obj_ptr = wxlua_touserdata(L, 1, false);
    const char *name = lua_tostring(L, 2); // name of the __index method called in Lua

    if (!name)
    {
        // name is NULL if it's not a string
        wxlua_error(L, wxString::Format(_("wxLua: Attempt to call a class method using '%s' on a '%s' wxLua type."),
            wxlua_luaL_typename(L, 2).c_str(), lua2wx(wxlClass->name).c_str()).c_str());
    }
    else if (wxluaT_type(L, 1) == *wxlClass->wxluatype)
    {
        // check if we're to call the baseclass function or if it's a Lua derived function
        bool callbase = (name[0] == '_');

        if (callbase)
            name++; // skip past "_"[FunctionName]
        else
        {
            // if there's a derived method in Lua, push it onto the stack to be run
            if (wxlua_hasderivedmethod(L, obj_ptr, name, true))
            {
                found = true;
                result = 1; // the function for Lua to call is on the stack
            }
        }

        // Search through the bindings for the function to call
        if (!found)
        {
            wxLuaBindMethod* wxlMethod = wxLuaBinding::GetClassMethod(wxlClass, name, WXLUAMETHOD_METHOD|WXLUAMETHOD_GETPROP, true);

            if ((wxlMethod != NULL) && (wxlMethod->wxluacfuncs != NULL))
            {
                if (WXLUA_HASBIT(wxlMethod->method_type, WXLUAMETHOD_GETPROP))
                {
                    // The user wants to call the C++ function as a property
                    // which is treated as though it were a member variable.
                    // It shouldn't have been called as a function with ()
                    // and so we call the function here and leave the value on the stack.
                    found = true;
                    if (WXLUA_HASBIT(wxlMethod->method_type, WXLUAMETHOD_STATIC))
                        lua_pop(L, 2); // remove the userdata and func name
                    else
                        lua_pop(L, 1); // remove the name of the function

                    result = (*wxlMethod->wxluacfuncs[0].lua_cfunc)(L);
                }
                else
                {
                    // The user has called a real C++ function and if it's
                    // overloaded we call wxlua_callOverloadedFunction() to
                    // find the correct one to call.
                    found = true;
                    result = 1;

                    lua_pushlightuserdata(L, wxlMethod);

                    if ((wxlMethod->wxluacfuncs_n > 1) || (wxlMethod->basemethod))
                        lua_pushcclosure(L, wxlua_callOverloadedFunction, 1);
                    else
                        lua_pushcclosure(L, wxlMethod->wxluacfuncs[0].lua_cfunc, 1);
                }
            }

            // Maybe this is an undeclared property? Prepend 'Get' and try again.
            if (!found)
            {
                int len = strlen(name);
                wxCharBuffer buf(len + 4);
                char* str = buf.data();
                str[0] = 'G'; str[1] = 'e'; str[2] = 't';
                memcpy(str+3, name, len+1); // include terminating NULL

                wxlMethod = wxLuaBinding::GetClassMethod(wxlClass, str, WXLUAMETHOD_METHOD, true);

                if ((wxlMethod != NULL) && WXLUA_HASBIT(wxlMethod->method_type, WXLUAMETHOD_METHOD))
                    //wxlMethod->funcs && (wxlMethod->funcs->minargs == 0) && // let it error out
                    //(wxlMethod->funcs->maxargs == 0))
                {
                    found = true;
                    if (WXLUA_HASBIT(wxlMethod->method_type, WXLUAMETHOD_STATIC))
                        lua_pop(L, 2); // remove the userdata and func name
                    else
                        lua_pop(L, 1); // remove the name of the function

                    result = (*wxlMethod->wxluacfuncs[0].lua_cfunc)(L);
                }
            }

            // This MUST be reset to false in the base class function
            if (found && callbase) wxlua_setcallbaseclassfunction(L, true);
        }
    }

    return result;
}

// ----------------------------------------------------------------------------
// Called by LUA to find the method that corresponds to a __newindex method name.
// ----------------------------------------------------------------------------

int LUACALL wxlua_wxLuaBindClass__newindex(lua_State *L)
{
    wxLuaBindClass *wxlClass = (wxLuaBindClass *)lua_touserdata(L, lua_upvalueindex(1));
    wxCHECK_MSG(wxlClass, 0, wxT("Invalid wxLuaBindClass")); // fail hard

    // Lua Stack: 1 = userdata, 2 = key, 3 = value; userdata.key = value

    const char *name = lua_tostring(L, 2);
    bool found = false;

    if (!name)
    {
        // name is NULL if it's not a string
        wxlua_error(L, wxString::Format(_("wxLua: Attempt to call or add a class method using '%s' on a '%s' type."),
            wxlua_luaL_typename(L, 2).c_str(), lua2wx(wxlClass->name).c_str()).c_str());
    }
    else if (wxluaT_type(L, 1) == *wxlClass->wxluatype)
    {
        // See if there is a WXLUAMETHOD_SETPROP in the wxLuaBindClass's wxLuaBindMethods
        wxLuaBindMethod *wxlMethod = wxLuaBinding::GetClassMethod(wxlClass, name, WXLUAMETHOD_SETPROP, true);

        if (wxlMethod != NULL)
        {
            found = true;
            lua_remove(L, 2); // remove the function name
            if (WXLUA_HASBIT(wxlMethod->method_type, WXLUAMETHOD_STATIC))
                lua_remove(L, 1); // remove the userdata too, leaving the value

            (*wxlMethod->wxluacfuncs[0].lua_cfunc)(L);
        }
        else
        {
            // Maybe this is an undeclared property? Prepend 'Set' and try again.
            int len = strlen(name);
            wxCharBuffer buf(len + 4);
            char* str = buf.data();
            str[0] = 'S'; str[1] = 'e'; str[2] = 't';
            memcpy(str+3, name, len+1); // include terminating NULL

            wxlMethod = wxLuaBinding::GetClassMethod(wxlClass, str, WXLUAMETHOD_METHOD, true);
            if ((wxlMethod != NULL) && WXLUA_HASBIT(wxlMethod->method_type, WXLUAMETHOD_METHOD))
            {
                found = true;
                lua_remove(L, 2); // remove the function name
                if (WXLUA_HASBIT(wxlMethod->method_type, WXLUAMETHOD_STATIC))
                    lua_remove(L, 1); // remove the userdata too, leaving the value

                (*wxlMethod->wxluacfuncs[0].lua_cfunc)(L);
            }
        }

        // They want to add this to the class so store it in the derived method table
        if (!found)
        {
            found = true;

            void *obj_ptr = wxlua_touserdata(L, 1, false);
            wxLuaObject* wxlObj = new wxLuaObject(L, 3);
            wxlua_setderivedmethod(L, obj_ptr, name, wxlObj);
        }
    }

    if (!found)
    {
        wxlua_error(L, wxString::Format(_("wxLua: Unable to call or add an unknown method '%s' on a '%s' type."),
            lua2wx(name).c_str(), lua2wx(wxlClass ? wxlClass->name : "").c_str()).c_str());
    }

    return 0;
}

// ----------------------------------------------------------------------------
// wxlua_wxLuaBindClass__tostring
// ----------------------------------------------------------------------------

int LUACALL wxlua_wxLuaBindClass__tostring(lua_State *L)
{
    // this should be identical to Lua's tostring for a userdata
    wxString str = wxString::Format(wxT("userdata: %p"), lua_touserdata(L, 1));

    int wxl_type = wxluaT_type(L, 1);
    if (wxlua_iswxuserdatatype(wxl_type))
    {
        wxString name = wxluaT_typename(L, wxl_type);
        if (!name.IsEmpty())
        {
            // GCC prints '(' for NULL %p for some reason.
            void* p = wxlua_touserdata(L, 1, false);
            if (p)
                str += wxString::Format(wxT(" [%s(%p, %d)]"), name.c_str(), p, wxl_type);
            else
                str += wxString::Format(wxT(" [%s(0x0, %d)]"), name.c_str(), wxl_type);
        }
    }
    else
        str += wxT(" [??? Unknown wxLua class type!]"); // get people's attention

    lua_pushstring(L, wx2lua(str));
    return 1;
}

// ----------------------------------------------------------------------------
// The __call metatable function to allow the class tables to be called as functions
// ----------------------------------------------------------------------------

int LUACALL wxlua_wxLuaBindMethod_table__call(lua_State *L)
{
    lua_remove(L, 1); // remove the table

    return wxlua_callOverloadedFunction(L);
}

int LUACALL wxlua_wxLuaBindMethod_table__index(lua_State *L)
{
    // Lua stack: 1 = table, 2 = key

    wxLuaBindClass *wxlClass = (wxLuaBindClass *)lua_touserdata(L, lua_upvalueindex(1));
    wxCHECK_MSG(wxlClass, 0, wxT("Invalid wxLuaBindClass")); // fail hard

    int result = 0;

    const char* name = lua_tostring(L, 2);
    if (!name)
    {
        // name is NULL if it's not a string
        wxlua_error(L, wxString::Format(_("wxLua: Attempt to call a static class method using '%s' on a '%s' type."),
            wxlua_luaL_typename(L, 2).c_str(), lua2wx(wxlClass->name).c_str()).c_str());
        return 0;
    }

    wxLuaBindMethod* wxlMethod = wxLuaBinding::GetClassMethod(wxlClass, name, WXLUAMETHOD_GETPROP, true);

    if (wxlMethod && WXLUA_HASBIT(wxlMethod->method_type, WXLUAMETHOD_STATIC))
    {
        lua_pop(L, 2); // remove the table and the name of the function
        result = (*wxlMethod->wxluacfuncs[0].lua_cfunc)(L);
    }
    else
    {
        lua_pushvalue(L, -1);  // copy key
        lua_rawget(L, -3);     // get t[key] = value, pops key pushes value
        result = 1;            // ok if nil
    }

    return result;
}

int LUACALL wxlua_wxLuaBindMethod_table__newindex(lua_State *L)
{
    // 1 = table, 2 = key, 3 = value

    wxLuaBindClass *wxlClass = (wxLuaBindClass *)lua_touserdata(L, lua_upvalueindex(1));
    wxCHECK_MSG(wxlClass, 0, wxT("Invalid wxLuaBindClass"));

    const char* name = lua_tostring(L, 2);
    if (!name)
    {
        // name is NULL if it's not a string
        wxlua_error(L, wxString::Format(_("wxLua: Attempt to call a static class method using '%s' on a '%s' type."),
            wxlua_luaL_typename(L, 2).c_str(), lua2wx(wxlClass->name).c_str()).c_str());
        return 0;
    }

    wxLuaBindMethod* wxlMethod = wxLuaBinding::GetClassMethod(wxlClass, name, WXLUAMETHOD_SETPROP, true);

    if (wxlMethod && WXLUA_HASBIT(wxlMethod->method_type, WXLUAMETHOD_STATIC))
    {
        lua_remove(L, 2); // remove the key
        lua_remove(L, 1); // remove the table
        (*wxlMethod->wxluacfuncs[0].lua_cfunc)(L);
    }
    else
    {
        lua_pushvalue(L, -2); // copy key
        lua_pushvalue(L, -2); // copy value
        lua_rawset(L, -5);    // set t[key] = value, pops key and value
    }

    return 0;
}

// ----------------------------------------------------------------------------
// Central function to call for overloaded functions
// ----------------------------------------------------------------------------

int LUACALL wxlua_callOverloadedFunction(lua_State* L)
{
    wxLuaBindMethod* wxlMethod = (wxLuaBindMethod *)lua_touserdata(L, lua_upvalueindex(1)); // lightuserdata
    wxCHECK_MSG(wxlMethod, 0, wxT("Invalid wxLuaBindMethod"));

    if ((wxlMethod->wxluacfuncs_n > 1) || (wxlMethod->basemethod))
        return wxlua_callOverloadedFunction(L, wxlMethod);
    else
        return (*wxlMethod->wxluacfuncs[0].lua_cfunc)(L);
}

int LUACALL wxlua_callOverloadedFunction(lua_State* L, struct wxLuaBindMethod* wxlMethod)
{
    // get number of arguments called from Lua
    int i, arg, arg_lua_count = lua_gettop(L);

    // only look at the methods that could possibly work and traverse base classes
    wxArrayPtrVoid cfuncArray;
    wxLuaBindMethod* method = wxlMethod;
    while (method)
    {
        wxLuaBindCFunc* wxlCFunc = method->wxluacfuncs;

        for (i = 0; i < method->wxluacfuncs_n; ++i, ++wxlCFunc)
        {
            if ((arg_lua_count >= wxlCFunc->minargs) &&
                (arg_lua_count <= wxlCFunc->maxargs))
            {
                cfuncArray.Add(wxlCFunc);
            }
        }

        method = method->basemethod;
    }

    wxLuaBindCFunc* bestCFunc = NULL; // stores the last function that worked.
    int invalid_lua_arg = 1; // arg that failed
    int cfunc_count = cfuncArray.GetCount();

    // Look at the available functions in parallel, per arg
    for (arg = 0; (arg < arg_lua_count) && (cfunc_count != 0); ++arg)
    {
        int arg_lua = arg+1; // arg N on the Lua stack
        int ltype = lua_type(L, arg_lua);

        for (i = 0; i < cfunc_count; ++i)
        {
            wxLuaBindCFunc* wxlCFunc = (wxLuaBindCFunc*)cfuncArray[i];
            bestCFunc = wxlCFunc;
            invalid_lua_arg = arg_lua;

            // does this method have any more arguments?
            if (!wxlCFunc->argtypes[arg])
            {
                cfuncArray.RemoveAt(i);
                cfunc_count--;
                i--;
                continue;
            }

            // get argument wxLua type
            int wxl_type = (int)*(wxlCFunc->argtypes[arg]);

            // Does the Lua type match the wxLua type
            int is_ok = wxlua_iswxluatype(ltype, wxl_type, L);

            // unknown/invalid standard wxLua type, check binding wxLua type
            if ((is_ok == -1) || ((is_ok == 0) && (wxl_type == WXLUA_TSTRING)))
            {
                is_ok = (wxluaT_isuserdatatype(L, arg_lua, wxl_type) ||
                        (wxl_type == wxluatype_NULL)) ? 1 : 0;
            }

            // this arg is not a match, remove this function as a possibility
            if (is_ok == 0)
            {
                cfuncArray.RemoveAt(i);
                cfunc_count--;
                i--;
                continue;
            }
        }
    }

    // Note that the top function is the one that is highest in the
    // derived functions from any baseclasses and should be the best choice.
    // Example is wxBookCtrlBaseEvent::GetSelection() and wxCommandEvent::GetSelection()
    if (cfunc_count > 0)
    {
        lua_CFunction lua_cfunc = ((wxLuaBindCFunc*)cfuncArray[0])->lua_cfunc;

        // successfully found overloaded function to handle wxLua call
        return (*lua_cfunc)(L);
    }

    // ----------------------------------------------------------------------
    // Did not find a suitable function to call, post error

    wxString fnCall = wxlua_getLuaArgsMsg(L, 1, arg_lua_count);

    wxString fnOverloadList = wxString::Format(wxT("Function called: '%s'\n"), fnCall.c_str());
    fnOverloadList += wxlua_getBindMethodArgsMsg(L, wxlMethod);

    wxString errmsg;

    if (cfunc_count > 1) // Note: we actually allow this.. for now
    {
        errmsg = wxT("wxLua: Function call is ambiguous.\nTry coercing values to proper types using tostring/number as appropriate.\n");
    }

    if (bestCFunc == NULL)
        errmsg += wxT("wxLua: Function call has invalid arguments.");
    else
    {
        // We have to count the methods that are displayed to find the one that failed
        // since we've skipped the ones with wrong number of args.
        method = wxlMethod;
        int i_cfunc = 0;
        bool found = false;
        while (method && !found)
        {
            for (i = 0; i < method->wxluacfuncs_n; ++i)
            {
                i_cfunc++;
                if (&method->wxluacfuncs[i] == bestCFunc)
                {
                    found = true;
                    break;
                }
            }

            method = method->basemethod;
        }

        errmsg += wxString::Format(wxT("wxLua: Function call has invalid argument %d on method %02d.\n"), invalid_lua_arg, i_cfunc);
    }

    errmsg += wxT("\n") + fnOverloadList;

    wxlua_error(L, errmsg.c_str());

    return 0;
}

wxString wxlua_getLuaArgsMsg(lua_State* L, int start_stack_idx, int end_stack_idx)
{
    lua_Debug ar = {0};

    // NOTE: We'd like to be able to give some info, however if we are not
    // running a Lua function the lua_Debug is empty and lua_getinfo() will panic.
    if (lua_getstack(L, 0, &ar) == 0) // returns 0 when called on a level greater than stack depth
        return wxT("?");

    lua_getinfo(L, "n", &ar);
    wxString funcName = lua2wx(ar.name);

    wxString funcCall = funcName + wxT("(");

    for (int arg = start_stack_idx; arg <= end_stack_idx; ++arg)
    {
        if (arg > start_stack_idx) funcCall += wxT(", ");

        funcCall += wxluaT_gettypename(L, arg);
    }
    funcCall += wxT(")");

    return funcCall;
}

wxString wxlua_getBindMethodArgsMsg(lua_State* L, struct wxLuaBindMethod* wxlMethod)
{
    wxCHECK_MSG(wxlMethod, wxEmptyString, wxT("Invalid method table"));

    wxString overloadMethods;

    int i_cfunc = 0; // count total number of overloads
    wxLuaBindMethod* method = wxlMethod;

    // traverse the methods down the baseclass methods if any
    while (method)
    {
        wxLuaBindCFunc* wxluacfuncs = method->wxluacfuncs;
        int i, arg, cfuncs_count = method->wxluacfuncs_n;

        const wxLuaBindClass* wxlClass = wxLuaBinding::FindBindClass(method);
        for (i = 0; i < cfuncs_count; ++i)
        {
            i_cfunc++;

            wxString className;
            if (wxlClass && !WXLUA_HASBIT(wxluacfuncs[i].method_type, WXLUAMETHOD_CONSTRUCTOR))
                className = lua2wx(wxlClass->name) + wxT(".");

            wxString funcStr = wxString::Format(wxT("%02d. %s%s("), i_cfunc, className.c_str(), lua2wx(method->name).c_str());

            for (arg = 0; arg < wxluacfuncs[i].maxargs; ++arg)
            {
                // optional args?
                if ((wxluacfuncs[i].minargs < wxluacfuncs[i].maxargs) && (arg == wxluacfuncs[i].minargs))
                {
                    if (arg > 0) funcStr += wxT(" ");
                    funcStr += wxT("[");
                }

                if (arg > 0)
                    funcStr += wxT(", ");

                int wxl_type = (int)*(wxluacfuncs[i].argtypes[arg]);
                funcStr += wxluaT_typename(L, wxl_type);

                if ((arg == 0) &&
                    !WXLUA_HASBIT(wxluacfuncs[i].method_type, WXLUAMETHOD_STATIC) &&
                    !WXLUA_HASBIT(wxluacfuncs[i].method_type, WXLUAMETHOD_CONSTRUCTOR) &&
                    !WXLUA_HASBIT(wxluacfuncs[i].method_type, WXLUAMETHOD_CFUNCTION))
                    funcStr += wxT("(self)");
            }

            // close optional args
            if (wxluacfuncs[i].minargs < wxluacfuncs[i].maxargs)
                funcStr += wxT("]");

            funcStr += wxT(")");

            if (WXLUA_HASBIT(wxluacfuncs[i].method_type, WXLUAMETHOD_STATIC))
                funcStr += wxT(" - static");

            if (overloadMethods.Length() > 0)
                overloadMethods += wxT("\n") + funcStr;
            else
                overloadMethods += funcStr;
        }

        method = method->basemethod;
    }

    return overloadMethods;
}

// ----------------------------------------------------------------------------
// Functions to compare binding structs using qsort and bsearch
// ----------------------------------------------------------------------------

// Function to compare to wxLuaBindEvents by eventType
int wxLuaBindEvent_CompareByEventTypeFn(const void *p1, const void *p2)
{
    return (*((const wxLuaBindEvent*)p1)->eventType) - (*((const wxLuaBindEvent*)p2)->eventType);
}
// Function to compare to wxLuaBindNumber by name
int wxLuaBindNumber_CompareByNameFn(const void *p1, const void *p2)
{
    return strcmp(((const wxLuaBindNumber*)p1)->name, ((const wxLuaBindNumber*)p2)->name);
}
// Function to compare to wxLuaBindStrings by name
int wxLuaBindString_CompareByNameFn(const void *p1, const void *p2)
{
    return strcmp(((const wxLuaBindString*)p1)->name, ((const wxLuaBindString*)p2)->name);
}
// Function to compare to wxLuaBindObjects by name
int wxLuaBindObject_CompareByNameFn(const void *p1, const void *p2)
{
    return strcmp(((const wxLuaBindObject*)p1)->name, ((const wxLuaBindObject*)p2)->name);
}
// Function to compare to wxLuaBindMethods by name
int wxLuaBindMethod_CompareByNameFnInit(const void *p1, const void *p2)
{
    int v = strcmp(((const wxLuaBindMethod*)p1)->name, ((const wxLuaBindMethod*)p2)->name);
    if (v == 0)
    {
        int t1 = ((const wxLuaBindMethod*)p1)->method_type;
        int t2 = ((const wxLuaBindMethod*)p2)->method_type;
        v = t1 - t2;
    }

    wxCHECK_MSG(v != 0, 0, wxT("Duplicate wxLuaBindMethod names and method_types"));

    return v;
}
// Function for wxLuaBinding::GetClassMethod()
int wxLuaBindMethod_CompareByNameFnGet(const void *p1, const void *p2)
{
    int v = strcmp(((const wxLuaBindMethod*)p1)->name, ((const wxLuaBindMethod*)p2)->name);
    if (v == 0)
    {
        int t1 = ((const wxLuaBindMethod*)p1)->method_type;
        int t2 = ((const wxLuaBindMethod*)p2)->method_type;

        if ((t1 & t2) != 0) return 0; // any matched bits will work

        v = t1 - t2;
    }

    return v;
}
// Function to compare the wxLuaBindClasses by name
int wxLuaBindClass_CompareByNameFn(const void *p1, const void *p2)
{
    return strcmp(((const wxLuaBindClass*)p1)->name, ((const wxLuaBindClass*)p2)->name);
}
// Function to compare the wxLuaBindClasses by wxluatype
int wxLuaBindClass_CompareBywxLuaTypeFn(const void *p1, const void *p2)
{
    return (*((const wxLuaBindClass*)p1)->wxluatype) - (*((const wxLuaBindClass*)p2)->wxluatype);
}

// ----------------------------------------------------------------------------
// wxLuaBinding
// ----------------------------------------------------------------------------

IMPLEMENT_ABSTRACT_CLASS(wxLuaBinding, wxObject)

wxLuaBindingArray wxLuaBinding::sm_bindingArray;
int wxLuaBinding::sm_bindingArray_initialized = 0;
int wxLuaBinding::sm_wxluatype_max = WXLUA_T_MAX+1; // highest wxLua type initially

wxLuaBinding::wxLuaBinding()
             :m_classCount(0),    m_classArray(NULL),
              m_numberCount(0),   m_numberArray(NULL),
              m_stringCount(0),   m_stringArray(NULL),
              m_eventCount(0),    m_eventArray(NULL),
              m_objectCount(0),   m_objectArray(NULL),
              m_functionCount(0), m_functionArray(NULL),
              m_first_wxluatype(WXLUA_TUNKNOWN),
              m_last_wxluatype(WXLUA_TUNKNOWN)
{
}

void wxLuaBinding::InitBinding()
{
    // Sort all the bindings by something useful for faster lookup later

    if (m_classArray && (m_classCount > 0))
    {
        // initialize types only once, we don't need to resort them either
        if (*m_classArray[0].wxluatype != WXLUA_TUNKNOWN)
            return;

        qsort(m_classArray, m_classCount, sizeof(wxLuaBindClass), wxLuaBindClass_CompareByNameFn);

        wxLuaBindClass* wxlClass = m_classArray;
        for (size_t i = 0; i < m_classCount; ++i, ++wxlClass)
        {
            *wxlClass->wxluatype = ++wxLuaBinding::sm_wxluatype_max;

            // Also sort the member functions for each class
            if (wxlClass->wxluamethods && (wxlClass->wxluamethods_n > 0))
                qsort(wxlClass->wxluamethods, wxlClass->wxluamethods_n, sizeof(wxLuaBindMethod), wxLuaBindMethod_CompareByNameFnInit);
            // And their enums
            if (wxlClass->enums && (wxlClass->enums_n > 0))
                qsort(wxlClass->enums, wxlClass->enums_n, sizeof(wxLuaBindNumber), wxLuaBindNumber_CompareByNameFn);
        }

        // these mark what types numbers are declared in this binding
        m_first_wxluatype = *m_classArray[0].wxluatype;
        m_last_wxluatype  = *m_classArray[m_classCount-1].wxluatype;
    }

    if (m_numberArray && (m_numberCount > 0))
        qsort(m_numberArray, m_numberCount, sizeof(wxLuaBindNumber), wxLuaBindNumber_CompareByNameFn);

    if (m_stringArray && (m_stringCount > 0))
        qsort(m_stringArray, m_stringCount, sizeof(wxLuaBindString), wxLuaBindString_CompareByNameFn);

    // sort by event type for fastest lookup
    if (m_eventArray && (m_eventCount > 0))
        qsort(m_eventArray, m_eventCount, sizeof(wxLuaBindEvent), wxLuaBindEvent_CompareByEventTypeFn);

    if (m_objectArray && (m_objectCount > 0))
        qsort(m_objectArray, m_objectCount, sizeof(wxLuaBindObject), wxLuaBindObject_CompareByNameFn);
}

// static
bool wxLuaBinding::RegisterBindings(const wxLuaState& wxlState)
{
    wxCHECK_MSG(wxlState.Ok(), false, wxT("Invalid wxLuaState"));

    lua_State *L = wxlState.GetLuaState();
    size_t n, binding_count = sm_bindingArray.GetCount();

    wxLuaBinding::InitAllBindings(); // only runs the first time through

    for (n = 0; n < binding_count; ++n)
    {
        sm_bindingArray[n]->RegisterBinding(wxlState);
        lua_pop(L, 1); // pop the Lua table the binding was installed into
    }

    return true;
}

bool wxLuaBinding::RegisterBinding(const wxLuaState& wxlState)
{
    wxCHECK_MSG(wxlState.Ok(), false, wxT("Invalid wxLuaState"));
    lua_State *L = wxlState.GetLuaState();

    // Let Lua create a new table for us and add it to these places.
    // We use an empty luaL_Reg since we just want luaL_register to create the
    // tables for us, but we want to install the elements ourselves since
    // wxLua is too large to follow the luaL_register method without being
    // wasteful of memory and slow down the initialization.
    //    LUA_REGISTRYINDEX["_LOADED"][m_nameSpace] = table
    //    LUA_GLOBALSINDEX[m_nameSpace] = table
    //    LUA_GLOBALSINDEX["package"]["loaded"][m_nameSpace] = table
    static const luaL_Reg wxlualib[] = { {NULL, NULL} };

    wxLuaState::luaL_Register(L, wx2lua(m_nameSpace), wxlualib);

    // luaL_register should have given an error message about why it couldn't
    // create the table for us
    if (!lua_istable(L, -1))
    {
        lua_pop(L, 1); // pop the nil value
        return false;
    }

    // Find a registered binding with the same namespace, if any,
    // and share the table with that of the previously loaded binding
    int luaTable_ref = -1;

    lua_pushlightuserdata(L, &wxlua_lreg_wxluabindings_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX);   // pop key, push value (the bindings table)

    lua_pushnil(L);
    while (lua_next(L, -2) != 0)
    {
        // value = -1, key = -2, table = -3
        wxLuaBinding* binding = (wxLuaBinding*)lua_touserdata(L, -2);

        if (binding->GetLuaNamespace() == m_nameSpace)
        {
            luaTable_ref = (int)lua_tonumber(L, -1);
            lua_pop(L, 2); // pop key and value
            break;
        }

        lua_pop(L, 1); // pop value, lua_next will pop key at end
    }

    lua_pop(L, 1); // pop table


    // first time adding this namespace table
    if (luaTable_ref < 1)
    {
        // create a ref for the wxLua table we're filling
        luaTable_ref = wxluaR_ref(L, -1, &wxlua_lreg_refs_key);
    }

    // Add us to the LUA_REGISTRYINDEX table of bindings
    lua_pushlightuserdata(L, &wxlua_lreg_wxluabindings_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX); // pop key, push value (the bindings table)

    lua_pushlightuserdata(L, this);  // push key
    lua_pushnumber(L, luaTable_ref); // push value
    lua_rawset(L, -3);               // set t[key] = value; pop key and value
    lua_pop(L, 1);                   // pop table

    // register all our classes etc. in the wxLua table
    DoRegisterBinding(wxlState);

    return true;
}

void wxLuaBinding::DoRegisterBinding(const wxLuaState& wxlState) const
{
    wxCHECK_RET(wxlState.Ok(), wxT("Invalid wxLuaState"));
    lua_State *L = wxlState.GetLuaState();

    size_t n;

    // install the classes, functions and methods, creating new wxLua types
    // if this is the first time we're registering them
    const wxLuaBindClass *wxlClass = m_classArray;
    for (n = 0; n < m_classCount; ++n, ++wxlClass)
    {
        InstallClassMetatable(L, wxlClass);
        InstallClass(L, wxlClass);
    }

    // register the global C style functions
    const wxLuaBindMethod* wxlMethod = m_functionArray;
    for (n = 0; n < m_functionCount; ++n, ++wxlMethod)
    {
        lua_pushstring(L, wxlMethod->name);
        lua_pushlightuserdata(L, (void*)wxlMethod);
        lua_pushcclosure(L, wxlMethod->wxluacfuncs[0].lua_cfunc, 1);
        lua_rawset(L, -3);
    }

    // install the numerical definitions
    const wxLuaBindNumber* wxlNumber = m_numberArray;
    for (n = 0; n < m_numberCount; ++n, ++wxlNumber)
    {
        lua_pushstring(L, wxlNumber->name);
        lua_pushnumber(L, wxlNumber->value);
        lua_rawset(L, -3);
    }

    // install the strings
    const wxLuaBindString *wxlString = m_stringArray;
    for (n = 0; n < m_stringCount; ++n, ++wxlString)
    {
        lua_pushstring(L, wxlString->name);
        if (wxlString->wxchar_string != NULL)
            lua_pushstring(L, wx2lua(wxlString->wxchar_string));
        else
            lua_pushstring(L, wxlString->c_string);
        lua_rawset(L, -3);
    }

    // install the objects and pointers
    const wxLuaBindObject *wxlObject = m_objectArray;
    for (n = 0; n < m_objectCount; ++n, ++wxlObject)
    {
        lua_pushstring(L, wxlObject->name);

        if (wxlObject->objPtr != 0)
            wxluaT_pushuserdatatype(L, wxlObject->objPtr, *wxlObject->wxluatype, true);
        else
            wxluaT_pushuserdatatype(L, *wxlObject->pObjPtr, *wxlObject->wxluatype, true);

        lua_rawset(L, -3);
    }

    // register the wxEvent types
    const wxLuaBindEvent *wxlEvent = m_eventArray;
    for (n = 0; n < m_eventCount; ++n, ++wxlEvent)
    {
        lua_pushstring(L, wxlEvent->name);
        lua_pushnumber(L, *wxlEvent->eventType);
        lua_rawset(L, -3);
    }
}

/* static */
bool wxLuaBinding::InstallClassMetatable(lua_State* L, const wxLuaBindClass* wxlClass)
{
    // Replace the metatable functions for the classes we push into Lua
    static const luaL_Reg s_funcTable[] =
    {
        {"__gc",       wxlua_wxLuaBindClass__gc },
        {"__index",    wxlua_wxLuaBindClass__index },
        {"__newindex", wxlua_wxLuaBindClass__newindex },
        {"__tostring", wxlua_wxLuaBindClass__tostring }
    };
    static const size_t s_funcCount = sizeof(s_funcTable)/sizeof(s_funcTable[0]);

    // ------------------------------------------------------------------
    // Add to the lookup table for "class name" to wxLuaBindClass struct
    lua_pushlightuserdata(L, &wxlua_lreg_classes_key);
    lua_rawget(L, LUA_REGISTRYINDEX);           // pop key, push result (the classes table)
    lua_pushstring(L, wxlClass->name);          // push key
    lua_pushlightuserdata(L, (void *)wxlClass); // push value
    lua_rawset(L, -3);                          // set t[key] = value, pops key and value
    lua_pop(L, 1);                              // pop wxlua_lreg_classes_key table

    // ------------------------------------------------------------------
    // Create a new metatable for this class with a numerical wxLua type index

    int wxl_type = *wxlClass->wxluatype;

    // we may be reregistering this binding, get the old metatable, we'll rewrite it
    if (!wxluaT_getmetatable(L, wxl_type))
        wxluaT_newmetatable(L, wxl_type); // create metatable, is on top of stack

    // store a lookup in the class metatable to the wxLuaBindClass struct
    lua_pushlightuserdata(L, &wxlua_metatable_wxluabindclass_key); // push key
    lua_pushlightuserdata(L, (void *)wxlClass);                    // push value
    lua_rawset(L, -3); // set t[key] = value, pops key and value

    // set the functions for the class in the metatable
    for (size_t i_func = 0; i_func < s_funcCount; ++i_func)
    {
        lua_pushstring(L, s_funcTable[i_func].name);      // push method name
        lua_pushlightuserdata(L, (void *)wxlClass);       // push the userdata
        lua_pushcclosure(L, s_funcTable[i_func].func, 1); // push func with wxlClass as upvalue
        lua_rawset(L, -3);  // t["method_name"] = closure of func and upvalues
    }

    lua_pop(L, 1); // pop metatable from wxluaT_newmetatable()

    return true;
}

/* static */
bool wxLuaBinding::InstallClass(lua_State* L, const wxLuaBindClass* wxlClass)
{
    // ------------------------------------------------------------------
    // Create and install the table for the class

    lua_pushstring(L, wxlClass->name); // push key
    lua_newtable(L);                   // push value, the table we use as the class

    // Install the member enums for the classname table
    for (int i_enum = 0; i_enum < wxlClass->enums_n; ++i_enum)
    {
        lua_pushstring(L, wxlClass->enums[i_enum].name);
        lua_pushnumber(L, wxlClass->enums[i_enum].value);
        lua_rawset(L, -3);
    }

    int method_count = wxlClass->wxluamethods_n;

    // Install the static functions for the classname table
    wxLuaBindMethod *wxlMethod = wxlClass->wxluamethods;
    for (int i_static_method = 0; i_static_method < method_count; ++i_static_method, ++wxlMethod)
    {
        // we will handle the WXLUAMETHOD_GET/SETPROP|WXLUAMETHOD_STATIC using __index and __newindex
        if (((wxlMethod->method_type & (WXLUAMETHOD_METHOD|WXLUAMETHOD_STATIC)) == (WXLUAMETHOD_METHOD|WXLUAMETHOD_STATIC)) &&
            (wxlMethod->wxluacfuncs_n > 0))
        {
            lua_pushstring(L, wxlMethod->name);
            lua_pushlightuserdata(L, wxlMethod);
            if (wxlMethod->wxluacfuncs_n > 1)
                lua_pushcclosure(L, wxlua_callOverloadedFunction, 1);
            else
                lua_pushcclosure(L, wxlMethod->wxluacfuncs[0].lua_cfunc, 1);

            lua_rawset(L, -3);
        }
    }

    // Create a metatable for the "class" table
    lua_newtable(L);
        lua_pushlstring(L, "__index", 7);
        lua_pushlightuserdata(L, (void*)wxlClass);
        lua_pushcclosure(L, wxlua_wxLuaBindMethod_table__index, 1);
        lua_rawset(L, -3);

        lua_pushlstring(L, "__newindex", 10);
        lua_pushlightuserdata(L, (void*)wxlClass);
        lua_pushcclosure(L, wxlua_wxLuaBindMethod_table__newindex, 1);
        lua_rawset(L, -3);

        //lua_pushstring(L, "__metatable");
        //lua_pushstring(L, "Metatable is not accessible");
        //lua_rawset(L, -3);
    lua_setmetatable(L, -2); // pops the metatable

    // Finalize the class table since we may not have a constructor
    // or have multiple constructors.
    lua_rawset(L, -3); // set t[key] = value, pops key and value

    // ------------------------------------------------------------------
    // Install public functions like constructors or global functions
    wxlMethod = wxlClass->wxluamethods;
    for (int i_method = 0; i_method < method_count; ++i_method, ++wxlMethod)
    {
        if (WXLUA_HASBIT(wxlMethod->method_type, WXLUAMETHOD_CONSTRUCTOR | WXLUAMETHOD_CFUNCTION) && wxlMethod->wxluacfuncs_n)
        {
            // push name of nested table and create the table or use existing
            // we do it this way since we can have multiple constructors (renamed)
            // that are of the same class and so they share the same wxLua type.
            lua_pushstring(L, wxlMethod->name);

            if (strcmp(wxlMethod->name, wxlClass->name) != 0)
                lua_newtable(L);
            else
                lua_getfield(L, -2, wxlMethod->name);

            // add the items to the table as t[first pushed] = second pushed
            lua_pushlstring(L, "new", 3);
            lua_pushlightuserdata(L, wxlMethod);
            lua_pushcclosure(L, wxlua_callOverloadedFunction, 1);
            lua_rawset(L, -3);

            // Add __call to the metatable for this table
            bool has_meta = (lua_getmetatable(L, -1) != 0);
            if (!has_meta) lua_newtable(L);

                lua_pushlstring(L, "__call", 6);
                lua_pushlightuserdata(L, wxlMethod);
                lua_pushcclosure(L, wxlua_wxLuaBindMethod_table__call, 1);
                lua_rawset(L, -3);

                //lua_pushstring(L, "__metatable");
                //lua_pushstring(L, "Metatable is not accessible");
                //lua_rawset(L, -3);

            if (!has_meta)
                lua_setmetatable(L, -2);
            else
                lua_pop(L, 1);

            // add table to the binding table t[wxlMethod->name] = { this table }
            lua_rawset(L, -3); // set t[key] = value, pops key and value
        }
    }

    return true;
}

// ---------------------------------------------------------------------------

const wxLuaBindEvent* wxLuaBinding::GetBindEvent(wxEventType eventType_) const
{
    const wxEventType eventType = eventType_;
    wxLuaBindEvent eventItem = { "", &eventType, NULL };

    const wxLuaBindEvent *pLuaEvent = (wxLuaBindEvent *)bsearch(&eventItem,
                                                    m_eventArray,
                                                    m_eventCount,
                                                    sizeof(wxLuaBindEvent),
                                                    wxLuaBindEvent_CompareByEventTypeFn);
    return pLuaEvent;
}

wxString wxLuaBinding::GetEventTypeName(wxEventType eventType) const
{
    const wxLuaBindEvent* wxlEvent = GetBindEvent(eventType);
    return (wxlEvent != NULL) ? lua2wx(wxlEvent->name) : wxString();
}

const wxLuaBindClass* wxLuaBinding::GetBindClass(int wxluatype_) const
{
    int wxluatype = wxluatype_; // create a local var to get the address of
    wxLuaBindClass classItem = { 0, 0, 0, 0, &wxluatype, 0, 0, 0, 0 };

    // this relies on LUA allocating the wxLua types in ascending order of definition
    // if LUA stops doing this, then the search may break. Note that we initially
    // sort the classes by name then allocate types in acending order.
    const wxLuaBindClass *wxlClass = (wxLuaBindClass *)bsearch(&classItem,
                                                       m_classArray,
                                                       m_classCount,
                                                       sizeof(wxLuaBindClass),
                                                       wxLuaBindClass_CompareBywxLuaTypeFn);

    return wxlClass;
}

const wxLuaBindClass* wxLuaBinding::GetBindClass(const char* className) const
{
    wxLuaBindClass classItem = { className, 0, 0, 0, 0, 0, 0, 0, 0 };

    const wxLuaBindClass *wxlClass = (wxLuaBindClass *)bsearch(&classItem,
                                                       m_classArray,
                                                       m_classCount,
                                                       sizeof(wxLuaBindClass),
                                                       wxLuaBindClass_CompareByNameFn);

    return wxlClass;
}

const wxLuaBindClass* wxLuaBinding::GetBindClass(const wxLuaBindMethod* wxlMethod_tofind) const
{
    size_t c, m, methods_n;
    wxLuaBindClass*  wxlClass  = m_classArray;
    wxLuaBindMethod* wxlMethod = NULL;

    for (c = 0; c < m_classCount; ++c, ++wxlClass)
    {
        wxlMethod = wxlClass->wxluamethods;
        methods_n = wxlClass->wxluamethods_n;

        for (m = 0; m < methods_n; ++m, ++wxlMethod)
        {
            if (wxlMethod == wxlMethod_tofind)
                return wxlClass;
        }
    }

    return NULL;
}

const wxLuaBindClass* wxLuaBinding::GetBindClass(const wxLuaBindCFunc* wxlCFunc_tofind) const
{
    size_t c, m, f, methods_n, funcs_n;
    wxLuaBindClass*  wxlClass  = m_classArray;
    wxLuaBindMethod* wxlMethod = NULL;
    wxLuaBindCFunc*  wxlCFunc  = NULL;

    for (c = 0; c < m_classCount; ++c, ++wxlClass)
    {
        wxlMethod = wxlClass->wxluamethods;
        methods_n = wxlClass->wxluamethods_n;

        for (m = 0; m < methods_n; ++m, ++wxlMethod)
        {
            wxlCFunc = wxlMethod->wxluacfuncs;
            funcs_n  = wxlMethod->wxluacfuncs_n;

            for (f = 0; f < funcs_n; ++f, ++wxlCFunc)
            {
                if (wxlCFunc == wxlCFunc_tofind)
                    return wxlClass;
            }
        }
    }

    return NULL;
}

// --------------------------------------------------------------------------

// static
wxLuaBinding* wxLuaBinding::GetLuaBinding(const wxString& bindingName)
{
    size_t i, binding_count = sm_bindingArray.GetCount();

    for (i = 0; i < binding_count; ++i)
    {
        if (sm_bindingArray[i]->GetBindingName() == bindingName)
            return sm_bindingArray[i];
    }

    return NULL;
}

// static
const wxLuaBindClass* wxLuaBinding::FindBindClass(const char* className)
{
    size_t i, binding_count = sm_bindingArray.GetCount();

    for (i = 0; i < binding_count; ++i)
    {
        const wxLuaBindClass* wxlClass = sm_bindingArray[i]->GetBindClass(className);

        if (wxlClass)
            return wxlClass;
    }

    return NULL;
}

// static
const wxLuaBindClass* wxLuaBinding::FindBindClass(int wxluatype)
{
    size_t i, binding_count = sm_bindingArray.GetCount();

    for (i = 0; i < binding_count; ++i)
    {
        const wxLuaBindClass* wxlClass = sm_bindingArray[i]->GetBindClass(wxluatype);

        if (wxlClass)
            return wxlClass;
    }

    return NULL;
}

// static
const wxLuaBindClass* wxLuaBinding::FindBindClass(const wxLuaBindMethod* wxlMethod)
{
    size_t i, binding_count = sm_bindingArray.GetCount();

    for (i = 0; i < binding_count; ++i)
    {
        const wxLuaBindClass* wxlClass = sm_bindingArray[i]->GetBindClass(wxlMethod);

        if (wxlClass)
            return wxlClass;
    }

    return NULL;
}

// static
const wxLuaBindClass* wxLuaBinding::FindBindClass(const wxLuaBindCFunc* wxlCFunc)
{
    size_t i, binding_count = sm_bindingArray.GetCount();

    for (i = 0; i < binding_count; ++i)
    {
        const wxLuaBindClass* wxlClass = sm_bindingArray[i]->GetBindClass(wxlCFunc);

        if (wxlClass)
            return wxlClass;
    }

    return NULL;
}

// static
const wxLuaBindEvent* wxLuaBinding::FindBindEvent(wxEventType eventType)
{
    size_t i, binding_count = sm_bindingArray.GetCount();

    for (i = 0; i < binding_count; ++i)
    {
        const wxLuaBindEvent* wxlEvent = sm_bindingArray[i]->GetBindEvent(eventType);

        if (wxlEvent)
            return wxlEvent;
    }

    return NULL;
}

// static
wxLuaBinding* wxLuaBinding::FindMethodBinding(const wxLuaBindMethod* wxlMethod)
{
    size_t i, binding_count = sm_bindingArray.GetCount();

    for (i = 0; i < binding_count; ++i)
    {
        size_t j, fn_count = sm_bindingArray[i]->GetFunctionCount();
        wxLuaBindMethod* m = sm_bindingArray[i]->GetFunctionArray();

        for (j = 0; j < fn_count; ++j, ++m)
        {
            if (m == wxlMethod)
                return sm_bindingArray[i];
        }
    }

    return NULL;
}


// --------------------------------------------------------------------------

// static
wxLuaBindMethod* wxLuaBinding::GetClassMethod(const wxLuaBindClass *wxlClass, const char *methodName, int method_type, bool search_baseclasses)
{
    wxCHECK_MSG(wxlClass, NULL, wxT("Invalid wxLuaBindClass to find method from."));

    wxLuaBindMethod methodItem = { methodName, method_type, 0, 0, 0 };

    wxLuaBindMethod *wxlMethod = (wxLuaBindMethod *)bsearch(&methodItem,
                                                       wxlClass->wxluamethods,
                                                       wxlClass->wxluamethods_n,
                                                       sizeof(wxLuaBindMethod),
                                                       wxLuaBindMethod_CompareByNameFnGet);

    if ((wxlMethod == NULL) && search_baseclasses && wxlClass->baseclassNames)
    {
        for (size_t i = 0; wxlClass->baseclassNames[i]; ++i)
        {
            // The class may not have been installed
            if (wxlClass->baseBindClasses[i])
            {
                wxlMethod = GetClassMethod(wxlClass->baseBindClasses[i], methodName, method_type, search_baseclasses);
                if (wxlMethod != NULL)
                    return wxlMethod;
            }
        }
    }

    return wxlMethod;
}

// --------------------------------------------------------------------------

// static
void wxLuaBinding::InitAllBindings(bool force_update)
{
    size_t n, i, j, k, binding_count = sm_bindingArray.GetCount();

    // update if a binding was added or removed
    if (((size_t)sm_bindingArray_initialized == binding_count) && !force_update)
        return;

    // set the base class wxLuaBindClass* using the base class names of the parent wxLuaBindClass
    for (n = 0; n < binding_count; ++n)
    {
        wxLuaBindClass* wxlClass = sm_bindingArray[n]->GetClassArray();
        size_t class_count       = sm_bindingArray[n]->GetClassCount();

        for (i = 0; i < class_count; ++i, ++wxlClass)
        {
            if (wxlClass->baseclassNames) // does it have any base classes at all?
            {
                // find the base class using their names in the bindings
                for (j = 0; wxlClass->baseclassNames[j]; ++j)
                {
                    wxLuaBindClass* wxlBaseClass = (wxLuaBindClass*)wxLuaBinding::FindBindClass(wxlClass->baseclassNames[j]);
                    if (wxlBaseClass)
                        wxlClass->baseBindClasses[j] = wxlBaseClass;
                }
            }
        }
    }

    // Link together all of the class member functions with base class functions
    // with the same name so the overloads work for them too.
    for (n = 0; n < binding_count; ++n)
    {
        wxLuaBindClass* wxlClass = sm_bindingArray[n]->GetClassArray();
        size_t i, class_count    = sm_bindingArray[n]->GetClassCount();

        for (i = 0; i < class_count; ++i, ++wxlClass)
        {
            if (wxlClass->baseclassNames) // does it have any base classes at all?
            {
                wxLuaBindMethod *wxlMethod = wxlClass->wxluamethods;
                size_t method_count        = wxlClass->wxluamethods_n;

                for (j = 0; j < method_count; ++j, ++wxlMethod)
                {
                    if (wxlClass->baseclassNames && !WXLUA_HASBIT(wxlMethod->method_type, WXLUAMETHOD_DELETE))
                    {
                        // Use the baseclassNames to check for terminating NULL
                        for (k = 0; wxlClass->baseclassNames[k]; ++k)
                        {
                            // Note that these may be NULL if the lib/module containing them wasn't loaded
                            wxLuaBindClass *baseClass = wxlClass->baseBindClasses[k];
                            if (baseClass != NULL)
                            {
                                wxLuaBindMethod* baseMethod = wxLuaBinding::GetClassMethod(baseClass, wxlMethod->name, WXLUAMETHOD_MASK, true);
                                if (baseMethod)
                                {
                                    // don't link to base class delete functions
                                    if (!WXLUA_HASBIT(baseMethod->method_type, WXLUAMETHOD_DELETE))
                                        wxlMethod->basemethod = baseMethod;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    sm_bindingArray_initialized = binding_count;
}
