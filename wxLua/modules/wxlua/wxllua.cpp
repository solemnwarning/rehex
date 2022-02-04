/////////////////////////////////////////////////////////////////////////////
// Name:        wxlstate.cpp
// Purpose:     wxLuaState, a wxWidgets interface to Lua
// Author:      Ray Gilbert, John Labenski, J Winwood (Reuben Thomas for bitlib at bottom)
// Created:     14/11/2001
// Copyright:   (c) 2012 John Labenski, 2001-2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx/wx.h"
#include <wx/wxprec.h>

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

// for all others, include the necessary headers
#ifndef WX_PRECOMP
    #include <wx/wx.h>
#endif

#include "wxlua/wxllua.h"
#include "wxlua/wxlstate.h"
#include "wxlua/wxlbind.h"
#include "wxlua/wxlcallb.h"

//#include "wxluadebug/include/wxldebug.h" // for debugging only

const char* wxlua_lreg_regtable_key            = "wxlua_lreg_regtable_key : wxLua LUA_REGISTRYINDEX tables";

const char* wxlua_lreg_wxluastate_key          = "wxlua_lreg_wxluastate_key : wxLuaState";
const char* wxlua_lreg_wxluastatedata_key      = "wxlua_lreg_wxluastatedata_key : wxLuaStateData";

const char* wxlua_lreg_wxluabindings_key       = "wxlua_lreg_wxluabindings_key : wxLuaBindings installed";
const char* wxlua_lreg_classes_key             = "wxlua_lreg_classes_key : wxLuaBindClass structs installed";
const char* wxlua_lreg_types_key               = "wxlua_lreg_types_key : wxLua metatable class types";

const char* wxlua_lreg_weakobjects_key         = "wxlua_lreg_weakobjects_key : wxLua objects pushed";
const char* wxlua_lreg_gcobjects_key           = "wxlua_lreg_gcobjects_key : wxLua gc objects to delete";
const char* wxlua_lreg_derivedmethods_key      = "wxlua_lreg_derivedmethods_key : wxLua derived class methods";
const char* wxlua_lreg_evtcallbacks_key        = "wxlua_lreg_evtcallbacks_key : wxLuaEventCallbacks";
const char* wxlua_lreg_windestroycallbacks_key = "wxlua_lreg_windestroycallbacks_key : wxLuaWinDestoyCallbacks";
const char* wxlua_lreg_topwindows_key          = "wxlua_lreg_topwindows_key : wxLua top level wxWindows";
const char* wxlua_lreg_wxeventtype_key         = "wxlua_lreg_wxeventtype_key : wxLua wxEventType";
const char* wxlua_lreg_callbaseclassfunc_key   = "wxlua_lreg_callbaseclassfunc_key : wxLua CallBaseClassFunc";

const char* wxlua_lreg_refs_key                = "wxlua_lreg_refs_key : wxLua Lua object refs";
const char* wxlua_lreg_debug_refs_key          = "wxlua_lreg_debug_refs_key : wxLuaDebugData refs";

const char* wxlua_metatable_type_key           = "wxlua_metatable_type_key : wxLua metatable class type";
const char* wxlua_metatable_wxluabindclass_key = "wxlua_metatable_wxluabindclass_key : wxLua metatable wxLuaBindClass";

// ----------------------------------------------------------------------------

void wxlua_lreg_createtable(lua_State* L, void* lightuserdata_reg_key, int narr, int nrec)
{
    // clear the old ref to the table, even though it's weak kv
    // it doesn't get cleared until the gc runs
    lua_pushlightuserdata(L, &wxlua_lreg_regtable_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                   // get table
      lua_pushlightuserdata(L, lightuserdata_reg_key);  // push key
      lua_rawget(L, LUA_REGISTRYINDEX);                 // get table or nil
      if (lua_istable(L, -1))
      {
          lua_pushnil(L);                               // push value
          lua_rawset(L, -3);                            // clear t[key] = nil
          lua_pop(L, 1);                                // pop wxlua_lreg_regtable_key table
      }
      else
        lua_pop(L, 2); // pop nil and wxlua_lreg_regtable_key table

    // Add new LUA_REGISTRYINDEX[&wxlua_lreg_regtable_key][lightuserdata_reg_key table] = lightuserdata_reg_key
    lua_pushlightuserdata(L, lightuserdata_reg_key); // push key
    lua_createtable(L, narr, nrec);                  // push value
        lua_pushlightuserdata(L, &wxlua_lreg_regtable_key); // push key
        lua_rawget(L, LUA_REGISTRYINDEX);                   // get wxlua_lreg_regtable_key table
        lua_pushvalue(L, -2);    // push key (copy of the new table)
        lua_pushvalue(L, -4);    // push value (copy of lightuserdata key)
        lua_rawset(L, -3);       // set t[key] = value; pops key and value
        lua_pop(L, 1);           // pop wxlua_lreg_regtable_key table
    lua_rawset(L, LUA_REGISTRYINDEX); // set the value
}

// ----------------------------------------------------------------------------
// Lua helper functions
// ----------------------------------------------------------------------------

wxString wxlua_LUA_ERR_msg(int LUA_ERRx)
{
    switch (LUA_ERRx)
    {
        case 0             : return wxEmptyString;
        case LUA_YIELD     : return wxT("Lua: Thread is suspended");
        case LUA_ERRRUN    : return wxT("Lua: Error while running chunk");
        case LUA_ERRSYNTAX : return wxT("Lua: Syntax error during pre-compilation");
        case LUA_ERRMEM    : return wxT("Lua: Memory allocation error");
        case LUA_ERRERR    : return wxT("Lua: Generic error or an error occurred while running the error handler");
        case LUA_ERRFILE   : return wxT("Lua: Error occurred while opening file");
    }

    return wxT("Lua: Unknown LUA_ERRx error value");
}

bool wxlua_errorinfo(lua_State* L, int status, int top, wxString* errorMsg_, int* line_num_)
{
    if (status == 0)
        return false;

    int newtop = lua_gettop(L);

    wxString errorMsg = wxlua_LUA_ERR_msg(status);

    switch(status)
    {
        case LUA_ERRMEM:
        case LUA_ERRERR:
        {
            if (newtop > top)
                errorMsg += wxT("\n");
            break;
        }
        case LUA_ERRRUN:
        case LUA_ERRFILE:
        case LUA_ERRSYNTAX:
        default:
        {
            if (newtop > top)
                errorMsg += wxT("\n") + lua2wx(lua_tostring(L, -1));
            break;
        }
    }

    errorMsg += wxT("\n");

    // Why can't I fill a lua_Debug here? Try to get the line number
    // by parsing the error message that looks like this, 3 is linenumber
    // [string "a = 1("]:3: unexpected symbol near `<eof>'
    wxString lineStr = errorMsg;
    long line_num = -1;
    while(!lineStr.IsEmpty())
    {
        // search through the str to find ']:LONG:' pattern
        lineStr = lineStr.AfterFirst(wxT(']'));
        if ((lineStr.Length() > 0) && (lineStr.GetChar(0) == wxT(':')))
        {
            lineStr = lineStr.AfterFirst(wxT(':'));
            if (lineStr.IsEmpty() || lineStr.BeforeFirst(wxT(':')).ToLong(&line_num))
                break;
        }
    }

    lua_settop(L, top); // pops the message if any

    if (errorMsg_) *errorMsg_ = errorMsg;
    if (line_num_) *line_num_ = (int)line_num;

    return true;
}

void LUACALL wxlua_error(lua_State *L, const char *errorMsg)
{
    // Use luaL_error(L, s) and not "lua_pushstring(L, s); lua_error(L)" since
    // luaL_error() provides the file and line number too.
    luaL_error(L, "%s", errorMsg);
}

void LUACALL wxlua_argerror(lua_State *L, int stack_idx, const wxString& expectedType)
{
    wxString argType = wxlua_luaL_typename(L, stack_idx);

    wxString msg(wxString::Format(_("wxLua: Expected %s for parameter %d, but got a '%s'."),
                                    expectedType.c_str(), stack_idx, argType.c_str()));

    wxlua_argerrormsg(L, msg);
}

void LUACALL wxlua_argerrormsg(lua_State *L, const wxString& msg_)
{
    wxString funcArgs(wxT("\n"));
    wxString argMsg  = wxlua_getLuaArgsMsg(L, 1, lua_gettop(L));

    wxLuaBindMethod* wxlMethod = (wxLuaBindMethod *)lua_touserdata(L, lua_upvalueindex(1)); // lightuserdata
    if (wxlMethod != NULL)
    {
        // Guarantee that this is a wxLuaBindMethod of ours so we don't crash.
        // Since we're going to error out we don't have to be quick about it.

        // check if this method is part of a class
        const wxLuaBindClass* wxlClass = wxLuaBinding::FindBindClass(wxlMethod);

        // if not, check if it's a global C style function
        wxLuaBinding* binding = NULL;
        if (wxlClass == NULL)
            binding = wxLuaBinding::FindMethodBinding(wxlMethod);

        if ((wxlClass != NULL) || (binding != NULL))
            funcArgs += wxlua_getBindMethodArgsMsg(L, wxlMethod);
    }

    wxString msg;
    msg.Printf(wxT("%s\nFunction called: '%s'%s"), msg_.c_str(), argMsg.c_str(), funcArgs.c_str());
    wxlua_error(L, msg.c_str());
}

void* LUACALL wxlua_touserdata(lua_State *L, int stack_idx, bool null_ptr /*= false*/)
{
    if (lua_islightuserdata(L, stack_idx) != 0)
    {
        // can't NULL the ptr, just return the lightuserdata as is
        return lua_touserdata(L, stack_idx);
    }

    void *pdata = NULL;
    void **ptr = (void **)lua_touserdata(L, stack_idx);

    if (ptr != NULL)
    {
        pdata = *ptr;       // get the pointer the userdata holds
        if (null_ptr)       // NULL ptr so Lua won't try to gc it
            *ptr = NULL;
    }

    return pdata;
}

// ----------------------------------------------------------------------------
// wxluaR_XXX - functions operate on tables in Lua's LUA_REGISTRYINDEX
// ----------------------------------------------------------------------------

#define ABS_LUA_STKIDX(n, added_items) ((n) > 0 ? (n) : (n)-(added_items))

// Note about luaL_ref() and luaL_unref().
// ref creates integer numbers from 1 to ...
// unref uses t[0] to hold the last unused reference and when you call unref
// again the next unused ref points back to the first and t[0] points to the
// last unrefed key.
// eg. create 5 refs, get refs 1,2,3,4,5, then call unref on 3 then 4 then
//     call ref 3 times and the new references will be 4, 3, 6

int wxluaR_ref(lua_State* L, int stack_idx, void* lightuserdata_reg_key)
{
    // nothing on stack to insert and don't bother inserting nil
    if (lua_isnoneornil(L, stack_idx))
        return LUA_REFNIL;

    lua_pushlightuserdata(L, lightuserdata_reg_key);    // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                   // pop key, push value (table)

    lua_pushvalue(L, ABS_LUA_STKIDX(stack_idx,1));      // push value to store

    int ref_idx = luaL_ref(L, -2);                      // t[ref_idx] = value; pops value

    // We also store t[value] = table_idx for this table for faster lookup
    if (lightuserdata_reg_key == &wxlua_lreg_debug_refs_key)
    {
        lua_pushvalue(L, ABS_LUA_STKIDX(stack_idx,1));  // push key
        lua_pushnumber(L, ref_idx);                     // push value
        lua_rawset(L, -3);                              // set t[key] = value; pops key and value
    }

    lua_pop(L, 1);                                      // pop table

    return ref_idx;
}

bool wxluaR_unref(lua_State* L, int ref_idx, void* lightuserdata_reg_key)
{
    if (ref_idx == LUA_REFNIL)                       // nothing to remove
        return false;

    lua_pushlightuserdata(L, lightuserdata_reg_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                // pop key, push value (table)

    // Also remove the t[value] = table_idx for this table
    if (lightuserdata_reg_key == &wxlua_lreg_debug_refs_key)
    {
        lua_pushnumber(L, ref_idx);   // push key
        lua_rawget(L, -2);            // get t[key] = value; pop key, push value;

        lua_pushnil(L);
        lua_rawset(L, -3);            // t[value] = nil; pops key and value
    }

    luaL_unref(L, -1, ref_idx);       // remove key and value in refs table
                                      // note: this key will be used for the next wxluaR_ref()

    lua_pop(L, 1);                    // pop table

    return true;
}

bool LUACALL wxluaR_getref(lua_State *L, int ref_idx, void* lightuserdata_reg_key)
{
    if (ref_idx == LUA_REFNIL)          // nothing to get
        return false;

    lua_pushlightuserdata(L, lightuserdata_reg_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                // pop key, push value (table)

    lua_rawgeti(L, -1, ref_idx);        // get t[ref_idx] = value; push value

    if (lua_isnil(L, -1))               // not a valid table key
    {
        lua_pop(L, 2);                  // pop nil and table
        return false;
    }

    lua_remove(L, -2);                  // remove table, leaving value on top

    return true; // return if table has a valid value and it's on the stack
}

int LUACALL wxluaR_isrefed(lua_State* L, int stack_idx, void* lightuserdata_reg_key)
{
    int ref_idx = LUA_NOREF;

    lua_pushlightuserdata(L, lightuserdata_reg_key);    // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                   // pop key, push value (table)

    if (lightuserdata_reg_key == &wxlua_lreg_debug_refs_key)
    {
        // For this table we've pushed the value for a faster lookup
        lua_pushvalue(L, ABS_LUA_STKIDX(stack_idx,1));  // push key (the value)
        lua_rawget(L, -2);                              // get t[key] = value; pop key push value
        ref_idx = (int)lua_tonumber(L, -1);

        if ((ref_idx == 0) && !lua_isnumber(L, -1))     // if !isnumber it returns 0 (faster)
            ref_idx = LUA_NOREF;

        lua_pop(L, 2); // pop object we pushed and the ref table
    }
    else
    {
        // otherwise search through all the values
        lua_pushnil(L);
        while (lua_next(L, -2) != 0)
        {
            // value = -1, key = -2, table = -3, object = stack_idx before 3 added items
            if (lua_equal(L, -1, ABS_LUA_STKIDX(stack_idx,3)))
            {
                ref_idx = (int)lua_tonumber(L, -2);
                lua_pop(L, 2);               // pop key, value
                break;
            }
            else
                lua_pop(L, 1);               // pop value, lua_next will pop key at end
        }

        lua_pop(L, 1); // pop ref table
    }

    return ref_idx;
}

// ----------------------------------------------------------------------------
// wxluaO_XXX - functions operate on the "Objects"
// ----------------------------------------------------------------------------

bool LUACALL wxluaO_addgcobject(lua_State *L, void *obj_ptr, int wxl_type)
{
    lua_pushlightuserdata(L, &wxlua_lreg_gcobjects_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                    // pop key, push value (table)

    // Check if it's already tracked since that means the weak udata table isn't working right
    lua_pushlightuserdata(L, obj_ptr); // push key
    lua_rawget(L, -2);                 // get t[key] = value, pops key

    if (!lua_isnil(L, -1))
    {
        lua_pop(L, 2); // pop table and value
        wxCHECK_MSG(false, false, wxT("Tracking an object twice in wxluaO_addgcobject: ") + wxluaT_typename(L, wxl_type));
        return false;
    }

    lua_pop(L, 1); // pop nil

    // Then add it
    lua_pushlightuserdata(L, obj_ptr);  // push key
    lua_pushnumber(L, wxl_type);        // push value
    lua_rawset(L, -3);                  // set t[key] = value, pops key and value

    lua_pop(L, 1); // pop table

    return true;
}

bool LUACALL wxluaO_deletegcobject(lua_State *L, int stack_idx, int flags)
{
    void* udata   = lua_touserdata(L, stack_idx);
    void* obj_ptr = wxlua_touserdata(L, stack_idx, true); // clear lua userdata's ptr

    if (obj_ptr == NULL) return false; // can happen

    bool delete_all = WXLUA_HASBIT(flags, WXLUA_DELETE_OBJECT_ALL);

    wxLuaBindClass *wxlClass = NULL;

    if (lua_getmetatable(L, stack_idx))
    {
        lua_pushlightuserdata(L, &wxlua_metatable_wxluabindclass_key); // push key
        lua_rawget(L, -2);                                   // get t[key] = value; pop key push value
        wxlClass = (wxLuaBindClass *)lua_touserdata(L, -1);
        lua_pop(L, 2); // pop metatable and lightuserdata value
    }

    // Remove the weak ref to it, will optionally clear all the metatables
    // for an userdata created for this object to make them unusable.
    int udata_count = wxluaO_untrackweakobject(L, delete_all ? NULL : udata, obj_ptr);

    if (delete_all || (udata_count < 1))
    {
        // remove any derived methods attached to this object
        wxlua_removederivedmethods(L, obj_ptr);

        // check if we are really supposed to delete it
        lua_pushlightuserdata(L, &wxlua_lreg_gcobjects_key); // push key
        lua_rawget(L, LUA_REGISTRYINDEX);                    // pop key, push value (table)

        lua_pushlightuserdata(L, obj_ptr); // push key
        lua_rawget(L, -2);                 // get t[key] = value, pops key

        if (wxlClass && lua_isnumber(L, -1)) // the wxLua type for it
        {
            lua_pop(L, 1); // pop number value

            lua_pushlightuserdata(L, obj_ptr); // push key
            lua_pushnil(L);                    // push value
            lua_rawset(L, -3);                 // set t[key] = value, pops key and value

            lua_pop(L, 1); // pop delobj table

            // delete the object using the function stored in the wxLuaBindClass
            if (obj_ptr)
                wxlClass->delete_fn(&obj_ptr);
            else
                return false;

            return true;
        }
        else
        {
            // no error message since we're called from wxlua_wxLuaBindClass__gc
            // automatically for all our objects and this table stores which ones to delete
            // so we don't want to have to check first and then call this.
            lua_pop(L, 2); // pop nil and delobj
        }
    }

    return false;
}

bool LUACALL wxluaO_undeletegcobject(lua_State *L, void *obj_ptr)
{
    if (obj_ptr == NULL) return false;

    lua_pushlightuserdata(L, &wxlua_lreg_gcobjects_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                    // pop key, push value (table)

    lua_pushlightuserdata(L, obj_ptr); // push key
    lua_rawget(L, -2);                 // get t[key] = value, pops key

    if (lua_isnumber(L, -1)) // is the wxLua type of the object
    {
        lua_pop(L, 1); // pop number

        lua_pushlightuserdata(L, obj_ptr); // push key
        lua_pushnil(L);                    // push value
        lua_rawset(L, -3);                 // set t[key] = value, pops key and value

        lua_pop(L, 1); // pop delobj table
        return true;
    }
    else
        lua_pop(L, 2); // pop nil and gcobject table

    return false;
}

bool LUACALL wxluaO_isgcobject(lua_State *L, void *obj_ptr)
{
    lua_pushlightuserdata(L, &wxlua_lreg_gcobjects_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                    // pop key, push value (table)

    lua_pushlightuserdata(L, obj_ptr); // push key
    lua_rawget(L, -2);                 // get t[key] = value, pops key

    bool found = (0 != lua_isnumber(L, -1));
    lua_pop(L, 2); // pop udata and table

    return found;
}

wxArrayString LUACALL wxluaO_getgcobjectinfo(lua_State *L)
{
    wxArrayString arrStr;

    lua_pushlightuserdata(L, &wxlua_lreg_gcobjects_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                    // pop key, push value (table)

    lua_pushnil(L);
    while (lua_next(L, -2) != 0)
    {
        // value = -1, key = -2, table = -3
        wxString name(wxT("wxObject?"));

        int wxl_type = (int)lua_tonumber(L, -1);
        name = wxluaT_typename(L, wxl_type);

        arrStr.Add(wxString::Format(wxT("%s(%p)"), name.c_str(), lua_touserdata(L, -2)));

        lua_pop(L, 1); // pop value, lua_next will pop key at end
    }

    lua_pop(L, 1); // pop table

    arrStr.Sort();
    return arrStr;
}

void LUACALL wxluaO_trackweakobject(lua_State *L, int udata_stack_idx, void *obj_ptr, int wxl_type)
{
    lua_pushlightuserdata(L, &wxlua_lreg_weakobjects_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                      // pop key, push value (the obj table)

    lua_pushlightuserdata(L, obj_ptr); // push key
    lua_rawget(L, -2);

    if (lua_isnil(L, -1)) // not tracked yet, create new table to store items
    {
        lua_pop(L, 1); // pop nil

        lua_pushlightuserdata(L, obj_ptr);
        lua_newtable(L);
          lua_newtable(L);                    // metatable
            lua_pushlstring(L, "__mode", 6);
            lua_pushlstring(L, "v", 1);
            lua_rawset(L, -3);                // set mode of main table
          lua_setmetatable(L, -2);            // via the metatable
        lua_rawset(L, -3);

        lua_pushlightuserdata(L, obj_ptr); // get the table back
        lua_rawget(L, -2);
    }
    else
    {
        // check for dupes since that's what we're trying to avoid
        lua_pushnumber(L, wxl_type);
        lua_rawget(L, -2);
        // this must never happen
        if (!lua_isnil(L, -1))
        {
            wxFAIL_MSG(wxT("Trying to push userdata for object with same wxLua type twice"));
        }
        lua_pop(L, 1); // pop nil
    }

    lua_pushnumber(L, wxl_type);
    lua_pushvalue(L, ABS_LUA_STKIDX(udata_stack_idx, 3)); // push the Lua userdata as the value (note: weak valued table)
    lua_rawset(L, -3);    // t[key] = value; pops key and value
    lua_pop(L, 2);        // pop weakobj table and obj_ptr table
}

int LUACALL wxluaO_untrackweakobject(lua_State *L, void* udata, void *obj_ptr)
{
    lua_pushlightuserdata(L, &wxlua_lreg_weakobjects_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                      // pop key, push value (the object table)

    lua_pushlightuserdata(L, (void*)obj_ptr); // push key
    lua_rawget(L, -2);                        // get t[key] = value; pop key push value

    int count = 0;

    if (lua_istable(L, -1))
    {
        // clear the metatables for the userdata
        lua_pushnil(L);
        while (lua_next(L, -2) != 0)
        {
            // value = -1, key = -2, table = -3
            void *u = lua_touserdata(L, -1);

            if ((udata == NULL) || (udata == u))
            {
                lua_pushnil(L);
                lua_setmetatable(L, -2); // remove value's metatable
            }

            if (udata == u)
            {
                lua_pop(L, 1);        // pop value

                lua_pushvalue(L, -1); // copy key for next iteration
                lua_pushnil(L);
                lua_rawset(L, -4);    // set t[key] = nil to remove it
            }
            else
            {
                ++count;       // only count ones that still exist
                lua_pop(L, 1); // pop value, leave key for next iteration
            }
        }

        lua_pop(L, 1); // pop obj_ptr table

        // If we've cleared everything then remove the table
        if ((udata == NULL) || (count == 0))
        {
            count = 0;                                // removed them all
            lua_pushlightuserdata(L, (void*)obj_ptr); // push key
            lua_pushnil(L);                           // push value
            lua_rawset(L, -3);                        // set t[key] = nil; pops key and value
        }

        lua_pop(L, 1);                            // pop objects table
    }
    else
        lua_pop(L, 2); // pop nil and weakobj table

    return count;
}

bool LUACALL wxluaO_istrackedweakobject(lua_State *L, void *obj_ptr, int wxl_type, bool push_on_stack)
{
    lua_pushlightuserdata(L, &wxlua_lreg_weakobjects_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX);   // pop key, push value (the obj table)

    lua_pushlightuserdata(L, obj_ptr); // push key
    lua_rawget(L, -2);                 // get t[key] value; pop key push value

    if (lua_istable(L, -1))
    {
        lua_pushnumber(L, wxl_type); // push key
        lua_rawget(L, -2);           // get t[key] = value; pops key

        // check if they've dynamic casted the object or if it was casted in C++
        if (wxl_type == wxluaT_type(L, -1))
        {
            if (push_on_stack)
            {
                lua_remove(L, -3); // remove the obj table, leave value on the stack
                lua_remove(L, -2); // remove table of userdata, leave value on the stack
            }
            else
                lua_pop(L, 3);

            return true;
        }
        else
            lua_pop(L, 1); // pop the userdata that is not the right type
    }

    lua_pop(L, 2); // pop the weakobj table and the nil.
    return false;
}

wxArrayString LUACALL wxluaO_gettrackedweakobjectinfo(lua_State *L)
{
    wxArrayString arrStr;

    lua_pushlightuserdata(L, &wxlua_lreg_weakobjects_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                      // pop key, push value (table)

    lua_pushnil(L);
    while (lua_next(L, -2) != 0)
    {
        // value = -1, key = -2, table = -3
        void* obj_ptr = lua_touserdata(L, -2); // actually lightuserdata

        wxString name;

        // iterate the table of userdata
        lua_pushnil(L);
        while (lua_next(L, -2) != 0)
        {
            // value = -1, key = -2, table = -3
            int wxl_type = (int)lua_tonumber(L, -2);
            if (!name.IsEmpty()) name += wxT(", ");
            name += wxString::Format(wxT("%s(%p, type=%d)"), wxluaT_typename(L, wxl_type).c_str(), lua_touserdata(L, -1), wxl_type);
            lua_pop(L, 1); // pop value, lua_next will pop key at end
        }

        arrStr.Add(wxString::Format(wxT("%p = %s"), obj_ptr, name.c_str()));

        lua_pop(L, 1); // pop value, lua_next will pop key at end
    }

    lua_pop(L, 1); // pop table

    arrStr.Sort();
    return arrStr;
}

// ----------------------------------------------------------------------------
// wxluaW_XXX - functions operate on tracked wxWindows
// ----------------------------------------------------------------------------

void LUACALL wxluaW_addtrackedwindow(lua_State *L, wxObject* wxobj)
{
    if (!wxobj) return; // allow NULL w/o error

    // don't track these "windows" since they're supposed to be attached
    // and their parents are not properly set so we can't tell if
    // their parents are tracked.
    if (wxDynamicCast(wxobj, wxMenuBar) != NULL) return;
    if (wxDynamicCast(wxobj, wxToolBar) != NULL) return;

    wxWindow* win = wxDynamicCast(wxobj, wxWindow);

    // only need to track parent window, it deletes children for us
    if (win && !wxluaW_istrackedwindow(L, win, true))
    {
        lua_pushlightuserdata(L, &wxlua_lreg_topwindows_key); // push key
        lua_rawget(L, LUA_REGISTRYINDEX);                     // pop key, push value (table)

        lua_pushlightuserdata(L, win); // push key
        lua_pushnumber(L, 1);          // push value
        lua_rawset(L, -3);             // set t[key] = value, pops key and value

        lua_pop(L, 1); // pop topwindows table
    }
}

void LUACALL wxluaW_removetrackedwindow(lua_State *L, wxWindow* win)
{
    lua_pushlightuserdata(L, &wxlua_lreg_topwindows_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                     // pop key, push value (table)

    lua_pushlightuserdata(L, win); // push key
    lua_pushnil(L);                // push value
    lua_rawset(L, -3);             // set t[key] = value, pops key and value

    lua_pop(L, 1); // pop topwindows table
}

bool LUACALL wxluaW_istrackedwindow(lua_State *L, wxWindow* win, bool check_parents)
{
    lua_pushlightuserdata(L, &wxlua_lreg_topwindows_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                     // pop key, push value (table)

    wxWindow* parent = win;

    while (parent)
    {
        lua_pushlightuserdata(L, parent); // push key
        lua_rawget(L, -2);                // pop key, push value

        if (lua_isnumber(L, -1))
        {
            lua_pop(L, 2); // pop topwindows table and value
            return true;
        }

        parent = check_parents ? parent->GetParent() : NULL;
        lua_pop(L, 1); // pop value (nil)
    }

    lua_pop(L, 1); // pop topwindows table

    return false;
}

wxArrayString LUACALL wxluaW_gettrackedwindowinfo(lua_State *L)
{
    wxArrayString arrStr;

    lua_pushlightuserdata(L, &wxlua_lreg_topwindows_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                     // pop key, push value (table)

    lua_pushnil(L);
    while (lua_next(L, -2) != 0)
    {
        // value = -1, key = -2, table = -3
        wxWindow* win = (wxWindow*)lua_touserdata(L, -2);
        wxCHECK_MSG(win, arrStr, wxT("Invalid wxWindow"));

        wxString name(win->GetClassInfo()->GetClassName());
        arrStr.Add(wxString::Format(wxT("%s(%p id=%d)"), name.c_str(), win, win->GetId()));

        lua_pop(L, 1); // pop value, lua_next will pop key at end
    }

    lua_pop(L, 1); // pop table

    arrStr.Sort();
    return arrStr;
}

// ----------------------------------------------------------------------------
// wxluaT_XXX - functions operate on the wxLua types
// ----------------------------------------------------------------------------

int wxluaT_newmetatable(lua_State* L, int wxl_type)
{
    lua_newtable(L);                                     // create a table for our new type
    lua_pushlightuserdata(L, &wxlua_metatable_type_key); // push key
    lua_pushnumber(L, wxl_type);                         // push value
    lua_rawset(L, -3);                                   // set t[key] = value; pop key and value

    lua_pushlightuserdata(L, &wxlua_lreg_types_key);     // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                    // pop key, push value (table)

    // make sure that the Lua table array is contiguous
    int len = (int)lua_objlen(L, -1);                    // get the length of the table
    while (++len < wxl_type)
    {
        lua_pushnumber(L, 0);
        lua_rawseti(L, -2, len);
    }

    // It is not allowed to reregister this type
    lua_rawgeti(L, -1, wxl_type);
    int t = lua_type(L, -1);
    wxCHECK_MSG((t == LUA_TNUMBER) || (t == LUA_TNIL), WXLUA_TUNKNOWN, wxT("Attempting to reregister wxLua type"));
    lua_pop(L, 1);

    // Add the metatable to the wxlua_lreg_types_key table
    lua_pushvalue(L, -2);                                // copy the metatable
    lua_rawseti(L, -2, wxl_type);                        // add it, pops table
    lua_pop(L, 1);                                       // pop wxlua_lreg_types_key table

    return wxl_type; // leave the table on the stack
}

bool LUACALL wxluaT_getmetatable(lua_State* L, int wxl_type)
{
    if (wxluaR_getref(L, wxl_type, &wxlua_lreg_types_key)) // get the metatable
    {
        if (lua_type(L, -1) == LUA_TTABLE)
            return true;

        lua_pop(L, 1); // pop nil or 0 placeholder
    }

    return false;
}

bool LUACALL wxluaT_setmetatable(lua_State *L, int wxl_type)
{
    if (wxluaT_getmetatable(L, wxl_type)) // get the metatable
    {
        // set it as the metatable of the object at the top of the stack
        if (lua_setmetatable(L, -2)) // pops table
            return true;
        else
        {
            lua_pop(L, 1); // pop table
            wxlua_error(L, "wxLua: Unable to set metatable in wxluaT_setmetatable.");
        }
    }
    else
        wxlua_error(L, "wxLua: Unable to get metatable in wxluaT_setmetatable.");

    return false;
}

int LUACALL wxluaT_type(lua_State *L, int stack_idx)
{
    int wxl_type = WXLUA_TUNKNOWN;
    int ltype = lua_type(L, stack_idx);

    if ((ltype == LUA_TUSERDATA) && lua_getmetatable(L, stack_idx)) // see wxluaT_newmetatable()
    {
        lua_pushlightuserdata(L, &wxlua_metatable_type_key); // push key
        lua_rawget(L, -2);                                   // get t[key] = value; pop key push value
        wxl_type = (int)lua_tonumber(L, -1); // if !isnumber it returns 0 (check below is faster)

        // if it's not a number (it's probably nil) then it's someone else's userdata
        if ((wxl_type == 0) && !lua_isnumber(L, -1))
            wxl_type = WXLUA_TUSERDATA;

        lua_pop(L, 2); // pop metatable and wxl_type number
    }
    else
        wxl_type = wxlua_luatowxluatype(ltype);

    return wxl_type;
}

wxString LUACALL wxluaT_typename(lua_State* L, int wxl_type)
{
    // try to use wxString's ref counting and return this existing copy
    static wxString s[14] = {
        wxT("unknown"),
        wxT("none"),
        wxT("nil"),
        wxT("boolean"),
        wxT("lightuserdata"),
        wxT("number"),
        wxT("string"),
        wxT("table"),
        wxT("function"),
        wxT("userdata"),
        wxT("thread"),
        wxT("integer"),
        wxT("cfunction"),
        wxT("pointer")
    };

    // Check for real type or this is a predefined WXLUA_TXXX type
    if ((L == NULL) || (WXLUAT_IS_LUAT(wxl_type)))
    {
        switch (wxl_type)
        {
            case WXLUA_TUNKNOWN :       return s[0];
            case WXLUA_TNONE :          return s[1];
            case WXLUA_TNIL :           return s[2];
            case WXLUA_TBOOLEAN :       return s[3];
            case WXLUA_TLIGHTUSERDATA : return s[4];
            case WXLUA_TNUMBER :        return s[5];
            case WXLUA_TSTRING :        return s[6];
            case WXLUA_TTABLE :         return s[7];
            case WXLUA_TFUNCTION :      return s[8];
            case WXLUA_TUSERDATA :      return s[9];
            case WXLUA_TTHREAD :        return s[10];

            case WXLUA_TINTEGER :       return s[11];
            case WXLUA_TCFUNCTION :     return s[12];
            case WXLUA_TPOINTER :       return s[13];
        }
    }
    else
    {
        const wxLuaBindClass* wxlClass = wxluaT_getclass(L, wxl_type);
        if (wxlClass)
            return lua2wx(wxlClass->name);
    }

    return wxT("Unknown wxLua Type?");
}

wxString LUACALL wxluaT_gettypename(lua_State* L, int stack_idx)
{
    return wxluaT_typename(L, wxluaT_type(L, stack_idx));
}

wxString LUACALL wxlua_luaL_typename(lua_State* L, int stack_idx)
{
    // lua_typename(L, lua_type(L, stack_idx))
    return lua2wx(luaL_typename(L, stack_idx));
}

int LUACALL wxluaT_gettype(lua_State* L, const char* class_name)
{
    const wxLuaBindClass* wxlClass = wxluaT_getclass(L, class_name);
    if (wxlClass)
        return *wxlClass->wxluatype;

    return WXLUA_TUNKNOWN;
}

const wxLuaBindClass* LUACALL wxluaT_getclass(lua_State* L, int wxl_type)
{
    // note: wxluaT_getmetatable() doesn't leave anything on the stack on failure
    if (wxluaT_getmetatable(L, wxl_type))
    {
        // t[wxluatype] = { [bindclass_key] = lightuserdata wxLuaBindClass... (or nil if not a wxLua class type)
        lua_pushlightuserdata(L, &wxlua_metatable_wxluabindclass_key);
        lua_rawget(L, -2);
        const wxLuaBindClass* wxlClass = (wxLuaBindClass *)lua_touserdata(L, -1); // actually lightuserdata

        lua_pop(L, 2); // pop type table and lightuserdata (or nil if none)

        return wxlClass;
    }

    return NULL;
}

const wxLuaBindClass* LUACALL wxluaT_getclass(lua_State* L, const char* class_name)
{
    lua_pushlightuserdata(L, &wxlua_lreg_classes_key); // push key
    lua_rawget(L, LUA_REGISTRYINDEX);                  // pop key, push value (table)

    lua_pushstring(L, class_name); // push key
    lua_rawget(L, -2);             // get t["class_name"] = &wxLuaBindClass; pop key push value
    const wxLuaBindClass* wxlClass = (wxLuaBindClass *)lua_touserdata(L, -1); // actually lightuserdata

    lua_pop(L, 2); // pop table and lightuserdata (or nil if none)

    return wxlClass; // may be NULL
}

bool wxluaT_isuserdatatype(lua_State* L, int stack_idx, int wxl_type)
{
    int stack_type = wxluaT_type(L, stack_idx);
    
    if (wxlua_iswxuserdatatype(stack_type) &&
        ((wxluatype_NULL == stack_type) || // FIXME, how to check when NULL is valid or not?
        ((wxl_type == WXLUA_TSTRING) &&
         ((wxluaT_isderivedtype(L, stack_type, *p_wxluatype_wxString) >= 0) ||
          (wxluaT_isderivedtype(L, stack_type, *p_wxluatype_wxMemoryBuffer) >= 0))) ||
        (wxluaT_isderivedtype(L, stack_type, wxl_type) >= 0)))
        return true;
        
    return false;
}

// Note about multiple inheritance in wxLua :
// See wxLuaBindClass::baseclass_vtable_offsets
//
// class A { int x; }; class B { int y; }; class AB : public A, public B { int z; };
// AB ab; void *v_ab_a = (A*)&ab; void *v_ab_b = (B*)&ab;
// long int dummy = 0;
// long int AB_diff = ((long int)(B*)(AB*)&dummy) - ((long int)(A*)(AB*)&dummy);
// wxPrintf(wxT("AB*=%p, A*=%p, B*=%p, B*-A*=%d\n"), &ab, v_ab_a, v_ab_b, AB_diff);
// prints: "AB*=0x614dfc, A*=0x614dfc, B*=0x614e00, B*-A*=4"
//
// In order to call B's functions from a void* pointer to an AB object :
// 1) Ideally, we cast to an AB object and the compiler will appropriately lookup
//    and handle calls to B's functions.
// 2) Cast to an AB object then to a B object where the compiler has already
//    shifted the pointer and calls to B's functions are made directly.
// 3) Explicitly shift the void* pointer to the AB object to where the vtable for
//    B is. We now have an object that only knows about B and what B was derived from.
//    I'm sure this is frowned upon by C++ enthusiasts.
//
// Ways of doing 1 and 2 in wxLua with C++ constraints, wxLua does #3 above.
//
// 1) wxLua would duplicate all the the binding functions for second
//    and higher base classes and therefore each binding function will cast the
//    void* we get from Lua to exactly the object type that it is. This is best,
//    but it adds bloat.
// 2) Come up with a clever way using overloaded functions, templates,
//    or some sort of variant class to convert the void* pointer from Lua to
//    type of object that it really is (we know by the wxLuaType integer)
//    and then the binding function will cast it whatever base class it may be.
//    The problem is that we really need to overload this casting function by
//    return type, the function takes void* and returns ClassXYZ*, but this
//    is not allowed in C++.
// 3) Store an array of the offsets in each classes' wxLuaBindClass struct
//    to the second or higher base classes and automatically add this offset in
//    wxluaT_getuserdatatype(). The offsets are calculated at compile time
//    using the AB_diff method above.
//
// Various ways to cast a void* pointer to the second base class :
// void* v_ab = &ab;   // compilier doesn't know what v_ab is anymore
// AB* ab = (AB*)v_ab; // ok since we cast right back to original type
// A*  a  = (A*)v_ab;  // ok in GCC & MSVC since we are casting to 1st base class
// B*  b  = (B*)v_ab;  // segfault! since B*'s vtable is +4 bytes as shown above
// B*  b1 = (B*)(AB*)v_ab; // ok since compiler converts to AB* and knows that B* is shifted
// B*  b2 = (B*)((long int)v_ab + AB_diff); // ok since we've shifted to B


// forward declaration
static int wxluaT_isderivedtype_recurser(const wxLuaBindClass *wxlClass, int base_wxl_type, int levels, int* baseclass_n);

void* LUACALL wxluaT_getuserdatatype(lua_State* L, int stack_idx, int wxl_type)
{
    int stack_type = wxluaT_type(L, stack_idx);

    if (wxluatype_NULL == stack_type)
        return NULL;

    // Note: we directly use the recurser function since we may need the wxLuaBindClass
    //int level = wxluaT_isderivedtype(L, stack_type, wxl_type);

    int baseclass_n = 0;
    const wxLuaBindClass* wxlClass = wxluaT_getclass(L, stack_type);
    int level = wxluaT_isderivedtype_recurser(wxlClass, wxl_type, 0, &baseclass_n);

    if ((level >= 0) && (baseclass_n == 0))
    {
        // We can directly cast the void* pointer to the baseclass if baseclass_n == 0
        return wxlua_touserdata(L, stack_idx, false);
    }
    else if (level > 0)
    {
        // The class on the stack is derived from a second or higher base class
        // and therefore the pointer to the base class is not the same as the
        // pointer to the class object on the stack. We need to shift the
        // pointer by the number of bytes in wxLuaBindClass::baseclass_vtable_offsets
        // so that when it is casted to the base class we don't segfault.
        // Using 'long long' for 32 and 64 bit and compatibility with older compilers that don't have uintptr_t.
        unsigned long long o = (unsigned long long)wxlua_touserdata(L, stack_idx, false);

        if (wxlClass->baseclass_wxluatypes)
        {
            int i = 0;
            while (wxlClass->baseclass_wxluatypes[i]) // NULL terminated, the baseclass_vtable_offsets is not
            {
                if (*(wxlClass->baseclass_wxluatypes[i]) == wxl_type)
                {
                    o += wxlClass->baseclass_vtable_offsets[i];
                    break;
                }
                i++;
            }
        }

        return (void*)o;
    }



    wxlua_argerror(L, stack_idx, wxT("a '") + wxluaT_typename(L, wxl_type) + wxT("'"));

    return NULL;
}

bool LUACALL wxluaT_pushuserdatatype(lua_State* L, const void *obj_ptr, int wxl_type, bool track, bool allow_NULL)
{
    // FIXME allow_NULL is a hack for the NULL userdata type.

    if (allow_NULL || (obj_ptr != NULL))
    {
        // First check to see if we've already pushed this object into Lua.
        // This avoids the problem of the gc deleting a returned pointer to a permanent object.
        // Test code is this:
        // il = wx.wxImageList(16,16); ... noteBook:SetImageList(il); ... local il2 = noteBook:GetImageList()
        // When il2 gets gc it will delete il even though il may still be valid and used by the notebook.

        if (wxluaO_istrackedweakobject(L, (void*)obj_ptr, wxl_type, true))
            return true;

        // if the object we are referencing is derived from wxWindow
        if (obj_ptr && (wxluaT_isderivedtype(L, wxl_type, *p_wxluatype_wxWindow) >= 0))
        {
            wxWindow* win = wxDynamicCast(obj_ptr, wxWindow); // double check that it's a wxWindow
            if (win != NULL)
            {
                // check to make sure that we're not trying to attach another destroy callback
                lua_pushlightuserdata(L, &wxlua_lreg_windestroycallbacks_key); // push key
                lua_rawget(L, LUA_REGISTRYINDEX);                              // pop key, push value (table)

                lua_pushlightuserdata(L, win); // push key
                lua_rawget(L, -2);             // get t[key] = value; pops key

                if (!lua_islightuserdata(L, -1))
                {
                    // Connect the wxWindow to wxEVT_DESTROY callback so if Lua has
                    // a copy(s) of it we can clear the metatable when we get the
                    // event so we don't segfault if we try to access it by accident.
                    wxLuaState wxlState(L);
                    wxCHECK_MSG(wxlState.Ok(), false, wxT("Invalid wxLuaState"));
                    wxLuaWinDestroyCallback *pCallback =
                            new wxLuaWinDestroyCallback(wxlState, win);

                    if (pCallback == NULL)
                        wxlua_error(L, "wxLua: Out of memory creating wxLuaWinDestroyCallback.");
                    // assert should have been given in constructor so delete it
                    // since it's not attached as a callback user data
                    if (!pCallback->Ok())
                        delete pCallback;
                }

                lua_pop(L, 2); // pop windestroy table and value
            }
        }

        // Wrap the void* pointer in a newuserdata
        const void **ptr = (const void **)lua_newuserdata(L, sizeof(void *));
        if (ptr != NULL)
        {
            *ptr = obj_ptr;
            // try to get the object's references table and set the metatable to the object
            if (wxluaT_getmetatable(L, wxl_type))
            {
                // pop the table and set it as the metatable for the newuserdata
                lua_setmetatable(L, -2);

                if (track)
                    wxluaO_trackweakobject(L, -1, (void*)obj_ptr, wxl_type);

                return true; // leave value on the stack
            }
            else
                wxlua_error(L, "wxLua: Unable to get metatable in wxluaT_pushuserdatatype.");
        }
        else
            wxlua_error(L, "wxLua: Out of memory");
    }
    else
    {
        lua_pushnil(L);
        return true;
    }

    return false;
}

// ----------------------------------------------------------------------------
// Functions to get info about the wxLua types
// ----------------------------------------------------------------------------

static int wxluaT_isderivedtype_recurser(const wxLuaBindClass *wxlClass, int base_wxl_type, int levels, int* baseclass_n)
{
    if (wxlClass != NULL)
    {
        // check that input isn't what we want first since this func is used in a couple places
        if (*wxlClass->wxluatype == base_wxl_type)
            return levels;
        else if (wxlClass->baseclassNames != NULL) // check baseclass by baseclass
        {
            for (size_t i = 0; wxlClass->baseclassNames[i]; ++i)
            {
                // Note: base class may be NULL if lib/module containing it is not loaded
                wxLuaBindClass* baseClass = wxlClass->baseBindClasses[i];

                if (baseClass != NULL)
                {
                    if (*baseClass->wxluatype == base_wxl_type)
                    {
                        if (baseclass_n) *baseclass_n = wxMax(*baseclass_n, (int)i);
                        return levels+1;
                    }
                    else
                    {
                        // create a new baseclass_n since we may be going down the wrong path
                        // and we do not want to change the original.
                        int baseclass_n_tmp = wxMax(baseclass_n ? *baseclass_n : 0, (int)i);
                        int ret = wxluaT_isderivedtype_recurser(baseClass, base_wxl_type, levels+1, &baseclass_n_tmp);
                        if (ret > -1)
                        {
                            // now set the baseclass_n var to the tmp one
                            if (baseclass_n) *baseclass_n = wxMax(baseclass_n_tmp, (int)i);
                            return ret;
                        }
                    }
                }
            }
        }
    }

    return -1; // wxluatype is not derived from base_wxluatype
}

int LUACALL wxluaT_isderivedtype(lua_State* L, int wxl_type, int base_wxl_type, int* baseclass_n)
{
    // couldn't possibly be derived from each other
    if (!wxlua_iswxuserdatatype(wxl_type) || !wxlua_iswxuserdatatype(base_wxl_type))
        return -1;

    // These two types are the same, yes recurser also checks, but this is faster
    if (wxl_type == base_wxl_type)
        return 0;

    const wxLuaBindClass *wxlClass = wxluaT_getclass(L, wxl_type);

    if (baseclass_n != NULL) *baseclass_n = 0;

    return wxluaT_isderivedtype_recurser(wxlClass, base_wxl_type, 0, baseclass_n);
}

int LUACALL wxluaT_isderivedclass(const wxLuaBindClass* wxlClass, const wxLuaBindClass* base_wxlClass, int* baseclass_n)
{
    // Ok if either is NULL to allow blindly calling this
    if ((wxlClass == NULL) || (base_wxlClass == NULL))
        return -1;

    // These two types are the same
    if (wxlClass->wxluatype == base_wxlClass->wxluatype) // comparing pointers
        return 0;

    if (baseclass_n != NULL) *baseclass_n = 0;

    return wxluaT_isderivedtype_recurser(wxlClass, *base_wxlClass->wxluatype, 1, baseclass_n);
}

int LUACALL wxlua_iswxluatype(int luatype, int wxl_type, lua_State* L /* = NULL */)
{
    int ret = -1; // unknown wxlua arg type

    switch (wxl_type)
    {
        case WXLUA_TNONE :
            ret = (luatype == LUA_TNONE) ? 1 : 0;
            break;
        case WXLUA_TNIL :
            ret = (luatype == LUA_TNIL) ? 1 : 0;
            break;
        case WXLUA_TBOOLEAN :
            // LUA_TNIL:    nil == false
            // LUA_TNUMBER: 0 == false as in C
            ret = ((luatype == LUA_TBOOLEAN) || (luatype == LUA_TNUMBER) || (luatype == LUA_TNIL)) ? 1 : 0;
            break;
        case WXLUA_TLIGHTUSERDATA:
            ret = (luatype == LUA_TLIGHTUSERDATA) ? 1 : 0;
            break;
        case WXLUA_TNUMBER :
            // LUA_TNIL:     evaluates to 0, too easy to have a typo
            // LUA_TSTRING:  will be 0 unless really a number "2"
            // LUA_TBOOLEAN: can't do (bool_val or 1)
            ret = ((luatype == LUA_TNUMBER) || (luatype == LUA_TBOOLEAN)) ? 1 : 0;
            break;
        case WXLUA_TSTRING :
            // LUA_TNIL:    too easy to have a variable typo, use (str or "")
            // LUA_TNUMBER: can convert easily, always works, but breaks overload bindings
            ret = (luatype == LUA_TSTRING) ? 1 : 0;
            break;
        case WXLUA_TTABLE :
            ret = (luatype == LUA_TTABLE) ? 1 : 0;
            break;
        case WXLUA_TFUNCTION :
            ret = (luatype == LUA_TFUNCTION) ? 1 : 0;
            break;
        case WXLUA_TUSERDATA :
            ret = (luatype == LUA_TUSERDATA) ? 1 : 0;
            break;
        case WXLUA_TTHREAD :
            ret = (luatype == LUA_TTHREAD) ? 1 : 0;
            break;
        case WXLUA_TINTEGER :
            // LUA_TNIL: evaluates to 0 so wx.ENUM_typo = 0
            ret = (luatype == LUA_TNUMBER) ? 1 : 0;
            break;
        case WXLUA_TCFUNCTION :
            ret = (luatype == LUA_TFUNCTION) ? 1 : 0;
            break;
        case WXLUA_TPOINTER :
            ret = (luatype == LUA_TLIGHTUSERDATA) || (luatype == LUA_TUSERDATA) ||
                  (luatype == LUA_TFUNCTION) || (luatype == LUA_TTABLE) ||
                  (luatype == LUA_TTHREAD) ? 1 : 0;
            break;
        case WXLUA_TANY :
            ret = 1; // any type is acceptable
            break;
    }

    // if we don't know the type (it's not predefined)
    if ((ret < 0) && L &&(luatype == LUA_TTABLE))
    {
        const wxLuaBindClass* wxlClass = wxluaT_getclass(L, wxl_type);

        if (wxluaT_isderivedclass(wxlClass, wxluaT_getclass(L, "wxArrayString")) >= 0)
            ret = 1;
        else if (wxluaT_isderivedclass(wxlClass, wxluaT_getclass(L, "wxSortedArrayString")) >= 0)
            ret = 1;
        else if (wxluaT_isderivedclass(wxlClass, wxluaT_getclass(L, "wxArrayInt")) >= 0)
            ret = 1;
        else if (wxluaT_isderivedclass(wxlClass, wxluaT_getclass(L, "wxArrayDouble")) >= 0)
            ret = 1;
    }

    return ret;
}

int wxlua_luatowxluatype(int luatype)
{
    //int wxltype = LUAT_TO_WXLUAT(luatype);
    //if (!WXLUAT_IS_LUAT(wxltype))
    //    return WXLUA_TUNKNOWN;
    //return wxltype;

    switch (luatype)
    {
        case LUA_TNONE          : return WXLUA_TNONE;
        case LUA_TNIL           : return WXLUA_TNIL;
        case LUA_TBOOLEAN       : return WXLUA_TBOOLEAN;
        case LUA_TLIGHTUSERDATA : return WXLUA_TLIGHTUSERDATA;
        case LUA_TNUMBER        : return WXLUA_TNUMBER;
        case LUA_TSTRING        : return WXLUA_TSTRING;
        case LUA_TTABLE         : return WXLUA_TTABLE;
        case LUA_TFUNCTION      : return WXLUA_TFUNCTION;
        case LUA_TUSERDATA      : return WXLUA_TUSERDATA;
        case LUA_TTHREAD        : return WXLUA_TTHREAD;
        //case LUA_T???         : return WXLUA_TINTEGER;
        //case LUA_T???         : return WXLUA_TCFUNCTION;
        //case LUA_T???         : return WXLUA_TPOINTER;
    }

    return WXLUA_TUNKNOWN;
}

int wxlua_wxluatoluatype(int wxlarg)
{
    switch (wxlarg)
    {
        case WXLUA_TNONE :          return LUA_TNONE;
        case WXLUA_TNIL :           return LUA_TNIL;
        case WXLUA_TBOOLEAN :       return LUA_TBOOLEAN;
        case WXLUA_TLIGHTUSERDATA : return LUA_TLIGHTUSERDATA;
        case WXLUA_TNUMBER :        return LUA_TNUMBER;
        case WXLUA_TSTRING :        return LUA_TSTRING;
        case WXLUA_TTABLE :         return LUA_TTABLE;
        case WXLUA_TFUNCTION :      return LUA_TFUNCTION;
        case WXLUA_TUSERDATA :      return LUA_TUSERDATA;
        case WXLUA_TTHREAD :        return LUA_TTHREAD;
        case WXLUA_TINTEGER :       return LUA_TNUMBER;
        case WXLUA_TCFUNCTION :     return LUA_TFUNCTION;
        //case WXLUA_TPOINTER :       return LUA_T???; multiple types
    }

    return -1;
}

bool wxlua_iswxstringtype(lua_State* L, int stack_idx)
{
    // NOTE: If we ever allow numbers to be coerced to strings we must
    // change how we handle lua_tostring() calls since it will change a number
    // to a string on the stack. This could break people's code.
    if (wxlua_iswxluatype(lua_type(L, stack_idx), WXLUA_TSTRING) == 1)
        return true;
    else if (wxlua_iswxuserdata(L, stack_idx))
    {
        int wxl_type = wxluaT_type(L, stack_idx);
        return (wxluaT_isderivedtype(L, wxl_type, *p_wxluatype_wxString) >= 0);
    }

    return false;
}

const char* LUACALL wxlua_getstringtypelen(lua_State *L, int stack_idx, size_t *len)
{
    if (wxlua_isstringtype(L, stack_idx))
        return lua_tolstring(L, stack_idx, len);
    else if (wxlua_iswxuserdata(L, stack_idx))
    {
        int stack_type = wxluaT_type(L, stack_idx);

        if (wxluaT_isderivedtype(L, stack_type, *p_wxluatype_wxString) >= 0)
        {
            wxString* wxstr = (wxString*)wxlua_touserdata(L, stack_idx, false);
            wxCHECK_MSG(wxstr, NULL, wxT("Invalid userdata wxString"));
            const char *retp = (const char *)wx2lua(*wxstr);
            if (len != NULL)
                *len = strlen(retp);
            return retp;
        }
        else if (wxluaT_isderivedtype(L, stack_type, *p_wxluatype_wxMemoryBuffer) >= 0)
        {
            wxMemoryBuffer * wxmem = (wxMemoryBuffer *)wxluaT_getuserdatatype(L, stack_idx, *p_wxluatype_wxMemoryBuffer);
            const char *datap = (const char *)wxmem->GetData();
            if (len != NULL)
                *len = wxmem->GetDataLen();
            return datap;
        }
    }

    wxlua_argerror(L, stack_idx, wxT("a 'string' or 'wxString'"));

    return NULL;
}

const char* LUACALL wxlua_getstringtype(lua_State *L, int stack_idx)
{
    return wxlua_getstringtypelen(L, stack_idx, NULL);
}

wxString LUACALL wxlua_getwxStringtype(lua_State *L, int stack_idx)
{
    if (wxlua_isstringtype(L, stack_idx))
        return lua2wx(lua_tostring(L, stack_idx));
    else if (wxlua_iswxuserdata(L, stack_idx))
    {
        int stack_type = wxluaT_type(L, stack_idx);

        if (wxluaT_isderivedtype(L, stack_type, *p_wxluatype_wxString) >= 0)
        {
            wxString* wxstr = (wxString*)wxlua_touserdata(L, stack_idx, false);
            wxCHECK_MSG(wxstr, wxEmptyString, wxT("Invalid userdata wxString"));
            return *wxstr;
        }
    }

    wxlua_argerror(L, stack_idx, wxT("a 'string' or 'wxString'"));

    return wxEmptyString;
}

bool LUACALL wxlua_getbooleantype(lua_State *L, int stack_idx)
{
    int l_type = lua_type(L, stack_idx);

    if (!wxlua_iswxluatype(l_type, WXLUA_TBOOLEAN))
        wxlua_argerror(L, stack_idx, wxT("a 'boolean'"));

    int num = 0;
    // we also allow 0 = false and !0 = true (Lua thinks 0 == true, i.e. !nil)
    if (l_type == LUA_TNUMBER)
        num = (int)lua_tonumber(L, stack_idx);
    else
        num = (int)lua_toboolean(L, stack_idx);

    return (num != 0);
}
long LUACALL wxlua_getenumtype(lua_State *L, int stack_idx)
{
    int l_type = lua_type(L, stack_idx);

    if (!wxlua_iswxluatype(l_type, WXLUA_TINTEGER))
        wxlua_argerror(L, stack_idx, wxT("an 'integer enum'"));

    // we don't allow bool or round, enums must strictly be integers
    double value = lua_tonumber(L, stack_idx);
    long long_value = (long)value;

    if (value != long_value)
        wxlua_argerror(L, stack_idx, wxT("an 'integer enum'"));

    return long_value;
}
long LUACALL wxlua_getintegertype(lua_State *L, int stack_idx)
{
    int l_type = lua_type(L, stack_idx);

    if (!wxlua_iswxluatype(l_type, WXLUA_TINTEGER))
        wxlua_argerror(L, stack_idx, wxT("an 'integer'"));

    double value = 0;
    // we also allow bool = 1/0 which Lua evaluates to nil in lua_tonumber
    if (l_type == LUA_TBOOLEAN)
        value = lua_toboolean(L, stack_idx) ? 1 : 0;
    else
        value = lua_tonumber(L, stack_idx);

    long long_value = (long)value;

    if (value != long_value)
        wxlua_argerror(L, stack_idx, wxT("an 'integer'"));

    return long_value;
}
unsigned long LUACALL wxlua_getuintegertype(lua_State *L, int stack_idx)
{
    int l_type = lua_type(L, stack_idx);

    if (!wxlua_iswxluatype(l_type, WXLUA_TINTEGER))
        wxlua_argerror(L, stack_idx, wxT("an 'unsigned integer'"));

    double value = 0;
    // we also allow bool = 1/0 which Lua evaluates to nil in lua_tonumber
    if (l_type == LUA_TBOOLEAN)
        value = lua_toboolean(L, stack_idx) ? 1 : 0;
    else
        value = lua_tonumber(L, stack_idx);

    unsigned long ulong_value = (unsigned long)value;

    if ((value != ulong_value) || (value < 0))
        wxlua_argerror(L, stack_idx, wxT("an 'unsigned integer'"));

    return ulong_value;
}
double LUACALL wxlua_getnumbertype(lua_State *L, int stack_idx)
{
    int l_type = lua_type(L, stack_idx);

    if (!wxlua_iswxluatype(l_type, WXLUA_TNUMBER))
        wxlua_argerror(L, stack_idx, wxT("a 'number'"));

    double value = 0;
    // we also allow bool = 1/0 which Lua evaluates to nil in lua_tonumber
    if (l_type == LUA_TBOOLEAN)
        value = lua_toboolean(L, stack_idx) ? 1 : 0;
    else
        value = lua_tonumber(L, stack_idx);

    return value;
}

void* LUACALL wxlua_getpointertype(lua_State* L, int stack_idx)
{
    int l_type = lua_type(L, stack_idx);

    if (!wxlua_iswxluatype(l_type, WXLUA_TPOINTER))
        wxlua_argerror(L, stack_idx, wxT("a 'pointer'"));

    void* value = (void *)lua_topointer(L, stack_idx);

    return value;
}

const char** LUACALL wxlua_getchararray(lua_State *L, int stack_idx, int &count)
{
    const char **arrChar = NULL;
    count = 0;

    if (lua_istable(L, stack_idx))
    {
        int table_len = lua_objlen(L, stack_idx);
        if (table_len > 0)
            arrChar = new const char *[table_len];

        if (arrChar != NULL)
        {
            for (int n = 0; n < table_len; ++n)
            {
                lua_rawgeti(L, stack_idx, n+1); // Lua array starts at 1
                const char *s = wxlua_getstringtype(L, -1);
                arrChar[n] = s; // share Lua string
                lua_pop(L, 1);
            }
        }

        count = table_len;
    }
    else
        wxlua_argerror(L, stack_idx, wxT("a 'table' array of strings"));

    return arrChar;
}

wxString* LUACALL wxlua_getwxStringarray(lua_State* L, int stack_idx, int& count)
{
    wxString *strArray = NULL;
    count = 0; // zero it in case we do a long jmp
    wxLuaSmartwxArrayString arr(wxlua_getwxArrayString(L, stack_idx));

    count = (int)((wxArrayString&)arr).GetCount();
    strArray = new wxString[count];
    for (int n = 0; n < count; ++n)
        strArray[n] = ((wxArrayString&)arr)[n];

    return strArray;
}

int* LUACALL wxlua_getintarray(lua_State* L, int stack_idx, int& count)
{
    int *intArray = NULL;
    count = 0; // zero it in case we do a long jmp
    wxLuaSmartwxArrayInt arr(wxlua_getwxArrayInt(L, stack_idx));

    count = (int)((wxArrayInt&)arr).GetCount();
    intArray = new int[count];
    for (int n = 0; n < count; ++n)
        intArray[n] = ((wxArrayInt&)arr)[n];

    return intArray;
}

wxLuaSmartwxArrayString LUACALL wxlua_getwxArrayString(lua_State* L, int stack_idx)
{
    wxLuaSmartwxArrayString arr(NULL, true); // will added to or replaced
    int count = -1;                          // used to check for failure

    if (lua_istable(L, stack_idx))
    {
        count = 0;

        while (1)
        {
            lua_rawgeti(L, stack_idx, count+1);

            if (wxlua_iswxstringtype(L, -1))
            {
                ((wxArrayString&)arr).Add(wxlua_getwxStringtype(L, -1));
                ++count;

                lua_pop(L, 1);
            }
            else if (lua_isnil(L, -1))
            {
                lua_pop(L, 1);
                break;
            }
            else
            {
                wxlua_argerror(L, stack_idx, wxT("a 'wxArrayString' or table array of strings"));
                return arr;
            }
        }
    }
    else if (wxlua_iswxuserdata(L, stack_idx))
    {
        int arrstr_wxltype = wxluaT_gettype(L, "wxArrayString");

        if (wxluaT_isuserdatatype(L, stack_idx, arrstr_wxltype))
        {
            wxArrayString *arrStr = (wxArrayString *)wxluaT_getuserdatatype(L, stack_idx, arrstr_wxltype);
            if (arrStr)
            {
                arr = wxLuaSmartwxArrayString(arrStr, false); // replace
                count = arrStr->GetCount();
            }
        }
    }

    if (count < 0)
        wxlua_argerror(L, stack_idx, wxT("a 'wxArrayString' or table array of strings"));

    return arr;
}

wxLuaSmartwxSortedArrayString LUACALL wxlua_getwxSortedArrayString(lua_State* L, int stack_idx)
{
    wxLuaSmartwxSortedArrayString arr(NULL, true); // will be replaced
    int count = -1;                                // used to check for failure

    if (lua_istable(L, stack_idx))
    {
        wxLuaSmartwxArrayString a = wxlua_getwxArrayString(L, stack_idx);
        arr = wxLuaSmartwxSortedArrayString(new wxSortedArrayString(a), true);
        count = 0;
    }
    else if (wxlua_iswxuserdata(L, stack_idx))
    {
        int arrstr_wxltype = wxluaT_gettype(L, "wxArrayString");

        if (wxluaT_isuserdatatype(L, stack_idx, arrstr_wxltype))
        {
            wxSortedArrayString *arrStr = (wxSortedArrayString *)wxluaT_getuserdatatype(L, stack_idx, arrstr_wxltype);
            if (arrStr)
            {
                arr = wxLuaSmartwxSortedArrayString(arrStr, false); // replace
                count = arrStr->GetCount();
            }
        }
    }

    if (count < 0)
        wxlua_argerror(L, stack_idx, wxT("a 'wxArrayString' or table array of strings"));

    return arr;
}

wxLuaSmartwxArrayInt LUACALL wxlua_getwxArrayInt(lua_State* L, int stack_idx)
{
    wxLuaSmartwxArrayInt arr(NULL, true); // will be replaced
    int count = -1;                       // used to check for failure

    if (lua_istable(L, stack_idx))
    {
        count = 0;

        while(1)
        {
            lua_rawgeti(L, stack_idx, count+1);

            if (wxlua_isnumbertype(L, -1))
            {
                ((wxArrayInt&)arr).Add((int)lua_tonumber(L, -1));
                ++count;

                lua_pop(L, 1);
            }
            else if (lua_isnil(L, -1))
            {
                lua_pop(L, 1);
                break;
            }
            else
            {
                wxlua_argerror(L, stack_idx, wxT("a 'wxArrayInt' or a table array of integers"));
                return arr;
            }
        }
    }
    else if (wxlua_iswxuserdata(L, stack_idx))
    {
        int arrint_wxltype = wxluaT_gettype(L, "wxArrayInt");

        if (wxluaT_isuserdatatype(L, stack_idx, arrint_wxltype))
        {
            wxArrayInt *arrInt = (wxArrayInt *)wxluaT_getuserdatatype(L, stack_idx, arrint_wxltype);
            if (arrInt)
            {
                arr = wxLuaSmartwxArrayInt(arrInt, false); // replace
                count = arrInt->GetCount();
            }
        }
    }

    if (count < 0)
        wxlua_argerror(L, stack_idx, wxT("a 'wxArrayInt' or a table array of integers"));

    return arr;
}

wxLuaSmartwxArrayDouble LUACALL wxlua_getwxArrayDouble(lua_State* L, int stack_idx)
{
    wxLuaSmartwxArrayDouble arr(NULL, true); // will be replaced
    int count = -1;                       // used to check for failure

    if (lua_istable(L, stack_idx))
    {
        count = 0;

        while(1)
        {
            lua_rawgeti(L, stack_idx, count+1);

            if (wxlua_isnumbertype(L, -1))
            {
                ((wxArrayDouble&)arr).Add(lua_tonumber(L, -1));
                ++count;

                lua_pop(L, 1);
            }
            else if (lua_isnil(L, -1))
            {
                lua_pop(L, 1);
                break;
            }
            else
            {
                wxlua_argerror(L, stack_idx, wxT("a 'wxArrayDouble' or a table array of integers"));
                return arr;
            }
        }
    }
    else if (wxlua_iswxuserdata(L, stack_idx))
    {
        int arrdouble_wxltype = wxluaT_gettype(L, "wxArrayDouble");

        if (wxluaT_isuserdatatype(L, stack_idx, arrdouble_wxltype))
        {
            wxArrayDouble *arrDouble = (wxArrayDouble *)wxluaT_getuserdatatype(L, stack_idx, arrdouble_wxltype);
            if (arrDouble)
            {
                arr = wxLuaSmartwxArrayDouble(arrDouble, false); // replace
                count = arrDouble->GetCount();
            }
        }
    }

    if (count < 0)
        wxlua_argerror(L, stack_idx, wxT("a 'wxArrayDouble' or a table array of numbers"));

    return arr;
}

wxLuaSharedPtr<std::vector<wxPoint> > LUACALL wxlua_getwxPointArray(lua_State* L, int stack_idx)
{
    wxLuaSharedPtr<std::vector<wxPoint> > pointArray(new std::vector<wxPoint>);
    int count = -1;       // used to check for failure
    int is_xy_table = -1; // is it a table with x,y fields or a number array {1,2}

    if (lua_istable(L, stack_idx))
    {
        count = lua_objlen(L, stack_idx); /* get size of table */

        double x, y;
        for (int i = 1; i <= count; ++i)
        {
            lua_rawgeti(L, stack_idx, i); /* get next point as {x,y} */
            int t = wxluaT_type(L, -1);
            if (t == WXLUA_TTABLE)
            {
                // First time, check how it was formatted
                if (is_xy_table == -1)
                {
                    lua_rawgeti(L, -1, 1);
                    is_xy_table = (lua_isnumber(L, -1) == 0) ? 1 : 0;
                    lua_pop(L, 1);
                }

                if (is_xy_table == 1)
                {
                    lua_pushstring(L, "x");
                    lua_rawget(L, -2);
                    if (!lua_isnumber(L, -1))
                        wxlua_argerror(L, stack_idx, wxT("a 'number' for x-coordinate of a wxPoint array, valid tables are {{1,2},...}, {{x=1,y=2},...}, or {wx.wxPoint(1,2),,...}."));
                    x = lua_tonumber(L, -1);
                    lua_pop(L, 1);

                    lua_pushstring(L, "y");
                    lua_rawget(L, -2);
                    if (!lua_isnumber(L, -1))
                        wxlua_argerror(L, stack_idx, wxT("a 'number' for y-coordinate of a wxPoint array, valid tables are {{1,2},...}, {{x=1,y=2},...}, or {wx.wxPoint(1,2),,...}."));
                    y = lua_tonumber(L, -1);
                    lua_pop(L, 1);
                }
                else
                {
                    lua_rawgeti(L, -1, 1);
                    if (!lua_isnumber(L, -1))
                        wxlua_argerror(L, stack_idx, wxT("a 'number' for [1] index (x-coordinate) of a wxPoint array, valid tables {{1,2},...}, {{x=1,y=2},...}, or {wx.wxPoint(1,2),,...}."));
                    x = lua_tonumber(L, -1);
                    lua_pop(L, 1);

                    lua_rawgeti(L, -1, 2);
                    if (!lua_isnumber(L, -1))
                        wxlua_argerror(L, stack_idx, wxT("a 'number' for [2] index (y-coordinate) of a wxPoint array, valid tables {{1,2},...}, {{x=1,y=2},...}, or {wx.wxPoint(1,2),,...}."));
                    y = lua_tonumber(L,-1);
                    lua_pop(L, 1);
                }

                pointArray->push_back(wxPoint((int)x, (int)y));
            }
            else if (t == *p_wxluatype_wxPoint)
            {
                const wxPoint* point = (const wxPoint *)wxluaT_getuserdatatype(L, -1, *p_wxluatype_wxPoint);
                pointArray->push_back(*point);
            }
            else
            {
                wxlua_argerror(L, stack_idx, wxT("a Lua table of 'wxPoints', valid tables {{1,2},...}, {{x=1,y=2},...}, or {wx.wxPoint(1,2),,...}."));
                return pointArray;
            }

            lua_pop(L, 1);
        }
    }
/*

    // Binding the wxPointList is a problem since we have to worry about
    // wxList::DeleteContents() and who calls it, it'll be accident waiting to happen.

    else if (wxlua_iswxuserdata(L, stack_idx))
    {
        int pointlist_wxltype = wxluaT_gettype(L, "wxPointList");

        if (wxluaT_isuserdatatype(L, stack_idx, pointlist_wxltype))
        {
            wxPointList *ptList = (wxPointList *)wxluaT_getuserdatatype(L, stack_idx, pointlist_wxltype);
            if (ptList)
            {
                //pointArray.reset(ptList);
                //pointArray.SetDelete(false);
                count = ptList->GetCount();
            }
        }
    }
*/

    if (count < 0)
        wxlua_argerror(L, stack_idx, wxT("a Lua table of 'wxPoints', valid tables {{1,2},...}, {{x=1,y=2},...}, or {wx.wxPoint(1,2),,...}."));

    return pointArray;
}

wxLuaSharedPtr<std::vector<wxPoint2DDouble> > LUACALL wxlua_getwxPoint2DDoubleArray(lua_State* L, int stack_idx)
{
    wxLuaSharedPtr<std::vector<wxPoint2DDouble> > pointArray(new std::vector<wxPoint2DDouble>);
    int count = -1;       // used to check for failure
    int is_xy_table = -1; // is it a table with x,y fields or a number array {1,2}
    
    if (lua_istable(L, stack_idx))
    {
        count = lua_objlen(L, stack_idx); /* get size of table */
        
        double x, y;
        for (int i = 1; i <= count; ++i)
        {
            lua_rawgeti(L, stack_idx, i); /* get next point as {x,y} */
            int t = wxluaT_type(L, -1);
            if (t == WXLUA_TTABLE)
            {
                // First time, check how it was formatted
                if (is_xy_table == -1)
                {
                    lua_rawgeti(L, -1, 1);
                    is_xy_table = (lua_isnumber(L, -1) == 0) ? 1 : 0;
                    lua_pop(L, 1);
                }
                
                if (is_xy_table == 1)
                {
                    lua_pushstring(L, "x");
                    lua_rawget(L, -2);
                    if (!lua_isnumber(L, -1))
                        wxlua_argerror(L, stack_idx, wxT("a 'number' for x-coordinate of a wxPoint2DDouble array, valid tables are {{1,2},...}, {{x=1,y=2},...}, or {wx.wxPoint2DDouble(1,2),,...}."));
                    x = lua_tonumber(L, -1);
                    lua_pop(L, 1);
                    
                    lua_pushstring(L, "y");
                    lua_rawget(L, -2);
                    if (!lua_isnumber(L, -1))
                        wxlua_argerror(L, stack_idx, wxT("a 'number' for y-coordinate of a wxPoint2DDouble array, valid tables are {{1,2},...}, {{x=1,y=2},...}, or {wx.wxPoint2DDouble(1,2),,...}."));
                    y = lua_tonumber(L, -1);
                    lua_pop(L, 1);
                }
                else
                {
                    lua_rawgeti(L, -1, 1);
                    if (!lua_isnumber(L, -1))
                        wxlua_argerror(L, stack_idx, wxT("a 'number' for [1] index (x-coordinate) of a wxPoint2DDouble array, valid tables {{1,2},...}, {{x=1,y=2},...}, or {wx.wxPoint2DDouble(1,2),,...}."));
                    x = lua_tonumber(L, -1);
                    lua_pop(L, 1);
                    
                    lua_rawgeti(L, -1, 2);
                    if (!lua_isnumber(L, -1))
                        wxlua_argerror(L, stack_idx, wxT("a 'number' for [2] index (y-coordinate) of a wxPoint2DDouble array, valid tables {{1,2},...}, {{x=1,y=2},...}, or {wx.wxPoint2DDouble(1,2),,...}."));
                    y = lua_tonumber(L,-1);
                    lua_pop(L, 1);
                }
                
                pointArray->push_back(wxPoint2DDouble(x, y));
            }
            else if (t == *p_wxluatype_wxPoint2DDouble)
            {
                const wxPoint* point = (const wxPoint *)wxluaT_getuserdatatype(L, -1, *p_wxluatype_wxPoint);
                pointArray->push_back(*point);
            }
            else
            {
                wxlua_argerror(L, stack_idx, wxT("a Lua table of 'wxPoint2DDoubles', valid tables {{1,2},...}, {{x=1,y=2},...}, or {wx.wxPoint2DDouble(1,2),,...}."));
                return pointArray;
            }
            
            lua_pop(L, 1);
        }
    }
    if (count < 0)
        wxlua_argerror(L, stack_idx, wxT("a Lua table of 'wxPoint2DDoubles', valid tables {{1,2},...}, {{x=1,y=2},...}, or {wx.wxPoint2DDouble(1,2),,...}."));
    
    return pointArray;
}

int LUACALL wxlua_pushwxArrayStringtable(lua_State *L, const wxArrayString &strArray)
{
    size_t idx, count = strArray.GetCount();
    lua_createtable(L, count, 0);

    for (idx = 0; idx < count; ++idx)
    {
        wxlua_pushwxString(L, strArray[idx]);
        lua_rawseti(L, -2, idx + 1);
    }
    return idx;
}

int LUACALL wxlua_pushwxArrayInttable(lua_State *L, const wxArrayInt &intArray)
{
    size_t idx, count = intArray.GetCount();
    lua_createtable(L, count, 0);

    for (idx = 0; idx < count; ++idx)
    {
#if LUA_VERSION_NUM >= 503
        lua_pushinteger(L, intArray[idx]);
#else
        lua_pushnumber(L, intArray[idx]);
#endif
        lua_rawseti(L, -2, idx + 1);
    }
    return idx;
}

int LUACALL wxlua_pushwxArrayDoubletable(lua_State *L, const wxArrayDouble &doubleArray)
{
    size_t idx, count = doubleArray.GetCount();
    lua_createtable(L, count, 0);

    for (idx = 0; idx < count; ++idx)
    {
        lua_pushnumber(L, doubleArray[idx]);
        lua_rawseti(L, -2, idx + 1);
    }
    return idx;
}

void LUACALL wxlua_pushwxString(lua_State* L, const wxString& str)
{
    lua_pushstring(L, wx2lua(str));
}

wxString wxlua_concatwxArrayString(const wxArrayString& arr, const wxString& sep)
{
    wxString s;
    size_t n, count = arr.GetCount();
    for (n = 0; n < count; ++n)
    {
        s += arr[n];
        if (n < count - 1) s += sep;
    }

    return s;
}

int wxlua_pushargs(lua_State* L, wxChar **argv, int argc, int start_n)
{
    if (argc == 0) return 0;

    int i = 0;
    int narg = argc - (start_n + 1);  // number of arguments to the script
    luaL_checkstack(L, narg + 3, "too many arguments to script");
    for (i = start_n+1; i < argc; i++)
        lua_pushstring(L, wx2lua(argv[i]));

    lua_createtable(L, narg, start_n + 1);

    for (i = 0; i < argc; i++)
    {
        lua_pushstring(L, wx2lua(argv[i]));
        lua_rawseti(L, -2, i - start_n);
    }

    lua_setglobal(L, "arg");

    return narg;
}

//----------------------------------------------------------------------------
// Derived class member functions for classes in wxLua
//----------------------------------------------------------------------------

bool LUACALL wxlua_setderivedmethod(lua_State* L, void *obj_ptr, const char *method_name, wxLuaObject* wxlObj)
{
    lua_pushlightuserdata(L, &wxlua_lreg_derivedmethods_key); // push key
    lua_rawget( L, LUA_REGISTRYINDEX );                       // pop key, push value (table)

    lua_pushlightuserdata(L, (void *)obj_ptr); // push key
    lua_rawget(L, -2);                         // get t[key] = value, pop key push value

    if (!lua_istable(L, -1))
    {
        lua_pop(L, 1); // pop nil value

        // add new table for this object
        lua_pushlightuserdata(L, (void *)obj_ptr); // push key
        lua_newtable(L);                           // push value
        lua_rawset(L, -3);                         // set t[key] = value; pops key and value

        // put the new table back on the top of the stack
        lua_pushlightuserdata(L, (void *)obj_ptr);
        lua_rawget(L, -2);
    }
    else
    {
        // see if there already is a method
        lua_pushstring( L, method_name );
        lua_rawget(L, -2);

        if (lua_islightuserdata(L, -1))
        {
            // already have a method, delete it before replacing it
            wxLuaObject* o = (wxLuaObject*)lua_touserdata( L, -1 );
            o->RemoveReference(L);
            delete o;
        }

        lua_pop(L, 1); // pop the deleted old object, or nil
    }

    lua_pushstring( L, method_name );        // push key
    lua_pushlightuserdata(L, (void*)wxlObj); // push value
    lua_rawset(L, -3);                       // set t[key] = value; pops key and value

    lua_pop(L, 2); // pop the object and overridden function table

    return true;
}
bool LUACALL wxlua_hasderivedmethod(lua_State* L, const void *obj_ptr, const char *method_name, bool push_method)
{
    bool found = false;
    wxLuaObject* wxlObj = NULL;

    lua_pushlightuserdata(L, &wxlua_lreg_derivedmethods_key);
    lua_rawget( L, LUA_REGISTRYINDEX ); // pop key, push table

    lua_pushlightuserdata(L, (void *)obj_ptr);
    lua_rawget(L, -2); // pop key, push table or nil

    if (lua_istable(L, -1))
    {
        // see if there is a method with the same name
        lua_pushstring( L, method_name );
        lua_rawget(L, -2);

        if (lua_islightuserdata(L, -1))
            wxlObj = (wxLuaObject*)lua_touserdata( L, -1 );

        lua_pop(L, 1); // pop the method object or nil
    }

    lua_pop(L, 2); // pop registry table and object table or nil

    if (wxlObj != NULL)
    {
        // if we've got the object, put it on top of the stack
        if (push_method && wxlObj->GetObject(L))
            found = true;
        else if (!push_method)
            found = true;
    }

    return found;
}
bool LUACALL wxlua_removederivedmethods(lua_State* L, void *obj_ptr)
{
    bool found = false;

    lua_pushlightuserdata(L, &wxlua_lreg_derivedmethods_key);
    lua_rawget( L, LUA_REGISTRYINDEX ); // pop key, push table

    lua_pushlightuserdata(L, (void *)obj_ptr);
    lua_rawget(L, -2); // pop key, push table or nil

    if (lua_istable(L, -1))
    {
        found = true;

        // delete all of the derived methods we've pushed
        lua_pushnil(L);
        while (lua_next(L, -2) != 0)
        {
            // value at -1, key at -2, table at -3
            if (lua_islightuserdata(L, -1))
            {
                wxLuaObject* o = (wxLuaObject*)lua_touserdata(L, -1);
                o->RemoveReference(L);
                delete o;
            }

            lua_pop(L, 1); // remove value; keep key for next iteration
        }

        lua_pop(L, 1);     // pop the obj table

        lua_pushlightuserdata(L, (void *)obj_ptr); // push key
        lua_pushnil(L);                            // push value, to remove it
        lua_rawset(L, -3);                         // set t[key] = value; pop key and value

        lua_pop(L, 1); // pop the derived table
    }
    else
        lua_pop(L, 2); // pop the derived table and nil for the obj table

    return found;
}

//----------------------------------------------------------------------------
// Other functions for wxLua's keys in the
//----------------------------------------------------------------------------

bool LUACALL wxlua_getcallbaseclassfunction(lua_State* L)
{
    lua_pushlightuserdata(L, &wxlua_lreg_callbaseclassfunc_key);
    lua_rawget( L, LUA_REGISTRYINDEX ); // pop key, push bool

    bool call_base = (0 != lua_toboolean(L, -1)); // nil == 0 too
    lua_pop(L, 1);                               // pop bool

    return call_base;
}

void LUACALL wxlua_setcallbaseclassfunction(lua_State* L, bool call_base)
{
    lua_pushlightuserdata(L, &wxlua_lreg_callbaseclassfunc_key);
    lua_pushboolean(L, call_base);
    lua_rawset( L, LUA_REGISTRYINDEX ); // pop key and bool
}

wxEventType LUACALL wxlua_getwxeventtype(lua_State* L)
{
    lua_pushlightuserdata(L, &wxlua_lreg_wxeventtype_key);
    lua_rawget( L, LUA_REGISTRYINDEX ); // pop key, push bool

    wxEventType evt_type = (wxEventType)lua_tonumber(L, -1);
    lua_pop(L, 1); // pop number

    return evt_type;
}

void LUACALL wxlua_setwxeventtype(lua_State* L, wxEventType evt_type)
{
    lua_pushlightuserdata(L, &wxlua_lreg_wxeventtype_key);
    lua_pushnumber(L, evt_type);
    lua_rawset( L, LUA_REGISTRYINDEX ); // pop key and number
}

wxLuaStateData* LUACALL wxlua_getwxluastatedata(lua_State* L)
{
    lua_pushlightuserdata(L, &wxlua_lreg_wxluastatedata_key);
    lua_rawget( L, LUA_REGISTRYINDEX ); // pop key, push bool

    wxLuaStateData* data = (wxLuaStateData*)lua_touserdata(L, -1);
    lua_pop(L, 1); // pop udata

    return data;
}
