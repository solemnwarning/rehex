///////////////////////////////////////////////////////////////////////////////
// Name:        wxldefs.h
// Purpose:     wxLua common defines
// Author:      John Labenski
// Created:     5/28/2005
// Copyright:   (c) 2012 John Labenski
// Licence:     wxWidgets licence
///////////////////////////////////////////////////////////////////////////////

#ifndef __WX_WXLDEFS_H__
#define __WX_WXLDEFS_H__

//-----------------------------------------------------------------------------
// Include the Lua headers
//-----------------------------------------------------------------------------

extern "C"
{
    #include "lua.h"
    #include "lualib.h"
    #include "lauxlib.h"

    #if LUA_VERSION_NUM < 502
        #define lua_pushglobaltable(L) lua_pushvalue(L, LUA_GLOBALSINDEX)
        // NOTE: luaL_getn was removed in LuaJIT 2.1.0-beta3
        #ifndef luaL_getn
            #define luaL_getn(L,i)              ((int)lua_objlen(L, i))
        #endif
    #else
        #define luaL_getn luaL_len
        #define LUA_GLOBALSINDEX LUA_RIDX_GLOBALS

        // For compatiblity with Lua 5.1 and 5.2, wxLua needs the luaL_openlib() function.
        // The function is compiled into the Lua library when -DLUA_COMPAT_MODULE is defined
        // when building the Lua library.
        // If you get a unresolved symbol luaL_openlib linker error, you need to rebuild your
        // Lua library with LUA_COMPAT_MODULE defined.
        #if (LUA_VERSION_NUM == 502) & !defined(LUA_COMPAT_MODULE)
            #error wxLua using Lua 5.2 requires LUA_COMPAT_MODULE defined for luaL_openlib().
        #endif

        // These are #defined with LUA_COMPAT_ALL (but we don't require that)
        #ifndef lua_strlen
            #define lua_strlen(L,i)             lua_rawlen(L, (i))
            #define lua_objlen(L,i)             lua_rawlen(L, (i))
            #define lua_equal(L,idx1,idx2)      lua_compare(L,(idx1),(idx2),LUA_OPEQ)
            #define lua_lessthan(L,idx1,idx2)   lua_compare(L,(idx1),(idx2),LUA_OPLT)
        #endif

        #ifndef lua_cpcall
            #define lua_cpcall(L,f,u)           (lua_pushcfunction(L, (f)), \
                                                lua_pushlightuserdata(L,(u)), \
                                                lua_pcall(L,1,0,0))
        #endif
    #endif // LUA_VERSION_NUM < 502
}

#include <wx/defs.h>

#include "wxlversion.h"

//-----------------------------------------------------------------------------
// 2.9 uses char* mostly so for compatibility we need wxT() to not append 'L'
// for wide chars for 2.8, but rather do nothing for 2.9.
// Mainly used for wxCmdLineEntryDesc.

#if wxCHECK_VERSION(2, 9, 0)
    #define wxLuaT(x) (x)
#else
    #define wxLuaT(x) wxT(x)
#endif

// ----------------------------------------------------------------------------
// If you're using stdcall in Lua, then override this with
//   "LUACALL = __stdcall" in your makefile or project.
// ----------------------------------------------------------------------------

#ifndef LUACALL
    #define LUACALL
#endif

// ----------------------------------------------------------------------------
// WXDLLIMPEXP macros for DLL export, import, or neither for static libs.
//   see wxWidgets include/wx/dlimpexp.h
// ----------------------------------------------------------------------------

#ifdef WXMAKINGDLL_WXLUA
    #define WXDLLIMPEXP_WXLUA WXEXPORT
    #define WXDLLIMPEXP_DATA_WXLUA(type) WXEXPORT type
#elif defined(WXUSINGDLL)
    #define WXDLLIMPEXP_WXLUA WXIMPORT
    #define WXDLLIMPEXP_DATA_WXLUA(type) WXIMPORT type
#else // not making nor using DLL
    #define WXDLLIMPEXP_WXLUA
    #define WXDLLIMPEXP_DATA_WXLUA(type) type
#endif

// Forward declare all wxLua classes with this macro
#if defined(HAVE_VISIBILITY) || (defined(__WINDOWS__) && defined(__GNUC__))
    #define WXDLLIMPEXP_FWD_WXLUA
#else
    #define WXDLLIMPEXP_FWD_WXLUA WXDLLIMPEXP_WXLUA
#endif

// ----------------------------------------------------------------------------
// Blank dummy defines that may be used in the bindings to not import or export
// a class or data in a DLL.
// ----------------------------------------------------------------------------

#define WXLUA_NO_DLLIMPEXP           // use if you don't want to export class
#define WXLUA_NO_DLLIMPEXP_DATA(x) x // use if you don't want to export data

// ----------------------------------------------------------------------------
// Useful macros to make coding easier
// ----------------------------------------------------------------------------

#if wxUSE_UNICODE && !wxCHECK_VERSION(2,9,0)
    #define wxLUA_UNICODE_ONLY(x) x
#else /* !Unicode */
    #define wxLUA_UNICODE_ONLY(x)
#endif // wxUSE_UNICODE


#define WXLUA_HASBIT(value, bit)      (((value) & (bit)) != 0)
#define WXLUA_SETBIT(value, bit, set) ((set) ? (value)|(bit) : (value)&(~(bit)))

// ----------------------------------------------------------------------------
// Lua defines for making the code more readable
// ----------------------------------------------------------------------------

// initializes a lua_debug by nulling everything before use since the
//  functions that take it do not initialize it properly
#if LUA_VERSION_NUM >= 504 // 5.4
#define INIT_LUA_DEBUG { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, {0}, 0 }
#elif LUA_VERSION_NUM >= 502 // 5.2
    #define INIT_LUA_DEBUG { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, {0}, 0 }
#else // 501, 5.1
    #define INIT_LUA_DEBUG { 0, 0, 0, 0, 0, 0, 0, 0, 0, {0}, 0 }
#endif

// Create a wxString from the lua_Debug struct for debugging
#define lua_Debug_to_wxString(ld) \
    wxString::Format(wxT("%p event=%d name='%s' namewhat='%s' what='%s' source='%s' currentline=%d nups=%d linedefined=%d lastlinedefined=%d short_src='%s' i_ci=%d"), \
    &ld, ld.event, lua2wx(ld.name).c_str(), lua2wx(ld.namewhat).c_str(), lua2wx(ld.what).c_str(), lua2wx(ld.source).c_str(), ld.currentline, ld.nups, ld.linedefined, ld.lastlinedefined, lua2wx(ld.short_src).c_str(), ld.i_ci)

// ----------------------------------------------------------------------------
// wxWidgets compatibility defines
// ----------------------------------------------------------------------------

#ifndef wxUSE_WAVE
    #define wxUSE_WAVE 0
#endif
#ifndef wxUSE_SOUND
    #define wxUSE_SOUND 0
#endif

// ----------------------------------------------------------------------------
// Forward declared classes
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_FWD_WXLUA wxLuaState;


#endif  // __WX_WXLDEFS_H__
