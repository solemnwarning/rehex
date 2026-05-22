/* Reverse Engineer's Hex Editor
 * Copyright (C) 2026 Daniel Collins <solemnwarning@solemnwarning.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "../platform.hpp"

#include <stdio.h>

#include <wxlua/wxlstate.h>

#include "rehex_lib_bind.h"

static wxLuaState s_wxlState; // This is our wxLuaState for the module

extern "C" {
    static int reportShutdown(lua_State *L)
    {
        s_wxlState.CloseLuaState(true, false);
        return 0;
    }
}

extern "C"
#ifdef _WIN32
__declspec(dllexport)
#endif
int luaopen_rehex_lib(lua_State *L)
{
    wxLuaBinding_rehex_lib_init();
    s_wxlState.Create(L, wxLUASTATE_SETSTATE|wxLUASTATE_OPENBINDINGS|wxLUASTATE_STATICSTATE);

    lua_getglobal(L, "rehex");

    if (lua_getmetatable(L, -1) != 0) {
        fprintf(stderr, "rehex_lib_module - Error setting up metatable for module rehex, aborting.\n");
        return 0;
    }
    else
    {
        lua_newtable(L); // new metatable for rehex table
        {
            lua_pushstring(L, "__gc");
            lua_pushcfunction(L, reportShutdown);
            lua_rawset(L, -3); // set metatable.__gc = reportShutdown
        }
        lua_setmetatable(L, -2); // sets metatable for rehex table
    }

    return 1;
}
