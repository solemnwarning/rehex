// ----------------------------------------------------------------------------
// Overridden functions for the wxLua binding for wxLua
//
// Please keep these functions in the same order as the .i file and in the
// same order as the listing of the functions in that file.
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// Overrides for wxlua.i
// ----------------------------------------------------------------------------

%override wxLua_function_CompileLuaScript
// %function int CompileLuaScript(const wxString& luaScript, const wxString& fileName)
static int LUACALL wxLua_function_CompileLuaScript(lua_State *L)
{
    int returns;
    // const wxString fileName
    const wxString fileName = wxlua_getwxStringtype(L, 2);
    // const wxString luaScript
    const wxString luaScript = wxlua_getwxStringtype(L, 1);
    wxString errMsg;
    int line_num = -1;
    wxLuaState wxlState2(true); // create a brand new empty lua state to compile in
    returns = wxlState2.CompileString(luaScript, fileName, &errMsg, &line_num);
    // push the result number
    lua_pushnumber(L, returns);
    wxlua_pushwxString(L, errMsg);
    lua_pushnumber(L, line_num);
    return 3;
}
%end

%override wxLua_function_GetTrackedWindowInfo
// %function LuaTable GetTrackedWindowInfo(bool as_string = false)
static int LUACALL wxLua_function_GetTrackedWindowInfo(lua_State *L)
{
    bool as_string = (0 != lua_toboolean(L, 1)); // ok if nil
    if (as_string)
        wxlua_pushwxString(L, wxlua_concatwxArrayString(wxluaW_gettrackedwindowinfo(L)));
    else
        wxlua_pushwxArrayStringtable(L, wxluaW_gettrackedwindowinfo(L));

    return 1;
}
%end

%override wxLua_function_GetGCUserdataInfo
// %function LuaTable GetGCUserdataInfo(bool as_string = false)
static int LUACALL wxLua_function_GetGCUserdataInfo(lua_State *L)
{
    bool as_string = (0 != lua_toboolean(L, 1)); // ok if nil
    if (as_string)
        wxlua_pushwxString(L, wxlua_concatwxArrayString(wxluaO_getgcobjectinfo(L)));
    else
        wxlua_pushwxArrayStringtable(L, wxluaO_getgcobjectinfo(L));

    return 1;
}
%end

%override wxLua_function_GetTrackedObjectInfo
// %function LuaTable GetTrackedObjectInfo(bool as_string = false)
static int LUACALL wxLua_function_GetTrackedObjectInfo(lua_State *L)
{
    bool as_string = (0 != lua_toboolean(L, 1)); // ok if nil
    if (as_string)
        wxlua_pushwxString(L, wxlua_concatwxArrayString(wxluaO_gettrackedweakobjectinfo(L)));
    else
        wxlua_pushwxArrayStringtable(L, wxluaO_gettrackedweakobjectinfo(L));

    return 1;
}
%end

%override wxLua_function_GetTrackedEventCallbackInfo
// %function LuaTable GetTrackedEventCallbackInfo(bool as_string = false)
static int LUACALL wxLua_function_GetTrackedEventCallbackInfo(lua_State *L)
{
    wxLuaState wxlState(L);
    bool as_string = (0 != lua_toboolean(L, 1)); // ok if nil
    if (as_string)
        wxlua_pushwxString(L, wxlua_concatwxArrayString(wxlState.GetTrackedEventCallbackInfo()));
    else
        wxlua_pushwxArrayStringtable(L, wxlState.GetTrackedEventCallbackInfo());

    return 1;
}
%end

%override wxLua_function_GetTrackedWinDestroyCallbackInfo
// %function LuaTable GetTrackedWinDestroyCallbackInfo(bool as_string = false)
static int LUACALL wxLua_function_GetTrackedWinDestroyCallbackInfo(lua_State *L)
{
    wxLuaState wxlState(L);
    bool as_string = (0 != lua_toboolean(L, 1)); // ok if nil
    if (as_string)
        wxlua_pushwxString(L, wxlua_concatwxArrayString(wxlState.GetTrackedWinDestroyCallbackInfo()));
    else
        wxlua_pushwxArrayStringtable(L, wxlState.GetTrackedWinDestroyCallbackInfo());

    return 1;
}
%end

%override wxLua_function_isgcobject
// %function bool isgcobject(void* object)
static int LUACALL wxLua_function_isgcobject(lua_State *L)
{
    bool ret = false;
    if (wxlua_iswxuserdatatype(wxluaT_type(L, 1)))
    {
        void* obj_ptr = wxlua_touserdata(L, 1, false);
        ret = wxluaO_isgcobject(L, obj_ptr);
    }

    lua_pushboolean(L, ret);
    return 1;
}
%end

%override wxLua_function_istrackedobject
// %function bool istrackedobject(void* object)
static int LUACALL wxLua_function_istrackedobject(lua_State *L)
{
    bool ret = false;
    int wxl_type = wxluaT_type(L, 1);

    if (wxlua_iswxuserdatatype(wxl_type))
    {
        void* obj_ptr = wxlua_touserdata(L, 1, false);
        ret = wxluaO_istrackedweakobject(L, obj_ptr, wxl_type, false);
    }

    lua_pushboolean(L, ret);
    return 1;
}
%end

%override wxLua_function_isrefed
// %function bool isrefed(void* object)
static int LUACALL wxLua_function_isrefed(lua_State *L)
{
    bool ret = wxluaR_isrefed(L, 1, &wxlua_lreg_refs_key) != LUA_NOREF;

    lua_pushboolean(L, ret);
    return 1;
}
%end


%override wxLua_function_gcobject
// %function bool gcobject(void* object)
static int LUACALL wxLua_function_gcobject(lua_State *L)
{
    bool ret = false;
    if (!wxluaO_isgcobject(L, 1))
    {
        FIXME do we need to implement this function for anybody
        ret = true;
    }

    lua_pushboolean(L, ret);
    return 1;
}
%end

%override wxLua_function_ungcobject
// %function bool ungcobject(void* object)
static int LUACALL wxLua_function_ungcobject(lua_State *L)
{
    bool ret = false;

    int l_type = lua_type(L, 1);

    if (!wxlua_iswxluatype(l_type, WXLUA_TUSERDATA))
        wxlua_argerror(L, 1, wxT("a 'userdata'"));

    void* o = wxlua_touserdata(L, 1, false);

    if (wxluaO_isgcobject(L, o))
    {
        ret = wxluaO_undeletegcobject(L, o);
    }

    lua_pushboolean(L, ret);
    return 1;
}
%end


%override wxLua_function_type
// %function int type(int wxluaarg_tag)
static int LUACALL wxLua_function_type(lua_State *L)
{
    int ltype = lua_type(L, 1);
    const char* ltypename = lua_typename(L, ltype);

    int wxl_type = wxluaT_type(L, 1);
    wxString wxltypeName = wxluaT_typename(L, wxl_type);

    // push the results
    lua_pushstring(L, wx2lua(wxltypeName));
    lua_pushnumber(L, wxl_type);

    lua_pushstring(L, ltypename);
    lua_pushnumber(L, ltype);

    return 4;
}
%end

%override wxLua_function_typename
// %function wxString typename(int wxluaarg_tag)
static int LUACALL wxLua_function_typename(lua_State *L)
{
    // int wxluaarg_tag
    int wxl_type = (int)wxlua_getnumbertype(L, 1);
    // call wxlua_getwxluatypename
    wxString returns = wxluaT_typename(L, wxl_type);
    // push the result string
    wxlua_pushwxString(L, returns);

    return 1;
}
%end

// ===========================================================================
// ===========================================================================

%override wxLua_function_GetBindings

int LUACALL wxluabind_wxLuaBinding__index(lua_State* L);

// %function LuaTable GetBindings()
static int LUACALL wxLua_function_GetBindings(lua_State *L)
{
    lua_newtable(L); // the table that we return

    int idx = 1;

    wxLuaBindingArray& wxlbArray = wxLuaBinding::GetBindingArray();
    size_t n, count = wxlbArray.GetCount();

    for (n = 0; n < count; n++, idx++)
    {
        // Push function to access the binding info
        const void **ptr = (const void **)lua_newuserdata(L, sizeof(void *));
        *ptr = wxlbArray[n];
            lua_newtable(L);
            lua_pushstring(L, "__index");
            lua_pushlightuserdata(L, wxlbArray[n]);                // push tag to recognize table call
            lua_pushcclosure(L, wxluabind_wxLuaBinding__index, 1); // push func with tag as upvalue
            lua_rawset(L, -3);

            //lua_pushstring(L, "__metatable");
            //lua_pushstring(L, "Metatable is not accessible");
            //lua_rawset(L, -3);

            lua_setmetatable(L, -2);

        lua_rawseti(L, -2, idx);
    }

    return 1;
}

//-----------------------------------------------------------------------------
// wxluabind_wxLuaBindCFunc__index
//-----------------------------------------------------------------------------
int LUACALL wxluabind_wxLuaBindClass__index(lua_State* L);

int LUACALL wxluabind_wxLuaBindCFunc__index(lua_State* L)
{
    static const char* fields[] = { "lua_cfunc",
                                    "method_type",
                                    "minargs",
                                    "maxargs",
                                    "argtypes",
                                    "class",
                                    "class_name" };
    static const size_t fields_count = sizeof(fields)/sizeof(fields[0]);

    void **ptr = (void **)lua_touserdata(L, 1);
    wxLuaBindCFunc* wxlCFunc= (wxLuaBindCFunc*)*ptr;
    wxLuaBinding *wxlBinding = (wxLuaBinding *)lua_touserdata(L, lua_upvalueindex(1));

    int idx_type = lua_type(L, 2);

    if (idx_type == LUA_TSTRING)
    {
        const char* idx_str = lua_tostring(L, 2);

        if (strcmp(idx_str, "fields") == 0)
        {
            lua_newtable(L);
            for (size_t i = 0; i < fields_count; ++i)
            {
                lua_pushstring(L, fields[i]);
                lua_rawseti(L, -2, i + 1);
            }
            return 1;
        }
        else if (strcmp(idx_str, "lua_cfunc") == 0)
        {
            lua_pushcfunction(L, wxlCFunc->lua_cfunc);
            return 1;
        }
        else if (strcmp(idx_str, "method_type") == 0)
        {
            lua_pushnumber(L, wxlCFunc->method_type);
            return 1;
        }
        else if (strcmp(idx_str, "minargs") == 0)
        {
            lua_pushnumber(L, wxlCFunc->minargs);
            return 1;
        }
        else if (strcmp(idx_str, "maxargs") == 0)
        {
            lua_pushnumber(L, wxlCFunc->maxargs);
            return 1;
        }
        else if (strcmp(idx_str, "argtypes") == 0)
        {
            size_t idx, count = wxlCFunc->maxargs;
            lua_createtable(L, count, 0);

            // check for terminating null in argtypes
            for (idx = 0; (idx < count) && wxlCFunc->argtypes[idx]; ++idx)
            {
                lua_pushnumber(L, *wxlCFunc->argtypes[idx]);
                lua_rawseti(L, -2, idx + 1);
            }

            return 1;
        }
        else if (strcmp(idx_str, "class") == 0)
        {
            const wxLuaBindClass* c = wxlBinding->GetBindClass(wxlCFunc);
            if (c != NULL)
            {
                const void **ptr = (const void **)lua_newuserdata(L, sizeof(void *));
                *ptr = c;
                    lua_newtable(L);
                    lua_pushstring(L, "__index");
                    lua_pushlightuserdata(L, wxlBinding);
                    lua_pushcclosure(L, wxluabind_wxLuaBindClass__index, 1); // push func with tag as upvalue
                    lua_rawset(L, -3);
                    lua_setmetatable(L, -2);

                return 1;
            }
        }
        else if (strcmp(idx_str, "class_name") == 0)
        {
            const wxLuaBindClass* c = wxlBinding->GetBindClass(wxlCFunc);
            if (c != NULL)
            {
                lua_pushstring(L, c->name);
                return 1;
            }
        }
    }

    return 0;
}

//-----------------------------------------------------------------------------
// wxluabind_wxLuaBindMethod__index
//-----------------------------------------------------------------------------

int LUACALL wxluabind_wxLuaBindMethod__index(lua_State* L)
{
    static const char* fields[] = { "name",
                                    "method_type",
                                    "wxluacfuncs",
                                    "wxluacfuncs_n",
                                    "basemethod",
                                    "class",
                                    "class_name" };
    static const size_t fields_count = sizeof(fields)/sizeof(fields[0]);

    void **ptr = (void **)lua_touserdata(L, 1);
    wxLuaBindMethod* wxlMethod = (wxLuaBindMethod*)*ptr;
    wxLuaBinding *wxlBinding = (wxLuaBinding *)lua_touserdata(L, lua_upvalueindex(1));

    int idx_type = lua_type(L, 2);

    if (idx_type == LUA_TSTRING)
    {
        const char* idx_str = lua_tostring(L, 2);

        if (strcmp(idx_str, "fields") == 0)
        {
            lua_newtable(L);
            for (size_t i = 0; i < fields_count; ++i)
            {
                lua_pushstring(L, fields[i]);
                lua_rawseti(L, -2, i + 1);
            }
            return 1;
        }
        else if (strcmp(idx_str, "name") == 0)
        {
            lua_pushstring(L, wxlMethod->name);
            return 1;
        }
        else if (strcmp(idx_str, "method_type") == 0)
        {
            lua_pushnumber(L, wxlMethod->method_type);
            return 1;
        }
        else if (strcmp(idx_str, "wxluacfuncs") == 0)
        {
            wxLuaBindCFunc* wxlCFunc = wxlMethod->wxluacfuncs;
            size_t idx, count = wxlMethod->wxluacfuncs_n;
            lua_createtable(L, count, 0);

            for (idx = 0; idx < count; ++idx, ++wxlCFunc)
            {
                const void **ptr = (const void **)lua_newuserdata(L, sizeof(void *));
                *ptr = wxlCFunc;
                    lua_newtable(L);
                    lua_pushstring(L, "__index");
                    lua_pushlightuserdata(L, wxlBinding);
                    lua_pushcclosure(L, wxluabind_wxLuaBindCFunc__index, 1); // push func with tag as upvalue
                    lua_rawset(L, -3);
                    lua_setmetatable(L, -2);

                lua_rawseti(L, -2, idx + 1);
            }

            return 1;
        }
        else if (strcmp(idx_str, "wxluacfuncs_n") == 0)
        {
            lua_pushnumber(L, wxlMethod->wxluacfuncs_n);
            return 1;
        }
        else if (strcmp(idx_str, "basemethod") == 0)
        {
            if (wxlMethod->basemethod)
            {
                const void **ptr = (const void **)lua_newuserdata(L, sizeof(void *));
                *ptr = wxlMethod->basemethod;
                    lua_newtable(L);
                    lua_pushstring(L, "__index");
                    lua_pushlightuserdata(L, wxlBinding);
                    lua_pushcclosure(L, wxluabind_wxLuaBindMethod__index, 1); // push func with tag as upvalue
                    lua_rawset(L, -3);
                    lua_setmetatable(L, -2);

                return 1;
            }

            return 0;
        }
        else if (strcmp(idx_str, "class") == 0)
        {
            const wxLuaBindClass* c = wxlBinding->GetBindClass(wxlMethod);
            if (c != NULL)
            {
                const void **ptr = (const void **)lua_newuserdata(L, sizeof(void *));
                *ptr = c;
                    lua_newtable(L);
                    lua_pushstring(L, "__index");
                    lua_pushlightuserdata(L, wxlBinding);
                    lua_pushcclosure(L, wxluabind_wxLuaBindClass__index, 1); // push func with tag as upvalue
                    lua_rawset(L, -3);
                    lua_setmetatable(L, -2);

                return 1;
            }
        }
        else if (strcmp(idx_str, "class_name") == 0)
        {
            const wxLuaBindClass* c = wxlBinding->GetBindClass(wxlMethod);
            if (c != NULL)
            {
                lua_pushstring(L, c->name);
                return 1;
            }
        }
    }

    return 0;
}

//-----------------------------------------------------------------------------
// wxluabind_wxLuaBindClass__index
//-----------------------------------------------------------------------------

int LUACALL wxluabind_wxLuaBindClass__index(lua_State* L)
{
    static const char* fields[] = { "name",
                                    "wxluamethods",
                                    "wxluamethods_n",
                                    "classInfo",
                                    "wxluatype",
                                    "baseclassNames",
                                    "baseBindClasses",
                                    "baseclass_wxluatypes",
                                    "baseclass_vtable_offsets",
                                    "enums",
                                    "enums_n" };
    static const size_t fields_count = sizeof(fields)/sizeof(fields[0]);

    void **ptr = (void **)lua_touserdata(L, 1);
    wxLuaBindClass* wxlClass = (wxLuaBindClass*)*ptr;
    wxLuaBinding *wxlBinding = (wxLuaBinding *)lua_touserdata(L, lua_upvalueindex(1));

    int idx_type = lua_type(L, 2);

    if (idx_type == LUA_TSTRING)
    {
        const char* idx_str = lua_tostring(L, 2);

        if (strcmp(idx_str, "fields") == 0)
        {
            lua_newtable(L);
            for (size_t i = 0; i < fields_count; ++i)
            {
                lua_pushstring(L, fields[i]);
                lua_rawseti(L, -2, i + 1);
            }
            return 1;
        }
        else if (strcmp(idx_str, "name") == 0)
        {
            lua_pushstring(L, wxlClass->name);
            return 1;
        }
        else if (strcmp(idx_str, "wxluamethods") == 0)
        {
            size_t idx, count = wxlClass->wxluamethods_n;
            lua_createtable(L, count, 0);
            if (wxlClass->wxluamethods_n > 0)
            {
                wxLuaBindMethod* wxlMethod = wxlClass->wxluamethods;

                for (idx = 0; idx < count; ++idx, ++wxlMethod)
                {
                    // Create table { wxLuaBindClass userdata }
                    const void **ptr = (const void **)lua_newuserdata(L, sizeof(void *));
                    *ptr = wxlMethod;
                        lua_newtable(L);
                        lua_pushstring(L, "__index");
                        lua_pushlightuserdata(L, wxlBinding);
                        lua_pushcclosure(L, wxluabind_wxLuaBindMethod__index, 1); // push func with tag as upvalue
                        lua_rawset(L, -3);
                        lua_setmetatable(L, -2);

                    lua_rawseti(L, -2, idx + 1);
                }

                lua_pushstring(L, "wxLuaBindClass"); // so we know where this came from
                lua_pushvalue(L, 1);
                lua_rawset(L, -3);
            }

            return 1;
        }
        else if (strcmp(idx_str, "wxluamethods_n") == 0)
        {
            lua_pushnumber(L, wxlClass->wxluamethods_n);
            return 1;
        }
        else if (strcmp(idx_str, "classInfo") == 0)
        {
            if (wxlClass->classInfo)
            {
                const wxLuaBindClass* classInfoClass = wxluaT_getclass(L, "wxClassInfo");
                if (classInfoClass)
                {
                    wxluaT_pushuserdatatype(L, wxlClass->classInfo, *classInfoClass->wxluatype);
                    return 1;
                }
            }

            return 0;
        }
        else if (strcmp(idx_str, "wxluatype") == 0)
        {
            lua_pushnumber(L, *wxlClass->wxluatype);
            return 1;
        }
        else if (strcmp(idx_str, "baseclassNames") == 0)
        {
            lua_newtable(L);
            if (wxlClass->baseclassNames)
            {
                for (size_t i = 0; wxlClass->baseclassNames[i]; ++i)
                {
                    lua_pushstring(L, wxlClass->baseclassNames[i]);
                    lua_rawseti(L, -2, i + 1);
                }
            }

            return 1;
        }
        else if (strcmp(idx_str, "baseBindClasses") == 0)
        {
            lua_newtable(L);
            if (wxlClass->baseBindClasses)
            {
                for (size_t i = 0; wxlClass->baseclassNames[i]; ++i) // use names to check for terminating NULL
                {
                    if (wxlClass->baseBindClasses[i] == NULL) // may be NULL if not loaded
                    {
                        lua_pushnil(L);
                    }
                    else
                    {
                        const void **ptr = (const void **)lua_newuserdata(L, sizeof(void *));
                        *ptr = wxlClass->baseBindClasses[i];
                            lua_newtable(L);
                            lua_pushstring(L, "__index");
                            lua_pushlightuserdata(L, wxlBinding);
                            lua_pushcclosure(L, wxluabind_wxLuaBindClass__index, 1); // push func with tag as upvalue
                            lua_rawset(L, -3);
                            lua_setmetatable(L, -2);
                    }

                    lua_rawseti(L, -2, i + 1);
                }
            }

            return 1;
        }
        else if (strcmp(idx_str, "baseclass_wxluatypes") == 0)
        {
            lua_newtable(L);
            if (wxlClass->baseclass_wxluatypes)
            {
                size_t i = 0;
                while (wxlClass->baseclass_wxluatypes[i])
                {
                    lua_pushnumber(L, *wxlClass->baseclass_wxluatypes[i]);
                    lua_rawseti(L, -2, i + 1);
                    ++i;
                }
            }

            return 1;
        }
        else if (strcmp(idx_str, "baseclass_vtable_offsets") == 0)
        {
            lua_newtable(L);
            if (wxlClass->baseclass_wxluatypes) // check this for NULL not baseclass_vtable_offsets
            {
                size_t i = 0;
                while (wxlClass->baseclass_wxluatypes[i]) // see above
                {
                    lua_pushnumber(L, wxlClass->baseclass_vtable_offsets[i]);
                    lua_rawseti(L, -2, i + 1);
                    ++i;
                }
            }

            return 1;
        }
        else if (strcmp(idx_str, "enums") == 0)
        {
            size_t idx, count = wxlClass->enums_n;
            lua_createtable(L, count, 0);
            if (wxlClass->enums_n > 0)
            {
                wxLuaBindNumber* wxlNumber = wxlClass->enums;

                for (idx = 0; idx < count; ++idx, ++wxlNumber)
                {
                    // Create table { name, value }
                    lua_createtable(L, 0, 2);
                    lua_pushstring(L, "name");
                    lua_pushstring(L, wxlNumber->name);
                    lua_rawset(L, -3);
                    lua_pushstring(L, "value");
                    lua_pushnumber(L, wxlNumber->value);
                    lua_rawset(L, -3);

                    lua_rawseti(L, -2, idx + 1);
                }

                //lua_pushstring(L, "wxLuaBindClass"); // so we know where this came from
                //lua_pushvalue(L, 1);
                //lua_rawset(L, -3);
            }

            return 1;
        }
        else if (strcmp(idx_str, "enums_n") == 0)
        {
            lua_pushnumber(L, wxlClass->enums_n);
            return 1;
        }
    }

    return 0;
}

//-----------------------------------------------------------------------------
// wxluabind_wxLuaBinding__index
//-----------------------------------------------------------------------------

int LUACALL wxluabind_wxLuaBinding__index(lua_State* L)
{
    static const char* fields[] = { "GetBindingName",
                                    "GetLuaNamespace",
                                    "GetClassCount",
                                    "GetFunctionCount",
                                    "GetNumberCount",
                                    "GetStringCount",
                                    "GetEventCount",
                                    "GetObjectCount",
                                    "GetClassArray",
                                    "GetFunctionArray",
                                    "GetNumberArray",
                                    "GetStringArray",
                                    "GetEventArray",
                                    "GetObjectArray" };
    static const size_t fields_count = sizeof(fields)/sizeof(fields[0]);

    void **ptr = (void **)lua_touserdata(L, 1);
    wxLuaBinding* wxlBinding = (wxLuaBinding*)*ptr;

    int idx_type = lua_type(L, 2);

    if (idx_type == LUA_TSTRING)
    {
        const char* idx_str = lua_tostring(L, 2);

        if (strcmp(idx_str, "fields") == 0)
        {
            lua_newtable(L);
            for (size_t i = 0; i < fields_count; ++i)
            {
                lua_pushstring(L, fields[i]);
                lua_rawseti(L, -2, i + 1);
            }
            return 1;
        }
        else if (strcmp(idx_str, "GetBindingName") == 0)
        {
            lua_pushstring(L, wx2lua(wxlBinding->GetBindingName()));
            return 1;
        }
        else if (strcmp(idx_str, "GetLuaNamespace") == 0)
        {
            lua_pushstring(L, wx2lua(wxlBinding->GetLuaNamespace()));
            return 1;
        }
        else if (strcmp(idx_str, "GetClassCount") == 0)
        {
            lua_pushnumber(L, wxlBinding->GetClassCount());
            return 1;
        }
        else if (strcmp(idx_str, "GetFunctionCount") == 0)
        {
            lua_pushnumber(L, wxlBinding->GetFunctionCount());
            return 1;
        }
        else if (strcmp(idx_str, "GetNumberCount") == 0)
        {
            lua_pushnumber(L, wxlBinding->GetNumberCount());
            return 1;
        }
        else if (strcmp(idx_str, "GetStringCount") == 0)
        {
            lua_pushnumber(L, wxlBinding->GetStringCount());
            return 1;
        }
        else if (strcmp(idx_str, "GetEventCount") == 0)
        {
            lua_pushnumber(L, wxlBinding->GetEventCount());
            return 1;
        }
        else if (strcmp(idx_str, "GetObjectCount") == 0)
        {
            lua_pushnumber(L, wxlBinding->GetObjectCount());
            return 1;
        }
        else if (strcmp(idx_str, "GetClassArray") == 0)
        {
            wxLuaBindClass* wxlClass = wxlBinding->GetClassArray();
            size_t idx, count = wxlBinding->GetClassCount();
            lua_createtable(L, count, 0);

            for (idx = 0; idx < count; ++idx, ++wxlClass)
            {
                // Create table { wxLuaBindClass userdata }
                const void **ptr = (const void **)lua_newuserdata(L, sizeof(void *));
                *ptr = wxlClass;
                    lua_newtable(L);
                    lua_pushstring(L, "__index");
                    lua_pushlightuserdata(L, wxlBinding);
                    lua_pushcclosure(L, wxluabind_wxLuaBindClass__index, 1); // push func with tag as upvalue
                    lua_rawset(L, -3);
                    lua_setmetatable(L, -2);

                lua_rawseti(L, -2, idx + 1);
            }

            return 1;
        }
        else if (strcmp(idx_str, "GetFunctionArray") == 0)
        {
            wxLuaBindMethod* wxlMethod = wxlBinding->GetFunctionArray();
            size_t idx, count = wxlBinding->GetFunctionCount();
            lua_createtable(L, count, 0);

            for (idx = 0; idx < count; ++idx, ++wxlMethod)
            {
                // Create table { wxLuaBindClass userdata }
                const void **ptr = (const void **)lua_newuserdata(L, sizeof(void *));
                *ptr = wxlMethod;
                    lua_newtable(L);
                    lua_pushstring(L, "__index");
                    lua_pushlightuserdata(L, wxlBinding);
                    lua_pushcclosure(L, wxluabind_wxLuaBindMethod__index, 1); // push func with tag as upvalue
                    lua_rawset(L, -3);
                    lua_setmetatable(L, -2);

                lua_rawseti(L, -2, idx + 1);
            }

            return 1;
        }
        else if (strcmp(idx_str, "GetNumberArray") == 0)
        {
            wxLuaBindNumber* wxlNumber = wxlBinding->GetNumberArray();
            size_t idx, count = wxlBinding->GetNumberCount();
            lua_createtable(L, count, 0);

            for (idx = 0; idx < count; ++idx, ++wxlNumber)
            {
                // Create table { name, value }
                lua_createtable(L, 0, 2);
                lua_pushstring(L, "name");
                lua_pushstring(L, wxlNumber->name);
                lua_rawset(L, -3);
                lua_pushstring(L, "value");
                lua_pushnumber(L, wxlNumber->value);
                lua_rawset(L, -3);

                lua_rawseti(L, -2, idx + 1);
            }

            return 1;
        }
        else if (strcmp(idx_str, "GetStringArray") == 0)
        {
            wxLuaBindString* wxlString = wxlBinding->GetStringArray();
            size_t idx, count = wxlBinding->GetStringCount();
            lua_createtable(L, count, 0);

            for (idx = 0; idx < count; ++idx, ++wxlString)
            {
                // Create table { name, value }
                lua_createtable(L, 0, 2);
                lua_pushstring(L, "name");
                lua_pushstring(L, wxlString->name);
                lua_rawset(L, -3);
                lua_pushstring(L, "value");
                if (wxlString->wxchar_string != NULL)
                    lua_pushstring(L, wx2lua(wxlString->wxchar_string));
                else
                    lua_pushstring(L, wxlString->c_string);
                lua_rawset(L, -3);

                lua_rawseti(L, -2, idx + 1);
            }

            return 1;
        }
        else if (strcmp(idx_str, "GetEventArray") == 0)
        {
            wxLuaBindEvent* wxlEvent = wxlBinding->GetEventArray();
            size_t idx, count = wxlBinding->GetEventCount();
            lua_createtable(L, count, 0);

            for (idx = 0; idx < count; ++idx, ++wxlEvent)
            {
                // Create table { name, eventType, wxluatype }
                lua_createtable(L, 0, 3);
                lua_pushstring(L, "name");
                lua_pushstring(L, wxlEvent->name);
                lua_rawset(L, -3);
                lua_pushstring(L, "eventType");
                lua_pushnumber(L, *wxlEvent->eventType);
                lua_rawset(L, -3);
                lua_pushstring(L, "wxluatype");
                lua_pushnumber(L, *wxlEvent->wxluatype);
                lua_rawset(L, -3);

                lua_pushstring(L, "wxLuaBindClass");
                const wxLuaBindClass* wxlClass = wxlBinding->GetBindClass(*wxlEvent->wxluatype);
                if (wxlClass == NULL)
                {
                    lua_pushnil(L);
                }
                else
                {
                    const void **ptr = (const void **)lua_newuserdata(L, sizeof(void *));
                    *ptr = wxlClass;
                        lua_newtable(L);
                        lua_pushstring(L, "__index");
                        lua_pushlightuserdata(L, wxlBinding);
                        lua_pushcclosure(L, wxluabind_wxLuaBindClass__index, 1); // push func with tag as upvalue
                        lua_rawset(L, -3);
                        lua_setmetatable(L, -2);
                }
                lua_rawset(L, -3);

                lua_rawseti(L, -2, idx + 1);
            }

            return 1;
        }
        else if (strcmp(idx_str, "GetObjectArray") == 0)
        {
            wxLuaBindObject* wxlObject = wxlBinding->GetObjectArray();
            size_t idx, count = wxlBinding->GetObjectCount();
            lua_createtable(L, count, 0);

            for (idx = 0; idx < count; ++idx, ++wxlObject)
            {
                // Create table { name, object, wxluatype }
                lua_createtable(L, 0, 3);
                lua_pushstring(L, "name");
                lua_pushstring(L, wxlObject->name);
                lua_rawset(L, -3);

                lua_pushstring(L, "object");
                if (wxlObject->objPtr != 0)
                    wxluaT_pushuserdatatype(L, wxlObject->objPtr, *wxlObject->wxluatype, false);
                else
                    wxluaT_pushuserdatatype(L, *wxlObject->pObjPtr, *wxlObject->wxluatype, false);
                lua_rawset(L, -3);

                lua_pushstring(L, "wxluatype");
                lua_pushnumber(L, *wxlObject->wxluatype);
                lua_rawset(L, -3);

                lua_pushstring(L, "wxLuaBindClass");
                const wxLuaBindClass* wxlClass = wxlBinding->GetBindClass(*wxlObject->wxluatype);
                if (wxlClass == NULL)
                {
                    lua_pushnil(L);
                }
                else
                {
                    const void **ptr = (const void **)lua_newuserdata(L, sizeof(void *));
                    *ptr = wxlClass;
                        lua_newtable(L);
                        lua_pushstring(L, "__index");
                        lua_pushlightuserdata(L, wxlBinding);
                        lua_pushcclosure(L, wxluabind_wxLuaBindClass__index, 1); // push func with tag as upvalue
                        lua_rawset(L, -3);
                        lua_setmetatable(L, -2);
                }
                lua_rawset(L, -3);

                lua_rawseti(L, -2, idx + 1);
            }

            return 1;
        }
    }

    return 0;
}

%end


// ===========================================================================
// ===========================================================================

%override wxLua_wxLuaObject_constructor
// wxLuaObject(void *object)
static int LUACALL wxLua_wxLuaObject_constructor(lua_State *L)
{
    wxLuaObject *returns;
    // call constructor
    returns = new wxLuaObject(L, 1);
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxLuaObject);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxLuaObject);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxLuaObject_SetObject
// void SetObject(void *object)
static int LUACALL wxLua_wxLuaObject_SetObject(lua_State *L)
{
    // get this
    wxLuaObject *self = (wxLuaObject *)wxluaT_getuserdatatype(L, 1, wxluatype_wxLuaObject);
    // call SetObject
    self->SetObject(L, 2);
    // return the number of parameters
    return 0;
}
%end

%override wxLua_wxLuaObject_GetObject
// void *GetObject() const
static int LUACALL wxLua_wxLuaObject_GetObject(lua_State *L)
{
    // get this
    wxLuaObject *self = (wxLuaObject *)wxluaT_getuserdatatype(L, 1, wxluatype_wxLuaObject);
    // call GetObject that push the item onto the stack, or nil
    if (self->GetObject(L))
        return 1;

    return 0;
}
%end
