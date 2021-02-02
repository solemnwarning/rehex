// ----------------------------------------------------------------------------
// Overridden functions for the wxWidgets binding for wxLua
//
// Please keep these functions in the same order as the .i file and in the
// same order as the listing of the functions in that file.
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// Overrides for wxstc_stc.i
// ----------------------------------------------------------------------------

%override wxLua_wxStyledTextCtrl_GetCurLine
// wxString GetCurLine(int* linePos=NULL)
static int LUACALL wxLua_wxStyledTextCtrl_GetCurLine(lua_State *L)
{
    int linePos;
    // get this
    wxStyledTextCtrl *self = (wxStyledTextCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxStyledTextCtrl);
    // call GetCurLine
    wxString returns = self->GetCurLine(&linePos);
    // push the result string
    lua_pushstring(L, wx2lua(returns));
    lua_pushinteger(L, linePos);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxStyledTextCtrl_SetStyleBytes
// void    SetStyleBytes(int length, const wxString &styleBytes)
static int LUACALL wxLua_wxStyledTextCtrl_SetStyleBytes(lua_State *L)
{
    // const wxString &styleBytes
    char* styleBytes = (char*)lua_tostring(L, 3);
    // int length
    int length = (int)lua_tonumber(L, 2);
    // get this
    wxStyledTextCtrl *self = (wxStyledTextCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxStyledTextCtrl);
    // call SetStyleBytes
    self->SetStyleBytes(length, styleBytes);
    // return the number of parameters
    return 0;
}
%end

%override wxLua_wxStyledTextCtrl_PrivateLexerCall
static int LUACALL wxLua_wxStyledTextCtrl_PrivateLexerCall(lua_State *L)
{
    // void pointer
    // check if the parameter is a string; if not, assume it's userdata
    void * pointer = (void *)lua_tostring(L, 3);
    if (pointer == NULL) pointer = (void *)wxlua_touserdata(L, 3);
    // int operation
    int operation = (int)wxlua_getnumbertype(L, 2);
    // get this
    wxStyledTextCtrl * self = (wxStyledTextCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxStyledTextCtrl);
    // call PrivateLexerCall
    void* returns = (void*)self->PrivateLexerCall(operation, pointer);
    // push the result pointer
    lua_pushlightuserdata(L, (void *)returns);

    return 1;
}
%end

%override wxLua_wxStyledTextCtrl_GetSelection
// void GetSelection(int* startPos, int* endPos)
static int LUACALL wxLua_wxStyledTextCtrl_GetSelection(lua_State *L)
{
    int endPos;
    int startPos;
    // get this
    wxStyledTextCtrl *self = (wxStyledTextCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxStyledTextCtrl);
    // call GetSelection
    self->GetSelection(&startPos, &endPos);
    // push results
    lua_pushinteger(L, startPos);
    lua_pushinteger(L, endPos);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxStyledTextCtrl_MarkerDefinePixmap
// void MarkerDefinePixmap(int markerNumber, const char* const* xpmData);
static int LUACALL wxLua_wxStyledTextCtrl_MarkerDefinePixmap(lua_State *L)
{
    // const char const xpmData
    const char* const* xpmData = (const char* const*)wxlua_touserdata(L, 3);
    // int markerNumber
    int markerNumber = (int)wxlua_getnumbertype(L, 2);
    // get this
    wxStyledTextCtrl * self = (wxStyledTextCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxStyledTextCtrl);
    // call MarkerDefinePixmap
    self->MarkerDefinePixmap(markerNumber, xpmData);

    return 0;
}
%end

%override wxLua_wxStyledTextCtrl_RegisterImage
// void RegisterImage(int type, const char* const* xpmData);
static int LUACALL wxLua_wxStyledTextCtrl_RegisterImage(lua_State *L)
{
    // const char const xpmData
    const char* const* xpmData = (const char* const*)wxlua_touserdata(L, 3);
    // int type
    int type = (int)wxlua_getnumbertype(L, 2);
    // get this
    wxStyledTextCtrl * self = (wxStyledTextCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxStyledTextCtrl);
    // call RegisterImage
    self->RegisterImage(type, xpmData);

    return 0;
}
%end
