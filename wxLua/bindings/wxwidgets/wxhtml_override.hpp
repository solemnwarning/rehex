// ----------------------------------------------------------------------------
// Overridden functions for the wxWidgets binding for wxLua
//
// Please keep these functions in the same order as the .i file and in the
// same order as the listing of the functions in that file.
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// Overrides for wxhtml_html.i
// ----------------------------------------------------------------------------

%override wxLua_wxHtmlCell_AdjustPagebreak
// virtual bool AdjustPagebreak(int * pagebreak)

#if !wxCHECK_VERSION(2, 7, 0)
static int LUACALL wxLua_wxHtmlCell_AdjustPagebreak(lua_State *L)
{
    // int * pagebreak
    int pagebreak  = (int)wxlua_getintegertype(L, 2);
    // get this
    wxHtmlCell *self = (wxHtmlCell *)wxluaT_getuserdatatype(L, 1, wxluatype_wxHtmlCell);
    // call AdjustPagebreak
    bool returns = self->AdjustPagebreak(&pagebreak);
    // push the result number
    lua_pushboolean(L, returns);
    //
    lua_pushinteger(L, pagebreak);
    // return the number of parameters
    return 2;
}
#elif wxCHECK_VERSION(2, 8, 0) && !wxCHECK_VERSION(2, 9, 4)
// virtual bool AdjustPagebreak(int * pagebreak, wxArrayInt& known_pagebreaks)
static int LUACALL wxLua_wxHtmlCell_AdjustPagebreak(lua_State *L)
{
    // wxArrayInt& known_pagebreaks
    wxArrayInt* known_pagebreaks  = (wxArrayInt *)wxluaT_getuserdatatype(L, 3, wxluatype_wxArrayInt);
    // int * pagebreak
    int pagebreak  = (int)wxlua_getintegertype(L, 2);
    // get this
    wxHtmlCell *self = (wxHtmlCell *)wxluaT_getuserdatatype(L, 1, wxluatype_wxHtmlCell);
    // call AdjustPagebreak
    bool returns = self->AdjustPagebreak(&pagebreak, *known_pagebreaks);
    // push the result number
    lua_pushboolean(L, returns);
    //
    lua_pushinteger(L, pagebreak);
    // return the number of parameters
    return 2;
}
#elif wxCHECK_VERSION(2, 9, 4) && !wxCHECK_VERSION(3, 1, 2)
// virtual bool AdjustPagebreak(int * pagebreak, wxArrayInt& known_pagebreaks, int pageHeight)
static int LUACALL wxLua_wxHtmlCell_AdjustPagebreak(lua_State *L)
{
    // int pageHeight
    int pageHeight  = (int)wxlua_getintegertype(L, 4);
    // wxArrayInt& known_pagebreaks
    wxArrayInt* known_pagebreaks  = (wxArrayInt *)wxluaT_getuserdatatype(L, 3, wxluatype_wxArrayInt);
    // int * pagebreak
    int pagebreak  = (int)wxlua_getintegertype(L, 2);
    // get this
    wxHtmlCell *self = (wxHtmlCell *)wxluaT_getuserdatatype(L, 1, wxluatype_wxHtmlCell);
    // call AdjustPagebreak
    bool returns = self->AdjustPagebreak(&pagebreak, *known_pagebreaks, pageHeight);
    // push the result number
    lua_pushboolean(L, returns);
    //
    lua_pushinteger(L, pagebreak);
    // return the number of parameters
    return 2;
}
#elif wxCHECK_VERSION(3, 1, 2)
// virtual bool AdjustPagebreak(int * pagebreak, int pageHeight)
static int LUACALL wxLua_wxHtmlCell_AdjustPagebreak(lua_State *L)
{
    // int pageHeight
    int pageHeight  = (int)wxlua_getintegertype(L, 3);
    // int * pagebreak
    int pagebreak  = (int)wxlua_getintegertype(L, 2);
    // get this
    wxHtmlCell *self = (wxHtmlCell *)wxluaT_getuserdatatype(L, 1, wxluatype_wxHtmlCell);
    // call AdjustPagebreak
    bool returns = self->AdjustPagebreak(&pagebreak, pageHeight);
    // push the result number
    lua_pushboolean(L, returns);
    //
    lua_pushinteger(L, pagebreak);
    // return the number of parameters
    return 2;
}
#endif
%end

%override wxLua_wxHtmlCell_Find
// virtual const wxHtmlCell* Find(int condition, void *param = 0)
static int LUACALL wxLua_wxHtmlCell_Find(lua_State *L)
{
    const wxHtmlCell *returns = NULL;
    // int condition
    int condition = (int)wxlua_getintegertype(L, 2);
    // get this
    wxHtmlCell *self = (wxHtmlCell *)wxluaT_getuserdatatype(L, 1, wxluatype_wxHtmlCell);
    // call Find
    switch(lua_type(L, 3))
    {
        case LUA_TNIL:
            returns = self->Find(condition, NULL);
            break;

        case LUA_TSTRING:
            {
                wxString param = wxlua_getwxStringtype(L, 3);
                returns = self->Find(condition, &param);
            }
            break;

        case LUA_TNUMBER:
            {
                int param = (int)wxlua_getnumbertype(L, 3);
                returns = self->Find(condition, &param);
            }
            break;

        default:
            wxlua_argerror(L, 3, wxT("a 'nil', 'string', or a 'number'"));
            break;
    }

    // push the result datatype
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxHtmlCell);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxHtmlTag_GetParamAsColour
// %alias GetParamAsColor bool GetParamAsColour(const wxString& par, wxColour *clr) const
static int LUACALL wxLua_wxHtmlTag_GetParamAsColour(lua_State *L)
{
    wxColour *retColour = new wxColour;
    // const wxString& par
    wxString par = wxlua_getwxStringtype(L, 2);
    // get this
    wxHtmlTag *self = (wxHtmlTag *)wxluaT_getuserdatatype(L, 1, wxluatype_wxHtmlTag);
    // call GetParamAsColour
    bool returns = self->GetParamAsColour(par, retColour);
    //
    // push the result number
    lua_pushboolean(L, returns);
    wxluaT_pushuserdatatype(L, retColour, wxluatype_wxColour);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxHtmlTag_GetParamAsInt
// bool GetParamAsInt(const wxString& par, int *value) const
static int LUACALL wxLua_wxHtmlTag_GetParamAsInt(lua_State *L)
{
    int value;
    // const wxString& par
    wxString par = wxlua_getwxStringtype(L, 2);
    // get this
    wxHtmlTag *self = (wxHtmlTag *)wxluaT_getuserdatatype(L, 1, wxluatype_wxHtmlTag);
    // call GetParamAsInt
    bool returns = self->GetParamAsInt(par, &value);
    // push the result number
    lua_pushboolean(L, returns);
    //
    lua_pushinteger(L, value);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxHtmlWinParser_SetFonts
// void SetFonts(wxString normal_face, wxString fixed_face, const int *sizes)
static int LUACALL wxLua_wxHtmlWinParser_SetFonts(lua_State *L)
{
    // const int *sizes
#ifdef __WXMSW__
    int sizes[7] = { 7,8,10,12,16,22,30 };
#else
    int sizes[7] = { 10,12,14,16,19,24,32 };
#endif

    const int arraySize = sizeof(sizes)/sizeof(sizes[0]);

    int argCount = lua_gettop(L);

    if (argCount >= 4)
    {
        if (lua_istable(L, 4))
        {
            int count = 0;

            int *sizeArray = wxlua_getintarray(L, 4, count);

            if (count > arraySize)
                count = arraySize;

            memcpy(sizes, sizeArray, count * sizeof(int));

            delete[] sizeArray;
        }
        else
        {
            int idx;

            if (argCount > 4 + arraySize)
                argCount = 4 + arraySize;

            for (idx = 4; idx < argCount; ++idx)
                sizes[idx - 4] = (int)lua_tonumber(L, idx);
        }
    }

    // wxString fixed_face
    wxString fixed_face = wxlua_getwxStringtype(L, 3);
    // wxString normal_face
    wxString normal_face = wxlua_getwxStringtype(L, 2);
    // get this
    wxHtmlWinParser *self = (wxHtmlWinParser *)wxluaT_getuserdatatype(L, 1, wxluatype_wxHtmlWinParser);
    // call SetFonts
    self->SetFonts(normal_face, fixed_face, sizes);
    // return the number of parameters
    return 0;
}
%end

%override wxLua_wxHtmlWindow_SetFonts
// void SetFonts(wxString normal_face, wxString fixed_face, const int *sizes)
static int LUACALL wxLua_wxHtmlWindow_SetFonts(lua_State *L)
{
    // const int *sizes
#ifdef __WXMSW__
    int sizes[7] = { 7,8,10,12,16,22,30 };
#else
    int sizes[7] = { 10,12,14,16,19,24,32 };
#endif

    const int arraySize = sizeof(sizes)/sizeof(sizes[0]);

    int argCount = lua_gettop(L);

    if (argCount >= 4)
    {
        if (lua_istable(L, 4))
        {
            int count = 0;

            int *sizeArray = wxlua_getintarray(L, 4, count);

            if (count > arraySize)
                count = arraySize;

            memcpy(sizes, sizeArray, count * sizeof(int));

            delete[] sizeArray;
        }
        else
        {
            int idx;

            if (argCount > 4 + arraySize)
                argCount = 4 + arraySize;

            for (idx = 4; idx < argCount; ++idx)
                sizes[idx - 4] = (int)lua_tonumber(L, idx);
        }
    }

    // wxString fixed_face
    wxString fixed_face = wxlua_getwxStringtype(L, 3);
    // wxString normal_face
    wxString normal_face = wxlua_getwxStringtype(L, 2);
    // get this
    wxHtmlWindow *self = (wxHtmlWindow *)wxluaT_getuserdatatype(L, 1, wxluatype_wxHtmlWindow);
    // call SetFonts
    self->SetFonts(normal_face, fixed_face, sizes);

    // return the number of parameters
    return 0;
}
%end

%override wxLua_wxLuaHtmlWindow_constructor
//     wxLuaHtmlWindow(wxWindow *parent, wxWindowID id = -1, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxHW_SCROLLBAR_AUTO, const wxString& name = "wxLuaHtmlWindow")
static int LUACALL wxLua_wxLuaHtmlWindow_constructor(lua_State *L)
{
    wxLuaState wxlState(L);
    // get number of arguments
    int argCount = lua_gettop(L);
    // const wxString name = "wxLuaHtmlWindow"
    const wxString name = (argCount >= 6 ? wxlua_getwxStringtype(L, 6) : wxString(wxT("wxLuaHtmlWindow")));
    // long style = wxHW_SCROLLBAR_AUTO
    long style = (argCount >= 5 ? (long)wxlua_getintegertype(L, 5) : wxHW_SCROLLBAR_AUTO);
    // const wxSize size = wxDefaultSize
    const wxSize * size = (argCount >= 4 ? (const wxSize *)wxluaT_getuserdatatype(L, 4, wxluatype_wxSize) : &wxDefaultSize);
    // const wxPoint pos = wxDefaultPosition
    const wxPoint * pos = (argCount >= 3 ? (const wxPoint *)wxluaT_getuserdatatype(L, 3, wxluatype_wxPoint) : &wxDefaultPosition);
    // wxWindowID id = -1
    wxWindowID id = (argCount >= 2 ? (wxWindowID)wxlua_getintegertype(L, 2) : -1);
    // wxWindow parent
    wxWindow * parent = (wxWindow *)wxluaT_getuserdatatype(L, 1, wxluatype_wxWindow);
    // call constructor
    wxLuaHtmlWindow *returns = new wxLuaHtmlWindow(wxlState, parent, id, *pos, *size, style, name);
    // add to tracked window list
    if (returns && returns->IsKindOf(CLASSINFO(wxWindow)))
        wxluaW_addtrackedwindow(L, (wxWindow*)returns);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxLuaHtmlWindow);

    return 1;
}
%end
