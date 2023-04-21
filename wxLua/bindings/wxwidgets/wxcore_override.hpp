// ----------------------------------------------------------------------------
// Overridden functions for the wxWidgets binding for wxLua
//
// Please keep these functions in the same order as the .i file and in the
// same order as the listing of the functions in that file.
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// Overrides for wxcore_appframe.i
// ----------------------------------------------------------------------------

%override wxLua_function_wxGetApp
// %function wxApp* wxGetApp()
static int LUACALL wxLua_function_wxGetApp(lua_State *L)
{
    // call wxGetApp(), actually not since you have to have IMPLEMENT_APP
    wxApp *returns = wxTheApp;
    // push the result datatype
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxApp);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxApp_MainLoop
//     int MainLoop()
static int LUACALL wxLua_wxApp_MainLoop(lua_State *L)
{
    // get this
    wxApp * self = (wxApp *)wxluaT_getuserdatatype(L, 1, wxluatype_wxApp);
    int returns = 0;

    if (!wxLuaState::sm_wxAppMainLoop_will_run && !wxApp::IsMainLoopRunning())
        returns = self->MainLoop();

    // push the result number
    lua_pushinteger(L, returns);

    return 1;
}
%end

%override wxLua_wxAppConsole_MainLoop
//     int MainLoop()
static int LUACALL wxLua_wxAppConsole_MainLoop(lua_State *L)
{
    // get this
    wxAppConsole * self = (wxAppConsole *)wxluaT_getuserdatatype(L, 1, wxluatype_wxAppConsole);
    int returns = 0;

    if (!wxLuaState::sm_wxAppMainLoop_will_run && !wxAppConsole::IsMainLoopRunning())
        returns = self->MainLoop();

    // push the result number
    lua_pushinteger(L, returns);

    return 1;
}
%end

%override wxLua_wxStatusBar_SetFieldsCount
// virtual void SetFieldsCount(int number = 1, int* widths = NULL)
static int LUACALL wxLua_wxStatusBar_SetFieldsCount(lua_State *L)
{
    int  count  = 0;
    int *widths = NULL;

    wxLuaSmartIntArray ptr;

    if (lua_istable(L, 2))
        ptr = widths = wxlua_getintarray(L, 2, count);
    else
        count = wxlua_getintegertype(L, 2);

    // get this
    wxStatusBar *self = (wxStatusBar *)wxluaT_getuserdatatype(L, 1, wxluatype_wxStatusBar);
    // call SetFieldsCount
    self->SetFieldsCount(count, widths);
    // return the number of parameters
    return 0;
}
%end

%override wxLua_wxAcceleratorTable_constructor
// wxAcceleratorTable(int n, wxAcceleratorEntry* entries)
static int LUACALL wxLua_wxAcceleratorTable_constructor(lua_State *L)
{
    wxAcceleratorEntry *pItems  = NULL;
    int                 nItems  = 0;
    if (lua_istable(L, 1))
    {
        nItems = luaL_getn(L, 1);
        if (nItems > 0)
            pItems = new wxAcceleratorEntry[nItems];

        if (pItems != NULL)
        {
            int idx, idxMax = nItems;
            nItems = 0;
            for (idx = 1; idx <= idxMax; ++idx)
            {
                lua_pushinteger(L, idx);
                lua_gettable(L, -2);

                int  iFlags  = 0;
                int  keyCode = 0;
                int  cmd     = 0;
                bool fValid  = false;

                if (lua_istable(L, -1))
                {
                    lua_pushinteger(L, 1);
                    lua_gettable(L, -2);
                    iFlags = (int)lua_tonumber(L, -1);
                    lua_pop(L, 1);

                    lua_pushinteger(L, 2);
                    lua_gettable(L, -2);
                    keyCode = (int)lua_tonumber(L, -1);
                    lua_pop(L, 1);

                    lua_pushinteger(L, 3);
                    lua_gettable(L, -2);
                    cmd = (int)lua_tonumber(L, -1);
                    lua_pop(L, 1);

                    fValid = true;
                }
                else
                if (lua_isuserdata(L, -1))
                {
                    wxAcceleratorEntry *pEntry = (wxAcceleratorEntry *)wxluaT_getuserdatatype(L, -1, wxluatype_wxAcceleratorEntry);
                    if (pEntry != NULL)
                    {
                        iFlags  = pEntry->GetFlags();
                        keyCode = pEntry->GetKeyCode();
                        cmd     = pEntry->GetCommand();

                        fValid = true;
                    }
                }
                lua_pop(L, 1);

                if (fValid)
                {
                    pItems[nItems].Set(iFlags, keyCode, cmd);
                    ++nItems;
                }
            }
        }
    }

    // call constructor
    if (pItems != NULL)
    {
        wxAcceleratorTable *returns = NULL;
        if (nItems > 0)
            returns = new wxAcceleratorTable(nItems, pItems);

        delete[] pItems;

        if (returns != NULL)
        {
		    wxluaO_addgcobject(L, returns, wxluatype_wxAcceleratorTable);
            // push the constructed class pointer
            wxluaT_pushuserdatatype(L, returns, wxluatype_wxAcceleratorTable);
            // return the number of parameters
            return 1;
        }
    }
    return 0;
}
%end

// ----------------------------------------------------------------------------
// Overrides for clipdrag.i
// ----------------------------------------------------------------------------

%override wxLua_wxDataObject_GetAllFormats
// virtual void GetAllFormats(wxDataFormat *formats, wxDataObject::Direction dir = wxDataObject::Get) const
static int LUACALL wxLua_wxDataObject_GetAllFormats(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // wxDataObject::Direction dir = wxDataObject::Get
    wxDataObject::Direction dir = (argCount >= 2 ? (wxDataObject::Direction)(int)wxlua_getenumtype(L, 2) : wxDataObject::Get);
    // get this
    wxDataObject *self = (wxDataObject *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDataObject);
    // wxDataFormat *formats
    int idx, formatCount = self->GetFormatCount(dir);

    if (formatCount > 0)
    {
        wxDataFormat *formats = new wxDataFormat[formatCount];
        if (formats != NULL)
        {
            // call GetAllFormats
            self->GetAllFormats(formats, dir);
            // return the number of parameters

            lua_newtable(L);
            for (idx = 0; idx < formatCount; ++idx)
            {
                wxDataFormat *pFormat = new wxDataFormat(formats[idx]);
                wxluaT_pushuserdatatype(L, pFormat, wxluatype_wxDataFormat);
                lua_rawseti(L, -2, idx + 1);
            }
            delete[] formats;
            return 1;
        }
    }
    return 0;
}
%end

%override wxLua_wxDataObject_SetData
// virtual bool SetData(const wxDataFormat& format, int len, const void *buf)
static int LUACALL wxLua_wxDataObject_SetData(lua_State *L)
{
    // const void *buf
    const void *buf = lua_tostring(L, 3);
    // int len
    int len = lua_strlen(L, 3);
    // const wxDataFormat& format
    const wxDataFormat *format = (wxDataFormat *)wxluaT_getuserdatatype(L, 2, wxluatype_wxDataFormat);
    // get this
    wxDataObject *self = (wxDataObject *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDataObject);
    // call SetData
    bool returns = self->SetData(*format, len, buf);
    // push the result number
    lua_pushboolean(L, returns);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxDataObjectSimple_SetData
// virtual bool SetData(size_t len, const void *buf)
static int LUACALL wxLua_wxDataObjectSimple_SetData(lua_State *L)
{
    // const void *buf
    const void *buf = lua_tostring(L, 2);
    // size_t len
    size_t len = (size_t)lua_strlen(L, 2);
    // get this
    wxDataObjectSimple *self = (wxDataObjectSimple *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDataObjectSimple);
    // call SetData
    bool returns = self->SetData(len, buf);
    // push the result number
    lua_pushboolean(L, returns);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxDataObject_GetDataHere
// virtual bool GetDataHere(const wxDataFormat& format, void *buf) const
static int LUACALL wxLua_wxDataObject_GetDataHere(lua_State *L)
{
    // const wxDataFormat& format
    const wxDataFormat *format = (wxDataFormat *)wxluaT_getuserdatatype(L, 2, wxluatype_wxDataFormat);
    // get this
    wxDataObject *self = (wxDataObject *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDataObject);

    size_t size = self->GetDataSize(*format);

    void *buf = malloc(size);

    if (buf != NULL)
    {
        // call GetDataHere
        bool returns = self->GetDataHere(*format, buf);

        // push the result number
        lua_pushboolean(L, returns);
        // push the result string
        lua_pushlstring(L, (const char *) buf, size);

        free(buf);

        // return the number of parameters
        return 2;
    }
    return 0;
}
%end

%override wxLua_wxDataObjectSimple_GetDataHere
// virtual bool GetDataHere(void *buf) const
static int LUACALL wxLua_wxDataObjectSimple_GetDataHere(lua_State *L)
{
    // get this
    wxDataObjectSimple *self = (wxDataObjectSimple *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDataObjectSimple);

    size_t size = self->GetDataSize();

    void *buf = malloc(size);
    if (buf != NULL)
    {
        // call GetDataHere
        bool returns = self->GetDataHere(buf);

        // push the result number
        lua_pushboolean(L, returns);
        // push the result string
        lua_pushlstring(L, (const char *) buf, size);

        free(buf);

        // return the number of parameters
        return 2;
    }
    return 0;
}
%end

%override wxLua_wxLuaDataObjectSimple_constructor
//     wxLuaDataObjectSimple(const wxDataFormat& format = wxFormatInvalid)
static int LUACALL wxLua_wxLuaDataObjectSimple_constructor(lua_State *L)
{
    wxLuaState wxlState(L);

    // get number of arguments
    int argCount = lua_gettop(L);
    // const wxDataFormat format = wxFormatInvalid
    const wxDataFormat * format = (argCount >= 1 ? (const wxDataFormat *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDataFormat) : &wxFormatInvalid);
    // call constructor
    wxLuaDataObjectSimple* returns = new wxLuaDataObjectSimple(wxlState, *format);
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxLuaDataObjectSimple);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxLuaDataObjectSimple);

    return 1;
}
%end

%override wxLua_wxDropFilesEvent_GetFiles
// wxString* GetFiles() const
static int LUACALL wxLua_wxDropFilesEvent_GetFiles(lua_State *L)
{
    // get this
    wxDropFilesEvent *self = (wxDropFilesEvent *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDropFilesEvent);
    // call GetFiles
    int       numFiles = self->GetNumberOfFiles();
    wxString *files    = self->GetFiles();

    lua_newtable(L);

    int idx;
    for (idx = 0; idx < numFiles; ++idx)
    {
        wxlua_pushwxString(L, files[idx]);
        lua_rawseti(L, -2, idx + 1);
    }
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxLuaFileDropTarget_constructor
//     wxLuaFileDropTarget()
static int LUACALL wxLua_wxLuaFileDropTarget_constructor(lua_State *L)
{
    wxLuaState wxlState(L);

    // call constructor
    wxLuaFileDropTarget* returns = new wxLuaFileDropTarget(wxlState);
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxLuaFileDropTarget);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxLuaFileDropTarget);

    return 1;
}
%end

%override wxLua_wxLuaTextDropTarget_constructor
//     wxLuaTextDropTarget()
static int LUACALL wxLua_wxLuaTextDropTarget_constructor(lua_State *L)
{
    wxLuaState wxlState(L);

    // call constructor
    wxLuaTextDropTarget* returns = new wxLuaTextDropTarget(wxlState);
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxLuaTextDropTarget);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxLuaTextDropTarget);

    return 1;
}
%end

%override wxLua_wxLuaURLDropTarget_constructor
//     wxLuaTextDropTarget()
static int LUACALL wxLua_wxLuaURLDropTarget_constructor(lua_State *L)
{
    wxLuaState wxlState(L);

    // call constructor
    wxLuaURLDropTarget* returns = new wxLuaURLDropTarget(wxlState);
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxLuaURLDropTarget);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxLuaURLDropTarget);

    return 1;
}
%end

// ----------------------------------------------------------------------------
// Overrides for controls.i
// ----------------------------------------------------------------------------

%override wxLua_wxListBox_GetSelections
//     int      GetSelections(wxArrayInt& selections) const
static int LUACALL wxLua_wxListBox_GetSelections(lua_State *L)
{
    // wxArrayInt selections
    wxArrayInt selections;
    // get this
    wxListBox * self = (wxListBox *)wxluaT_getuserdatatype(L, 1, wxluatype_wxListBox);
    // call GetSelections
    int returns = self->GetSelections(selections);
    // push the result number
    lua_pushinteger(L, returns);
    // push the selects as a table
    wxlua_pushwxArrayInttable(L, selections);

    return 2;
}
%end

%override wxLua_wxListCtrl_HitTest
// long     HitTest(const wxPoint& point, int& flags)
static int LUACALL wxLua_wxListCtrl_HitTest(lua_State *L)
{
    // int& flags
    int flags;
    // const wxPoint& point
    const wxPoint *point = (wxPoint *)wxluaT_getuserdatatype(L, 2, wxluatype_wxPoint);
    // get this
    wxListCtrl *self = (wxListCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxListCtrl);
    // call HitTest
    long returns = self->HitTest(*point, flags);
    // push the result number
    lua_pushinteger(L, returns);
    // push the result flags
    lua_pushinteger(L, flags);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxListCtrl_SortItems


struct wxLua_LCF_data // wrap up the wxLuaState, lua_tag, and the compare data
{
    wxLuaState* wxlState;
    int lua_tag;
    long data;
};

// type of compare function for wxListCtrl sort operation (as of 2.9.3)
//typedef int (wxCALLBACK *wxListCtrlCompare)(wxIntPtr item1, wxIntPtr item2, wxIntPtr sortData);

#if !wxCHECK_VERSION(2, 8, 9)
    typedef long wxIntPtr;
#endif

int wxCALLBACK wxLua_ListCompareFunction(wxIntPtr item1, wxIntPtr item2, wxIntPtr sortData)
{
    wxLua_LCF_data* LCF_data = (wxLua_LCF_data*)sortData;

    lua_State *L = LCF_data->wxlState->GetLuaState();
    int old_top = lua_gettop(L);

    lua_rawgeti(L, LUA_REGISTRYINDEX, LCF_data->lua_tag);
    lua_pushnumber(L, item1);
    lua_pushnumber(L, item2);
    lua_pushnumber(L, LCF_data->data);

    LCF_data->wxlState->LuaPCall(3, 1);

    // for some bizarre reason lua converts the return to a string! try to get it back as a number
    // Happens with lua 5.1.2
    int ret = (int)lua_tonumber(L, -1); //LCF_data->wxlState->GetNumberType(0);
    lua_settop(L, old_top); // pop results

    return ret;
}

// bool SortItems(LuaFunction fnSortCallBack, long data)
static int LUACALL wxLua_wxListCtrl_SortItems(lua_State *L)
{
    wxLuaState wxlState(L);

    // long data
    long data = (long)wxlua_getintegertype(L, 3);
    wxLua_LCF_data LCF_data = { &wxlState, -1, data }; // only exists for this function

    if (lua_isfunction (L, 2))
    {
        lua_pushvalue(L, 2); // push function to top of stack
        LCF_data.lua_tag = luaL_ref(L, LUA_REGISTRYINDEX); // ref function and pop it from stack
    }
    else
        wxlua_argerror(L, 2, wxT("a 'Lua function(long item1, long item2, long data)'"));

    // get this
    wxListCtrl *self = (wxListCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxListCtrl);

    // call SortItems
    bool returns = self->SortItems(wxLua_ListCompareFunction, (wxUIntPtr)&LCF_data);

    luaL_unref(L, LUA_REGISTRYINDEX, LCF_data.lua_tag); // remove ref to function

    // push the result number
    lua_pushboolean(L, returns);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxLuaListCtrl_constructor
// wxLuaListCtrl(const wxLuaState& wxlState);
// wxLuaListCtrl(const wxLuaState& wxlState,
//               wxWindow *parent, wxWindowID id,
//               const wxPoint &pos=wxDefaultPosition,
//               const wxSize &size=wxDefaultSize, long style=wxLC_REPORT|wxLC_VIRTUAL,
//               const wxValidator &validator=wxDefaultValidator,
//               const wxString &name=wxListCtrlNameStr);
static int LUACALL wxLua_wxLuaListCtrl_constructor(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);

    wxLuaState wxlState(L);
    wxListCtrl* returns;

    if (argCount == 0) // Default constructor
    {
        returns = new wxLuaListCtrl(wxlState);
    }
    else // Construct and create
    {
        // const wxString name = "wxLuaListCtrl"
        const wxString name = (argCount >= 7 ? wxlua_getwxStringtype(L, 7) : wxString(wxT("wxLuaListCtrl")));
        // const wxValidator validator = wxDefaultValidator
        const wxValidator * validator = (argCount >= 6 ? (const wxValidator *)wxluaT_getuserdatatype(L, 6, wxluatype_wxValidator) : &wxDefaultValidator);
        // long style = wxLC_ICON
        long style = (argCount >= 5 ? (long)wxlua_getnumbertype(L, 5) : wxLC_REPORT|wxLC_VIRTUAL);
        // const wxSize size = wxDefaultSize
        const wxSize * size = (argCount >= 4 ? (const wxSize *)wxluaT_getuserdatatype(L, 4, wxluatype_wxSize) : &wxDefaultSize);
        // const wxPoint pos = wxDefaultPosition
        const wxPoint * pos = (argCount >= 3 ? (const wxPoint *)wxluaT_getuserdatatype(L, 3, wxluatype_wxPoint) : &wxDefaultPosition);
        // wxWindowID id
        wxWindowID id = (wxWindowID)wxlua_getnumbertype(L, 2);
        // wxWindow parent
        wxWindow * parent = (wxWindow *)wxluaT_getuserdatatype(L, 1, wxluatype_wxWindow);
        // call constructor
        returns = new wxLuaListCtrl(wxlState, parent, id, *pos, *size, style, *validator, name);
    }
    // add to tracked window list, it will check validity
    wxluaW_addtrackedwindow(L, returns);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxLuaListCtrl);

    return 1;
}
%end

#if wxCHECK_VERSION(3, 0, 0)
%override wxLua_wxTextEntry_GetSelection
// virtual void GetSelection(long* from, long* to)
static int LUACALL wxLua_wxTextEntry_GetSelection(lua_State *L)
{
    long to;
    long from;
    // get this
    wxTextEntry *self = (wxTextEntry *)wxluaT_getuserdatatype(L, 1, wxluatype_wxTextEntry);
    // call GetSelection
    self->GetSelection(&from, &to);
    lua_pushinteger(L, from);
    lua_pushinteger(L, to);
    // return the number of parameters
    return 2;
}
%end
#else
%override wxLua_wxTextCtrl_GetSelection
// virtual void GetSelection(long* from, long* to)
static int LUACALL wxLua_wxTextCtrl_GetSelection(lua_State *L)
{
    long to;
    long from;
    // get this
    wxTextCtrl *self = (wxTextCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxTextCtrl);
    // call GetSelection
    self->GetSelection(&from, &to);
    lua_pushinteger(L, from);
    lua_pushinteger(L, to);
    // return the number of parameters
    return 2;
}
%end
#endif

#if wxCHECK_VERSION(3, 0, 0)
%override wxLua_wxTextAreaBase_HitTest
//     wxTextCtrlHitTestResult HitTest(const wxPoint& pt, wxTextCoord *col, wxTextCoord *row) const
static int LUACALL wxLua_wxTextAreaBase_HitTest(lua_State *L)
{
    // wxTextCoord row
    wxTextCoord row = wxInvalidTextCoord;
    // wxTextCoord col
    wxTextCoord col = wxInvalidTextCoord;
    // const wxPoint pt
    const wxPoint * pt = (const wxPoint *)wxluaT_getuserdatatype(L, 2, wxluatype_wxPoint);
    // get this
    wxTextAreaBase * self = (wxTextAreaBase *)wxluaT_getuserdatatype(L, 1, wxluatype_wxTextAreaBase);
    // call HitTest
    wxTextCtrlHitTestResult returns = self->HitTest(*pt, &col, &row);
    // push the result number
    lua_pushinteger(L, returns);
    lua_pushinteger(L, row);
    lua_pushinteger(L, col);

    return 3;
}
%end

%override wxLua_wxTextAreaBase_HitTestPos
//     wxTextCtrlHitTestResult HitTestPos(const wxPoint& pt, long *pos) const
static int LUACALL wxLua_wxTextAreaBase_HitTestPos(lua_State *L)
{
    // long pos
    long pos = wxInvalidTextCoord;
    // wxTextCoord col
    const wxPoint * pt = (const wxPoint *)wxluaT_getuserdatatype(L, 2, wxluatype_wxPoint);
    // get this
    wxTextAreaBase * self = (wxTextAreaBase *)wxluaT_getuserdatatype(L, 1, wxluatype_wxTextAreaBase);
    // call HitTest
    wxTextCtrlHitTestResult returns = self->HitTest(*pt, &pos);
    // push the result number
    lua_pushinteger(L, returns);
    lua_pushinteger(L, pos);

    return 2;
}
%end

%override wxLua_wxTextAreaBase_PositionToXY
// bool PositionToXY(long pos, long *x, long *y) const
static int LUACALL wxLua_wxTextAreaBase_PositionToXY(lua_State *L)
{
    long y;
    long x;
    // long pos
    long pos = (long)wxlua_getintegertype(L, 2);
    // get this
    wxTextAreaBase *self = (wxTextCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxTextAreaBase);
    // call PositionToXY
    bool returns = self->PositionToXY(pos, &x, &y);
    // push the result number
    lua_pushboolean(L, returns);
    lua_pushinteger(L, x);
    lua_pushinteger(L, y);
    // return the number of parameters
    return 3;
}
%end

#else
%override wxLua_wxTextCtrl_HitTest
//     wxTextCtrlHitTestResult HitTest(const wxPoint& pt, wxTextCoord *col, wxTextCoord *row) const
static int LUACALL wxLua_wxTextCtrl_HitTest(lua_State *L)
{
    // wxTextCoord row
    wxTextCoord row = wxInvalidTextCoord;
    // wxTextCoord col
    wxTextCoord col = wxInvalidTextCoord;
    // const wxPoint pt
    const wxPoint * pt = (const wxPoint *)wxluaT_getuserdatatype(L, 2, wxluatype_wxPoint);
    // get this
    wxTextCtrl * self = (wxTextCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxTextCtrl);
    // call HitTest
    wxTextCtrlHitTestResult returns = self->HitTest(*pt, &col, &row);
    // push the result number
    lua_pushinteger(L, returns);
    lua_pushinteger(L, row);
    lua_pushinteger(L, col);

    return 3;
}
%end

%override wxLua_wxTextCtrl_HitTestPos
//     wxTextCtrlHitTestResult HitTestPos(const wxPoint& pt, long *pos) const
static int LUACALL wxLua_wxTextCtrl_HitTestPos(lua_State *L)
{
    // long pos
    long pos = wxInvalidTextCoord;
    // wxTextCoord col
    const wxPoint * pt = (const wxPoint *)wxluaT_getuserdatatype(L, 2, wxluatype_wxPoint);
    // get this
    wxTextCtrl * self = (wxTextCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxTextCtrl);
    // call HitTest
    wxTextCtrlHitTestResult returns = self->HitTest(*pt, &pos);
    // push the result number
    lua_pushinteger(L, returns);
    lua_pushinteger(L, pos);

    return 2;
}
%end

%override wxLua_wxTextCtrl_PositionToXY
// bool PositionToXY(long pos, long *x, long *y) const
static int LUACALL wxLua_wxTextCtrl_PositionToXY(lua_State *L)
{
    long y;
    long x;
    // long pos
    long pos = (long)wxlua_getintegertype(L, 2);
    // get this
    wxTextCtrl *self = (wxTextCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxTextCtrl);
    // call PositionToXY
    bool returns = self->PositionToXY(pos, &x, &y);
    // push the result number
    lua_pushboolean(L, returns);
    lua_pushinteger(L, x);
    lua_pushinteger(L, y);
    // return the number of parameters
    return 3;
}
%end

#endif

%override wxLua_wxTreeItemId_GetValue
// long  GetValue() const;
static int LUACALL wxLua_wxTreeItemId_GetValue(lua_State *L)
{
    // get this
    wxTreeItemId *self = (wxTreeItemId *)wxluaT_getuserdatatype(L, 1, wxluatype_wxTreeItemId);
    // call GetValue
    wxUIntPtr returns = (wxUIntPtr)self->m_pItem;
    // push the result number
    lua_pushnumber(L, returns);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxTreeCtrl_GetFirstChild
// wxTreeItemId GetFirstChild(const wxTreeItemId& item, wxTreeItemIdValue& cookie) const
static int LUACALL wxLua_wxTreeCtrl_GetFirstChild(lua_State *L)
{
    wxTreeItemIdValue cookie = 0;

    // const wxTreeItemId& item
    const wxTreeItemId *item = (wxTreeItemId *)wxluaT_getuserdatatype(L, 2, wxluatype_wxTreeItemId);
    // get this
    wxTreeCtrl *self = (wxTreeCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxTreeCtrl);
    // call GetFirstChild
    // allocate a new object using the copy constructor
    wxTreeItemId *returns = new wxTreeItemId(self->GetFirstChild(*item, cookie));
    // add the new object to the tracked memory list
    wxluaO_addgcobject(L, (void*)returns, wxluatype_wxTreeItemId);
    // push the result datatype
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxTreeItemId);
    // push the cookie
    lua_pushlightuserdata(L, cookie); // wxTreeItemIdValue is void*
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxTreeCtrl_GetNextChild
// wxTreeItemId GetNextChild(const wxTreeItemId& item, wxTreeItemIdValue& cookie) const
static int LUACALL wxLua_wxTreeCtrl_GetNextChild(lua_State *L)
{
    wxTreeItemIdValue cookie = (wxTreeItemIdValue)wxlua_getpointertype(L, 3);

    // const wxTreeItemId& item
    const wxTreeItemId *item = (wxTreeItemId *)wxluaT_getuserdatatype(L, 2, wxluatype_wxTreeItemId);
    // get this
    wxTreeCtrl *self = (wxTreeCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxTreeCtrl);
    // call GetNextChild
    // allocate a new object using the copy constructor
    wxTreeItemId *returns = new wxTreeItemId(self->GetNextChild(*item, cookie));
    // add the new object to the tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxTreeItemId);
    // push the result datatype
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxTreeItemId);
    // push the cookie
    lua_pushlightuserdata(L, cookie); // wxTreeItemIdValue is void*
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxTreeCtrl_GetSelections
// size_t GetSelections(wxArrayTreeItemIds& selection) const
static int LUACALL wxLua_wxTreeCtrl_GetSelections(lua_State *L)
{
    // get this
    wxTreeCtrl *self = (wxTreeCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxTreeCtrl);
    // call GetSelections
    wxArrayTreeItemIds selection;
    size_t count = self->GetSelections(selection);

    lua_newtable(L);

    size_t idx;
    for (idx = 0; idx < count; ++idx)
    {
        wxTreeItemId* treeId = new wxTreeItemId(selection[idx]);
        wxluaO_addgcobject(L, treeId, wxluatype_wxTreeItemId);
        wxluaT_pushuserdatatype(L, treeId, wxluatype_wxTreeItemId);
        lua_rawseti(L, -2, idx + 1);
    }
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxTreeCtrl_HitTest
// wxTreeItemId HitTest(const wxPoint& point, int& flags)
static int LUACALL wxLua_wxTreeCtrl_HitTest(lua_State *L)
{
    // int& flags
    int flags = 0;
    // const wxPoint& point
    const wxPoint *point = (wxPoint *)wxluaT_getuserdatatype(L, 2, wxluatype_wxPoint);
    // get this
    wxTreeCtrl *self = (wxTreeCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxTreeCtrl);
    // call HitTest
    // allocate a new object using the copy constructor
    wxTreeItemId *returns = new wxTreeItemId(self->HitTest(*point, flags));
    // add the new object to the tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxTreeItemId);

    // push the result datatype
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxTreeItemId);
    lua_pushinteger(L, flags);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxLuaTreeItemData_GetData
//     wxLuaObject* GetData() const;
static int LUACALL wxLua_wxLuaTreeItemData_GetData(lua_State *L)
{
    // get this
    wxLuaTreeItemData * self = (wxLuaTreeItemData *)wxluaT_getuserdatatype(L, 1, wxluatype_wxLuaTreeItemData);
    // call GetData
    wxLuaObject* returns = (wxLuaObject*)self->GetData();
    // push the result datatype
    if ((returns == NULL) || !returns->GetObject(L))
        lua_pushnil(L);

    return 1;
}
%end

%override wxLua_wxLuaTreeItemData_SetData
//     void         SetData(%ungc wxLuaObject* obj); // obj is deleted when tree item data is deleted
static int LUACALL wxLua_wxLuaTreeItemData_SetData(lua_State *L)
{
    // wxLuaObject obj
    //wxLuaObject * obj = (wxLuaObject *)wxluaT_getuserdatatype(L, 2, wxluatype_wxLuaObject);
    //if (wxluaO_isgcobject(L, obj)) wxluaO_undeletegcobject(L, obj);
    wxLuaObject* obj = new wxLuaObject(L, 2);

    // get this
    wxLuaTreeItemData * self = (wxLuaTreeItemData *)wxluaT_getuserdatatype(L, 1, wxluatype_wxLuaTreeItemData);
    // call SetData
    self->SetData(obj);

    return 0;
}
%end

%override wxLua_wxLuaTreeItemData_constructor1
//     wxLuaTreeItemData(%ungc wxLuaObject* obj) // obj is deleted when tree item data is deleted
static int LUACALL wxLua_wxLuaTreeItemData_constructor1(lua_State *L)
{
    // wxLuaObject obj
    //wxLuaObject * obj = (wxLuaObject *)wxluaT_getuserdatatype(L, 1, wxluatype_wxLuaObject);
    //if (wxluaO_isgcobject(L, obj)) wxluaO_undeletegcobject(L, obj);
    wxLuaObject* obj = new wxLuaObject(L, 1);

    // call constructor
    wxLuaTreeItemData* returns = new wxLuaTreeItemData(obj);
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxLuaTreeItemData);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxLuaTreeItemData);

    return 1;
}
%end

%override wxLua_wxTreeListItem_GetValue
// wxUIntPtr GetValue() const;
static int LUACALL wxLua_wxTreeListItem_GetValue(lua_State *L)
{
    // get this
    wxTreeListItem *self = (wxTreeListItem *)wxluaT_getuserdatatype(L, 1, wxluatype_wxTreeListItem);
    // call GetValue
    wxUIntPtr returns = (wxUIntPtr)self->m_pItem;
    // push the result number
    lua_pushnumber(L, returns);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxTreeListCtrl_GetSelections
// unsigned int GetSelections(wxTreeListItems& selections) const;
static int LUACALL wxLua_wxTreeListCtrl_GetSelections(lua_State *L)
{
    // get this
    wxTreeListCtrl *self = (wxTreeListCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxTreeListCtrl);
    // call GetSelections
    wxVector<wxTreeListItem> selection;
    size_t count = self->GetSelections(selection);

    lua_newtable(L);

    size_t idx;
    for (idx = 0; idx < count; ++idx)
    {
        wxTreeListItem* treeId = new wxTreeListItem(selection[idx]);
        wxluaO_addgcobject(L, treeId, wxluatype_wxTreeListItem);
        wxluaT_pushuserdatatype(L, treeId, wxluatype_wxTreeListItem);
        lua_rawseti(L, -2, idx + 1);
    }
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxTextValidator_constructor
// wxTextValidator(long style = wxFILTER_NONE, wxString *valPtr = NULL)
static int LUACALL wxLua_wxTextValidator_constructor(lua_State *L)
{
    wxTextValidator *returns;
    // get number of arguments
    int argCount = lua_gettop(L);
    // long style = wxFILTER_NONE
    long style = (argCount >= 1 ? (long)wxlua_getintegertype(L, 1) : wxFILTER_NONE);

    // call constructor
    if (argCount >= 2)
    {
        wxLuaObject *valPtr = (wxLuaObject *)wxluaT_getuserdatatype(L, 2, wxluatype_wxLuaObject);
        returns = new wxTextValidator(style, valPtr->GetStringPtr(L));
    }
    else
        returns = new wxTextValidator(style);

    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxTextValidator);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxGenericValidatorBool_constructor
// %constructor wxGenericValidatorBool(wxLuaObject *boolPtr)
static int LUACALL wxLua_wxGenericValidatorBool_constructor(lua_State *L)
{
    // wxLuaObject *boolPtr
    wxLuaObject *boolPtr = (wxLuaObject *)wxluaT_getuserdatatype(L, 1, wxluatype_wxLuaObject);
    // call constructor
    wxGenericValidator *returns = new wxGenericValidator(boolPtr->GetBoolPtr(L));
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxGenericValidator);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxGenericValidator);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxGenericValidatorString_constructor
// %constructor wxGenericValidatorString(wxLuaObject *valPtr)
static int LUACALL wxLua_wxGenericValidatorString_constructor(lua_State *L)
{
    // wxLuaObject *valPtr
    wxLuaObject *valPtr = (wxLuaObject *)wxluaT_getuserdatatype(L, 1, wxluatype_wxLuaObject);
    // call constructor
    wxGenericValidator *returns = new wxGenericValidator(valPtr->GetStringPtr(L));
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxGenericValidator);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxGenericValidator);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxGenericValidatorInt_constructor
// %constructor wxGenericValidatorInt(wxLuaObject *valPtr)
static int LUACALL wxLua_wxGenericValidatorInt_constructor(lua_State *L)
{
    // wxLuaObject *valPtr
    wxLuaObject *valPtr = (wxLuaObject *)wxluaT_getuserdatatype(L, 1, wxluatype_wxLuaObject);
    // call constructor
    wxGenericValidator *returns = new wxGenericValidator(valPtr->GetIntPtr(L));
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxGenericValidator);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxGenericValidator);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxGenericValidatorArrayInt_constructor
// %constructor wxGenericValidatorArrayInt(wxLuaObject *valPtr)
static int LUACALL wxLua_wxGenericValidatorArrayInt_constructor(lua_State *L)
{
    // wxLuaObject *valPtr
    wxLuaObject *valPtr = (wxLuaObject *)wxluaT_getuserdatatype(L, 1, wxluatype_wxLuaObject);
    // call constructor
    wxGenericValidator *returns = new wxGenericValidator(valPtr->GetArrayPtr(L));
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxGenericValidator);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxGenericValidator);
    // return the number of parameters
    return 1;
}
%end

// ----------------------------------------------------------------------------
// Overrides for datetime.i
// ----------------------------------------------------------------------------

%override wxLua_wxDatePickerCtrl_GetRange
//        bool GetRange(wxDateTime *dt1, wxDateTime *dt2) const
static int LUACALL wxLua_wxDatePickerCtrl_GetRange(lua_State *L)
{
    wxDateTime *dt1 = new wxDateTime();
    wxDateTime *dt2 = new wxDateTime();
    // get this
    wxDatePickerCtrl * self = (wxDatePickerCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDatePickerCtrl);
    // call GetRange
    bool returns = self->GetRange(dt1, dt2);
    // push the result flag
    lua_pushboolean(L, returns);
    wxluaT_pushuserdatatype(L, dt1, wxluatype_wxDateTime);
    wxluaT_pushuserdatatype(L, dt2, wxluatype_wxDateTime);

    return 3;
}
%end

// ----------------------------------------------------------------------------
// Overrides for defsutils.i
// ----------------------------------------------------------------------------

%override wxLua_wxLuaProcess_Exists
//     static bool Exists(int pid);
static int LUACALL wxLua_wxLuaProcess_Exists(lua_State *L)
{
    // int pid
    int pid = (int)wxlua_getnumbertype(L, 1);
    // call Exists
    bool returns = (wxProcess::Exists(pid));
    // push the result flag
    lua_pushboolean(L, returns);

    return 1;
}
%end

%override wxLua_wxLuaProcess_Kill
//     static wxKillError Kill(int pid, wxSignal sig = wxSIGTERM, int flags = wxKILL_NOCHILDREN);
static int LUACALL wxLua_wxLuaProcess_Kill(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // int flags = wxKILL_NOCHILDREN
    int flags = (argCount >= 3 ? (int)wxlua_getnumbertype(L, 3) : wxKILL_NOCHILDREN);
    // wxSignal sig = wxSIGTERM
    wxSignal sig = (argCount >= 2 ? (wxSignal)wxlua_getenumtype(L, 2) : wxSIGTERM);
    // int pid
    int pid = (int)wxlua_getnumbertype(L, 1);
    // call Kill
    wxKillError returns = (wxProcess::Kill(pid, sig, flags));
    // push the result number
    lua_pushinteger(L, returns);

    return 1;
}
%end

%override wxLua_wxLuaProcess_Open
//     static wxLuaProcess *Open(const wxString& cmd, int flags = wxEXEC_ASYNC);
static int LUACALL wxLua_wxLuaProcess_Open(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // int flags = wxEXEC_ASYNC
    int flags = (argCount >= 2 ? (int)wxlua_getnumbertype(L, 2) : wxEXEC_ASYNC);
    // const wxString cmd
    const wxString cmd = wxlua_getwxStringtype(L, 1);
    // call Open
    wxLuaProcess* returns = (wxLuaProcess*)wxProcess::Open(cmd, flags);
    // push the result datatype
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxLuaProcess);

    return 1;
}
%end

%override wxLua_function_wxKill
// %function int wxKill(long pid, wxSignal sig = wxSIGTERM, wxKillError *rc = NULL, int flags = 0)
static int LUACALL wxLua_function_wxKill(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // int flags = 0
    int flags = (argCount >= 3 ? (int)wxlua_getnumbertype(L, 3) : 0);
    // wxKillError rc = NULL
    wxKillError rc = wxKILL_OK;
    //wxKillError * rc = (argCount >= 3 ? (wxKillError *)wxlua_touserdata(L, 3) : NULL);
    // wxSignal sig = wxSIGTERM
    wxSignal sig = (argCount >= 2 ? (wxSignal)wxlua_getenumtype(L, 2) : wxSIGTERM);
    // long pid
    long pid = (long)wxlua_getnumbertype(L, 1);
    // call wxKill
    int returns = (wxKill(pid, sig, &rc, flags));
    // push the result number
    lua_pushinteger(L, returns);
    lua_pushinteger(L, rc);

    return 2;
}
%end

%override wxLua_function_wxExecuteStdout
// %function %rename wxExecuteStdout long wxExecute(const wxString& command, wxArrayString& output, int flags = 0)
static int LUACALL wxLua_function_wxExecuteStdout(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // int flags = 0
    int flags = (argCount >= 2 ? (int)wxlua_getintegertype(L, 2) : 0);
    // const wxString command
    const wxString command = wxlua_getwxStringtype(L, 1);
    // call wxExecute
    wxArrayString output;
    long returns = wxExecute(command, output, flags);
    // push the result number
    lua_pushinteger(L, returns);
    wxlua_pushwxArrayStringtable(L, output);

    return 2;
}
%end

%override wxLua_function_wxExecuteStdoutStderr
// %function %rename wxExecuteStdoutStderr long wxExecute(const wxString& command, wxArrayString& output, wxArrayString& errors, int flags = 0)
static int LUACALL wxLua_function_wxExecuteStdoutStderr(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // int flags = 0
    int flags = (argCount >= 2 ? (int)wxlua_getintegertype(L, 2) : 0);
    // const wxString command
    const wxString command = wxlua_getwxStringtype(L, 1);
    // call wxExecute
    wxArrayString output;
    wxArrayString errors;
    long returns = wxExecute(command, output, errors, flags);
    // push the result number
    lua_pushinteger(L, returns);
    wxlua_pushwxArrayStringtable(L, output);
    wxlua_pushwxArrayStringtable(L, errors);

    return 3;
}
%end

%override wxLua_function_wxDisplaySize
// %function void wxDisplaySize(int *width, int *height)
static int LUACALL wxLua_function_wxDisplaySize(lua_State *L)
{
    int height = 0, width = 0;
    // call wxDisplaySize
    wxDisplaySize(&width, &height);
    // return the number of parameters
    lua_pushinteger(L, width);
    lua_pushinteger(L, height);
    return 2;
}
%end

%override wxLua_function_wxDisplaySizeMM
// %function void wxDisplaySizeMM(int *width, int *height)
static int LUACALL wxLua_function_wxDisplaySizeMM(lua_State *L)
{
    int height = 0, width = 0;
    // call wxDisplaySizeMM
    wxDisplaySizeMM(&width, &height);
    // return the number of parameters
    lua_pushinteger(L, width);
    lua_pushinteger(L, height);
    return 2;
}
%end

%override wxLua_function_wxClientDisplayRect
// %function void wxClientDisplayRect(int *x, int *y,int *width, int *height)
static int LUACALL wxLua_function_wxClientDisplayRect(lua_State *L)
{
    int x = 0, y = 0, width = 0, height = 0;
    // call wxClientDisplayRect
    wxClientDisplayRect(&x, &y, &width, &height);
    lua_pushinteger(L, x);
    lua_pushinteger(L, y);
    lua_pushinteger(L, width);
    lua_pushinteger(L, height);
    // return the number of parameters
    return 4;
}
%end

%override wxLua_wxBusyCursor_constructor
//     wxBusyCursor(wxCursor* cursor = wxHOURGLASS_CURSOR)
static int LUACALL wxLua_wxBusyCursor_constructor(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // const wxCursor cursor = wxHOURGLASS_CURSOR

    // NOTE: gcc complains that wxHOURGLASS_CURSOR is const, if changed to const MSVC complains wxBusyCursor takes non const
    wxCursor * cursor = (argCount >= 1 ? (wxCursor *)wxluaT_getuserdatatype(L, 1, wxluatype_wxCursor) : (wxCursor*)wxHOURGLASS_CURSOR);
    // call constructor
    wxBusyCursor *returns = new wxBusyCursor(cursor);
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxBusyCursor);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxBusyCursor);

    return 1;
}
%end

// ----------------------------------------------------------------------------
// Overrides for dialogs.i
// ----------------------------------------------------------------------------

%override wxLua_function_wxGetMultipleChoices
// %function size_t wxGetMultipleChoices(wxArrayInt& selections,const wxString& message,const wxString& caption,int n, const wxString *choices,wxWindow *parent = (wxWindow *) NULL,int x = -1, int y = -1, bool centre = true, int width = wxCHOICE_WIDTH, int height = wxCHOICE_HEIGHT);
static int LUACALL wxLua_function_wxGetMultipleChoices(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // int height = wxCHOICE_HEIGHT
    int height = (argCount >= 10 ? (int)wxlua_getnumbertype(L, 10) : wxCHOICE_HEIGHT);
    // int width = wxCHOICE_WIDTH
    int width = (argCount >= 9 ? (int)wxlua_getnumbertype(L, 9) : wxCHOICE_WIDTH);
    // bool centre = true
    bool centre = (argCount >= 8 ? wxlua_getbooleantype(L, 8) : true);
    // int y = -1
    int y = (argCount >= 7 ? (int)wxlua_getnumbertype(L, 7) : -1);
    // int x = -1
    int x = (argCount >= 6 ? (int)wxlua_getnumbertype(L, 6) : -1);
    // wxWindow *parent = (wxWindow *) NULL
    wxWindow *parent = (argCount >= 5 ? (wxWindow *)wxluaT_getuserdatatype(L, 5, wxluatype_wxWindow) : (wxWindow *) NULL);
    // const wxString& choices[]
    int count = 0; wxLuaSmartStringArray choices = wxlua_getwxStringarray(L, 4, count);
    // const wxString& caption
    wxString caption = wxlua_getwxStringtype(L, 3);
    // const wxString& message
    wxString message = wxlua_getwxStringtype(L, 2);
    // wxArrayInt& selections
    wxLuaSmartwxArrayInt selections = wxlua_getwxArrayInt(L, 1);

    // call wxGetMultipleChoices
    size_t returns = wxGetMultipleChoices(selections, message, caption, count, choices, parent, x, y, centre, width, height);

    wxlua_pushwxArrayInttable(L, selections);

    // push the result number
    lua_pushinteger(L, returns);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxFileDialog_GetFilenames
// void GetFilenames(wxArrayString& filenames) const
static int LUACALL wxLua_wxFileDialog_GetFilenames(lua_State *L)
{
    wxArrayString fileNames;
    wxFileDialog *self = (wxFileDialog *)wxluaT_getuserdatatype(L, 1, wxluatype_wxFileDialog);
    // call GetPaths
    self->GetFilenames(fileNames);
    // return values
    wxlua_pushwxArrayStringtable(L, fileNames);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxFileDialog_GetPaths
// void GetPaths(wxArrayString& paths) const
static int LUACALL wxLua_wxFileDialog_GetPaths(lua_State *L)
{
    wxArrayString paths;
    wxFileDialog *self = (wxFileDialog *)wxluaT_getuserdatatype(L, 1, wxluatype_wxFileDialog);
    // call GetPaths
    self->GetPaths(paths);
    // return values
    wxlua_pushwxArrayStringtable(L, paths);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxSingleChoiceDialog_constructor
//     wxSingleChoiceDialog(wxWindow* parent, const wxString& message, const wxString& caption, const wxArrayString& choices, long style = wxCHOICEDLG_STYLE, const wxPoint& pos = wxDefaultPosition)
static int LUACALL wxLua_wxSingleChoiceDialog_constructor(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // const wxPoint pos = wxDefaultPosition
    const wxPoint * pos = (argCount >= 6 ? (const wxPoint *)wxluaT_getuserdatatype(L, 6, wxluatype_wxPoint) : &wxDefaultPosition);
    // long style = wxCHOICEDLG_STYLE
    long style = (argCount >= 5 ? (long)wxlua_getintegertype(L, 5) : wxCHOICEDLG_STYLE);
    // const wxArrayString choices
    wxLuaSmartwxArrayString choices = wxlua_getwxArrayString(L, 4);
    // const wxString caption
    const wxString caption = wxlua_getwxStringtype(L, 3);
    // const wxString message
    const wxString message = wxlua_getwxStringtype(L, 2);
    // wxWindow parent
    wxWindow * parent = (wxWindow *)wxluaT_getuserdatatype(L, 1, wxluatype_wxWindow);
    // call constructor
    wxSingleChoiceDialog *returns = new wxSingleChoiceDialog(parent, message, caption, choices, (void**)NULL, style, *pos);
    // add to tracked window list
    if (returns && returns->IsKindOf(CLASSINFO(wxWindow)))
        wxluaW_addtrackedwindow(L, (wxWindow*)returns);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxSingleChoiceDialog);

    return 1;
}
%end

%override wxLua_wxProgressDialog_Update
//     bool    Update(int value = -1, const wxString &newmsg = "")
static int LUACALL wxLua_wxProgressDialog_Update(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // const wxString newmsg = ""
    const wxString newmsg = (argCount >= 3 ? wxlua_getwxStringtype(L, 3) : wxString(wxEmptyString));
    // int value = -1
    int value = (argCount >= 2 ? (int)wxlua_getnumbertype(L, 2) : -1);
    // get this
    wxProgressDialog * self = (wxProgressDialog *)wxluaT_getuserdatatype(L, 1, wxluatype_wxProgressDialog);
    // call Update
    bool skip = false;
    bool returns = self->Update(value, newmsg, &skip);
    // push the result flag
    lua_pushboolean(L, returns);
    lua_pushboolean(L, skip);

    return 2;
}
%end

// ----------------------------------------------------------------------------
// Overrides for event.i
// ----------------------------------------------------------------------------

%override wxLua_wxKeyEvent_GetPositionXY
static int LUACALL wxLua_wxKeyEvent_GetPositionXY(lua_State *L)
{
    wxCoord y;
    wxCoord x;
    // get this
    wxKeyEvent *self = (wxKeyEvent *)wxluaT_getuserdatatype(L, 1, wxluatype_wxKeyEvent);
    // call GetPositionXY
    self->GetPosition(&x, &y);
    // push results
    lua_pushinteger(L, x);
    lua_pushinteger(L, y);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxMouseEvent_GetPositionXY
// void GetPositionXY(wxCoord* x, wxCoord* y) const
static int LUACALL wxLua_wxMouseEvent_GetPositionXY(lua_State *L)
{
    wxCoord y;
    wxCoord x;
    // get this
    wxMouseEvent *self = (wxMouseEvent *)wxluaT_getuserdatatype(L, 1, wxluatype_wxMouseEvent);
    // call GetPosition
    self->GetPosition(&x, &y);
    // push results
    lua_pushinteger(L, x);
    lua_pushinteger(L, y);
    // return the number of parameters
    return 2;
}
%end

// ----------------------------------------------------------------------------
// Overrides for gdi.i
// ----------------------------------------------------------------------------

%override wxLua_wxPoint_GetXY
// int GetXY()
static int LUACALL wxLua_wxPoint_GetXY(lua_State *L)
{
    // get this
    wxPoint *self = (wxPoint *)wxluaT_getuserdatatype(L, 1, wxluatype_wxPoint);
    // push the result number
    lua_pushinteger(L, self->x);
    lua_pushinteger(L, self->y);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxPoint_Set
// void Set(int x, int y)
static int LUACALL wxLua_wxPoint_Set(lua_State *L)
{
    // int y
    int y = (int)wxlua_getnumbertype(L, 3);
    // int x
    int x = (int)wxlua_getnumbertype(L, 2);
    // get this
    wxPoint *self = (wxPoint *)wxluaT_getuserdatatype(L, 1, wxluatype_wxPoint);
    self->x = x;
    self->y = y;
    // return the number of parameters
    return 0;
}
%end

%override wxLua_wxRegion_GetBoxXYWH
// %rename GetBoxCoords void GetBox(int &x, int &y, int &width, int &height)
static int LUACALL wxLua_wxRegion_GetBoxXYWH(lua_State *L)
{
    int height;
    int width;
    int y;
    int x;
    // get this
    wxRegion *self = (wxRegion *)wxluaT_getuserdatatype(L, 1, wxluatype_wxRegion);
    // call GetBox
    self->GetBox(x, y, width, height);
    lua_pushinteger(L, x);
    lua_pushinteger(L, y);
    lua_pushinteger(L, width);
    lua_pushinteger(L, height);
    // return the number of parameters
    return 4;
}
%end

%override wxLua_wxRegionIterator_Next
// void Next()
static int LUACALL wxLua_wxRegionIterator_Next(lua_State *L)
{
    // get this
    wxRegionIterator *self = (wxRegionIterator *)wxluaT_getuserdatatype(L, 1, wxluatype_wxRegionIterator);
    // call Next
    (*self)++;
    // return the number of parameters
    return 0;
}
%end

%override wxLua_wxFontMapper_GetAltForEncoding
// bool GetAltForEncoding(wxFontEncoding encoding, wxFontEncoding *altEncoding, const wxString &faceName = wxEmptyString, bool interactive = true)
static int LUACALL wxLua_wxFontMapper_GetAltForEncoding(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // bool interactive = true
    bool interactive = (argCount >= 5 ? wxlua_getbooleantype(L, 4) : true);
    // const wxString &faceName = wxEmptyString
    wxString faceName = (argCount >= 4 ? wxlua_getwxStringtype(L, 3) : wxString(wxT("")));
    // wxFontEncoding *altEncoding
    wxFontEncoding altEncoding;
    // wxFontEncoding encoding
    wxFontEncoding encoding = (wxFontEncoding)wxlua_getenumtype(L, 2);
    // get this
    wxFontMapper *self = (wxFontMapper *)wxluaT_getuserdatatype(L, 1, wxluatype_wxFontMapper);
    // call GetAltForEncoding
    bool returns = self->GetAltForEncoding(encoding, &altEncoding, faceName, interactive);
    // push the result number
    lua_pushboolean(L, returns);
    // push the result encoding
    lua_pushinteger(L, altEncoding);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxPen_GetDashes
// void GetDashes()
static int LUACALL wxLua_wxPen_GetDashes(lua_State *L)
{
    // get this
    wxPen *self = (wxPen *)wxluaT_getuserdatatype(L, 1, wxluatype_wxPen);
    // get dashes
    wxDash *dashes;
    int nb_dashes = self->GetDashes(&dashes);
    if (nb_dashes == 0)
        return 0;  //  No dashes are defined
    // create a table (which will be the return value)
    lua_newtable(L);
    for (int idx = 0; idx < nb_dashes; ++idx) {
        lua_pushinteger(L, dashes[idx]);
        lua_rawseti(L, -2, idx + 1);
    }
    //  return the number of parameters
    return 1;
}
%end

%override wxLua_wxPen_SetDashes
// void SetDashes()
static int LUACALL wxLua_wxPen_SetDashes(lua_State *L)
{
    // get this
    wxPen *self = (wxPen *)wxluaT_getuserdatatype(L, 1, wxluatype_wxPen);
    // check if we have a table argument
    if (!wxlua_iswxluatype(lua_type(L, 2), WXLUA_TTABLE))
        wxlua_argerror(L, 2, wxT("a 'table'"));
    int count = lua_objlen(L, 2);
    // allocate an array of wxDashes
    // TODO: this memory will leak when wxPen is destroyed. The wxWidgets document states
    // that we should not free 'dashes' until we destroy the wxPen.
    wxDash *dashes = new wxDash[count];
    for (int idx = 1; idx <= count; idx++) {
        lua_rawgeti(L, 2, idx);
        dashes[idx - 1] = (wxDash)lua_tonumber(L, -1);
        lua_pop(L, 1);
    }
    self->SetDashes(count, dashes);
    return 0;
}
%end

%override wxLua_wxPalette_Create
// bool Create(int n, const unsigned char* red, const unsigned char* green, const unsigned char* blue)
static int LUACALL wxLua_wxPalette_Create(lua_State *L)
{
    // const unsigned char* blue
    size_t blue_len = 0;
    const unsigned char *blue = (unsigned char *)lua_tolstring(L, 5, &blue_len);
    // const unsigned char* green
    size_t green_len = 0;
    const unsigned char *green = (unsigned char *)lua_tolstring(L, 4, &green_len);
    // const unsigned char* red
    size_t red_len = 0;
    const unsigned char *red = (unsigned char *)lua_tolstring(L, 3, &red_len);
    // int n
    int n = (int)wxlua_getintegertype(L, 2);
    size_t nn = (size_t)n;
    if ((nn > blue_len)||(nn > green_len)||(nn > red_len))
        wxlua_argerrormsg(L, wxT("Invalid palette lengths for wxPalette constructor."));
    // get this
    wxPalette *self = (wxPalette *)wxluaT_getuserdatatype(L, 1, wxluatype_wxPalette);
    // call Create
#if wxCHECK_VERSION(2,9,0) && defined(__WXMSW__) && !wxCHECK_VERSION(2,9,5)
    bool returns = self->Create(n, (unsigned char*)red, (unsigned char*)green, (unsigned char*)blue); // NOTE: wxMSW does not modify these, see SVN rev 50727
#else
    bool returns = self->Create(n, red, green, blue);
#endif
    // push the result number
    lua_pushboolean(L, returns);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxPalette_GetRGB
// bool GetRGB(int pixel, unsigned char* red, unsigned char* green, unsigned char* blue) const
static int LUACALL wxLua_wxPalette_GetRGB(lua_State *L)
{
    // int pixel
    int pixel = (int)wxlua_getintegertype(L, 2);
    // get this
    wxPalette *self = (wxPalette *)wxluaT_getuserdatatype(L, 1, wxluatype_wxPalette);
    // call GetRGB
    unsigned char red = 0, green = 0, blue = 0;
    bool returns = self->GetRGB(pixel, &red, &green, &blue);
    // push the result number
    lua_pushboolean(L, returns);
    lua_pushinteger(L, red);
    lua_pushinteger(L, green);
    lua_pushinteger(L, blue);
    // return the number of parameters
    return 4;
}
%end

%override wxLua_wxCaret_GetPositionXY
// %rename GetPositionXY void GetPosition(int *x, int *y)
static int LUACALL wxLua_wxCaret_GetPositionXY(lua_State *L)
{
    int x;
    int y;
    // get this
    wxCaret *self = (wxCaret *)wxluaT_getuserdatatype(L, 1, wxluatype_wxCaret);
    // call GetPosition
    self->GetPosition(&x, &y);
    // return the number of parameters
    lua_pushinteger(L, x);
    lua_pushinteger(L, y);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxCaret_GetSizeWH
// %rename GetSizeWH void GetSize(int *x, int *y)
static int LUACALL wxLua_wxCaret_GetSizeWH(lua_State *L)
{
    int x;
    int y;
    // get this
    wxCaret *self = (wxCaret *)wxluaT_getuserdatatype(L, 1, wxluatype_wxCaret);
    // call GetSize
    self->GetSize(&x, &y);
    lua_pushinteger(L, x);
    lua_pushinteger(L, y);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxBitmapFromBits_constructor
// %win wxBitmap(const char* bits, int width, int height, int depth = -1)
static int LUACALL wxLua_wxBitmapFromBits_constructor(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // int depth = -1
    int depth = (argCount >= 4 ? (int)wxlua_getintegertype(L, 4) : -1);
    // int height
    int height = (int)wxlua_getintegertype(L, 3);
    // int width
    int width = (int)wxlua_getintegertype(L, 2);
    // const char* bits
    const char *bits = (const char *)lua_tostring(L, 1);
    // call constructor
    wxBitmap *returns = new wxBitmap(bits, width, height, depth);
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxBitmap);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxBitmap);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxBitmapFromBitTable_constructor
// %win wxBitmap(LuaTable charTable, int width, int height, int depth = -1)
static int LUACALL wxLua_wxBitmapFromBitTable_constructor(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // int depth = -1
    int depth = (argCount >= 4 ? (int)wxlua_getintegertype(L, 4) : -1);
    // int height
    int height = (int)wxlua_getintegertype(L, 3);
    // int width
    int width = (int)wxlua_getintegertype(L, 2);

    if (!wxlua_iswxluatype(lua_type(L, 1), WXLUA_TTABLE))
        wxlua_argerror(L, 1, wxT("a 'table'"));

    // const char* bits
    int size = height*width/8;
    char *bits = (char*)malloc(size);

    for (int n = 0; n < size; ++n)
    {
        lua_rawgeti(L, 1, n+1); // Lua array starts at 1

        if (!wxlua_iswxluatype(lua_type(L, -1), WXLUA_TINTEGER))
        {
            free(bits);
            wxlua_argerror(L, 1, wxT("a 'table of chars of size width*height/8'"));
        }

        bits[n] = (char)lua_tonumber(L, -1);
        lua_pop(L, 1);
    }

    // call constructor
    wxBitmap *returns = new wxBitmap(bits, width, height, depth);
    free(bits);

    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxBitmap);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxBitmap);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxBitmapFromData_constructor
// %win wxBitmap(void* data, wxBitmapType type, int width, int height, int depth = -1)
#ifdef __WXMSW__
static int LUACALL wxLua_wxBitmapFromData_constructor(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // int depth = -1
    int depth = (argCount >= 5 ? (int)wxlua_getintegertype(L, 5) : -1);
    // int height
    int height = (int)wxlua_getintegertype(L, 4);
    // int width
    int width = (int)wxlua_getintegertype(L, 3);
    // int type
    wxBitmapType type = (wxBitmapType)wxlua_getintegertype(L, 2);
    // void* data
    void *data = (void *)lua_tostring(L, 1);
    // call constructor
    wxBitmap *returns = new wxBitmap(data, type, width, height, depth);
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxBitmap);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxBitmap);
    // return the number of parameters
    return 1;
}
#endif
%end

%override wxLua_wxBitmapFromXPMData_constructor
// %constructor wxXmlResourceGetDefault()
static int LUACALL wxLua_wxBitmapFromXPMData_constructor(lua_State *L)
{
    int count = 0;

    const char **sizeArray = wxlua_getchararray(L, 1, count);
    if (sizeArray != NULL)
    {
        // call constructor
        wxBitmap *returns = new wxBitmap(sizeArray);
        delete [] sizeArray;
        // add to tracked memory list
        wxluaO_addgcobject(L, returns, wxluatype_wxBitmap);
        // push the constructed class pointer
        wxluaT_pushuserdatatype(L, returns, wxluatype_wxBitmap);
        // return the number of parameters
        return 1;
    }

    return 0;
}
%end

%override wxLua_wxImageList_GetSize
// void    GetSize(int index, int& width, int& height)
static int LUACALL wxLua_wxImageList_GetSize(lua_State *L)
{
    // int& height
    int height;
    // int& width
    int width;
    // int index
    int index = (int)wxlua_getintegertype(L, 2);
    // get this
    wxImageList *self = (wxImageList *)wxluaT_getuserdatatype(L, 1, wxluatype_wxImageList);
    // call GetSize
    self->GetSize(index, width, height);
    lua_pushinteger(L, width);
    lua_pushinteger(L, height);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxDC_GetSize
// void GetSize(wxCoord *width, wxCoord *height)
static int LUACALL wxLua_wxDC_GetSize(lua_State *L)
{
    wxCoord width;
    wxCoord height;
    // get this
    wxDC *self = (wxDC *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDC);
    // call GetSize
    self->GetSize(&width, &height);
    lua_pushinteger(L, width);
    lua_pushinteger(L, height);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxDC_GetUserScale
// void GetUserScale(double *x, double *y)
static int LUACALL wxLua_wxDC_GetUserScale(lua_State *L)
{
    double y = 0;
    double x = 0;
    // get this
    wxDC *self = (wxDC *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDC);
    // call GetUserScale
    self->GetUserScale(&x, &y);
    lua_pushnumber(L, x);
    lua_pushnumber(L, y);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxDC_GetTextExtent
// void GetTextExtent(const wxString& string, wxCoord *w, wxCoord *h, wxCoord *descent = NULL, wxCoord *externalLeading = NULL, wxFont *font = NULL)
static int LUACALL wxLua_wxDC_GetTextExtent(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // wxFont *font = NULL
    wxFont *font = (argCount >= 3 ? (wxFont *)wxluaT_getuserdatatype(L, 3, wxluatype_wxFont) : NULL);

    wxCoord externalLeading;
    wxCoord descent;
    wxCoord h;
    wxCoord w;

    wxString string = wxlua_getwxStringtype(L, 2);
    // get this
    wxDC *self = (wxDC *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDC);
    // call GetTextExtent
    self->GetTextExtent(string, &w, &h, &descent, &externalLeading, font);
    lua_pushinteger(L, w);
    lua_pushinteger(L, h);
    lua_pushinteger(L, descent);
    lua_pushinteger(L, externalLeading);
    // return the number of parameters
    return 4;
}
%end

%override wxLua_wxDC_GetMultiLineTextExtent
// void GetMultiLineTextExtent(const wxString& string, wxCoord *w, wxCoord *h, wxCoord *heightLine = NULL, wxFont *font = NULL)
static int LUACALL wxLua_wxDC_GetMultiLineTextExtent(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // wxFont *font = NULL
    wxFont *font = (argCount >= 3 ? (wxFont *)wxluaT_getuserdatatype(L, 3, wxluatype_wxFont) : NULL);

    wxCoord heightLine;
    wxCoord h;
    wxCoord w;

    wxString string = wxlua_getwxStringtype(L, 2);
    // get this
    wxDC *self = (wxDC *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDC);
    // call GetTextExtent
    self->GetMultiLineTextExtent(string, &w, &h, &heightLine, font);
    lua_pushinteger(L, w);
    lua_pushinteger(L, h);
    lua_pushinteger(L, heightLine);
    // return the number of parameters
    return 4;
}
%end

%override wxLua_wxDC_GetClippingBox
// void GetClippingBox(wxCoord *x, wxCoord *y, wxCoord *width, wxCoord *height)
static int LUACALL wxLua_wxDC_GetClippingBox(lua_State *L)
{
    wxCoord height;
    wxCoord width;
    wxCoord y;
    wxCoord x;
    // get this
    wxDC *self = (wxDC *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDC);
    // call GetClippingBox
    self->GetClippingBox(&x, &y, &width, &height);
    // push results
    lua_pushinteger(L, x);
    lua_pushinteger(L, y);
    lua_pushinteger(L, width);
    lua_pushinteger(L, height);
    // return the number of parameters
    return 4;
}
%end

// ----------------------------------------------------------------------------
// Overrides for geometry.i
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// Overrides for help.i
// ----------------------------------------------------------------------------

%override wxLua_wxHelpControllerBase_GetFrameParameters
// virtual wxFrame* GetFrameParameters(wxSize* size = NULL, wxPoint* pos = NULL, bool *newFrameEachTime = NULL)
static int LUACALL wxLua_wxHelpControllerBase_GetFrameParameters(lua_State *L)
{
    bool    newFrameEachTime = false;
    wxPoint *pos = new wxPoint();
    wxSize  *size = new wxSize();
    // get this
    wxHelpControllerBase *self = (wxHelpControllerBase *)wxluaT_getuserdatatype(L, 1, wxluatype_wxHelpControllerBase);
    // call GetFrameParameters
    wxFrame *returns = self->GetFrameParameters(size, pos, &newFrameEachTime);
    // push the result datatype

    wxluaT_pushuserdatatype(L, returns, wxluatype_wxFrame);
    wxluaT_pushuserdatatype(L, size, wxluatype_wxSize);
    wxluaT_pushuserdatatype(L, pos, wxluatype_wxPoint);
    lua_pushboolean(L, newFrameEachTime);
    // return the number of parameters
    return 4;
}
%end

// ----------------------------------------------------------------------------
// Overrides for image.i
// ----------------------------------------------------------------------------

%override wxLua_wxImageFromData_constructor
// %constructor wxImageFromData(int width, int height, unsigned char* data, bool static_data = false)
static int LUACALL wxLua_wxImageFromData_constructor(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // bool static_data = false
    bool static_data = (argCount >= 4 ? wxlua_getbooleantype(L, 4) : false);
    // unsigned char* data
    unsigned char *data = (unsigned char *)wxlua_getstringtype(L, 3);
    // int height
    int height = (int)wxlua_getintegertype(L, 2);
    // int width
    int width = (int)wxlua_getintegertype(L, 1);
    // call constructor
    wxImage *returns = new wxImage(width, height, data, static_data);
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxImage);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxImage);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxImageFromBitmap_constructor
// %constructor wxImageFromBitmap(const wxBitmap& bitmap)
static int LUACALL wxLua_wxImageFromBitmap_constructor(lua_State *L)
{
    // const wxBitmap& bitmap
    const wxBitmap *bitmap = (wxBitmap *)wxluaT_getuserdatatype(L, 1, wxluatype_wxBitmap);
    // call constructor
    wxImage *returns = new wxImage(bitmap->ConvertToImage());
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxImage);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxImage);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxImage_FindFirstUnusedColour
//     bool FindFirstUnusedColour(unsigned char* r, unsigned char* g, unsigned char* b, unsigned char startR = 1, unsigned char startG = 0, unsigned char startB = 0)
static int LUACALL wxLua_wxImage_FindFirstUnusedColour(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // unsigned char startB = 0
    unsigned char startB = (argCount >= 4 ? (char)wxlua_getnumbertype(L, 4) : 0);
    // unsigned char startG = 0
    unsigned char startG = (argCount >= 3 ? (char)wxlua_getnumbertype(L, 3) : 0);
    // unsigned char startR = 1
    unsigned char startR = (argCount >= 2 ? (char)wxlua_getnumbertype(L, 2) : 1);
    // get this
    wxImage * self = (wxImage *)wxluaT_getuserdatatype(L, 1, wxluatype_wxImage);
    // call FindFirstUnusedColour
    unsigned char r = 0, g = 0, b = 0;
    bool returns = self->FindFirstUnusedColour(&r, &g, &b, startR, startG, startB);
    // push the result flag
    lua_pushboolean(L, returns);
    lua_pushinteger(L, r);
    lua_pushinteger(L, g);
    lua_pushinteger(L, b);

    return 4;
}
%end

%override wxLua_wxImage_GetData
//     unsigned char* GetData() const
static int LUACALL wxLua_wxImage_GetData(lua_State *L)
{
    // get this
    wxImage * self = (wxImage *)wxluaT_getuserdatatype(L, 1, wxluatype_wxImage);
    // call GetData
    char* returns = (char*)self->GetData();
    // push the result pointer
    lua_pushlstring(L, returns, self->GetWidth()*self->GetHeight()*3);

    return 1;
}
%end

%override wxLua_wxImage_GetOrFindMaskColour
// bool GetOrFindMaskColour(unsigned char *r, unsigned char *g, unsigned char *b) const
static int LUACALL wxLua_wxImage_GetOrFindMaskColour(lua_State *L)
{
    // get this
    wxImage * self = (wxImage *)wxluaT_getuserdatatype(L, 1, wxluatype_wxImage);
    // call FindFirstUnusedColour
    unsigned char r = 0, g = 0, b = 0;
    bool returns = self->GetOrFindMaskColour(&r, &g, &b);
    // push the result flag
    lua_pushboolean(L, returns);
    lua_pushinteger(L, r);
    lua_pushinteger(L, g);
    lua_pushinteger(L, b);

    return 4;
}
%end

%override wxLua_wxImage_RGBtoHSV
//     static int RGBtoHSV(unsigned char r, unsigned char g, unsigned char b)
static int LUACALL wxLua_wxImage_RGBtoHSV(lua_State *L)
{
    // unsigned char b
    unsigned char b = (char)wxlua_getnumbertype(L, 4);
    // unsigned char g
    unsigned char g = (char)wxlua_getnumbertype(L, 3);
    // unsigned char r
    unsigned char r = (char)wxlua_getnumbertype(L, 2);
    // call HSVtoRGB
    wxImage::HSVValue hsvValue = wxImage::RGBtoHSV(wxImage::RGBValue(r, g, b));
    // push the result number
    lua_pushinteger(L, hsvValue.hue);
    lua_pushinteger(L, hsvValue.saturation);
    lua_pushinteger(L, hsvValue.value);

    return 3;
}
%end

%override wxLua_wxImage_HSVtoRGB
//     static int HSVtoRGB(double h, double s, double v)
static int LUACALL wxLua_wxImage_HSVtoRGB(lua_State *L)
{
    // double v
    double v = (double)wxlua_getnumbertype(L, 4);
    // double s
    double s = (double)wxlua_getnumbertype(L, 3);
    // double h
    double h = (double)wxlua_getnumbertype(L, 2);
    // call HSVtoRGB
    wxImage::RGBValue rgbValue = wxImage::HSVtoRGB(wxImage::HSVValue(h, s, v));
    // push the result number
    lua_pushinteger(L, rgbValue.red);
    lua_pushinteger(L, rgbValue.green);
    lua_pushinteger(L, rgbValue.blue);

    return 3;
}
%end

%override wxLua_wxImage_GetAlphaData
//     unsigned char* GetAlpha() const
static int LUACALL wxLua_wxImage_GetAlphaData(lua_State *L)
{
    // get this
    wxImage * self = (wxImage *)wxluaT_getuserdatatype(L, 1, wxluatype_wxImage);
    // call GetAlpha
    char* returns = (char*)self->GetAlpha();

    if(returns) {
        // push the result pointer
        lua_pushlstring(L, returns, self->GetWidth()*self->GetHeight());
    } else {
        lua_pushnil(L);
    }

    return 1;
}
%end

%override wxLua_wxImage_SetAlphaData
// void SetAlpha(unsigned char *alpha = NULL,bool static_data = false)
static int LUACALL wxLua_wxImage_SetAlphaData(lua_State *L)
{
    // unsigned char *data
    size_t len = 0;
    unsigned char *data = (unsigned char *)wxlua_getstringtypelen(L, 2, &len);
    // get this
    wxImage *self = (wxImage *)wxluaT_getuserdatatype(L, 1, wxluatype_wxImage);
    // call SetData
    if ((len == 0) || !self->Ok()) wxlua_argerrormsg(L, wxT("Invalid data or wxImage to call SetAlphaData() to."));
    // don't actually call SetAlpha since it takes ownership of data
    // just copy it to the image
    self->SetAlpha(NULL); // the wxImage will create the alpha channel for us
    size_t size = self->GetWidth()*self->GetHeight();
    memcpy(self->GetAlpha(), data, wxMin(len, size));
    // return the number of parameters
    return 0;
}
%end

%override wxLua_wxImage_SetData
// void SetData(unsigned char *data)
static int LUACALL wxLua_wxImage_SetData(lua_State *L)
{
    // unsigned char *data
    size_t len = 0;
    unsigned char *data = (unsigned char *)wxlua_getstringtypelen(L, 2, &len);
    // get this
    wxImage *self = (wxImage *)wxluaT_getuserdatatype(L, 1, wxluatype_wxImage);
    // call SetData
    if ((len == 0) || !self->Ok()) wxlua_argerrormsg(L, wxT("Invalid data or wxImage to call SetData() on."));
    // don't actually call SetData since it takes ownership of data
    // just copy it to the image
    size_t size = 3*self->GetWidth()*self->GetHeight();
    memcpy(self->GetData(), data, wxMin(len, size));
    // return the number of parameters
    return 0;
}
%end

%override wxLua_wxImageHistogram_iterator_Get_first
//     %member long first
static int LUACALL wxLua_wxImageHistogram_iterator_Get_first(lua_State *L)
{
    // get this
    wxImageHistogram::iterator *self = (wxImageHistogram::iterator *) wxluaT_getuserdatatype(L, 1, wxluatype_wxImageHistogram_iterator);
    // push the result number
    lua_pushnumber(L, (*self)->first); // *** need to cast self to object from pointer
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxImageHistogram_iterator_Set_first
//     %member long first
static int LUACALL wxLua_wxImageHistogram_iterator_Set_first(lua_State *L)
{
    wxlua_argerrormsg(L, wxT("You cannot set the first element of a wxHashTable, do not use wxImageHistogram::iterator::SetFirst()."));
    return 0;
/*
    // get the number value
    long val = (long)wxlua_getnumbertype(L, 2);
    // get this
    wxImageHistogram::iterator *self = (wxImageHistogram::iterator *)wxluaT_getuserdatatype(L, 1, wxluatype_wxImageHistogram_iterator);
    (*self)->first = val; // *** need to cast self to object from pointer
    // return the number of parameters
    return 0;
*/
}
%end

%override wxLua_wxImageHistogram_iterator_Get_second
//     %member wxImageHistogramEntry second
static int LUACALL wxLua_wxImageHistogram_iterator_Get_second(lua_State *L)
{
    // get this
    wxImageHistogram::iterator *self = (wxImageHistogram::iterator *) wxluaT_getuserdatatype(L, 1, wxluatype_wxImageHistogram_iterator);
    // push the result datatype
    wxluaT_pushuserdatatype(L, &(*self)->second, wxluatype_wxImageHistogramEntry); // *** need to cast self to object from pointer
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxImageHistogram_iterator_Set_second
//     %member wxImageHistogramEntry second
static int LUACALL wxLua_wxImageHistogram_iterator_Set_second(lua_State *L)
{
    // get the data type value
    wxImageHistogramEntry* val = (wxImageHistogramEntry*)wxluaT_getuserdatatype(L, 2, wxluatype_wxImageHistogramEntry);
    // get this
    wxImageHistogram::iterator *self = (wxImageHistogram::iterator *)wxluaT_getuserdatatype(L, 1, wxluatype_wxImageHistogram_iterator);
    (*self)->second = *val; // *** need to cast self to object from pointer
    // return the number of parameters
    return 0;
}
%end

%override wxLua_wxQuantize_Quantize
//     static bool Quantize(const wxImage& src, wxImage& dest, wxPalette** pPalette, int desiredNoColours = 236, unsigned char** eightBitData = 0, int flags = wxQUANTIZE_INCLUDE_WINDOWS_COLOURS|wxQUANTIZE_FILL_DESTINATION_IMAGE|wxQUANTIZE_RETURN_8BIT_DATA);
static int LUACALL wxLua_wxQuantize_Quantize(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // int flags = wxQUANTIZE_INCLUDE_WINDOWS_COLOURS | wxQUANTIZE_FILL_DESTINATION_IMAGE | wxQUANTIZE_RETURN_8BIT_DATA
    int flags = (argCount >= 6 ? (int)wxlua_getnumbertype(L, 4) : wxQUANTIZE_INCLUDE_WINDOWS_COLOURS | wxQUANTIZE_FILL_DESTINATION_IMAGE | wxQUANTIZE_RETURN_8BIT_DATA);
    // int desiredNoColours = 236
    int desiredNoColours = (argCount >= 4 ? (int)wxlua_getnumbertype(L, 3) : 236);
    // wxImage dest
    wxImage * dest = (wxImage *)wxluaT_getuserdatatype(L, 2, wxluatype_wxImage);
    // const wxImage src
    const wxImage * src = (const wxImage *)wxluaT_getuserdatatype(L, 1, wxluatype_wxImage);
    // call Quantize
    bool returns = (wxQuantize::Quantize(*src, *dest, NULL, desiredNoColours, NULL, flags));
    // push the result flag
    lua_pushboolean(L, returns);

    return 1;
}
%end

%override wxLua_wxLuaArtProvider_constructor
//     wxLuaArtprovider()
static int LUACALL wxLua_wxLuaArtProvider_constructor(lua_State *L)
{
    wxLuaState wxlState(L);

    // call constructor
    wxLuaArtProvider *returns = new wxLuaArtProvider(wxlState);
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxLuaArtProvider);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxLuaArtProvider);

    return 1;
}
%end


// ----------------------------------------------------------------------------
// Overrides for mdi.i
// ----------------------------------------------------------------------------

// FIXME - do we really need to copy the wxList here?
%override wxLua_wxDocManager_GetDocuments
// wxList& GetDocuments()
static int LUACALL wxLua_wxDocManager_GetDocuments(lua_State *L)
{
    // get this
    wxDocManager *self = (wxDocManager *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDocManager);
    // call GetDocuments
    wxList &docs = self->GetDocuments();
    wxList *returns = new wxList(docs);
    // push the result datatype
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxList);
    // return the number of parameters
    return 1;
}
%end

// FIXME - do we really need to copy the wxList here?
%override wxLua_wxDocManager_GetTemplates
// wxList& GetTemplates()
static int LUACALL wxLua_wxDocManager_GetTemplates(lua_State *L)
{
    // get this
    wxDocManager *self = (wxDocManager *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDocManager);
    // call GetDocuments
    wxList &docs = self->GetTemplates();
    wxList *returns = new wxList(docs);
    // push the result datatype
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxList);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxDocManager_MakeDefaultName
//     bool MakeDefaultName(wxString& buf)
static int LUACALL wxLua_wxDocManager_MakeDefaultName(lua_State *L)
{
    // wxString buf
    wxString buf = wxlua_getwxStringtype(L, 2);
    // get this
    wxDocManager * self = (wxDocManager *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDocManager);
    // call MakeDefaultName
    bool returns = self->MakeDefaultName(buf);
    // push the result flag
    lua_pushboolean(L, returns);
    wxlua_pushwxString(L, buf);

    return 2;
}
%end

%override wxLua_wxDocument_GetPrintableName
//     virtual void GetPrintableName(wxString& name) const
static int LUACALL wxLua_wxDocument_GetPrintableName(lua_State *L)
{
    // wxString name
    wxString name = wxlua_getwxStringtype(L, 2);
    // get this
    wxDocument * self = (wxDocument *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDocument);
    // call GetPrintableName
    self->GetPrintableName(name);
    wxlua_pushwxString(L, name);

    return 1;
}
%end

%override wxLua_wxDocument_GetViews
// wxList& GetViews() const
static int LUACALL wxLua_wxDocument_GetViews(lua_State *L)
{
    // get this
    wxDocument *self = (wxDocument *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDocument);
    // call GetViews
    wxList &views = self->GetViews();
    wxList *returns = new wxList(views);
    // push the result datatype
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxList);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxCommandProcessor_GetCommands
// wxList& GetCommands() const
static int LUACALL wxLua_wxCommandProcessor_GetCommands(lua_State *L)
{
    // get this
    wxCommandProcessor *self = (wxCommandProcessor *)wxluaT_getuserdatatype(L, 1, wxluatype_wxCommandProcessor);
    // call GetCommands
    wxList &commands = self->GetCommands();
    wxList *returns = new wxList(commands);
    // push the result datatype
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxList);
    // return the number of parameters
    return 1;
}
%end

// ----------------------------------------------------------------------------
// Overrides for menutool.i
// ----------------------------------------------------------------------------

%override wxLua_wxCreateMenu_constructor
// %constructor wxCreateMenu(int table, const wxString& title = "", long style = 0)
static int LUACALL wxLua_wxCreateMenu_constructor(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // long style = 0
    long style = (argCount >= 3 ? (long)wxlua_getintegertype(L, 3) : 0);
    // const wxString& title = ""
    wxString title = (argCount >= 2 ? wxlua_getwxStringtype(L, 2) : wxString(wxT("")));
    // int table
    if (lua_istable(L, 1))
    {
        // call constructor
        wxMenu *returns = new wxMenu(title, style);

        int idx, count = luaL_getn(L, 1);

        for (idx = 1; idx <= count; ++idx)
        {
            lua_pushinteger(L, idx);
            lua_gettable(L, -2);

            if (lua_istable(L, -1))
            {
                lua_pushinteger(L, 1);
                lua_gettable(L, -2);
                if (lua_isnil(L, -1))
                {
                    returns->AppendSeparator();
                    lua_pop(L, 1);
                }
                else
                {
                    wxString helpText;
                    wxString menuText;
                    wxItemKind kind = wxITEM_NORMAL;

                    int iValue = (int)lua_tonumber(L, -1);
                    lua_pop(L, 1);

                    lua_pushinteger(L, 2);
                    lua_gettable(L, -2);
                    menuText = wxlua_getwxStringtype(L, -1);
                    lua_pop(L, 1);

                    lua_pushinteger(L, 3);
                    lua_gettable(L, -2);
                    if (lua_isstring(L, -1))
                        helpText = wxlua_getwxStringtype(L, -1);
                    lua_pop(L, 1);

                    lua_pushinteger(L, 4);
                    lua_gettable(L, -2);
                    if (lua_isnumber(L, -1))
                        kind = (wxItemKind)wxlua_getenumtype(L, -1);
                    lua_pop(L, 1);

                    returns->Append(iValue, menuText, helpText, kind);
                }
            }
            lua_pop(L, 1);
        }

        // push the constructed class pointer
        wxluaT_pushuserdatatype(L, returns, wxluatype_wxMenu);
        // return the number of parameters
        return 1;
    }
    return 0;
}
%end

%override wxLua_wxMenu_FindItemById
//     %rename FindItemById wxMenuItem* FindItem(int id, wxMenu **menu = NULL) const
static int LUACALL wxLua_wxMenu_FindItemById(lua_State *L)
{
    // int id
    int id = (int)wxlua_getintegertype(L, 2);
    // get this
    wxMenu * self = (wxMenu *)wxluaT_getuserdatatype(L, 1, wxluatype_wxMenu);
    // call FindItem
    wxMenu* foundMenu = NULL;
    wxMenuItem *returns = self->FindItem(id, &foundMenu);
    // push the result datatype
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxMenuItem);
    if (foundMenu != NULL)
    {
        wxluaT_pushuserdatatype(L, foundMenu, wxluatype_wxMenu);
        return 2;
    }

    return 1;
}
%end

%override wxLua_wxMenuBar_FindItem
//     wxMenuItem* FindItem(int id, wxMenu **menu = NULL) const
static int LUACALL wxLua_wxMenuBar_FindItem(lua_State *L)
{
    // int id
    int id = (int)wxlua_getintegertype(L, 2);
    // get this
    wxMenuBar * self = (wxMenuBar *)wxluaT_getuserdatatype(L, 1, wxluatype_wxMenuBar);
    // call FindItem
    wxMenu* foundMenu = NULL;
    wxMenuItem *returns = self->FindItem(id, &foundMenu);
    // push the result datatype
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxMenuItem);
    if (foundMenu != NULL)
    {
        wxluaT_pushuserdatatype(L, foundMenu, wxluatype_wxMenu);
        return 2;
    }

    return 1;
}
%end

%override wxLua_wxMenuItem_constructor
// wxMenuItem(wxMenu *parentMenu = NULL, int id = wxID_SEPARATOR, const wxString& text = wxEmptyString, const wxString& help = wxEmptyString, wxItemKind = 0, wxMenu *subMenu = NULL)
static int LUACALL wxLua_wxMenuItem_constructor(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // wxMenu *subMenu = NULL
    wxMenu *subMenu = (argCount >= 6 ? (wxMenu *)wxluaT_getuserdatatype(L, 6, wxluatype_wxMenu) : NULL);
    // bool isCheckable = false
    // This used to be a bool instead of a wxItemKind
    wxItemKind itemkind = (wxItemKind)(argCount >= 5 ? wxlua_getenumtype(L, 5) : wxITEM_NORMAL);
    // const wxString& help = wxEmptyString
    wxString help = (argCount >= 4 ? wxlua_getwxStringtype(L, 4) : wxString(wxEmptyString));
    // const wxString& text = wxEmptyString
    wxString text = (argCount >= 3 ? wxlua_getwxStringtype(L, 3) : wxString(wxEmptyString));
    // int id = wxID_SEPARATOR
    int id = (argCount >= 2 ? (int)wxlua_getintegertype(L, 2) : wxID_SEPARATOR);
    // wxMenu *parentMenu = NULL
    wxMenu *parentMenu = (argCount >= 1 ? (wxMenu *)wxluaT_getuserdatatype(L, 1, wxluatype_wxMenu) : NULL);
    // call constructor
    wxMenuItem *returns = new wxMenuItem(parentMenu, id, text, help, itemkind, subMenu);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxMenuItem);
    // return the number of parameters
    return 1;
}
%end

// ----------------------------------------------------------------------------
// Overrides for print.i
// ----------------------------------------------------------------------------

%override wxLua_wxPrintout_GetPageInfo
// void GetPageInfo(int *minPage, int *maxPage, int *pageFrom, int *pageTo)
static int LUACALL wxLua_wxPrintout_GetPageInfo(lua_State *L)
{
    int pageTo;
    int pageFrom;
    int maxPage;
    int minPage;
    // get this
    wxPrintout *self = (wxPrintout *)wxluaT_getuserdatatype(L, 1, wxluatype_wxPrintout);
    // call GetPageInfo
    self->GetPageInfo(&minPage, &maxPage, &pageFrom, &pageTo);
    lua_pushinteger(L, minPage);
    lua_pushinteger(L, maxPage);
    lua_pushinteger(L, pageFrom);
    lua_pushinteger(L, pageTo);
    // return the number of parameters
    return 4;
}
%end

%override wxLua_wxPrintout_GetPageSizeMM
// void GetPageSizeMM(int *w, int *h)
static int LUACALL wxLua_wxPrintout_GetPageSizeMM(lua_State *L)
{
    int h;
    int w;
    // get this
    wxPrintout *self = (wxPrintout *)wxluaT_getuserdatatype(L, 1, wxluatype_wxPrintout);
    // call GetPageSizeMM
    self->GetPageSizeMM(&w, &h);
    // return the number of parameters
    lua_pushinteger(L, w);
    lua_pushinteger(L, h);
    return 2;
}
%end

%override wxLua_wxPrintout_GetPageSizePixels
// void GetPageSizePixels(int *w, int *h)
static int LUACALL wxLua_wxPrintout_GetPageSizePixels(lua_State *L)
{
    int h;
    int w;
    // get this
    wxPrintout *self = (wxPrintout *)wxluaT_getuserdatatype(L, 1, wxluatype_wxPrintout);
    // call GetPageSizePixels
    self->GetPageSizePixels(&w, &h);
    // return the number of parameters
    lua_pushinteger(L, w);
    lua_pushinteger(L, h);
    return 2;
}
%end

%override wxLua_wxPrintout_GetPPIPrinter
// void GetPPIPrinter(int *w, int *h)
static int LUACALL wxLua_wxPrintout_GetPPIPrinter(lua_State *L)
{
    int h;
    int w;
    // get this
    wxPrintout *self = (wxPrintout *)wxluaT_getuserdatatype(L, 1, wxluatype_wxPrintout);
    // call GetPPIPrinter
    self->GetPPIPrinter(&w, &h);
    // return the number of parameters
    lua_pushinteger(L, w);
    lua_pushinteger(L, h);
    return 2;
}
%end

%override wxLua_wxPrintout_GetPPIScreen
// void GetPPIScreen(int *w, int *h)
static int LUACALL wxLua_wxPrintout_GetPPIScreen(lua_State *L)
{
    int h;
    int w;
    // get this
    wxPrintout *self = (wxPrintout *)wxluaT_getuserdatatype(L, 1, wxluatype_wxPrintout);
    // call GetPPIScreen
    self->GetPPIScreen(&w, &h);
    // return the number of parameters
    lua_pushinteger(L, w);
    lua_pushinteger(L, h);
    return 2;
}
%end

%override wxLua_wxPrintData_Copy
// wxPrintData *Copy()
static int LUACALL wxLua_wxPrintData_Copy(lua_State *L)
{
    wxPrintData *self    = (wxPrintData *)wxluaT_getuserdatatype(L, 1, wxluatype_wxPrintData);
    wxPrintData *returns = new wxPrintData;
    // Copy data over
    *returns = *self;
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxPrintData);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxPrintData);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxPageSetupDialogData_Copy
// wxPrintData *Copy()
static int LUACALL wxLua_wxPageSetupDialogData_Copy(lua_State *L)
{
    wxPageSetupDialogData *self    = (wxPageSetupDialogData *)wxluaT_getuserdatatype(L, 1, wxluatype_wxPageSetupDialogData);
    wxPageSetupDialogData *returns = new wxPageSetupDialogData;
    // Copy data over
    *returns = *self;
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxPageSetupDialogData);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxPageSetupDialogData);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxPrintPreview_constructor
// wxPrintPreview(wxLuaPrintout* printout, wxLuaPrintout* printoutForPrinting, wxPrintData* data=NULL)
static int LUACALL wxLua_wxPrintPreview_constructor(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // wxPrintData* data=NULL
    wxPrintData *data = (argCount >= 3 ? (wxPrintData *)wxluaT_getuserdatatype(L, 3, wxluatype_wxPrintData) : NULL);
    // wxLuaPrintout* printoutForPrinting
    wxLuaPrintout *printoutForPrinting = (argCount >= 2 ? (wxLuaPrintout *)wxluaT_getuserdatatype(L, 2, wxluatype_wxLuaPrintout) : NULL);
    // wxLuaPrintout* printout
    wxLuaPrintout *printout = (wxLuaPrintout *)wxluaT_getuserdatatype(L, 1, wxluatype_wxLuaPrintout);

    // when the wxPrintPreview constructor is called, the
    // object takes over ownership of the wxPrintout objects, therefore
    // we must disconnect them from our tracking list
    if (printoutForPrinting != NULL)
        wxluaO_undeletegcobject(L, printoutForPrinting);
    wxluaO_undeletegcobject(L, printout);

    // call constructor
    wxPrintPreview *returns = new wxPrintPreview(printout, printoutForPrinting, data);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxPrintPreview);
    // return the number of parameters
    return 1;
}
%end

// ----------------------------------------------------------------------------
// Overrides for sizer.i
// ----------------------------------------------------------------------------

%override wxLua_wxGBSizerItem_GetEndPos
//     void GetEndPos(int& row, int& col)
static int LUACALL wxLua_wxGBSizerItem_GetEndPos(lua_State *L)
{
    int col = 0;
    int row = 0;
    // get this
    wxGBSizerItem * self = (wxGBSizerItem *)wxluaT_getuserdatatype(L, 1, wxluatype_wxGBSizerItem);
    // call GetEndPos
    self->GetEndPos(row, col);
    lua_pushinteger(L, row);
    lua_pushinteger(L, col);
    return 2;
}
%end

// ----------------------------------------------------------------------------
// Overrides for thread.i
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// Overrides for wave.i
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// Overrides for windows.i
// ----------------------------------------------------------------------------

%override wxLua_wxWindow_ClientToScreenXY
// %rename ClientToScreenXY virtual void ClientToScreen(int* x, int* y) const
static int LUACALL wxLua_wxWindow_ClientToScreenXY(lua_State *L)
{
    int y = (int)lua_tonumber(L,  3);
    int x = (int)lua_tonumber(L,  2);
    // get this
    wxWindow *self = (wxWindow *)wxluaT_getuserdatatype(L, 1, wxluatype_wxWindow);
    // call ClientToScreen
    self->ClientToScreen(&x, &y);
    lua_pushinteger(L, x);
    lua_pushinteger(L, y);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxWindow_GetClientSizeWH
// virtual wxSize GetClientSize() const
static int LUACALL wxLua_wxWindow_GetClientSizeWH(lua_State *L)
{
    wxWindow *self = (wxWindow *)wxluaT_getuserdatatype(L, 1, wxluatype_wxWindow);
    // call GetClientSize
    wxSize size = self->GetClientSize();
    lua_pushinteger(L, size.x);
    lua_pushinteger(L, size.y);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxWindow_GetPositionXY
// virtual void GetPositionXY(int* x, int* y) const
static int LUACALL wxLua_wxWindow_GetPositionXY(lua_State *L)
{
    int y = 0;
    int x = 0;
    // get this
    wxWindow *self = (wxWindow *)wxluaT_getuserdatatype(L, 1, wxluatype_wxWindow);
    // call GetPosition
    self->GetPosition(&x, &y);
    lua_pushinteger(L, x);
    lua_pushinteger(L, y);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxWindow_GetScreenPositionXY
// virtual void GetScreenPositionXY(int* x, int* y) const
static int LUACALL wxLua_wxWindow_GetScreenPositionXY(lua_State *L)
{
    int y = 0;
    int x = 0;
    // get this
    wxWindow *self = (wxWindow *)wxluaT_getuserdatatype(L, 1, wxluatype_wxWindow);
    // call GetPosition
    self->GetScreenPosition(&x, &y);
    lua_pushinteger(L, x);
    lua_pushinteger(L, y);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxWindow_GetSizeWH
// void GetSize(int *width, int *height)
static int LUACALL wxLua_wxWindow_GetSizeWH(lua_State *L)
{
    int width = 0;
    int height = 0;
    // get this
    wxWindow *self = (wxWindow *)wxluaT_getuserdatatype(L, 1, wxluatype_wxWindow);
    // call ClientToScreen
    self->GetSize(&width, &height);
    lua_pushinteger(L, width);
    lua_pushinteger(L, height);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxWindow_GetTextExtent
// virtual void GetTextExtent(const wxString& string, int* x, int* y, int* descent = NULL, int* externalLeading = NULL, const wxFont* font = NULL) const
static int LUACALL wxLua_wxWindow_GetTextExtent(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // const wxFont* font = NULL
    const wxFont *font = (argCount >= 3 ? (wxFont *)wxluaT_getuserdatatype(L, 3, wxluatype_wxFont) : NULL);

    int externalLeading;
    int descent;
    int w;
    int h;
    // const wxString& string
    wxString string = wxlua_getwxStringtype(L, 2);
    // get this
    wxWindow *self = (wxWindow *)wxluaT_getuserdatatype(L, 1, wxluatype_wxWindow);
    // call GetTextExtent
    self->GetTextExtent(string, &w, &h, &descent, &externalLeading, font);
    // return the number of parameters
    lua_pushinteger(L, w);
    lua_pushinteger(L, h);
    lua_pushinteger(L, descent);
    lua_pushinteger(L, externalLeading);
    return 4;
}
%end

%override wxLua_wxWindow_GetVirtualSizeWH
// void GetVirtualSize(int *width, int *height)
static int LUACALL wxLua_wxWindow_GetVirtualSizeWH(lua_State *L)
{
    int width = 0;
    int height = 0;
    // get this
    wxWindow *self = (wxWindow *)wxluaT_getuserdatatype(L, 1, wxluatype_wxWindow);
    // call ClientToScreen
    self->GetVirtualSize(&width, &height);
    lua_pushinteger(L, width);
    lua_pushinteger(L, height);
    // return the number of parameters
    return 2;
}
%end


%override wxLua_wxWindow_ScreenToClientXY
// %rename ScreenToClientXY virtual void ScreenToClient(int* x, int* y) const
static int LUACALL wxLua_wxWindow_ScreenToClientXY(lua_State *L)
{
    int y;
    int x;
    // get this
    wxWindow *self = (wxWindow *)wxluaT_getuserdatatype(L, 1, wxluatype_wxWindow);
    // call ScreenToClient
    self->ScreenToClient(&x, &y);
    lua_pushinteger(L, x);
    lua_pushinteger(L, y);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxWindow_GetHandle
// void *GetHandle() const
static int LUACALL wxLua_wxWindow_GetHandle(lua_State *L)
{
    // get this
    wxWindow *self = (wxWindow *)wxluaT_getuserdatatype(L, 1, wxluatype_wxWindow);
    // call GetHandle
    void *handle = (void *)self->GetHandle();
    // push handle
    lua_pushlightuserdata(L, handle);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxNotebook_HitTest
// int     HitTest(const wxPoint& point, int* flags)
static int LUACALL wxLua_wxNotebook_HitTest(lua_State *L)
{
    // int& flags
    long flags;
    // const wxPoint& point
    const wxPoint *point = (wxPoint *)wxluaT_getuserdatatype(L, 2, wxluatype_wxPoint);
    // get this
    wxNotebook *self = (wxNotebook *)wxluaT_getuserdatatype(L, 1, wxluatype_wxNotebook);
    // call HitTest
    int returns = self->HitTest(*point, &flags);
    // push the result number
    lua_pushinteger(L, returns);
    // push the result flags
    lua_pushinteger(L, flags);
    // return the number of parameters
    return 2;
}
%end

#if %wxchkver_3_0_0

%override wxLua_wxScrollHelper_CalcScrolledPosition
// void CalcScrolledPosition(int x, int y, int *xx, int *yy) const
static int LUACALL wxLua_wxScrollHelper_CalcScrolledPosition(lua_State *L)
{
    int yy;
    int xx;
    // int y
    int y = (int)wxlua_getnumbertype(L, 3);
    // int x
    int x = (int)wxlua_getnumbertype(L, 2);
    // get this
    wxScrollHelper *self = (wxScrollHelper *)wxluaT_getuserdatatype(L, 1, wxluatype_wxScrollHelper);
    // call CalcScrolledPosition
    self->CalcScrolledPosition(x, y, &xx, &yy);
    lua_pushinteger(L, xx);
    lua_pushinteger(L, yy);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxScrollHelper_CalcUnscrolledPosition
// void CalcUnscrolledPosition(int x, int y, int *xx, int *yy) const
static int LUACALL wxLua_wxScrollHelper_CalcUnscrolledPosition(lua_State *L)
{
    int yy;
    int xx;
    // int y
    int y = (int)wxlua_getnumbertype(L, 3);
    // int x
    int x = (int)wxlua_getnumbertype(L, 2);
    // get this
    wxScrollHelper *self = (wxScrollHelper *)wxluaT_getuserdatatype(L, 1, wxluatype_wxScrollHelper);
    // call CalcUnscrolledPosition
    self->CalcUnscrolledPosition(x, y, &xx, &yy);
    lua_pushinteger(L, xx);
    lua_pushinteger(L, yy);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxScrollHelper_GetScrollPixelsPerUnit
// void GetScrollPixelsPerUnit(int* xUnit, int* yUnit) const
static int LUACALL wxLua_wxScrollHelper_GetScrollPixelsPerUnit(lua_State *L)
{
    int yUnit;
    int xUnit;
    // get this
    wxScrollHelper *self = (wxScrollHelper *)wxluaT_getuserdatatype(L, 1, wxluatype_wxScrollHelper);
    // call GetScrollPixelsPerUnit
    self->GetScrollPixelsPerUnit(&xUnit, &yUnit);
    lua_pushinteger(L, xUnit);
    lua_pushinteger(L, yUnit);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxScrollHelper_GetViewStart
// void GetViewStart(int* x, int* y) const
static int LUACALL wxLua_wxScrollHelper_GetViewStart(lua_State *L)
{
    int y;
    int x;
    // get this
    wxScrollHelper *self = (wxScrollHelper *)wxluaT_getuserdatatype(L, 1, wxluatype_wxScrollHelper);
    // call GetViewStart
    self->GetViewStart(&x, &y);
    lua_pushinteger(L, x);
    lua_pushinteger(L, y);
    // return the number of parameters
    return 2;
}
%end

#else

%override wxLua_wxScrolledWindow_CalcScrolledPosition
// void CalcScrolledPosition(int x, int y, int *xx, int *yy) const
static int LUACALL wxLua_wxScrolledWindow_CalcScrolledPosition(lua_State *L)
{
    int yy;
    int xx;
    // int y
    int y = (int)wxlua_getnumbertype(L, 3);
    // int x
    int x = (int)wxlua_getnumbertype(L, 2);
    // get this
    wxScrolledWindow *self = (wxScrolledWindow *)wxluaT_getuserdatatype(L, 1, wxluatype_wxScrolledWindow);
    // call CalcScrolledPosition
    self->CalcScrolledPosition(x, y, &xx, &yy);
    lua_pushinteger(L, xx);
    lua_pushinteger(L, yy);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxScrolledWindow_CalcUnscrolledPosition
// void CalcUnscrolledPosition(int x, int y, int *xx, int *yy) const
static int LUACALL wxLua_wxScrolledWindow_CalcUnscrolledPosition(lua_State *L)
{
    int yy;
    int xx;
    // int y
    int y = (int)wxlua_getnumbertype(L, 3);
    // int x
    int x = (int)wxlua_getnumbertype(L, 2);
    // get this
    wxScrolledWindow *self = (wxScrolledWindow *)wxluaT_getuserdatatype(L, 1, wxluatype_wxScrolledWindow);
    // call CalcUnscrolledPosition
    self->CalcUnscrolledPosition(x, y, &xx, &yy);
    lua_pushinteger(L, xx);
    lua_pushinteger(L, yy);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxScrolledWindow_GetScrollPixelsPerUnit
// void GetScrollPixelsPerUnit(int* xUnit, int* yUnit) const
static int LUACALL wxLua_wxScrolledWindow_GetScrollPixelsPerUnit(lua_State *L)
{
    int yUnit;
    int xUnit;
    // get this
    wxScrolledWindow *self = (wxScrolledWindow *)wxluaT_getuserdatatype(L, 1, wxluatype_wxScrolledWindow);
    // call GetScrollPixelsPerUnit
    self->GetScrollPixelsPerUnit(&xUnit, &yUnit);
    lua_pushinteger(L, xUnit);
    lua_pushinteger(L, yUnit);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxScrolledWindow_GetViewStart
// void GetViewStart(int* x, int* y) const
static int LUACALL wxLua_wxScrolledWindow_GetViewStart(lua_State *L)
{
    int y;
    int x;
    // get this
    wxScrolledWindow *self = (wxScrolledWindow *)wxluaT_getuserdatatype(L, 1, wxluatype_wxScrolledWindow);
    // call GetViewStart
    self->GetViewStart(&x, &y);
    lua_pushinteger(L, x);
    lua_pushinteger(L, y);
    // return the number of parameters
    return 2;
}
%end
#endif

%override wxLua_wxTabCtrl_HitTest
// int HitTest(const wxPoint& pt, long& flags)
static int LUACALL wxLua_wxTabCtrl_HitTest(lua_State *L)
{
    // long& flags
    long flags;
    // const wxPoint& pt
    const wxPoint *pt = (wxPoint *)wxluaT_getuserdatatype(L, 2, wxluatype_wxPoint);
    // get this
    wxTabCtrl *self = (wxTabCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxTabCtrl);
    // call HitTest
    int returns = self->HitTest(*pt, flags);
    // push the result number
    lua_pushinteger(L, returns);
    // push the result flags
    lua_pushinteger(L, flags);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxTabCtrl_GetItemData
// wxObject * GetItemData(int item) const
static int LUACALL wxLua_wxTabCtrl_GetItemData(lua_State *L)
{
    // int item
    int item = (int)wxlua_getintegertype(L, 2);
    // get this
    wxTabCtrl *self = (wxTabCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxTabCtrl);
    // call GetItemData
    wxObject *returns = (wxObject *) self->GetItemData(item);
    // push the result datatype
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxObject);
    // return the number of parameters
    return 1;
}
%end

// ----------------------------------------------------------------------------
// Overrides for wxlua.i
// ----------------------------------------------------------------------------

%override wxLua_wxLuaPrintout_constructor
//     wxLuaPrintout(const wxString& title = "Printout", wxLuaObject *pObject = NULL)
static int LUACALL wxLua_wxLuaPrintout_constructor(lua_State *L)
{
    wxLuaState wxlState(L);

    // get number of arguments
    int argCount = lua_gettop(L);
    // wxLuaObject pObject = NULL
    wxLuaObject * pObject = (argCount >= 2 ? (wxLuaObject *)wxluaT_getuserdatatype(L, 2, wxluatype_wxLuaObject) : NULL);
    // const wxString title = "Printout"
    const wxString title = (argCount >= 1 ? wxlua_getwxStringtype(L, 1) : wxString(wxT("Printout")));
    // call constructor
    wxLuaPrintout *returns = new wxLuaPrintout(wxlState, title, pObject);
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxLuaPrintout);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxLuaPrintout);

    return 1;
}
%end

// ----------------------------------------------------------------------------
// Overrides for wxcore_graphics.i
// ----------------------------------------------------------------------------

%override wxLua_wxGraphicsContext_GetTextExtent
// void GetTextExtent(const wxString& string, wxCoord *w, wxCoord *h, wxCoord *descent = NULL, wxCoord *externalLeading = NULL, wxFont *font = NULL)
static int LUACALL wxLua_wxGraphicsContext_GetTextExtent(lua_State *L)
{
    wxDouble externalLeading;
    wxDouble descent;
    wxDouble h;
    wxDouble w;

    wxString string = wxlua_getwxStringtype(L, 2);
    // get this
    wxGraphicsContext *self = (wxGraphicsContext *)wxluaT_getuserdatatype(L, 1, wxluatype_wxGraphicsContext);
    // call GetTextExtent
    self->GetTextExtent(string, &w, &h, &descent, &externalLeading);
    lua_pushnumber(L, w);
    lua_pushnumber(L, h);
    lua_pushnumber(L, descent);
    lua_pushnumber(L, externalLeading);
    // return the number of parameters
    return 4;
}
%end

%override wxLua_wxGraphicsContext_StrokeLines1
//     virtual void StrokeLines( wxPoint2DDoubleArray_FromLuaTable beginPoints, wxPoint2DDoubleArray_FromLuaTable endPoints );
static int LUACALL wxLua_wxGraphicsContext_StrokeLines1(lua_State *L)
{
    // wxPoint2DDoubleArray_FromLuaTable endPoints
    wxLuaSharedPtr<std::vector<wxPoint2DDouble> > endPoints = wxlua_getwxPoint2DDoubleArray(L, 3);
    // wxPoint2DDoubleArray_FromLuaTable beginPoints
    wxLuaSharedPtr<std::vector<wxPoint2DDouble> > beginPoints = wxlua_getwxPoint2DDoubleArray(L, 2);
    // get this
    wxGraphicsContext * self = (wxGraphicsContext *)wxluaT_getuserdatatype(L, 1, wxluatype_wxGraphicsContext);
    // call StrokeLines
    self->StrokeLines((size_t)(beginPoints ? beginPoints->size() : 0), (beginPoints && (!beginPoints->empty())) ? &beginPoints->at(0) : NULL, (endPoints && (!endPoints->empty())) ? &endPoints->at(0) : NULL);

    return 0;
}
%end

%override wxLua_wxGraphicsPenInfo_GetDashes
// void GetDashes()
static int LUACALL wxLua_wxGraphicsPenInfo_GetDashes(lua_State *L)
{
    // get this
    wxGraphicsPenInfo *self = (wxGraphicsPenInfo *)wxluaT_getuserdatatype(L, 1, wxluatype_wxGraphicsPenInfo);
    // get dashes
    wxDash *dashes;
    int nb_dashes = self->GetDashes(&dashes);
    if (nb_dashes == 0)
        return 0;  //  No dashes are defined
    // create a table (which will be the return value)
    lua_newtable(L);
    for (int idx = 0; idx < nb_dashes; ++idx) {
        lua_pushinteger(L, dashes[idx]);
        lua_rawseti(L, -2, idx + 1);
    }
    //  return the number of parameters
    return 1;
}
%end

%override wxLua_wxGraphicsPenInfo_Dashes
// wxGraphicsPenInfo& Dashes()
static int LUACALL wxLua_wxGraphicsPenInfo_Dashes(lua_State *L)
{
    // get this
    wxGraphicsPenInfo *self = (wxGraphicsPenInfo *)wxluaT_getuserdatatype(L, 1, wxluatype_wxGraphicsPenInfo);
    // check if we have a table argument
    if (!wxlua_iswxluatype(lua_type(L, 2), WXLUA_TTABLE))
        wxlua_argerror(L, 2, wxT("a 'table'"));
    int count = lua_objlen(L, 2);
    // allocate an array of wxDashes
    // TODO: this memory will leak when wxGraphicsPenInfo is destroyed.
    wxDash *dashes = new wxDash[count];
    for (int idx = 1; idx <= count; idx++) {
        lua_rawgeti(L, 2, idx);
        dashes[idx - 1] = (wxDash)lua_tonumber(L, -1);
        lua_pop(L, 1);
    }
    wxGraphicsPenInfo *returns = &(self->Dashes(count, dashes));
    // push the result data
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxGraphicsPenInfo);
    return 1;
}
%end

