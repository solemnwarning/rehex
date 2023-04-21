// ----------------------------------------------------------------------------
// Overridden functions for the wxWidgets binding for wxLua
//
// Please keep these functions in the same order as the .i file and in the
// same order as the listing of the functions in that file.
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// Overrides for wxbase_base.i
// ----------------------------------------------------------------------------

%override wxLua_wxLog_SetTimestamp
//     static void SetTimestamp(const wxString& ts)
static int LUACALL wxLua_wxLog_SetTimestamp(lua_State *L)
{
    // docs say that using NULL will disable time stamping. The actual arg is "const wxChar* ts"
    if (lua_isnoneornil(L, 1))
    {
#if wxCHECK_VERSION(2, 9, 0)
        wxLog::SetTimestamp(wxEmptyString);
#else
        wxLog::SetTimestamp(NULL);
#endif
    }
    else
    {
        // const wxString ts
        const wxString ts = wxlua_getwxStringtype(L, 1);
        // call SetTimestamp
        wxLog::SetTimestamp(ts);
    }

    return 0;
}
%end

%override wxLua_function_wxGetOsVersion
// %function int wxGetOsVersion(int *major = NULL, int *minor = NULL)
static int LUACALL wxLua_function_wxGetOsVersion(lua_State *L)
{
    // int *minor = NULL
    int minor= 0;
    // int *major = NULL
    int major = 0;
    // call wxGetOsVersion
    int returns = wxGetOsVersion(&major, &minor);
    // push the result numbers
    lua_pushinteger(L, returns);
    lua_pushinteger(L, major);
    lua_pushinteger(L, minor);
    // return the number of parameters
    return 3;
}
%end

%override wxLua_function_wxGetEnv
// %function bool wxGetEnv(const wxString& var, wxString *value)
static int LUACALL wxLua_function_wxGetEnv(lua_State *L)
{
    wxString var = wxlua_getwxStringtype(L, 1);
    wxString value;
    // call wxGetEnv
    bool returns = wxGetEnv(var, &value);
    // push the result number
    lua_pushboolean(L, returns);
    wxlua_pushwxString(L, value);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxStandardPaths_Get
//     static wxStandardPaths& Get();
static int LUACALL wxLua_wxStandardPaths_Get(lua_State *L)
{
    // call Get
    wxStandardPathsBase *returns = &wxStandardPaths::Get();
    // push the result datatype
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxStandardPaths);

    return 1;
}
%end

%override wxLua_wxRegEx_GetMatchIndexes
// %rename GetMatchPointer bool GetMatch(size_t* start, size_t* len, size_t index = 0) const
static int LUACALL wxLua_wxRegEx_GetMatchIndexes(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // size_t index = 0
    size_t index = (argCount >= 2 ? (size_t)wxlua_getintegertype(L, 2) : 0);
    // size_t* len
    size_t len = 0;
    // size_t* start
    size_t start = 0;
    // get this
    wxRegEx *self = (wxRegEx *)wxluaT_getuserdatatype(L, 1, wxluatype_wxRegEx);
    // call GetMatch
    bool returns = self->GetMatch(&start, &len, index);
    // push the result number
    lua_pushboolean(L, returns);
    // push the match start and length indexes
    lua_pushinteger(L, start);
    lua_pushinteger(L, len);
    // return the number of parameters
    return 3;
}
%end

%override wxLua_wxRegEx_Replace
// int Replace(wxString* text, const wxString& replacement, size_t maxMatches = 0) const
static int LUACALL wxLua_wxRegEx_Replace(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // size_t maxMatches = 0
    size_t maxMatches = (argCount >= 4 ? (size_t)wxlua_getintegertype(L, 4) : 0);
    // const wxString& replacement
    wxString replacement = wxlua_getwxStringtype(L, 3);
    // wxString* text
    wxString text = wxlua_getwxStringtype(L, 2);
    // get this
    wxRegEx *self = (wxRegEx *)wxluaT_getuserdatatype(L, 1, wxluatype_wxRegEx);
    // call Replace
    int returns = self->Replace(&text, replacement, maxMatches);
    // push the result number
    lua_pushinteger(L, returns);
    // push the result text
    wxlua_pushwxString(L, text);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxRegEx_ReplaceAll
// int ReplaceAll(wxString* text, const wxString& replacement) const
static int LUACALL wxLua_wxRegEx_ReplaceAll(lua_State *L)
{
    // const wxString& replacement
    wxString replacement = wxlua_getwxStringtype(L, 3);
    // wxString* text
    wxString text = wxlua_getwxStringtype(L, 2);
    // get this
    wxRegEx *self = (wxRegEx *)wxluaT_getuserdatatype(L, 1, wxluatype_wxRegEx);
    // call ReplaceAll
    int returns = self->ReplaceAll(&text, replacement);
    // push the result number
    lua_pushinteger(L, returns);
    // push the result text
    wxlua_pushwxString(L, text);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxRegEx_ReplaceFirst
// int ReplaceFirst(wxString* text, const wxString& replacement) const
static int LUACALL wxLua_wxRegEx_ReplaceFirst(lua_State *L)
{
    // const wxString& replacement
    wxString replacement = wxlua_getwxStringtype(L, 3);
    // wxString* text
    wxString text = wxlua_getwxStringtype(L, 2);
    // get this
    wxRegEx *self = (wxRegEx *)wxluaT_getuserdatatype(L, 1, wxluatype_wxRegEx);
    // call ReplaceFirst
    int returns = self->ReplaceFirst(&text, replacement);
    // push the result number
    lua_pushinteger(L, returns);
    // push the result text
    wxlua_pushwxString(L, text);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxEvtHandler_CallAfter
class wxEvtHandlerLuaCallback : public wxEvtHandler
{
public:
    void Callback(lua_State *L, int funcref) {
        int old_top = lua_gettop(L);
        lua_rawgeti(L, LUA_REGISTRYINDEX, funcref);
        luaL_unref(L, LUA_REGISTRYINDEX, funcref); // remove ref to function
        int res = lua_pcall(L, 0, 0, 0);
        if (res > 0) lua_error(L);
        lua_settop(L, old_top);
    }
};

static int LUACALL wxLua_wxEvtHandler_CallAfter(lua_State *L)
{
    if (!lua_isfunction(L, 2))
        wxlua_argerror(L, 2, wxT("a Lua function"));

    lua_pushvalue(L, 2); // push function to top of stack
    int funcref = luaL_ref(L, LUA_REGISTRYINDEX); // ref function and pop it from stack

    wxEvtHandler *self = (wxEvtHandler *)wxluaT_getuserdatatype(L, 1, wxluatype_wxEvtHandler);
    self->CallAfter(&wxEvtHandlerLuaCallback::Callback, L, funcref);

    return 0;
}
%end

%override wxLua_wxEvtHandler_Connect
// void Connect(int id, int lastId, wxEventType eventType, LuaFunction func)

#include "wxlua/wxlcallb.h"
// Connect an event to a handler. This Lua 'C' function supports
// function calls with either three or four parameters. These parameters
// are:         The class (which must be derived from wxEvtHandler),
//              The event type
// (Optional)   The ID of the object the event is for
//              A Lua function to call to handle the event.
//              The Lua function gets called with a single parameter
//              which is a reference to the event object
//              associated with the event.
static int LUACALL wxLua_wxEvtHandler_Connect(lua_State *L)
{
    wxCHECK_MSG(wxluatype_wxEvtHandler != -1, 0, wxT("wxEvtHandler is not wrapped by wxLua"));
    wxLuaState wxlState(L);
    wxCHECK_MSG(wxlState.Ok(), 0, wxT("Invalid wxLuaState"));

    wxWindowID  winId     = wxID_ANY;
    wxWindowID  lastId    = wxID_ANY;
    wxEventType eventType = wxEVT_NULL;

    int nParams = lua_gettop(L);

    wxEvtHandler *evtHandler = (wxEvtHandler *)wxluaT_getuserdatatype(L, 1, wxluatype_wxEvtHandler);

    int func_idx = 0;
    int evttype_idx = 0;

    switch (nParams)
    {
        case 5:
        {
            //void Connect(int winid, int lastId, int eventType, wxObjectEventFunction func, wxObject *userData = (wxObject *) NULL, wxEvtHandler *eventSink = (wxEvtHandler *) NULL);
            func_idx = 5;
            evttype_idx = 4;

            if (wxlua_isintegertype(L, 3))
                lastId = (wxWindowID)lua_tonumber(L, 3);
            else
            {
                wxlua_argerror(L, 3, wxT("an 'integer wxWindowID'"));
                return 0;
            }

            if (wxlua_isintegertype(L, 2))
                winId = (wxWindowID)lua_tonumber(L, 2);
            else
            {
                wxlua_argerror(L, 2, wxT("an 'integer wxWindowID'"));
                return 0;
            }

            break;
        }
        case 4:
        {
            //void Connect(int winid, int eventType, wxObjectEventFunction func, wxObject *userData = (wxObject *) NULL, wxEvtHandler *eventSink = (wxEvtHandler *) NULL)
            func_idx = 4;
            evttype_idx = 3;

            if (wxlua_isintegertype(L, 2))
                winId  = (wxWindowID)lua_tonumber(L, 2);
            else
            {
                wxlua_argerror(L, 2, wxT("an 'integer wxWindowID'"));
                return 0;
            }

            break;
        }
        case 3:
        {
            //void Connect(int eventType, wxObjectEventFunction func, wxObject *userData = (wxObject *) NULL, wxEvtHandler *eventSink = (wxEvtHandler *) NULL)
            func_idx = 3;
            evttype_idx = 2;
            break;
        }
        default:
        {
            wxlua_argerrormsg(L, wxT("Incorrect number of arguments to wxEventHandler::Connect()."));
            return 0;
        }
    }

    if (!lua_isfunction(L, func_idx))
    {
        wxlua_argerror(L, func_idx, wxT("a 'Lua function'"));
        return 0;
    }

    if (wxlua_isintegertype(L, evttype_idx))
        eventType = (wxEventType)lua_tonumber(L, evttype_idx);
    else
    {
        wxlua_argerror(L, evttype_idx, wxT("an 'integer wxEventType'"));
        return 0;
    }

    // Create and connect the callback
    wxLuaEventCallback* pCallback = new wxLuaEventCallback;
    wxString errMsg(pCallback->Connect(wxlState, func_idx, winId, lastId, eventType, evtHandler));
    if (!errMsg.IsEmpty())
    {
        delete pCallback;
        wxlua_error(L, errMsg.c_str());
    }

    return 0;
}
%end

%override wxLua_wxEvtHandler_Disconnect
// void Disconnect(int id, int lastId, wxEventType eventType)

#include "wxlua/wxlcallb.h"
static int LUACALL wxLua_wxEvtHandler_Disconnect(lua_State *L)
{
    wxCHECK_MSG(wxluatype_wxEvtHandler != -1, 0, wxT("wxEvtHandler is not wrapped by wxLua"));
    wxLuaState wxlState(L);
    wxCHECK_MSG(wxlState.Ok(), 0, wxT("Invalid wxLuaState"));

    wxWindowID  winId     = wxID_ANY;
    wxWindowID  lastId    = wxID_ANY;
    wxEventType eventType = wxEVT_NULL;

    int nParams = lua_gettop(L);

    wxEvtHandler *evtHandler = (wxEvtHandler *)wxluaT_getuserdatatype(L, 1, wxluatype_wxEvtHandler);

    int evttype_idx = 0;

    switch (nParams)
    {
        case 4:
        {
            //bool Disconnect(int winid, int lastId, wxEventType eventType, wxObjectEventFunction func = NULL, wxObject *userData = (wxObject *) NULL, wxEvtHandler *eventSink = (wxEvtHandler *) NULL);
            evttype_idx = 4;

            if (wxlua_isintegertype(L, 3))
                lastId = (wxWindowID)lua_tonumber(L, 3);
            else
            {
                wxlua_argerror(L, 3, wxT("an 'integer wxWindowID'"));
                return 0;
            }

            if (wxlua_isintegertype(L, 2))
                winId = (wxWindowID)lua_tonumber(L, 2);
            else
            {
                wxlua_argerror(L, 2, wxT("an 'integer wxWindowID'"));
                return 0;
            }

            break;
        }
        case 3:
        {
            //bool Disconnect(int winid = wxID_ANY, wxEventType eventType = wxEVT_NULL, wxObjectEventFunction func = NULL, wxObject *userData = (wxObject *) NULL, wxEvtHandler *eventSink = (wxEvtHandler *) NULL)
            evttype_idx = 3;

            if (wxlua_isintegertype(L, 2))
                winId  = (wxWindowID)lua_tonumber(L, 2);
            else
            {
                wxlua_argerror(L, 1, wxT("an 'integer wxWindowID'"));
                return 0;
            }

            break;
        }
        case 2:
        {
            //bool Disconnect(wxEventType eventType, wxObjectEventFunction func, wxObject *userData = (wxObject *) NULL, wxEvtHandler *eventSink = (wxEvtHandler *) NULL)
            evttype_idx = 2;

            break;
        }
        default:
        {
            wxlua_argerrormsg(L, wxT("Incorrect number of arguments to wxEventHandler::Disconnect()."));
            return 0;
        }
    }

    if (wxlua_isintegertype(L, evttype_idx))
        eventType = (wxEventType)lua_tonumber(L, evttype_idx);
    else
    {
        wxlua_argerror(L, evttype_idx, wxT("an 'integer wxEventType'"));
        return 0;
    }

    // Try to disconnect from the callback, it will delete the wxLuaEventCallback.
    bool returns = evtHandler->Disconnect(winId, lastId, eventType, (wxObjectEventFunction)&wxLuaEventCallback::OnAllEvents);

    lua_pushboolean(L, returns);
    return 1;
}
%end

// ----------------------------------------------------------------------------
// Overrides for wxbase_config.i
// ----------------------------------------------------------------------------

%override wxLua_wxConfigBase_delete
// void delete()
static int LUACALL wxLua_wxConfigBase_delete(lua_State *L)
{
    // get this
    wxConfigBase *self = (wxConfigBase *)wxluaT_getuserdatatype(L, 1, wxluatype_wxConfigBase);

    if (wxConfigBase::Get(false) == self) // clear us from the wxConfigBase
        wxConfigBase::Set(NULL);

    // we may not be tracked, but delete us anyway
    if (!wxluaO_deletegcobject(L, 1, WXLUA_DELETE_OBJECT_ALL))
        delete self;

    // return the number of parameters
    return 0;
}
%end

%override wxLua_wxConfigBase_Read
// bool Read(const wxString& key, wxString* str, const wxString& defaultVal = wxEmptyString) const
static int LUACALL wxLua_wxConfigBase_Read(lua_State *L)
{
    wxString returns;
    // get number of arguments
    int argCount = lua_gettop(L);
    // wxString defaultVal
    wxString defaultVal = (argCount >= 3 ? wxlua_getwxStringtype(L, 3) : wxString(wxEmptyString));
    // const wxString& key
    wxString key = wxlua_getwxStringtype(L, 2);
    // get this
    wxConfigBase *self = (wxConfigBase *)wxluaT_getuserdatatype(L, 1, wxluatype_wxConfigBase);
    // call Read
    bool ret = self->Read(key, &returns, defaultVal);
    // push the result bool
    lua_pushboolean(L, ret);
    // push the result string
    wxlua_pushwxString(L, returns);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxConfigBase_ReadInt
// %rename ReadInt bool Read(const wxString&  key, long* l, long defaultVal = 0) const
static int LUACALL wxLua_wxConfigBase_ReadInt(lua_State *L)
{
    long returns = 0;
    // get number of arguments
    int argCount = lua_gettop(L);
    // double defaultVal = 0
    long defaultVal = (argCount >= 3 ? (long)wxlua_getnumbertype(L, 3) : 0);
    // const wxString& key
    wxString key = wxlua_getwxStringtype(L, 2);
    // get this
    wxConfigBase *self = (wxConfigBase *)wxluaT_getuserdatatype(L, 1, wxluatype_wxConfigBase);
    // call Read
    bool ret = self->Read(key, &returns, defaultVal);
    // push the result bool
    lua_pushboolean(L, ret);
    // push the result number
    lua_pushinteger(L, returns);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxConfigBase_ReadFloat
// %rename ReadFloat bool Read(const wxString&  key, double* d, double defaultVal = 0) const
static int LUACALL wxLua_wxConfigBase_ReadFloat(lua_State *L)
{
    double returns = 0;
    // get number of arguments
    int argCount = lua_gettop(L);
    // double defaultVal = 0
    double defaultVal = (argCount >= 3 ? (double)wxlua_getnumbertype(L, 3) : 0);
    // const wxString& key
    wxString key = wxlua_getwxStringtype(L, 2);
    // get this
    wxConfigBase *self = (wxConfigBase *)wxluaT_getuserdatatype(L, 1, wxluatype_wxConfigBase);
    // call Read
    bool ret = self->Read(key, &returns, defaultVal);
    // push the result bool
    lua_pushboolean(L, ret);
    // push the result number
    lua_pushinteger(L, returns);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxConfigBase_GetFirstGroup
// bool GetFirstGroup(wxString& str, long& index) const
static int LUACALL wxLua_wxConfigBase_GetFirstGroup(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // these are optional and are not used anyway
    long     index = (argCount >= 3 ? (long)wxlua_getintegertype(L, 3) : 0);
    wxString str   = (argCount >= 2 ? wxlua_getwxStringtype(L, 2) : wxString(wxEmptyString));
    // get this
    wxConfig *self = (wxConfig *)wxluaT_getuserdatatype(L, 1, wxluatype_wxConfigBase);
    // call GetFirstGroup
    bool returns = self->GetFirstGroup(str, index);
    // push the result number
    lua_pushboolean(L, returns);
    // push the result string
    wxlua_pushwxString(L, str);
    // push the next index
    lua_pushinteger(L, index);
    // return the number of parameters
    return 3;
}
%end

%override wxLua_wxConfigBase_GetFirstEntry
// bool GetFirstEntry(wxString& str, long& index) const
static int LUACALL wxLua_wxConfigBase_GetFirstEntry(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // these are optional and are not used anyway
    long     index = (argCount >= 3 ? (long)wxlua_getintegertype(L, 3) : 0);
    wxString str   = (argCount >= 2 ? wxlua_getwxStringtype(L, 2) : wxString(wxEmptyString));
    // get this
    wxConfig *self = (wxConfig *)wxluaT_getuserdatatype(L, 1, wxluatype_wxConfigBase);
    // call GetFirstEntry
    bool returns = self->GetFirstEntry(str, index);
    // push the result number
    lua_pushboolean(L, returns);
    // push the next string
    wxlua_pushwxString(L, str);
    // push the next index
    lua_pushinteger(L, index);
    // return the number of parameters
    return 3;
}
%end

%override wxLua_wxConfigBase_GetNextGroup
// bool GetNextGroup(wxString& str, long& index) const
static int LUACALL wxLua_wxConfigBase_GetNextGroup(lua_State *L)
{
    // only the number is needed
    long     index = (long)wxlua_getintegertype(L, 2);
    wxString str;
    // get this
    wxConfig *self = (wxConfig *)wxluaT_getuserdatatype(L, 1, wxluatype_wxConfigBase);
    // call GetNextGroup
    bool returns = self->GetNextGroup(str, index);
    // push the result number
    lua_pushboolean(L, returns);
    // push the next result string
    wxlua_pushwxString(L, str);
    // push the next index
    lua_pushinteger(L, index);
    // return the number of parameters
    return 3;
}
%end

%override wxLua_wxConfigBase_GetNextEntry
// bool GetNextEntry(wxString& str, long& index) const
static int LUACALL wxLua_wxConfigBase_GetNextEntry(lua_State *L)
{
    // only the number is needed
    long     index = (long)wxlua_getintegertype(L, 2);
    wxString str;
    // get this
    wxConfig *self = (wxConfig *)wxluaT_getuserdatatype(L, 1, wxluatype_wxConfigBase);
    // call GetNextEntry
    bool returns = self->GetNextEntry(str, index);
    // push the result number
    lua_pushboolean(L, returns);
    // push the result string
    wxlua_pushwxString(L, str);
    // push the next index
    lua_pushinteger(L, index);
    // return the number of parameters
    return 3;
}
%end

// ----------------------------------------------------------------------------
// Overrides for wxbase_data.i
// ----------------------------------------------------------------------------

%override wxLua_wxString_constructor
//     wxString(const wxString& str = "")
static int LUACALL wxLua_wxString_constructor(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // const wxString str = ""
    const wxString str = (argCount >= 1 ? wxlua_getwxStringtype(L, 1) : wxString(wxEmptyString));
    // call constructor
    wxString* returns = new wxString(str);
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxString);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxString);

    return 1;
}
%end

%override wxLua_wxUniChar_constructor
//     wxUniChar(const string& str = "")
static int LUACALL wxLua_wxUniChar_constructor(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // const wxUniChar c
    const wxUniChar c = (argCount >= 1 ? wxlua_getwxUniChartype(L, 1) : wxUniChar());
    // call constructor
    wxUniChar* returns = new wxUniChar(c);
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxUniChar);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxUniChar);

    return 1;
}
%end

%override wxLua_wxClassInfo_constructor
// wxClassInfo(const wxString &name)
static int LUACALL wxLua_wxClassInfo_constructor(lua_State *L)
{
    // const wxString &name
    wxString name = wxlua_getwxStringtype(L, 1);
    // call constructor
#if wxCHECK_VERSION(2, 9, 0)
    wxClassInfo *returns = wxClassInfo::FindClass(name);
#else
    wxClassInfo *returns = wxClassInfo::FindClass(name.wx_str());
#endif
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxClassInfo);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxObjectRefData_delete_function

#if wxCHECK_VERSION(2,9,0)
void wxLua_wxObjectRefData_delete_function(void** p)
{
    wxObjectRefData* o = (wxObjectRefData*)(*p);
    o->DecRef();
}
#else
void wxLua_wxObjectRefData_delete_function(void** p)
{
    wxObjectRefData* o = (wxObjectRefData*)(*p);
    delete o;
}
#endif

%end

%override wxLua_wxObject_DynamicCast
// void *DynamicCast(const char *class)

// Attempt to cast an object reference (the first parameter) to another type.
// The type requested is specified by the second parameter. Presumably the
// type requested will be derived from the supplied object, otherwise
// bad things will happen.
static int LUACALL wxLua_wxObject_DynamicCast(lua_State *L)
{
    int         iResult   = 0;
    const char *className = lua_tostring(L, 2);
    if (className != NULL)
    {
        // The userdata object must be derived from a wxObject for this
        // function be be called.
        wxObject *pObject = (wxObject *)wxlua_touserdata(L, 1, false);
        //wxObject *pObject = (wxObject *)wxluaT_getuserdatatype(L, 1, wxluatype_wxObject);

        const wxLuaBindClass *wxlClass = wxluaT_getclass(L, className);
        if (pObject && wxlClass && wxlClass->classInfo)
        {
            if (pObject->IsKindOf(wxlClass->classInfo))
            {
                if (*wxlClass->wxluatype != wxluaT_type(L, 1))
                    wxluaT_pushuserdatatype(L, pObject, *wxlClass->wxluatype);
                else
                    lua_pushvalue(L, 1); // return same userdata

                iResult = 1;
            }
            else
                wxlua_argerrormsg(L, wxString::Format(wxT("wxLua: wxObject::DynamicCast() Unable to cast a '%s' to a '%s' with wxClassInfo '%s'."),
                                     pObject->GetClassInfo()->GetClassName(),
                                     lua2wx(className).c_str(),
                                     wxString(wxlClass ? wxlClass->classInfo->GetClassName() : wxT("Unknown")).c_str()));
        }

        if (iResult == 0)
            wxlua_argerrormsg(L, wxString::Format(wxT("wxLua: wxObject::DynamicCast() Cannot cast a wxLua type '%s' with wxClassInfo '%s' to a '%s'."),
                                 wxluaT_gettypename(L, 1).c_str(),
                                 wxString(pObject ? pObject->GetClassInfo()->GetClassName() : wxT("Unknown")).c_str(),
                                 lua2wx(className).c_str()));
    }
    else
        wxlua_argerror(L, 2, wxT("a 'string name of the class'"));

    return iResult;
}
%end

%override wxLua_wxArrayInt_ToLuaTable
// int ToLuaTable() const
static int LUACALL wxLua_wxArrayInt_ToLuaTable(lua_State *L)
{
    wxArrayInt * self = (wxArrayInt *)wxluaT_getuserdatatype(L, 1, wxluatype_wxArrayInt);
    wxlua_pushwxArrayInttable(L, *self);
    return 1;
}
%end

%override wxLua_wxArrayDouble_ToLuaTable
// int ToLuaTable() const
static int LUACALL wxLua_wxArrayDouble_ToLuaTable(lua_State *L)
{
    wxArrayDouble * self = (wxArrayDouble *)wxluaT_getuserdatatype(L, 1, wxluatype_wxArrayDouble);
    wxlua_pushwxArrayDoubletable(L, *self);
    return 1;
}
%end

%override wxLua_wxArrayString_ToLuaTable
// int ToLuaTable() const
static int LUACALL wxLua_wxArrayString_ToLuaTable(lua_State *L)
{
    wxArrayString * self = (wxArrayString *)wxluaT_getuserdatatype(L, 1, wxluatype_wxArrayString);
    wxlua_pushwxArrayStringtable(L, *self);
    return 1;
}
%end

%override wxLua_wxMemoryBuffer_GetByte
//     unsigned char GetByte(int index, size_t length = 1);
static int LUACALL wxLua_wxMemoryBuffer_GetByte(lua_State *L)
{
    // int index
    int index = (int)wxlua_getnumbertype(L, 2);
    // get this
    wxMemoryBuffer * self = (wxMemoryBuffer *)wxluaT_getuserdatatype(L, 1, wxluatype_wxMemoryBuffer);
    if (index < 0 || (unsigned)index >= self->GetDataLen())
        return 0;
    // int length (optional)
    int length = 1;
    if (lua_gettop(L) >= 3)
        length = (size_t)wxlua_getnumbertype(L, 3);
    if (length <= 0)
        return 0;
    if ((unsigned)(index + length) > self->GetDataLen())
        length = self->GetDataLen() - index;
    int count = 0;
    while (count < length) {
        unsigned char returns = ((unsigned char *)(self->GetData()))[index + count];
        lua_pushinteger(L, returns);
        count++;
    }
    return length;
}
%end

%override wxLua_wxMemoryBuffer_SetByte
//     void SetByte(int index, unsigned char data);
static int LUACALL wxLua_wxMemoryBuffer_SetByte(lua_State *L)
{
    // int index
    int index = (int)wxlua_getnumbertype(L, 2);
    wxASSERT_MSG(index >= 0, "index out of range");
    // get this
    wxMemoryBuffer * self = (wxMemoryBuffer *)wxluaT_getuserdatatype(L, 1, wxluatype_wxMemoryBuffer);
    // more data? (optional)
    int length = lua_gettop(L) - 2;
    if (length <= 0)
        return 0;  //  Do nothing
    // get data pointer
    unsigned char *dptr = (unsigned char *)self->GetWriteBuf(index + length);
    wxASSERT_MSG(dptr != NULL, "cannot reallocate buffer");
    int count = 0;
    while (count < length) {
        ((unsigned char *)(self->GetData()))[index + count] = (unsigned char)wxlua_getnumbertype(L, 3 + count);
        count++;
    }
    if (self->GetDataLen() < (unsigned)(index + length))
        self->SetDataLen(index + length);
    return 0;
}
%end

%override wxLua_wxMemoryBuffer_Fill
//     void Fill(unsigned char data, int start_index, size_t length);
static int LUACALL wxLua_wxMemoryBuffer_Fill(lua_State *L)
{
    // size_t length
    size_t length = (size_t)wxlua_getnumbertype(L, 4);
    // int start_index
    int start_index = (int)wxlua_getnumbertype(L, 3);
    // unsigned char data
    int data = (unsigned char)wxlua_getnumbertype(L, 2);
    wxASSERT_MSG(start_index >= 0, "index out of range");
    // get this
    wxMemoryBuffer * self = (wxMemoryBuffer *)wxluaT_getuserdatatype(L, 1, wxluatype_wxMemoryBuffer);
    if (length <= 0)
        return 0;  //  Do nothing
    // get data pointer
    unsigned char *dptr = (unsigned char *)self->GetWriteBuf(start_index + length);
    wxASSERT_MSG(dptr != NULL, "cannot reallocate buffer");
    memset(dptr + start_index, data, length);
    if (self->GetDataLen() < start_index + length)
        self->SetDataLen(start_index + length);
    return 0;
}
%end

#if wxUSE_VARIANT

%override wxLua_wxVariant_ConvertToBool
// C++: bool Convert(bool *value)
// Lua: [bool, bool]ConvertToBool()
static int LUACALL wxLua_wxVariant_ConvertToBool(lua_State *L)
{
    // get this
    wxVariant * self = (wxVariant *)wxluaT_getuserdatatype(L, 1, wxluatype_wxVariant);
    // call Convert(bool*)
    bool value;
    bool returns = (self->Convert(&value));
    // push the result flag and value
    lua_pushboolean(L, returns);
    lua_pushboolean(L, value);

    return 2;
}
%end

#if wxUSE_DATETIME
%override wxLua_wxVariant_ConvertToDateTime
// C++: bool Convert(wxDateTime *value)
// Lua: [bool, wxDateTime]ConvertToDateTime()
static int LUACALL wxLua_wxVariant_ConvertToDateTime(lua_State *L)
{
    // get this
    wxVariant * self = (wxVariant *)wxluaT_getuserdatatype(L, 1, wxluatype_wxVariant);
    // call Convert(wxDateTime*)
    wxDateTime value;
    wxDateTime *newValue = NULL;
    bool returns = (self->Convert(&value));
    if (returns)
        newValue = new wxDateTime(value);
    else
        newValue = new wxDateTime();   //  Empty value
    // push the result flag
    lua_pushboolean(L, returns);
    // add the new object to the tracked memory list
    wxluaO_addgcobject(L, newValue, wxluatype_wxDateTime);
    // push the result datatype
    wxluaT_pushuserdatatype(L, newValue, wxluatype_wxDateTime);

    return 2;
}
%end
#endif  // wxUSE_DATETIME

%override wxLua_wxVariant_ConvertToDouble
// C++: bool Convert(double *value)
// Lua: [bool, double]ConvertToDouble()
static int LUACALL wxLua_wxVariant_ConvertToDouble(lua_State *L)
{
    // get this
    wxVariant * self = (wxVariant *)wxluaT_getuserdatatype(L, 1, wxluatype_wxVariant);
    // call Convert(double*)
    double value;
    bool returns = (self->Convert(&value));
    // push the result flag and value
    lua_pushboolean(L, returns);
    lua_pushnumber(L, value);

    return 2;
}
%end

%override wxLua_wxVariant_ConvertToLong
// C++: bool Convert(long *value)
// Lua: [bool, long]ConvertToLong()
static int LUACALL wxLua_wxVariant_ConvertToLong(lua_State *L)
{
    // get this
    wxVariant * self = (wxVariant *)wxluaT_getuserdatatype(L, 1, wxluatype_wxVariant);
    // call Convert(long*)
    long value;
    bool returns = (self->Convert(&value));
    // push the result flag and value
    lua_pushboolean(L, returns);
    // push the result number
#if LUA_VERSION_NUM >= 503
if ((double)(lua_Integer)value == (double)value) {
    // Exactly representable as lua_Integer
    lua_pushinteger(L, value);
} else
#endif
{
    lua_pushnumber(L, value);
}
    return 2;
}
%end

#if wxUSE_LONGLONG
%override wxLua_wxVariant_ConvertToLongLong
// C++: bool Convert(wxLongLong *value)
// Lua: [bool, wxLongLong]ConvertToLongLong()
static int LUACALL wxLua_wxVariant_ConvertToLongLong(lua_State *L)
{
    // get this
    wxVariant * self = (wxVariant *)wxluaT_getuserdatatype(L, 1, wxluatype_wxVariant);
    // call Convert(wxLongLong*)
    wxLongLong value;
    bool returns = (self->Convert(&value));
    // allocate a new object using the copy constructor
    wxLongLong *newValue;
    if (returns)
        newValue = new wxLongLong(value);
    else
        newValue = new wxLongLong();
    // push the result flag
    lua_pushboolean(L, returns);
    // add the new object to the tracked memory list
    wxluaO_addgcobject(L, newValue, wxluatype_wxLongLong);
    // push the result datatype
    wxluaT_pushuserdatatype(L, newValue, wxluatype_wxLongLong);

    return 2;
}
%end
#endif // wxUSE_LONGLONG

%override wxLua_wxVariant_ConvertToString
// C++: bool Convert(wxString *value)
// Lua: [bool, string]ConvertToString()
static int LUACALL wxLua_wxVariant_ConvertToString(lua_State *L)
{
    // get this
    wxVariant * self = (wxVariant *)wxluaT_getuserdatatype(L, 1, wxluatype_wxVariant);
    // call Convert(wxString*)
    wxString value;
    bool returns = (self->Convert(&value));
    // push the result flag
    lua_pushboolean(L, returns);
    // push the string
    wxlua_pushwxString(L, value);

    return 2;
}
%end

#if wxUSE_LONGLONG
%override wxLua_wxVariant_ConvertToULongLong
// C++: bool Convert(wxULongLong *value)
// Lua: [bool, wxULongLong]ConvertToULongLong()
static int LUACALL wxLua_wxVariant_ConvertToULongLong(lua_State *L)
{
    // get this
    wxVariant * self = (wxVariant *)wxluaT_getuserdatatype(L, 1, wxluatype_wxVariant);
    // call Convert(wxULongLong*)
    wxULongLong value;
    bool returns = (self->Convert(&value));
    // allocate a new object using the copy constructor
    wxULongLong *newValue;
    if (returns)
        newValue = new wxULongLong(value);
    else
        newValue = new wxULongLong();
    // push the result flag
    lua_pushboolean(L, returns);
    // add the new object to the tracked memory list
    wxluaO_addgcobject(L, newValue, wxluatype_wxULongLong);
    // push the result datatype
    wxluaT_pushuserdatatype(L, newValue, wxluatype_wxULongLong);

    return 2;
}
%end
#endif // wxUSE_LONGLONG

%override wxLua_wxVariant_op_eq2
//     bool operator== (double value) const;
// C++: bool operator==(bool val);
//      bool operator==(long val);
//      bool operator==(double val);
// Lua: bool operator==(number);
// The type of 'number' is checked within this function
static int LUACALL wxLua_wxVariant_op_eq2(lua_State *L)
{
    // get this
    wxVariant * self = (wxVariant *)wxluaT_getuserdatatype(L, 1, wxluatype_wxVariant);
    bool returns;
    // Check the lua type of the second argument
    int arg_type = lua_type(L, 2);
    if (arg_type == LUA_TBOOLEAN) {
        //  Call the boolean version
        bool value =  wxlua_getbooleantype(L, 1);
        returns = ((*self) == (value));
    } else {
        //  Call the double or long version
        double value = wxlua_getnumbertype(L, 1);
        if ((double)(long)value == value) {
            //  Call the 'long' version
            long lval = (long)value;
            returns = ((*self) == (lval));
        } else {
            //  Call the 'double' version
            returns = ((*self) == (value));
        }
    }
    // push the result flag
    lua_pushboolean(L, returns);

    return 1;
}
%end

%override wxLua_wxVariant_op_eq1
//     bool operator== (const wxArrayString& value) const;
static int LUACALL wxLua_wxVariant_op_eq1(lua_State *L)
{
    // const wxArrayString value
    wxLuaSmartwxArrayString value = wxlua_getwxArrayString(L, 2);
    // get this
    wxVariant * self = (wxVariant *)wxluaT_getuserdatatype(L, 1, wxluatype_wxVariant);
    // call op_eq
    bool returns = ((*self)==((wxArrayString&)value));
    // push the result flag
    lua_pushboolean(L, returns);

    return 1;
}
%end

%override wxLua_wxVariant_op_ne2
//     bool operator!= (double value) const;
// C++: bool operator!=(bool val);
//      bool operator!=(long val);
//      bool operator!=(double val);
// Lua: bool operator!=(number);
// The type of 'number' is checked within this function
static int LUACALL wxLua_wxVariant_op_ne2(lua_State *L)
{
    // get this
    wxVariant * self = (wxVariant *)wxluaT_getuserdatatype(L, 1, wxluatype_wxVariant);
    bool returns;
    // Check the lua type of the second argument
    int arg_type = lua_type(L, 2);
    if (arg_type == LUA_TBOOLEAN) {
        //  Call the boolean version
        bool value =  wxlua_getbooleantype(L, 1);
        returns = ((*self) != (value));
    } else {
        //  Call the double or long version
        double value = wxlua_getnumbertype(L, 1);
        if ((double)(long)value == value) {
            //  Call the 'long' version
            long lval = (long)value;
            returns = ((*self) != (lval));
        } else {
            //  Call the 'double' version
            returns = ((*self) != (value));
        }
    }
    // push the result flag
    lua_pushboolean(L, returns);

    return 1;
}
%end

%override wxLua_wxVariant_op_ne1
//     bool operator!= (const wxArrayString& value) const;
static int LUACALL wxLua_wxVariant_op_ne1(lua_State *L)
{
    // const wxArrayString value
    wxLuaSmartwxArrayString value = wxlua_getwxArrayString(L, 2);
    // get this
    wxVariant * self = (wxVariant *)wxluaT_getuserdatatype(L, 1, wxluatype_wxVariant);
    // call op_ne
    bool returns = ((*self)!=((wxArrayString&)value));
    // push the result flag
    lua_pushboolean(L, returns);

    return 1;
}
%end

%override wxLua_wxVariant_constructor3
// C++: wxVariant(long val, const wxString& name = wxEmptyString);
//      wxVariant(bool val, const wxString& name = wxEmptyString);
//      wxVariant(double val, const wxString& name = wxEmptyString);
// Lua: wxVariant(number, const wxString& name = wxEmptyString);
// The type of 'number' is checked within this function
static int LUACALL wxLua_wxVariant_constructor3(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // const wxString name = wxEmptyString
    const wxString name = (argCount >= 2 ? wxlua_getwxStringtype(L, 2) : wxString(wxEmptyString));
    // Return value
    wxVariant *returns;
    // Check the lua type of the first argument
    int arg_type = lua_type(L, 1);
    if (arg_type == LUA_TBOOLEAN) {
        //  Call the boolean version
        bool val = wxlua_getbooleantype(L, 1);
        returns = new wxVariant(val, name);
    } else {
        //  Call the double or long version
        double val = wxlua_getnumbertype(L, 1);
        if ((double)(long)val == val) {
            //  Call the 'long' version
            long lval = (long)val;
            returns = new wxVariant(lval, name);
        } else {
            //  Call the 'double' version
            returns = new wxVariant(val, name);
        }
    }
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxVariant);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxVariant);

    return 1;
}
%end

%override wxLua_wxVariant_constructor2
//     wxVariant(const wxArrayString& val, const wxString& name = wxEmptyString);
static int LUACALL wxLua_wxVariant_constructor2(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // const wxString name = wxEmptyString
    const wxString name = (argCount >= 2 ? wxlua_getwxStringtype(L, 2) : wxString(wxEmptyString));
    // const wxArrayString val
    wxLuaSmartwxArrayString val = wxlua_getwxArrayString(L, 1);
    // call constructor
    wxVariant* returns = new wxVariant((wxArrayString&)val, name);
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxVariant);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxVariant);

    return 1;
}
%end

#endif // wxUSE_VARIANT


// ----------------------------------------------------------------------------
// Overrides for wxbase_datetime.i
// ----------------------------------------------------------------------------

%override wxLua_wxDateTime_ParseRfc822Date
//     %wxchkver_2_9 bool ParseRfc822Date(const wxString& date)
static int LUACALL wxLua_wxDateTime_ParseRfc822Date(lua_State *L)
{
    // const wxString date
    const wxString date = wxlua_getwxStringtype(L, 2);
    wxString::const_iterator it(date.begin());
    // get this
    wxDateTime * self = (wxDateTime *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDateTime);
    // call ParseRfc822Date
    bool returns = (self->ParseRfc822Date(date, &it));
    // push the result flag
    lua_pushboolean(L, returns);

    if (!returns && (it != date.end()))
    {
        wxlua_pushwxString(L, wxString(it, date.end()));
        return 2;
    }

    return 1;
}
%end

%override wxLua_wxDateTime_ParseFormat2
//     %wxchkver_2_9 bool ParseFormat(const wxString& date)
static int LUACALL wxLua_wxDateTime_ParseFormat2(lua_State *L)
{
    // const wxString date
    const wxString date = wxlua_getwxStringtype(L, 2);
    wxString::const_iterator it(date.begin());
    // get this
    wxDateTime * self = (wxDateTime *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDateTime);
    // call ParseFormat
    bool returns = (self->ParseFormat(date, &it));
    // push the result flag
    lua_pushboolean(L, returns);

    if (!returns && (it != date.end()))
    {
        wxlua_pushwxString(L, wxString(it, date.end()));
        return 2;
    }


    return 1;
}
%end

%override wxLua_wxDateTime_ParseFormat1
//     %wxchkver_2_9 bool ParseFormat(const wxString& date, wxString format)
static int LUACALL wxLua_wxDateTime_ParseFormat1(lua_State *L)
{
    // wxString format
    wxString format = wxlua_getwxStringtype(L, 3);
    // const wxString date
    const wxString date = wxlua_getwxStringtype(L, 2);
    wxString::const_iterator it(date.begin());
    // get this
    wxDateTime * self = (wxDateTime *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDateTime);
    // call ParseFormat
    bool returns = (self->ParseFormat(date, format, &it));
    // push the result flag
    lua_pushboolean(L, returns);

    if (!returns && (it != date.end()))
    {
        wxlua_pushwxString(L, wxString(it, date.end()));
        return 2;
    }

    return 1;
}
%end

%override wxLua_wxDateTime_ParseFormat
//     %wxchkver_2_9 bool ParseFormat(const wxString& date, wxString format, const wxDateTime& dateDef)
static int LUACALL wxLua_wxDateTime_ParseFormat(lua_State *L)
{
    // const wxDateTime dateDef
    const wxDateTime * dateDef = (const wxDateTime *)wxluaT_getuserdatatype(L, 4, wxluatype_wxDateTime);
    // wxString format
    wxString format = wxlua_getwxStringtype(L, 3);
    // const wxString date
    const wxString date = wxlua_getwxStringtype(L, 2);
    wxString::const_iterator it(date.begin());
    // get this
    wxDateTime * self = (wxDateTime *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDateTime);
    // call ParseFormat
    bool returns = (self->ParseFormat(date, format, *dateDef, &it));
    // push the result flag
    lua_pushboolean(L, returns);

    if (!returns && (it != date.end()))
    {
        wxlua_pushwxString(L, wxString(it, date.end()));
        return 2;
    }

    return 1;
}
%end

%override wxLua_wxDateTime_ParseDateTime
//     %wxchkver_2_9 bool ParseDateTime(const wxString& datetime)
static int LUACALL wxLua_wxDateTime_ParseDateTime(lua_State *L)
{
    // const wxString datetime
    const wxString datetime = wxlua_getwxStringtype(L, 2);
    wxString::const_iterator it(datetime.begin());
    // get this
    wxDateTime * self = (wxDateTime *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDateTime);
    // call ParseDateTime
    bool returns = (self->ParseDateTime(datetime, &it));
    // push the result flag
    lua_pushboolean(L, returns);

    if (!returns && (it != datetime.end()))
    {
        wxlua_pushwxString(L, wxString(it, datetime.end()));
        return 2;
    }

    return 1;
}
%end

%override wxLua_wxDateTime_ParseDate
//     %wxchkver_2_9 bool ParseDate(const wxString& date)
static int LUACALL wxLua_wxDateTime_ParseDate(lua_State *L)
{
    // const wxString date
    const wxString date = wxlua_getwxStringtype(L, 2);
    wxString::const_iterator it(date.begin());
    // get this
    wxDateTime * self = (wxDateTime *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDateTime);
    // call ParseDate
    bool returns = (self->ParseDate(date, &it));
    // push the result flag
    lua_pushboolean(L, returns);

    if (!returns && (it != date.end()))
    {
        wxlua_pushwxString(L, wxString(it, date.end()));
        return 2;
    }

    return 1;
}
%end

%override wxLua_wxDateTime_ParseTime
//     %wxchkver_2_9 bool ParseTime(const wxString& time)
static int LUACALL wxLua_wxDateTime_ParseTime(lua_State *L)
{
    // const wxString time
    const wxString time = wxlua_getwxStringtype(L, 2);
    wxString::const_iterator it(time.begin());
    // get this
    wxDateTime * self = (wxDateTime *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDateTime);
    // call ParseTime
    bool returns = (self->ParseTime(time, &it));
    // push the result flag
    lua_pushboolean(L, returns);

    if (!returns && (it != time.end()))
    {
    wxString s(it, time.end());
        wxlua_pushwxString(L, s);
        return 2;
    }

    return 1;
}
%end

// ----------------------------------------------------------------------------
// Overrides for wxbase_file.i
// ----------------------------------------------------------------------------

%override wxLua_function_wxDos2UnixFilename
// %function wxString wxDos2UnixFilename(const wxString& s)
static int LUACALL wxLua_function_wxDos2UnixFilename(lua_State *L)
{
    wxString str = lua2wx(lua_tostring(L, 1));
    if (!str.IsEmpty())
    {
        // call wxDos2UnixFilename
        wxDos2UnixFilename((wxChar*)str.GetData());
        // push the result string
        wxlua_pushwxString(L, str);

        return 1;
    }
    return 0;
}
%end

%override wxLua_function_wxUnix2DosFilename
// %function wxString wxUnix2DosFilename(const wxString& s)
static int LUACALL wxLua_function_wxUnix2DosFilename(lua_State *L)
{
    wxString str = lua2wx(lua_tostring(L, 1));
    if (!str.IsEmpty())
    {
        // call wxUnix2DosFilename
        wxUnix2DosFilename((wxChar*)str.GetData());
        // push the result string
        wxlua_pushwxString(L, str);

        return 1;
    }
    return 0;
}
%end

%override wxLua_function_wxFileSize
// %function long wxFileSize(const wxString& fileName)
static int LUACALL wxLua_function_wxFileSize(lua_State *L)
{
    wxString str = lua2wx(lua_tostring(L, 1));
    if (!str.IsEmpty())
    {
        wxStructStat statstr;
        wxStat(str, &statstr);
        // push the result string
        lua_pushinteger(L, (int)statstr.st_size);

        return 1;
    }
    return 0;
}
%end

%override wxLua_wxFileName_GetDirs
//     const wxArrayString& GetDirs() const
static int LUACALL wxLua_wxFileName_GetDirs(lua_State *L)
{
    // get this
    wxFileName * self = (wxFileName *)wxluaT_getuserdatatype(L, 1, wxluatype_wxFileName);
    // call GetDirs
    wxArrayString returns = self->GetDirs();
    // push the result datatype
    wxlua_pushwxArrayStringtable(L, returns);

    return 1;
}
%end

%override wxLua_wxFileName_GetTimes
// bool GetTimes(wxDateTime* dtAccess, wxDateTime* dtMod, wxDateTime* dtCreate) const
static int LUACALL wxLua_wxFileName_GetTimes(lua_State *L)
{
    wxDateTime *dtCreate = new wxDateTime();
    wxDateTime *dtMod = new wxDateTime();
    wxDateTime *dtAccess= new wxDateTime();
    // get this
    wxFileName *self = (wxFileName *)wxluaT_getuserdatatype(L, 1, wxluatype_wxFileName);
    // call GetTimes
    bool returns = self->GetTimes(dtAccess, dtMod, dtCreate);
    // push the result flag
    lua_pushboolean(L, returns);
    // add to tracked memory list
    wxluaO_addgcobject(L, (void*)dtAccess, wxluatype_wxDateTime);
    wxluaO_addgcobject(L, (void*)dtMod,    wxluatype_wxDateTime);
    wxluaO_addgcobject(L, (void*)dtCreate, wxluatype_wxDateTime);
    // push the constructed class pointers
    wxluaT_pushuserdatatype(L, dtAccess, wxluatype_wxDateTime);
    wxluaT_pushuserdatatype(L, dtMod,    wxluatype_wxDateTime);
    wxluaT_pushuserdatatype(L, dtCreate, wxluatype_wxDateTime);
    // return the number of parameters
    return 4;
}
%end

%override wxLua_wxFileName_SplitPath
// static void SplitPath(const wxString& fullpath, wxString* volume, wxString* path, wxString* name, wxString* ext, wxPathFormat format = wxPATH_NATIVE)
static int LUACALL wxLua_wxFileName_SplitPath(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // wxPathFormat format = wxPATH_NATIVE
    wxPathFormat format = (argCount >= 2 ? (wxPathFormat)wxlua_getenumtype(L, 2) : wxPATH_NATIVE);
    wxString ext;
    wxString name;
    wxString path;
    // const wxString& fullpath
    wxString fullpath = wxlua_getwxStringtype(L, 1);
    // call SplitPath
    wxFileName::SplitPath(fullpath, &path, &name, &ext, format);
    // push the result strings
    wxlua_pushwxString(L, path);
    wxlua_pushwxString(L, name);
    wxlua_pushwxString(L, ext);
    // return the number of parameters
    return 3;
}
%end

%override wxLua_wxFileName_SplitPathVolume
// static void SplitPath(const wxString& fullpath, wxString* volume, wxString* path, wxString* name, wxString* ext, wxPathFormat format = wxPATH_NATIVE)
static int LUACALL wxLua_wxFileName_SplitPathVolume(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // wxPathFormat format = wxPATH_NATIVE
    wxPathFormat format = (argCount >= 2 ? (wxPathFormat)wxlua_getenumtype(L, 2) : wxPATH_NATIVE);
    wxString ext;
    wxString name;
    wxString path;
    wxString volume;
    // const wxString& fullpath
    wxString fullpath = wxlua_getwxStringtype(L, 1);
    // call SplitPath
    wxFileName::SplitPath(fullpath, &volume, &path, &name, &ext, format);
    // push the result strings
    wxlua_pushwxString(L, volume);
    wxlua_pushwxString(L, path);
    wxlua_pushwxString(L, name);
    wxlua_pushwxString(L, ext);
    // return the number of parameters
    return 4;
}
%end

%override wxLua_wxFileName_SplitVolume
//     static void SplitVolume(const wxString& fullpath, wxString* volume, wxString* path, wxPathFormat format = wxPATH_NATIVE)
static int LUACALL wxLua_wxFileName_SplitVolume(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // wxPathFormat format = wxPATH_NATIVE
    wxPathFormat format = (argCount >= 2 ? (wxPathFormat)wxlua_getenumtype(L, 2) : wxPATH_NATIVE);
    // const wxString fullpath
    const wxString fullpath = wxlua_getwxStringtype(L, 1);
    wxString volume;
    wxString path;
    // call SplitVolume
    wxFileName::SplitVolume(fullpath, &volume, &path, format);
    // push the result strings
    wxlua_pushwxString(L, volume);
    wxlua_pushwxString(L, path);
    return 2;
}
%end

%override wxLua_wxDir_GetFirst
// bool GetFirst(wxString * filename, const wxString& filespec = "", int flags = wxDIR_DEFAULT) const
static int LUACALL wxLua_wxDir_GetFirst(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // int flags = wxDIR_DEFAULT
    int flags = (argCount >= 3 ? (int)wxlua_getintegertype(L, 3) : wxDIR_DEFAULT);
    // const wxString& filespec = ""
    wxString filespec = (argCount >= 2 ? wxlua_getwxStringtype(L, 2) : wxString(wxT("")));
    // wxString * filename
    wxString filename;
    // get this
    wxDir *self = (wxDir *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDir);
    // call GetFirst
    bool returns = self->GetFirst(&filename, filespec, flags);
    lua_pushboolean(L, returns);
    // push the result number
    wxlua_pushwxString(L, filename);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxDir_GetNext
// bool GetNext(wxString * filename) const
static int LUACALL wxLua_wxDir_GetNext(lua_State *L)
{
    // wxString * filename
    wxString filename;
    // get this
    wxDir *self = (wxDir *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDir);
    // call GetNext
    bool returns = self->GetNext(&filename);
    lua_pushboolean(L, returns);
    // push the result number
    wxlua_pushwxString(L, filename);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxDir_GetAllFiles
// static unsigned int GetAllFiles(const wxString& dirname, wxArrayString *files, const wxString& filespec = "", int flags = wxDIR_DEFAULT)
static int LUACALL wxLua_wxDir_GetAllFiles(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // int flags = wxDIR_DEFAULT
    int flags = (argCount >= 3 ? (int)wxlua_getintegertype(L, 3) : wxDIR_DEFAULT);
    // const wxString& filespec = ""
    wxString filespec = (argCount >= 2 ? wxlua_getwxStringtype(L, 2) : wxString(wxT("")));
    // wxArrayString *files
    wxArrayString files;
    // const wxString& dirname
    wxString dirname = wxlua_getwxStringtype(L, 1);
    // call GetAllFiles
    unsigned int returns = wxDir::GetAllFiles(dirname, &files, filespec, flags);
    // push the result number
    lua_pushinteger(L, returns);
    wxlua_pushwxArrayStringtable(L, files);
    // return the number of parameters
    return 2;
}
%end

%override wxLua_wxFile_Read
// unsigned int Read(void * buffer,  unsigned int count)
static int LUACALL wxLua_wxFile_Read(lua_State *L)
{
    // unsigned int count
    unsigned int count = (unsigned int)wxlua_getintegertype(L, 2);
    // void * buffer
    void *buffer = malloc(count);
    if (buffer != NULL)
    {
        // get this
        wxFile *self = (wxFile *)wxluaT_getuserdatatype(L, 1, wxluatype_wxFile);
        // call Read
        unsigned int returns = self->Read(buffer, count);
        // push the result number
        lua_pushinteger(L, returns);
        lua_pushlstring(L, (const char *) buffer, returns);
        free(buffer);
        // return the number of parameters
        return 2;
    }
    return 0;
}
%end

%override wxLua_wxFile_Write
// unsigned int Write(const void * buffer, unsigned int nbytes)
static int LUACALL wxLua_wxFile_Write(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // unsigned long nbytes
    unsigned long nbytes = (argCount >= 3 ? (unsigned long)wxlua_getintegertype(L, 3) : lua_strlen(L, 2));
    // const void * buffer
    const void *buffer = (const void *)lua_tostring(L, 2);
    // get this
    wxFile *self = (wxFile *)wxluaT_getuserdatatype(L, 1, wxluatype_wxFile);
    // call Write
    unsigned int returns = self->Write(buffer, nbytes);
    // push the result number
    lua_pushinteger(L, returns);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxFileType_GetDescription
//     bool GetDescription(wxString *desc) const;
static int LUACALL wxLua_wxFileType_GetDescription(lua_State *L)
{
    // wxString desc
    wxString desc; // = wxlua_getwxStringtype(L, 2);
    // get this
    wxFileType * self = (wxFileType *)wxluaT_getuserdatatype(L, 1, wxluatype_wxFileType);
    // call GetDescription
    bool returns = (self->GetDescription(&desc));
    // push the result flag
    lua_pushboolean(L, returns);
    wxlua_pushwxString(L, desc);

    return 2;
}
%end

%override wxLua_wxFileType_GetPrintCommand
//     bool GetPrintCommand(wxString *printCmd, const wxFileType::MessageParameters& params) const;
static int LUACALL wxLua_wxFileType_GetPrintCommand(lua_State *L)
{
    // const wxFileType::MessageParameters params
    const wxFileType::MessageParameters * params = (const wxFileType::MessageParameters *)wxluaT_getuserdatatype(L, 3, wxluatype_wxFileType_MessageParameters);
    // wxString printCmd
    wxString printCmd; // = wxlua_getwxStringtype(L, 2);
    // get this
    wxFileType * self = (wxFileType *)wxluaT_getuserdatatype(L, 1, wxluatype_wxFileType);
    // call GetPrintCommand
    bool returns = (self->GetPrintCommand(&printCmd, *params));
    // push the result flag
    lua_pushboolean(L, returns);
    wxlua_pushwxString(L, printCmd);

    return 2;
}
%end

%override wxLua_wxInputStream_Read
// wxInputStream& Read(void *buffer, size_t size)
static int LUACALL wxLua_wxInputStream_Read(lua_State *L)
{
    // size_t size
    size_t size = (size_t)wxlua_getintegertype(L, 2);
    // void *buffer
    void *buffer = malloc(size);
    // get this
    wxInputStream *self = (wxInputStream *)wxluaT_getuserdatatype(L, 1, wxluatype_wxInputStream);
    if (buffer != NULL)
    {
        // call Read
        // wxInputStream *returns = & // we don't return wxInputStream
        self->Read(buffer, size);
        // only return the data that was read, they already have self
        //wxluaT_pushuserdatatype(L, returns, wxluatype_wxInputStream);
        lua_pushlstring(L, (const char *)buffer, size);
        free(buffer);
        return 1;
    }
    return 0;
}
%end

%override wxLua_wxInputStream_UngetchString
// size_t Ungetch(const char* buffer, size_t size)
static int LUACALL wxLua_wxInputStream_UngetchString(lua_State *L)
{
    // size_t size
    size_t size = (size_t)wxlua_getintegertype(L, 3);
    // const char* buffer
    const char *buffer = (const char *)lua_tostring(L, 2);
    // get this
    wxInputStream *self = (wxInputStream *)wxluaT_getuserdatatype(L, 1, wxluatype_wxInputStream);
    // call Ungetch
    size_t returns = self->Ungetch(buffer, size);
    // push the result number
    lua_pushinteger(L, returns);
    // return the number of parameters
    return 1;
}
%end

%override wxLua_wxOutputStream_Write
// wxOutputStream& Write(const void *buffer, size_t size)
static int LUACALL wxLua_wxOutputStream_Write(lua_State *L)
{
    // size_t size
    size_t size = (size_t)wxlua_getintegertype(L, 3);
    // const void *buffer
    const void *buffer = (void *)lua_tostring(L, 2);
    // get this
    wxOutputStream *self = (wxOutputStream *)wxluaT_getuserdatatype(L, 1, wxluatype_wxOutputStream);
    // call Write
    wxOutputStream *returns = &self->Write(buffer, size);
    // push the result datatype
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxOutputStream);
    // return the number of parameters
    return 1;
}
%end


%override wxLua_wxMemoryInputStream_constructor
//     wxMemoryInputStream(const char *data, size_t length)
static int LUACALL wxLua_wxMemoryInputStream_constructor(lua_State *L)
{
    // size_t length
    size_t length = (size_t)wxlua_getnumbertype(L, 2);
    // const char data
    const char* data = (const char*)wxlua_getstringtype(L, 1);
    // call constructor
    wxMemoryInputStream* returns = new wxMemoryInputStream(data, length);
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxMemoryInputStream);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxMemoryInputStream);

    return 1;
}
%end

%override wxLua_wxMemoryOutputStream_constructor1
//     wxMemoryOutputStream(wxMemoryBuffer &buffer, size_t length = 0);
// C++ Func: wxMemoryOutputStream(void *data = NULL, size_t length = 0);
static int LUACALL wxLua_wxMemoryOutputStream_constructor1(lua_State *L)
{
    // size_t length
    size_t length = (lua_gettop(L) >= 2 ? (size_t)wxlua_getnumbertype(L, 2) : 0);
    // wxMemoryBuffer buffer
    wxMemoryBuffer * buffer = (wxMemoryBuffer *)wxluaT_getuserdatatype(L, 1, wxluatype_wxMemoryBuffer);
    void *data;
    if (length > 0) {
        data = buffer->GetWriteBuf(length);
    } else {
        data = buffer->GetData();
        length = buffer->GetDataLen();
    }
    // call constructor
    wxMemoryOutputStream* returns = new wxMemoryOutputStream(data, length);
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxMemoryOutputStream);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxMemoryOutputStream);

    return 1;
}
%end

%override wxLua_wxMemoryOutputStream_CopyTo
//     size_t CopyTo(wxMemoryBuffer &buffer, size_t length = 0);
// C++ Func: wxMemoryOutputStream(void *data = NULL, size_t length = 0);
static int LUACALL wxLua_wxMemoryOutputStream_CopyTo(lua_State *L)
{
    // size_t length
    size_t length = (lua_gettop(L) >= 2 ? (size_t)wxlua_getnumbertype(L, 2) : 0);
    // wxMemoryBuffer buffer
    wxMemoryBuffer * buffer = (wxMemoryBuffer *)wxluaT_getuserdatatype(L, 2, wxluatype_wxMemoryBuffer);
    void *data;
    if (length > 0) {
        data = buffer->GetWriteBuf(length);
    } else {
        data = buffer->GetData();
        length = buffer->GetDataLen();
    }
    // get this
    wxMemoryOutputStream * self = (wxMemoryOutputStream *)wxluaT_getuserdatatype(L, 1, wxluatype_wxMemoryOutputStream);
    // call CopyTo
    size_t returns = (self->CopyTo(data, length));
    // push the result number
#if LUA_VERSION_NUM >= 503
if ((double)(lua_Integer)returns == (double)returns) {
    // Exactly representable as lua_Integer
        lua_pushinteger(L, returns);
    } else
#endif
    {
        lua_pushnumber(L, returns);
    }
    return 1;
}
%end

%override wxLua_wxFileSystem_FindFileInPath
//     bool FindFileInPath(wxString *pStr, const wxChar *path, const wxChar *file);
//     bool FindFileInPath(const wxString& path, const wxString& file);
static int LUACALL wxLua_wxFileSystem_FindFileInPath(lua_State *L)
{
    // const wxString file
    const wxString file_ = wxlua_getwxStringtype(L, 3);
    // const wxString path
    const wxString path = wxlua_getwxStringtype(L, 2);
    // get this
    wxFileSystem * self = (wxFileSystem *)wxluaT_getuserdatatype(L, 1, wxluatype_wxFileSystem);
    // call FindFileInPath
    wxString str;
    bool returns = (self->FindFileInPath(&str, path, file_));
    // push the result flag
    lua_pushboolean(L, returns);
    wxlua_pushwxString(L, str);

    return 2;
}
%end


%override wxLua_wxVariantFromString_constructor
//     wxVariant(const wxString& str)
static int LUACALL wxLua_wxVariantFromString_constructor(lua_State *L)
{
    // const wxString str = ""
    const wxString str = wxlua_getwxStringtype(L, 1);
    // call constructor
    wxVariant* returns = new wxVariant(str);
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxVariant);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxVariant);

    return 1;
}
%end


%override wxLua_wxVariantFromDouble_constructor
//     wxVariant(double d)
static int LUACALL wxLua_wxVariantFromDouble_constructor(lua_State *L)
{
    wxVariant* returns;

    if (lua_isboolean(L, 1)) {
        bool b = (bool)wxlua_getbooleantype(L, 1);
        returns = new wxVariant(b);
    }
    else {
        double d = (double)wxlua_getnumbertype(L, 1);
        if ((int)d == d) {
            int i = (int)d;
            returns = new wxVariant(i);
        } else {
            returns = new wxVariant(d);
        }
    }

    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxVariant);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxVariant);

    return 1;
}
%end


%override wxLua_wxVariantFromArrayString_constructor
//     wxVariant(const wxArrayString& a)
static int LUACALL wxLua_wxVariantFromArrayString_constructor(lua_State *L)
{
    // wxLuaSmartwxArrayString a
    wxLuaSmartwxArrayString a(wxlua_getwxArrayString(L, 1));
    // call constructor
    wxVariant* returns = new wxVariant((wxArrayString&)a);
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxVariant);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxVariant);

    return 1;
}
%end


%override wxLua_wxVariantFromDateTime_constructor
//     wxVariant(const wxDateTime& d)
static int LUACALL wxLua_wxVariantFromDateTime_constructor(lua_State *L)
{
    // wxDateTime d
    wxDateTime * d = (wxDateTime *)wxluaT_getuserdatatype(L, 1, wxluatype_wxDateTime);
    // call constructor
    wxVariant* returns = new wxVariant(*d);
    // add to tracked memory list
    wxluaO_addgcobject(L, returns, wxluatype_wxVariant);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxVariant);

    return 1;
}
%end


%override wxLua_wxVariantFromVoidPtr_constructor
//     wxVariant(void *p)
static int LUACALL wxLua_wxVariantFromVoidPtr_constructor(lua_State *L)
{
    wxVariant* returns;

    if (lua_isnil(L, 1)) {
        returns = new wxVariant();
    } else {
        void * p = (void *)wxlua_touserdata(L, 1);
        returns = new wxVariant(p);
    }

    wxluaO_addgcobject(L, returns, wxluatype_wxVariant);
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxVariant);

    return 1;
}
%end


%override wxLua_wxVariantFromObject_constructor
//     wxVariant(wxObject *o)
static int LUACALL wxLua_wxVariantFromObject_constructor(lua_State *L)
{
    // wxObject o
    wxObject * o = (wxObject *)wxluaT_getuserdatatype(L, 1, wxluatype_wxObject);
    if (wxluaO_isgcobject(L, o)) wxluaO_undeletegcobject(L, o);
    // call constructor
    wxVariant* returns = new wxVariant(o);
    // push the constructed class pointer
    wxluaO_addgcobject(L, returns, wxluatype_wxVariant);
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxVariant);

    return 1;
}
%end


%override wxLua_wxVariant_ToLuaValue
// int ToLuaValue() const
static int LUACALL wxLua_wxVariant_ToLuaValue(lua_State *L)
{
    wxVariant * self = (wxVariant *)wxluaT_getuserdatatype(L, 1, wxluatype_wxVariant);

    if (self->IsType("arrstring")) {
        wxArrayString returns = self->GetArrayString();
        wxlua_pushwxArrayStringtable(L, returns);
        return 1;
    } else if (self->IsType("datetime")) {
        wxDateTime* returns = new wxDateTime(self->GetDateTime());
        wxluaT_pushuserdatatype(L, returns, wxluatype_wxDateTime);
        return 1;
    } else if (self->IsType("string")) {
        wxString returns = self->GetString();
        wxlua_pushwxString(L, returns);
        return 1;
    } else if (self->IsType("char")) {
        wxUniChar returns = self->GetChar();
        lua_pushnumber(L, returns.GetValue());
        return 1;
    } else if (self->IsType("double")) {
        double returns = self->GetDouble();
        lua_pushnumber(L, returns);
        return 1;
    } else if (self->IsType("longlong")) {
        wxLongLong returns = self->GetLongLong();
        lua_pushnumber(L, returns.ToLong());
        return 1;
    } else if (self->IsType("ulonglong")) {
        wxULongLong returns = self->GetULongLong();
        lua_pushnumber(L, returns.GetValue());
        return 1;
    } else if (self->IsType("long")) {
        long returns = self->GetLong();
        lua_pushnumber(L, returns);
        return 1;
    } else if (self->IsType("bool")) {
        long returns = self->GetBool();
        lua_pushboolean(L, returns);
        return 1;
    } else if (self->IsNull()) {
        lua_pushnil(L);
        return 1;
    }

    wxlua_argerror(L, 1, wxT("a 'convertable variant'"));
    return 0;
}
%end


%override wxLua_wxVariantData_delete_function
// delete is private in wxVariantData
void wxLua_wxVariantData_delete_function(void** p)
{
}
%end
