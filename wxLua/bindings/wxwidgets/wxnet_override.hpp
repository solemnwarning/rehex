// ----------------------------------------------------------------------------
// Overridden functions for the wxWidgets binding for wxLua
//
// Please keep these functions in the same order as the .i file and in the
// same order as the listing of the functions in that file.
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// Overrides for wxnet_net.i
// ----------------------------------------------------------------------------

%override wxLua_wxSocketBase_Peek
// void Peek(void * buffer, unsigned long nbytes)
static int LUACALL wxLua_wxSocketBase_Peek(lua_State *L)
{
    // unsigned long nbytes
    unsigned long nbytes = (unsigned long)wxlua_getintegertype(L, 2);
    // void * buffer
    void *buffer = malloc(nbytes);
    if (buffer != NULL)
    {
        // get this
        wxSocketBase *self = (wxSocketBase *)wxluaT_getuserdatatype(L, 1, wxluatype_wxSocketBase);
        // call Peek
        self->Peek(buffer, nbytes);
        // return the number of parameters
        lua_pushlstring(L, (const char *)buffer, nbytes);
        free(buffer);
        return 1;
    }
    return 0;
}
%end

%override wxLua_wxSocketBase_Read
// void Read(void * buffer, unsigned long nbytes)
static int LUACALL wxLua_wxSocketBase_Read(lua_State *L)
{
    // unsigned long nbytes
    unsigned long nbytes = (unsigned long)wxlua_getintegertype(L, 2);
    // void * buffer
    void *buffer = malloc(nbytes);
    if (buffer != NULL)
    {
        // get this
        wxSocketBase *self = (wxSocketBase *)wxluaT_getuserdatatype(L, 1, wxluatype_wxSocketBase);
        // call Peek
        self->Read(buffer, nbytes);
        // return the number of parameters
        lua_pushlstring(L, (const char *)buffer, nbytes);
        free(buffer);
        return 1;
    }
    return 0;
}
%end

%override wxLua_wxSocketBase_ReadMsg
// void ReadMsg(void * buffer, unsigned long nbytes)
static int LUACALL wxLua_wxSocketBase_ReadMsg(lua_State *L)
{
    // unsigned long nbytes
    unsigned long nbytes = (unsigned long)wxlua_getintegertype(L, 2);
    // void * buffer
    void *buffer = malloc(nbytes);
    if (buffer != NULL)
    {
        // get this
        wxSocketBase *self = (wxSocketBase *)wxluaT_getuserdatatype(L, 1, wxluatype_wxSocketBase);
        // call Peek
        self->ReadMsg(buffer, nbytes);
        // return the number of parameters
        lua_pushlstring(L, (const char *)buffer, self->LastCount()); // not nbytes since it may return less
        free(buffer);
        return 1;
    }
    return 0;
}
%end

%override wxLua_wxSocketBase_Unread
// void Unread(const void * buffer, unsigned long nbytes)
static int LUACALL wxLua_wxSocketBase_Unread(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // const void * buffer
    const char *buffer = lua_tostring(L, 2);
    // unsigned long nbytes
    unsigned long nbytes = (argCount >= 3 ? (unsigned long)wxlua_getintegertype(L, 3) : lua_strlen(L, 2));
    // get this
    wxSocketBase *self = (wxSocketBase *)wxluaT_getuserdatatype(L, 1, wxluatype_wxSocketBase);
    // call Unread
    self->Unread(buffer, nbytes);
    // return the number of parameters
    return 0;
}
%end

%override wxLua_wxSocketBase_Write
// void Write(const void * buffer, unsigned long nbytes)
static int LUACALL wxLua_wxSocketBase_Write(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // const void * buffer
    const char *buffer = lua_tostring(L, 2);
    // unsigned long nbytes
    unsigned long nbytes = (argCount >= 3 ? (unsigned long)wxlua_getintegertype(L, 3) : lua_strlen(L, 2));
    // get this
    wxSocketBase *self = (wxSocketBase *)wxluaT_getuserdatatype(L, 1, wxluatype_wxSocketBase);
    // call Write
    self->Write(buffer, nbytes);
    // return the number of parameters
    return 0;
}
%end

%override wxLua_wxSocketBase_WriteMsg
// void WriteMsg(const void * buffer, wxUint32 nbytes)
static int LUACALL wxLua_wxSocketBase_WriteMsg(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // const void * buffer
    const char *buffer = lua_tostring(L, 2);
    // unsigned long nbytes
    unsigned long nbytes = (argCount >= 3 ? (unsigned long)wxlua_getintegertype(L, 3) : lua_strlen(L, 2));
    // get this
    wxSocketBase *self = (wxSocketBase *)wxluaT_getuserdatatype(L, 1, wxluatype_wxSocketBase);
    // call WriteMsg
    self->WriteMsg(buffer, nbytes);
    // return the number of parameters
    return 0;
}
%end

