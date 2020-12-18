// ----------------------------------------------------------------------------
// Overridden functions for the wxLuaDebugger binding for wxLua
//
// Please keep these functions in the same order as the .i file and in the
// same order as the listing of the functions in that file.
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// Overrides for wxluadebugger.i
// ----------------------------------------------------------------------------

%override wxLua_function_LuaStackDialog
// %function void LuaStackDialog()
static int LUACALL wxLua_function_LuaStackDialog(lua_State *L)
{
    // call StackDialog

    wxLuaStackDialog stackDialog(wxLuaState(L), NULL);
    stackDialog.ShowModal();

    return 0;
}
%end
