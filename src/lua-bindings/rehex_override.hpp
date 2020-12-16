// ----------------------------------------------------------------------------
// Overridden functions for the wxWidgets binding for wxLua
//
// Please keep these functions in the same order as the .i file and in the
// same order as the listing of the functions in that file.
// ----------------------------------------------------------------------------

%override wxLua_REHex_App_SetupHookRegistration_constructor
static int LUACALL wxLua_REHex_App_SetupHookRegistration_constructor(lua_State *L)
{
	// REHex::App::SetupPhase phase
	REHex::App::SetupPhase phase = (REHex::App::SetupPhase)wxlua_getenumtype(L, 1);
	
	if (!lua_isfunction(L, 2))
	{
		wxlua_argerror(L, 2, wxT("a 'Lua function'"));
		return 0;
	}
	
	/* TODO: Implement callable class that holds a Lua function object and doesn't leak
	 * references like the below does.
	*/
	
	wxLuaState wxlState(L);
	int luafunc_ref = wxlState.wxluaR_Ref(2, &wxlua_lreg_refs_key);
	
	// call constructor
	REHex::App::SetupHookRegistration* returns = new REHex::App::SetupHookRegistration(phase,
		[wxlState, luafunc_ref]() mutable
		{
			int oldTop = wxlState.lua_GetTop();
			if (wxlState.wxluaR_GetRef(luafunc_ref, &wxlua_lreg_refs_key))
			{
			#if LUA_VERSION_NUM < 502
				// lua_setfenv() is not in Lua 5.2 nor can you set an env for a function anymore
				wxlState.GetGlobals();
				if (wxlState.lua_SetFenv(-2) != 0)
			#endif // LUA_VERSION_NUM < 502
				{
					wxlState.LuaPCall(0, 0); // one input no returns
				}
			#if LUA_VERSION_NUM < 502
				else
				wxlState.wxlua_Error("wxLua: wxEvtHandler::Connect() in wxLuaEventCallback::OnEvent(), callback function is not a Lua function.");
			#endif // LUA_VERSION_NUM < 502
			}
			else
				wxlState.wxlua_Error("wxLua: wxEvtHandler::Connect() in wxLuaEventCallback::OnEvent(), callback function to call is not refed.");

			wxlState.lua_SetTop(oldTop); // pop function and error message from the stack (if they're there)
		});
	
	// add to tracked memory list
	wxluaO_addgcobject(L, returns, wxluatype_REHex_App_SetupHookRegistration);
	// push the constructed class pointer
	wxluaT_pushuserdatatype(L, returns, wxluatype_REHex_App_SetupHookRegistration);
	
	return 1;
}
%end
