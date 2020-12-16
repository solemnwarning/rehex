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
	
	FuncWrapper func_wrapper(L, 2);
	
	// call constructor
	REHex::App::SetupHookRegistration* returns = new REHex::App::SetupHookRegistration(phase,
		[func_wrapper]()
		{
			func_wrapper();
		});
	
	// add to tracked memory list
	wxluaO_addgcobject(L, returns, wxluatype_REHex_App_SetupHookRegistration);
	// push the constructed class pointer
	wxluaT_pushuserdatatype(L, returns, wxluatype_REHex_App_SetupHookRegistration);
	
	return 1;
}
%end
