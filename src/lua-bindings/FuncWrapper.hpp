class FuncWrapper
{
	public:
		FuncWrapper(lua_State *wxlState, int lua_func_stack_idx);
		~FuncWrapper();
		
		FuncWrapper(const FuncWrapper &src);
		
		void operator()() const;
	
	private:
		int *refcount;
		
		lua_State *lua_state;
		int func_ref;
};

FuncWrapper::FuncWrapper(lua_State *wxlState, int lua_func_stack_idx):
	lua_state(wxlState)
{
	refcount = new int(1);
	
	func_ref = wxluaR_ref(lua_state, lua_func_stack_idx, &wxlua_lreg_refs_key);
}

FuncWrapper::~FuncWrapper()
{
	if(--(*refcount) == 0)
	{
		wxluaR_unref(lua_state, func_ref, &wxlua_lreg_refs_key);
		delete refcount;
	}
}

FuncWrapper::FuncWrapper(const FuncWrapper &src):
	refcount(src.refcount),
	lua_state(src.lua_state),
	func_ref(src.func_ref)
{
	++(*refcount);
}

void FuncWrapper::operator()() const
{
	wxLuaState wxlState(lua_state);
	
	wxlState.lua_CheckStack(LUA_MINSTACK);
	int oldTop = wxlState.lua_GetTop();
	if (wxlState.wxluaR_GetRef(func_ref, &wxlua_lreg_refs_key))
	{
	#if LUA_VERSION_NUM < 502
		// lua_setfenv() is not in Lua 5.2 nor can you set an env for a function anymore
		wxlState.GetGlobals();
		if (wxlState.lua_SetFenv(-2) != 0)
	#endif // LUA_VERSION_NUM < 502
		{
			wxlState.LuaPCall(0, 0); // no input no returns
		}
	#if LUA_VERSION_NUM < 502
		else
			wxlState.wxlua_Error("FuncWrapper: func_ref is not a Lua function.");
	#endif // LUA_VERSION_NUM < 502
	}
	else
		wxlState.wxlua_Error("FuncWrapper: func_ref is not refed.");
	
	wxlState.lua_SetTop(oldTop); // pop function and error message from the stack (if they're there)
}
