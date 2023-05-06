// ----------------------------------------------------------------------------
// Overridden functions for the wxWidgets binding for wxLua
//
// Please keep these functions in the same order as the .i file and in the
// same order as the listing of the functions in that file.
// ----------------------------------------------------------------------------

%override wxLua_function_print_debug
static int LUACALL wxLua_function_print_debug(lua_State *L)
{
    const wxString text = wxlua_getwxStringtype(L, 1);
    wxGetApp().print_debug(text.ToStdString());

    return 0;
}
%end

%override wxLua_function_print_info
static int LUACALL wxLua_function_print_info(lua_State *L)
{
    const wxString text = wxlua_getwxStringtype(L, 1);
    wxGetApp().print_info(text.ToStdString());

    return 0;
}
%end

%override wxLua_function_print_error
static int LUACALL wxLua_function_print_error(lua_State *L)
{
    const wxString text = wxlua_getwxStringtype(L, 1);
    wxGetApp().print_error(text.ToStdString());

    return 0;
}
%end

%override wxLua_function_bulk_updates_freeze
static int LUACALL wxLua_function_bulk_updates_freeze(lua_State *L)
{
	wxGetApp().bulk_updates_freeze();
	return 0;
}
%end

%override wxLua_function_bulk_updates_thaw
static int LUACALL wxLua_function_bulk_updates_thaw(lua_State *L)
{
	wxGetApp().bulk_updates_thaw();
	return 0;
}
%end

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

%override wxLua_REHex_MainWindow_SetupHookRegistration_constructor
static int LUACALL wxLua_REHex_MainWindow_SetupHookRegistration_constructor(lua_State *L)
{
	// REHex::MainWindow::SetupPhase phase
	REHex::MainWindow::SetupPhase phase = (REHex::MainWindow::SetupPhase)(wxlua_getenumtype(L, 1));
	
	if (!lua_isfunction(L, 2))
	{
		wxlua_argerror(L, 2, wxT("a 'Lua function'"));
		return 0;
	}
	
	FuncWrapper_MainWindow func_wrapper(L, 2);
	
	// call constructor
	REHex::MainWindow::SetupHookRegistration* returns = new REHex::MainWindow::SetupHookRegistration(phase, func_wrapper);
	
	// add to tracked memory list
	wxluaO_addgcobject(L, returns, wxluatype_REHex_MainWindow_SetupHookRegistration);
	// push the constructed class pointer
	wxluaT_pushuserdatatype(L, returns, wxluatype_REHex_MainWindow_SetupHookRegistration);
	
	return 1;
}
%end

%override wxLua_REHex_Document_get_comments
static int LUACALL wxLua_REHex_Document_get_comments(lua_State *L)
{
	REHex::Document *self = (REHex::Document*)(wxluaT_getuserdatatype(L, 1, wxluatype_REHex_Document));
	
	const REHex::ByteRangeTree<REHex::Document::Comment> &comments = self->get_comments();
	
	lua_newtable(L);            /* Table to return */
	lua_Integer table_idx = 1;  /* Next index to use in return table */
	
	for(auto c = comments.begin(); c != comments.end(); ++c)
	{
		lua_pushinteger(L, table_idx++);
		
		lua_newtable(L);  /* Table for comment. */
		
		lua_pushstring(L, "offset");
		lua_pushinteger(L, c->first.offset);
		lua_settable(L, -3);
		
		lua_pushstring(L, "length");
		lua_pushinteger(L, c->first.length);
		lua_settable(L, -3);
		
		lua_pushstring(L, "text");
		lua_pushlstring(L, c->second.text->mb_str().data(), c->second.text->mb_str().length());
		lua_settable(L, -3);
		
		/* Push comment table onto return table */
		lua_settable(L, -3);
	}
	
	return 1;
}
%end

%override wxLua_REHex_Document_read_data
static int LUACALL wxLua_REHex_Document_read_data(lua_State *L)
{
	REHex::Document *self = (REHex::Document*)(wxluaT_getuserdatatype(L, 1, wxluatype_REHex_Document));
	
	off_t offset     = (off_t)(wxlua_getnumbertype(L, 2));
	off_t max_length = (off_t)(wxlua_getnumbertype(L, 3));
	
	// TODO: Handle exceptions(?)
	
	std::vector<unsigned char> data = self->read_data(offset, max_length);
	lua_pushlstring(L, (const char*)(data.data()), data.size());
	
	return 1;
}
%end

%override wxLua_REHex_Document_set_data_type
static int LUACALL wxLua_REHex_Document_set_data_type(lua_State *L)
{
	REHex::Document *self = (REHex::Document *)wxluaT_getuserdatatype(L, 1, wxluatype_REHex_Document);
	
	off_t offset = (off_t)wxlua_getnumbertype(L, 2);
	off_t length = (off_t)wxlua_getnumbertype(L, 3);
	const wxString type = wxlua_getwxStringtype(L, 4);
	
	bool returns = self->set_data_type(offset, length, type.ToStdString());
	lua_pushboolean(L, returns);
	
	return 1;
}
%end

%override wxLua_REHex_Document_transact_begin
static int LUACALL wxLua_REHex_Document_transact_begin(lua_State *L)
{
	const wxString desc = wxlua_getwxStringtype(L, 2);
	REHex::Document *self = (REHex::Document*)(wxluaT_getuserdatatype(L, 1, wxluatype_REHex_Document));
	
	self->transact_begin(desc.ToStdString());
	
	return 0;
}
%end

%override wxLua_REHex_Tab_get_selection_linear
static int LUACALL wxLua_REHex_Tab_get_selection_linear(lua_State *L)
{
	REHex::Tab * self = (REHex::Tab *)wxluaT_getuserdatatype(L, 1, wxluatype_REHex_Tab);
	
	std::pair<off_t,off_t> selection = self->doc_ctrl->get_selection_linear();
	if(selection.second > 0)
	{
		lua_pushinteger(L, selection.first);
		lua_pushinteger(L, selection.second);
		
		return 2;
	}
	else{
		return 0;
	}
}
%end

%override wxLua_REHex_CharacterEncoding_encoding_by_key
static int LUACALL wxLua_REHex_CharacterEncoding_encoding_by_key(lua_State *L)
{
	const wxString key = wxlua_getwxStringtype(L, 1);
	
	const REHex::CharacterEncoding* returns = REHex::CharacterEncoding::encoding_by_key(std::string(key));
	wxluaT_pushuserdatatype(L, returns, wxluatype_REHex_CharacterEncoding);
	
	return 1;
}
%end

%override wxLua_REHex_CharacterEncoding_all_encodings
static int LUACALL wxLua_REHex_CharacterEncoding_all_encodings(lua_State *L)
{
	auto all_encodings = REHex::CharacterEncoding::all_encodings();
	
	lua_newtable(L);            /* Table to return */
	lua_Integer table_idx = 1;  /* Next index to use in return table */
	
	for(auto e = all_encodings.begin(); e != all_encodings.end(); ++e)
	{
		lua_pushinteger(L, table_idx++);
		wxluaT_pushuserdatatype(L, *e, wxluatype_REHex_CharacterEncoding);
		
		lua_settable(L, -3);
	}
	
	return 1;
}
%end
