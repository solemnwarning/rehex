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

%override wxLua_function__verify_signature
#include <botan/ed25519.h>
#include <botan/hex.h>
#include <botan/pubkey.h>

static int LUACALL wxLua_function__verify_signature(lua_State *L)
{
	if(!(lua_isstring(L, 3)))
	{
		wxlua_argerror(L, 3, wxT("a hex string"));
		return 0;
	}
	
	std::string pubkey_string(lua_tostring(L, 3), lua_strlen(L, 3));

	if(!(lua_isstring(L, 2)))
	{
		wxlua_argerror(L, 2, wxT("a binary string"));
		return 0;
	}

	const uint8_t *signature = (const uint8_t*)(lua_tostring(L, 2));
	size_t signature_len = lua_strlen(L, 2);

	if(!(lua_isstring(L, 1)))
	{
		wxlua_argerror(L, 1, wxT("a binary string"));
		return 0;
	}

	const uint8_t *message = (const uint8_t*)(lua_tostring(L, 1));
	size_t message_len = lua_strlen(L, 1);

	uint8_t pubkey_bin[32];
	try {
		if(pubkey_string.length() != 64 || Botan::hex_decode(pubkey_bin, pubkey_string) != 32)
		{
			luaL_error(L, "Invalid public key");
			return 0;
		}
	}
	catch(const Botan::Exception &e)
	{
		luaL_error(L, "Invalid public key");
		return 0;
	}

	Botan::Ed25519_PublicKey pubkey(pubkey_bin, 32);
	
	Botan::PK_Verifier verifier(pubkey, "Pure");
	bool ok = verifier.verify_message(message, message_len, signature, signature_len);

	lua_pushboolean(L, ok);
	return 1;
}
%end

%override wxLua_function__get_version_info
#include "../../res/version.h"

static int LUACALL wxLua_function__get_version_info(lua_State *L)
{
	lua_pushstring(L, REHEX_VERSION);
	lua_pushstring(L, REHEX_SHORT_VERSION);
	lua_pushstring(L, REHEX_BUILD_DATE);
	return 3;
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
	
	const REHex::BitRangeTree<REHex::Document::Comment> &comments = self->get_comments();
	
	lua_newtable(L);            /* Table to return */
	lua_Integer table_idx = 1;  /* Next index to use in return table */
	
	for(auto c = comments.begin(); c != comments.end(); ++c)
	{
		lua_pushinteger(L, table_idx++);
		
		lua_newtable(L);  /* Table for comment. */
		
		lua_pushstring(L, "offset");
		push_BitOffset(L, c->first.offset);
		lua_settable(L, -3);
		
		lua_pushstring(L, "length");
		push_BitOffset(L, c->first.length);
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

%override wxLua_REHex_Document_set_data_type_bulk
static int LUACALL wxLua_REHex_Document_set_data_type_bulk(lua_State *L)
{
	REHex::Document *self = (REHex::Document *)wxluaT_getuserdatatype(L, 1, wxluatype_REHex_Document);
	
	std::vector< std::tuple<REHex::BitOffset, REHex::BitOffset, REHex::Document::TypeInfo> > *types_cpp
		= new std::vector< std::tuple<REHex::BitOffset, REHex::BitOffset, REHex::Document::TypeInfo> >();
	
	try {
		if(lua_istable(L, 2))
		{
			size_t num_types = lua_objlen(L, 2);
			types_cpp->reserve(num_types);
			
			for(size_t i = 0; i < num_types; ++i)
			{
				/* Get types[i] and push it onto the Lua stack. */
				lua_rawgeti(L, 2, (i + 1));
				
				if(lua_istable(L, -1) && lua_objlen(L, -1) == 5)
				{
					lua_rawgeti(L, -1, 1);
					off_t offset_byte = (off_t)(wxlua_getnumbertype(L, -1));
					lua_pop(L, 1);
					
					lua_rawgeti(L, -1, 2);
					off_t offset_bit = (off_t)(wxlua_getnumbertype(L, -1));
					lua_pop(L, 1);
					
					lua_rawgeti(L, -1, 3);
					off_t length_byte = (off_t)(wxlua_getnumbertype(L, -1));
					lua_pop(L, 1);
					
					lua_rawgeti(L, -1, 4);
					off_t length_bit = (off_t)(wxlua_getnumbertype(L, -1));
					lua_pop(L, 1);
					
					lua_rawgeti(L, -1, 5);
					const wxString type_name = wxlua_getwxStringtype(L, -1);
					lua_pop(L, 1);
					
					types_cpp->emplace_back(
						REHex::BitOffset(offset_byte, offset_bit),
						REHex::BitOffset(length_byte, length_bit),
						REHex::Document::TypeInfo(type_name.ToStdString()));
				}
				else{
					delete types_cpp;
					wxlua_argerror(L, 2, wxT("a table of tables"));
				}
				
				/* Pop types[i] off the Lua stack. */
				lua_pop(L, 1);
			}
		}
		else{
			delete types_cpp;
			wxlua_argerror(L, 2, wxT("a table of tables"));
		}
		
		bool returns = self->set_data_type_bulk(std::move(*types_cpp));
		
		delete types_cpp;
		
		lua_pushboolean(L, returns);
		return 1;
	}
	catch(...) {
		delete types_cpp;
		throw;
	}
}
%end

%override wxLua_REHex_Document_read_data
static int LUACALL wxLua_REHex_Document_read_data(lua_State *L)
{
	REHex::Document *self = (REHex::Document*)(wxluaT_getuserdatatype(L, 1, wxluatype_REHex_Document));
	
	REHex::BitOffset offset = *(REHex::BitOffset*)(wxluaT_getuserdatatype(L, 2, wxluatype_REHex_BitOffset));
	off_t max_length = (off_t)(wxlua_getnumbertype(L, 3));
	
	// TODO: Handle exceptions(?)
	
	std::vector<unsigned char> data = self->read_data(offset, max_length);
	lua_pushlstring(L, (const char*)(data.data()), data.size());
	
	return 1;
}
%end

%override wxLua_REHex_Document_read_data1
static int LUACALL wxLua_REHex_Document_read_data1(lua_State *L)
{
	wxGetApp().print_info("Warning: Calling rehex.Document:read_data() with a numeric offset is deprecated\n");
	
	REHex::Document *self = (REHex::Document*)(wxluaT_getuserdatatype(L, 1, wxluatype_REHex_Document));
	
	off_t offset = (off_t)(wxlua_getnumbertype(L, 2));
	off_t max_length = (off_t)(wxlua_getnumbertype(L, 3));
	
	// TODO: Handle exceptions(?)
	
	std::vector<unsigned char> data = self->read_data(REHex::BitOffset(offset, 0), max_length);
	lua_pushlstring(L, (const char*)(data.data()), data.size());
	
	return 1;
}
%end

%override wxLua_REHex_Document_set_comment1
static int LUACALL wxLua_REHex_Document_set_comment1(lua_State *L)
{
	wxGetApp().print_info("Warning: Calling rehex.Document:set_comment() with a numeric offset/length is deprecated\n");
	
	REHex::Document *self = (REHex::Document *)(wxluaT_getuserdatatype(L, 1, wxluatype_REHex_Document));
	
	const REHex::Document::Comment *comment = (const REHex::Document::Comment*)(wxluaT_getuserdatatype(L, 4, wxluatype_REHex_Document_Comment));
	off_t length = (off_t)(wxlua_getnumbertype(L, 3));
	off_t offset = (off_t)(wxlua_getnumbertype(L, 2));
	
	bool returns = self->set_comment(offset, length, *comment);
	lua_pushboolean(L, returns);
	
	return 1;
}
%end

%override wxLua_REHex_Document_set_comment_bulk
static int LUACALL wxLua_REHex_Document_set_comment_bulk(lua_State *L)
{
	REHex::Document *self = (REHex::Document *)wxluaT_getuserdatatype(L, 1, wxluatype_REHex_Document);
	
	if(lua_istable(L, 2))
	{
		size_t num_comments = lua_objlen(L, 2);
		
		for(size_t i = 0; i < num_comments; ++i)
		{
			/* Get comments[i] and push it onto the Lua stack. */
			lua_rawgeti(L, 2, (i + 1));
			
			if(lua_istable(L, -1) && lua_objlen(L, -1) == 5)
			{
				lua_rawgeti(L, -1, 1);
				off_t offset_byte = (off_t)(wxlua_getnumbertype(L, -1));
				lua_pop(L, 1);
				
				lua_rawgeti(L, -1, 2);
				off_t offset_bit = (off_t)(wxlua_getnumbertype(L, -1));
				lua_pop(L, 1);
				
				lua_rawgeti(L, -1, 3);
				off_t length_byte = (off_t)(wxlua_getnumbertype(L, -1));
				lua_pop(L, 1);
				
				lua_rawgeti(L, -1, 4);
				off_t length_bit = (off_t)(wxlua_getnumbertype(L, -1));
				lua_pop(L, 1);
				
				lua_rawgeti(L, -1, 5);
				const wxString comment_text = wxlua_getwxStringtype(L, -1);
				lua_pop(L, 1);
				
				self->set_comment(
					REHex::BitOffset(offset_byte, offset_bit),
					REHex::BitOffset(length_byte, length_bit),
					REHex::Document::Comment(comment_text));
			}
			else{
				wxlua_argerror(L, 2, wxT("a table of tables"));
			}
			
			/* Pop types[i] off the Lua stack. */
			lua_pop(L, 1);
		}
	}
	else{
		wxlua_argerror(L, 2, wxT("a table of tables"));
	}
	
	return 0;
}
%end

%override wxLua_REHex_Document_set_data_type
static int LUACALL wxLua_REHex_Document_set_data_type(lua_State *L)
{
	REHex::Document *self = (REHex::Document *)wxluaT_getuserdatatype(L, 1, wxluatype_REHex_Document);
	
	REHex::BitOffset offset = *(REHex::BitOffset*)(wxluaT_getuserdatatype(L, 2, wxluatype_REHex_BitOffset));
	REHex::BitOffset length = *(REHex::BitOffset*)(wxluaT_getuserdatatype(L, 3, wxluatype_REHex_BitOffset));
	const wxString type = wxlua_getwxStringtype(L, 4);
	
	bool returns = self->set_data_type(offset, length, type.ToStdString());
	lua_pushboolean(L, returns);
	
	return 1;
}
%end

%override wxLua_REHex_Document_set_data_type1
static int LUACALL wxLua_REHex_Document_set_data_type1(lua_State *L)
{
	wxGetApp().print_info("Warning: Calling rehex.Document:set_data_type() with a numeric offset/length is deprecated\n");
	
	REHex::Document *self = (REHex::Document *)wxluaT_getuserdatatype(L, 1, wxluatype_REHex_Document);
	
	off_t offset = (off_t)(wxlua_getnumbertype(L, 2));
	off_t length = (off_t)(wxlua_getnumbertype(L, 3));
	const wxString type = wxlua_getwxStringtype(L, 4);
	
	bool returns = self->set_data_type(offset, length, type.ToStdString());
	lua_pushboolean(L, returns);
	
	return 1;
}
%end

%override wxLua_REHex_Document_set_highlight
static int LUACALL wxLua_REHex_Document_set_highlight(lua_State *L)
{
	REHex::Document *self = (REHex::Document *)wxluaT_getuserdatatype(L, 1, wxluatype_REHex_Document);
	
	REHex::BitOffset offset = *(REHex::BitOffset*)(wxluaT_getuserdatatype(L, 2, wxluatype_REHex_BitOffset));
	REHex::BitOffset length = *(REHex::BitOffset*)(wxluaT_getuserdatatype(L, 3, wxluatype_REHex_BitOffset));
	int colour = (int)wxlua_getnumbertype(L, 4);
	
	if(colour == -1)
	{
		bool returns = self->erase_highlight(offset, length);
		lua_pushboolean(L, returns);
	}
	else if(colour >= 0)
	{
		bool returns = self->set_highlight(offset, length, colour);
		lua_pushboolean(L, returns);
	}
	else{
		wxlua_argerror(L, 4, wxT("a highlight colour index (or -1)"));
		return 0;
	}
	
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
	
	std::pair<REHex::BitOffset, REHex::BitOffset> selection = self->doc_ctrl->get_selection_linear();
	if(selection.second > REHex::BitOffset::ZERO)
	{
		
		push_BitOffset(L, selection.first);
		push_BitOffset(L, selection.second);
		
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

%override wxLua_REHex_ChecksumGenerator_constructor
static int LUACALL wxLua_REHex_ChecksumGenerator_constructor(lua_State *L)
{
	// const wxString algorithm
	const wxString algorithm = wxlua_getwxStringtype(L, 1);

	const REHex::ChecksumAlgorithm *algo = REHex::ChecksumAlgorithm::by_name(algorithm.ToStdString());
	if(algo == NULL)
	{
		return 0;
	}

	REHex::ChecksumGenerator* generator = algo->factory();

	// add to tracked memory list
	wxluaO_addgcobject(L, generator, wxluatype_REHex_ChecksumGenerator);
	// push the constructed class pointer
	wxluaT_pushuserdatatype(L, generator, wxluatype_REHex_ChecksumGenerator);

	return 1;
}
%end

%override wxLua_REHex_ChecksumGenerator_algorithms
static int LUACALL wxLua_REHex_ChecksumGenerator_algorithms(lua_State *L)
{
	lua_newtable(L);            /* Table to return */
	lua_Integer table_idx = 1;  /* Next index to use in return table */
	
	std::vector<const REHex::ChecksumAlgorithm*> algos = REHex::ChecksumAlgorithm::all_algos();
	
	for(auto it = algos.begin(); it != algos.end(); ++it)
	{
		lua_pushinteger(L, table_idx++);
		
		lua_newtable(L);  /* Table for comment. */
		
		lua_pushstring(L, "name");
		lua_pushstring(L, (*it)->name.c_str());
		lua_settable(L, -3);
		
		lua_pushstring(L, "group");
		lua_pushstring(L, (*it)->group.c_str());
		lua_settable(L, -3);
		
		lua_pushstring(L, "label");
		lua_pushstring(L, (*it)->label.c_str());
		lua_settable(L, -3);
		
		/* Push algo table onto return table */
		lua_settable(L, -3);
	}
	
	return 1;
}
%end

%override wxLua_REHex_ChecksumGenerator_update
static int LUACALL wxLua_REHex_ChecksumGenerator_update(lua_State *L)
{
	REHex::ChecksumGenerator * self = (REHex::ChecksumGenerator *)(wxluaT_getuserdatatype(L, 1, wxluatype_REHex_ChecksumGenerator));

	const char *data = lua_tostring(L, 2);
	size_t len = lua_strlen(L, 2);

    self->add_data(data, len);

    return 0;
}
%end
