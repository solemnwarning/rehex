#include "platform.hpp"

#include <assert.h>
#include <list>
#include <string>
#include <wx/dir.h>
#include <wx/event.h>
#include <wx/filename.h>

#include <wxlua/wxbind/include/wxadv_bind.h>
#include <wxlua/wxbind/include/wxaui_bind.h>
#include <wxlua/wxbind/include/wxbase_bind.h>
#include <wxlua/wxbind/include/wxbinddefs.h>
#include <wxlua/wxlua.h>

#include "app.hpp"
#include "lua-bindings/rehex_bind.h"
#include "lua-plugin-preload.h"
#include "mainwindow.hpp"

static std::list<wxLuaState> states;

static void load_lua_plugins()
{
	wxDir dir("./");
	wxString filename;
	
	/* Register wxLua wxWidgets bindings. */
	WXLUA_IMPLEMENT_BIND_WXLUA
	WXLUA_IMPLEMENT_BIND_WXBASE
	WXLUA_IMPLEMENT_BIND_WXCORE
	WXLUA_IMPLEMENT_BIND_WXADV
	WXLUA_IMPLEMENT_BIND_WXAUI
	
	/* Register wxLua REHex bindings. */
	wxLuaBinding_rehex_init();
	
	if (dir.GetFirst(&filename, "*.lua", wxDIR_FILES))
	{
		do
		{
			wxFileName file_path(dir.GetName(), filename);
			
			wxEvtHandler *eh = new wxEvtHandler;
			
			eh->Bind(wxEVT_LUA_ERROR, [&](wxLuaEvent &event)
			{
				fprintf(stderr, "wxEVT_LUA_ERROR: %s\n", event.GetString().mb_str().data());
				return;
			});
			
			wxLuaState s(eh);
			
			int run_state = s.RunBuffer((const char*)(LUA_PLUGIN_PRELOAD), sizeof(LUA_PLUGIN_PRELOAD), "lua-plugin-preload.lua");
			if(run_state == 0)
			{
				run_state = s.RunFile(file_path.GetFullPath());
			}
			
			if(run_state == 0)
			{
				states.push_back(s);
			}
			else{
				fprintf(stderr, "Failed to load plugin %s: %s\n",
					filename.mb_str().data(),
					wxlua_LUA_ERR_msg(run_state).mb_str().data());
			}
		} while (dir.GetNext(&filename));
	}
}

static REHex::App::SetupHookRegistration load_lua_plugins_hook(
	REHex::App::SetupPhase::READY,
	&load_lua_plugins);
