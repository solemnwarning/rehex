/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020 Daniel Collins <solemnwarning@solemnwarning.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "platform.hpp"

#include <assert.h>
#include <exception>
#include <stdexcept>
#include <string>
#include <wx/dir.h>
#include <wx/event.h>
#include <wx/filename.h>

#include <wxbind/include/wxadv_bind.h>
#include <wxbind/include/wxaui_bind.h>
#include <wxbind/include/wxbase_bind.h>
#include <wxbind/include/wxbinddefs.h>
#include <wxlua/wxlua.h>

#include "app.hpp"
#include "lua-bindings/rehex_bind.h"
#include "lua-plugin-preload.h"
#include "LuaPluginLoader.hpp"

static REHex::App::SetupHookRegistration load_lua_plugins_hook(
	REHex::App::SetupPhase::READY,
	&REHex::LuaPluginLoader::load_all_plugins);

std::unique_ptr<wxEvtHandler> REHex::LuaPluginLoader::default_handler;
std::list<REHex::LuaPlugin> REHex::LuaPluginLoader::loaded_plugins;

void REHex::LuaPluginLoader::load_all_plugins()
{
	static bool is_first_call = true;
	assert(is_first_call);
	is_first_call = false;
	
	default_handler.reset(new wxEvtHandler);
	
	default_handler->Bind(wxEVT_LUA_ERROR, [&](wxLuaEvent &event)
	{
		fprintf(stderr, "wxEVT_LUA_ERROR: %s\n", event.GetString().mb_str().data());
	});
	
	default_handler->Bind(wxEVT_LUA_PRINT, [&](wxLuaEvent &event)
	{
		fprintf(stderr, "wxEVT_LUA_PRINT: %s\n", event.GetString().mb_str().data());
	});
	
	/* Register wxLua wxWidgets bindings. */
	WXLUA_IMPLEMENT_BIND_WXLUA
	WXLUA_IMPLEMENT_BIND_WXBASE
	WXLUA_IMPLEMENT_BIND_WXCORE
	WXLUA_IMPLEMENT_BIND_WXADV
	WXLUA_IMPLEMENT_BIND_WXAUI
	
	/* Register wxLua REHex bindings. */
	wxLuaBinding_rehex_init();
	
	std::vector<std::string> plugin_directories = wxGetApp().get_plugin_directories();
	
	for(auto pd = plugin_directories.begin(); pd != plugin_directories.end(); ++pd)
	{
		wxDir dir(*pd);
		wxString filename;
		
		if (dir.GetFirst(&filename, "*.lua", wxDIR_FILES))
		{
			do
			{
				wxFileName file_path(dir.GetName(), filename);
				
				try {
					loaded_plugins.push_back(load_plugin(file_path.GetFullPath().ToStdString()));
				}
				catch(const std::exception &e)
				{
					fprintf(stderr, "====\nFailed to load plugin %s\n\n%s\n====\n", filename.mb_str().data(), e.what());
				}
			} while (dir.GetNext(&filename));
		}
	}
}

REHex::LuaPlugin REHex::LuaPluginLoader::load_plugin(const std::string &filename)
{
	wxEvtHandler local_handler;
	std::string output;
	
	local_handler.Bind(wxEVT_LUA_ERROR, [&](wxLuaEvent &event)
	{
		output += event.GetString().ToStdString() + "\n";
	});
	
	local_handler.Bind(wxEVT_LUA_PRINT, [&](wxLuaEvent &event)
	{
		output += event.GetString().ToStdString() + "\n";
	});
	
	wxLuaState s(&local_handler);
	
	int run_state = s.RunBuffer((const char*)(LUA_PLUGIN_PRELOAD), sizeof(LUA_PLUGIN_PRELOAD), "lua-plugin-preload.lua");
	if(run_state == 0)
	{
		run_state = s.RunFile(filename);
	}
	
	if(run_state != 0)
	{
		throw std::runtime_error(output + wxlua_LUA_ERR_msg(run_state).ToStdString());
	}
	
	s.SetEventHandler(default_handler.get());
	printf("%s", output.c_str());
	
	return LuaPlugin(s);
}

REHex::LuaPlugin::LuaPlugin(const wxLuaState &lua): lua(lua) {}
