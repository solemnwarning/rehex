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

#include "App.hpp"
#include "lua-bindings/rehex_bind.h"
#include "lua-plugin-preload.h"
#include "LuaPluginLoader.hpp"

REHex::App::SetupHookRegistration REHex::LuaPluginLoader::init_hook(
	REHex::App::SetupPhase::READY,
	&REHex::LuaPluginLoader::OnAppInit);

void REHex::LuaPluginLoader::OnAppInit()
{
	init();
	load_all_plugins();
}

REHex::App::SetupHookRegistration REHex::LuaPluginLoader::shutdown_hook(
	REHex::App::SetupPhase::SHUTDOWN,
	&REHex::LuaPluginLoader::OnAppShutdown);

void REHex::LuaPluginLoader::OnAppShutdown()
{
	unload_all_plugins();
	shutdown();
}

std::unique_ptr<wxEvtHandler> REHex::LuaPluginLoader::default_handler;
std::list<REHex::LuaPlugin> REHex::LuaPluginLoader::loaded_plugins;

void REHex::LuaPluginLoader::init()
{
	if(!default_handler)
	{
		default_handler.reset(new wxEvtHandler);
		
		default_handler->Bind(wxEVT_LUA_ERROR, [&](wxLuaEvent &event)
		{
			wxGetApp().print_error(event.GetString().mb_str().data());
		});
		
		default_handler->Bind(wxEVT_LUA_PRINT, [&](wxLuaEvent &event)
		{
			wxGetApp().print_info(event.GetString().ToStdString() + "\n");
		});
	}
	
	static bool bindings_initialised = false;
	if(!bindings_initialised)
	{
		/* Register wxLua wxWidgets bindings. */
		WXLUA_IMPLEMENT_BIND_WXLUA
		WXLUA_IMPLEMENT_BIND_WXBASE
		WXLUA_IMPLEMENT_BIND_WXCORE
		WXLUA_IMPLEMENT_BIND_WXADV
		WXLUA_IMPLEMENT_BIND_WXAUI
		
		/* Register wxLua REHex bindings. */
		wxLuaBinding_rehex_init();
		
		/* Don't let wxLua do things like printing output or invoking the wxWidgets event loop
		 * before the App::OnInit() method completes.
		*/
		wxLuaState::sm_wxAppMainLoop_will_run = true;
		
		bindings_initialised = true;
	}
}

void REHex::LuaPluginLoader::shutdown()
{
	assert(LuaPlugin::get_num_instances() == 0);
	default_handler.reset(NULL);
}

void REHex::LuaPluginLoader::load_all_plugins()
{
	std::vector<std::string> plugin_directories = wxGetApp().get_plugin_directories();
	
	for(auto pd = plugin_directories.begin(); pd != plugin_directories.end(); ++pd)
	{
		wxDir dir(*pd);
		wxString filename;

		if (!dir.IsOpened())
		{
			continue;
		}
		
		if (dir.GetFirst(&filename, "*.lua", wxDIR_FILES))
		{
			do
			{
				wxFileName file_path(dir.GetName(), filename);
				
				wxGetApp().printf_info("Loading %s\n", file_path.GetFullPath().mb_str().data());
				
				try {
					loaded_plugins.push_back(load_plugin(file_path.GetFullPath().ToStdString()));
					wxGetApp().printf_info("Loaded %s\n", file_path.GetFullPath().mb_str().data());
				}
				catch(const std::exception &e)
				{
					wxGetApp().printf_error("====\nFailed to load plugin %s\n\n%s\n====\n", file_path.GetFullPath().mb_str().data(), e.what());
				}
			} while (dir.GetNext(&filename));
		}
		
		if (dir.GetFirst(&filename, "", wxDIR_DIRS))
		{
			do
			{
				wxFileName file_path(dir.GetName(), "plugin.lua");
				file_path.AppendDir(filename);
				
				if(file_path.Exists(wxFILE_EXISTS_REGULAR))
				{
					wxGetApp().printf_info("Loading %s\n", file_path.GetFullPath().mb_str().data());
					
					try {
						loaded_plugins.push_back(load_plugin(file_path.GetFullPath().ToStdString(), file_path.GetPath().ToStdString()));
						wxGetApp().printf_info("Loaded %s\n", file_path.GetFullPath().mb_str().data());
					}
					catch(const std::exception &e)
					{
						wxGetApp().printf_error("====\nFailed to load plugin %s\n\n%s\n====\n", file_path.GetFullPath().mb_str().data(), e.what());
					}
				}
			} while (dir.GetNext(&filename));
		}
	}
}

void REHex::LuaPluginLoader::unload_all_plugins()
{
	loaded_plugins.clear();
}

REHex::LuaPlugin REHex::LuaPluginLoader::load_plugin(const std::string &filename, const std::string &plugin_dir)
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
	
	if(!plugin_dir.empty())
	{
		s.lua_PushString(plugin_dir.c_str());
		s.lua_SetGlobal("_rehex_plugin_dir");
	}
	
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
	wxGetApp().print_info(output);
	
	return LuaPlugin(s);
}

int REHex::LuaPlugin::num_instances = 0;

REHex::LuaPlugin::LuaPlugin(const wxLuaState &lua):
	lua(lua)
{
	++num_instances;
}

REHex::LuaPlugin::LuaPlugin(const LuaPlugin &src):
	lua(src.lua)
{
	++num_instances;
}

REHex::LuaPlugin::~LuaPlugin()
{
	assert(num_instances > 0);
	--num_instances;
}

int REHex::LuaPlugin::get_num_instances()
{
	return num_instances;
}
