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

#ifndef REHEX_PLUGINLOADER_HPP
#define REHEX_PLUGINLOADER_HPP

#include <list>
#include <memory>
#include <string>
#include <wx/event.h>
#include <wxlua/wxlua.h>

namespace REHex
{
	/**
	 * @brief Handle to a loaded Lua plugin.
	 *
	 * This (copyable, reference-counted) class holds the interpreter state for a loaded Lua
	 * plugin. When the last reference to a plugin is destroyed, the plugin is unloaded.
	 *
	 * Don't construct this directly - use REHex::LuaPluginLoader::load_plugin() instead.
	*/
	class LuaPlugin
	{
		public:
			LuaPlugin(const wxLuaState &lua);
			LuaPlugin(const LuaPlugin &src);
			~LuaPlugin();
			
			/**
			 * @brief Get the number of active instances of this class.
			*/
			static int get_num_instances();
			
		private:
			static int num_instances;
			
			wxLuaState lua;
	};
	
	/**
	 * @brief Static class which handles Lua interpreter initialisation and plugin loading.
	*/
	class LuaPluginLoader
	{
		private:
			static std::unique_ptr<wxEvtHandler> default_handler;
			static std::list<LuaPlugin> loaded_plugins;
			
			static App::SetupHookRegistration init_hook;
			static void OnAppInit();
			
			static App::SetupHookRegistration shutdown_hook;
			static void OnAppShutdown();
			
		public:
			/**
			 * @brief Initialise LuaPluginLoader.
			 *
			 * This method must be called before attempting to load any plugins.
			*/
			static void init();
			
			/**
			 * @brief Shutdown LuaPluginLoader.
			 *
			 * This releases objects created by init(), all plugins MUST be unloaded
			 * before it is called.
			*/
			static void shutdown();
			
			/**
			 * @brief Find and load all plugins.
			*/
			static void load_all_plugins();
			
			/**
			 * @brief Unload plugins loaded by load_all_plugins()
			*/
			static void unload_all_plugins();
			
			/**
			 * @brief Load a Lua plugin from the filesystem.
			 *
			 * @param filename   - Filename of Lua script.
			 * @param plugin_dir - Directory to load extra resources from.
			 *
			 * Loads a Lua plugin. If plugin_dir is provided, it will be added to Lua's module
			 * search path and provided to the script in the rehex.PLUGIN_DIR global.
			*/
			static LuaPlugin load_plugin(const std::string &filename, const std::string &plugin_dir = "");
	};
}

#endif /* !REHEX_PLUGINLOADER_HPP */
