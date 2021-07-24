/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2021 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <stdarg.h>
#include <stdlib.h>
#include <string>
#include <wx/filename.h>
#include <wx/font.h>
#include <wx/stdpaths.h>

#include "App.hpp"
#include "Events.hpp"
#include "mainwindow.hpp"
#include "../res/version.h"

const std::string &REHex::App::get_last_directory()
{
	return last_directory;
}

void REHex::App::set_last_directory(const std::string &last_directory)
{
	this->last_directory = last_directory;
}

int REHex::App::get_font_size_adjustment() const
{
	return font_size_adjustment;
}

void REHex::App::set_font_size_adjustment(int font_size_adjustment)
{
	this->font_size_adjustment = font_size_adjustment;
	
	FontSizeAdjustmentEvent event(font_size_adjustment);
	ProcessEvent(event);
}

std::string REHex::App::get_font_name() const
{
	return font_name;
}

void REHex::App::set_font_name(const std::string &font_name)
{
	wxFont test_font(wxFontInfo().FaceName(wxString(font_name)));
	
	if(test_font.IsFixedWidth())
	{
		this->font_name = font_name;
		
		FontSizeAdjustmentEvent event(font_size_adjustment);
		ProcessEvent(event);
	}
}

std::vector<std::string> REHex::App::get_plugin_directories()
{
	std::vector<std::string> plugin_directories;
	
	const char *REHEX_PLUGIN_DIR = getenv("REHEX_PLUGIN_DIR");
	if(REHEX_PLUGIN_DIR != NULL)
	{
		plugin_directories.push_back(REHEX_PLUGIN_DIR);
	}
	
	#if defined(_WIN32)
		/* Windows. Plugins should be alongside the EXE. */
		wxString exe_path = wxStandardPaths::Get().GetExecutablePath();
		wxFileName exe_wxfn(exe_path);
		
		plugin_directories.push_back((exe_wxfn.GetPathWithSep() + "Plugins\\").ToStdString());
	#elif defined(__APPLE__)
		/* Mac. Plugins should be in the application bundle. */
		std::string exe_path = wxStandardPaths::Get().GetExecutablePath().ToStdString();
		
		const std::string REPLACE      = "Contents/MacOS/REHex";
		const std::string REPLACE_WITH = "Contents/PlugIns/";
		
		if(exe_path.length() > REPLACE.length() && exe_path.substr((exe_path.length() - REPLACE.length())) == REPLACE)
		{
			plugin_directories.push_back(exe_path.substr(0, (exe_path.length() - REPLACE.length())) + REPLACE_WITH);
		}
		else{
			printf_error("Unexpected executable path (%s), bundle plugins will not be loaded\n", exe_path.c_str());
		}
	#else
		/* Assume Linux/UNIX */
		
		const char *XDG_DATA_HOME = getenv("XDG_DATA_HOME");
		if(XDG_DATA_HOME != NULL)
		{
			plugin_directories.push_back(std::string(XDG_DATA_HOME) + "/rehex/plugins/");
		}
		else{
			const char *HOME = getenv("HOME");
			if(HOME != NULL)
			{
				plugin_directories.push_back(std::string(HOME) + "/.local/share/rehex/plugins/");
			}
			else{
				printf_error("Neither $XDG_DATA_HOME nor $HOME is set in the environment, user plugins won't be loaded");
			}
		}
		
		/* If we're running from an AppImage, the APPDIR environment variable tells us
		 * where the squashfs image (e.g. our AppDir) is mounted.
		*/
		
		#ifdef REHEX_APPIMAGE
		const char *APPDIR = getenv("APPDIR");
		if(APPDIR != NULL)
		{
			plugin_directories.push_back(std::string(APPDIR) + "/" + REHEX_LIBDIR + "/rehex/");
		}
		else{
			printf_error("APPDIR environment variable not set, plugins inside the AppImage wont be loaded\n");
		}
		#else
		plugin_directories.push_back(std::string(REHEX_LIBDIR) + "/rehex/");
		#endif
	#endif
	
	return plugin_directories;
}

void REHex::App::print_debug(const std::string &text)
{
	console->print(ConsoleBuffer::Level::DEBUG, text);
}

void REHex::App::printf_debug(const char *fmt, ...)
{
	va_list argv;
	va_start(argv, fmt);
	
	console->vprintf(ConsoleBuffer::Level::DEBUG, fmt, argv);
	
	va_end(argv);
}

void REHex::App::print_info(const std::string &text)
{
	console->print(ConsoleBuffer::Level::INFO, text);
}

void REHex::App::printf_info(const char *fmt, ...)
{
	va_list argv;
	va_start(argv, fmt);
	
	console->vprintf(ConsoleBuffer::Level::INFO, fmt, argv);
	
	va_end(argv);
}

void REHex::App::print_error(const std::string &text)
{
	console->print(ConsoleBuffer::Level::ERROR, text);
}

void REHex::App::printf_error(const char *fmt, ...)
{
	va_list argv;
	va_start(argv, fmt);
	
	console->vprintf(ConsoleBuffer::Level::ERROR, fmt, argv);
	
	va_end(argv);
}

std::multimap<REHex::App::SetupPhase, const REHex::App::SetupHookFunction*> *REHex::App::setup_hooks = NULL;

void REHex::App::register_setup_hook(SetupPhase phase, const SetupHookFunction *func)
{
	if(setup_hooks == NULL)
	{
		setup_hooks = new std::multimap<SetupPhase, const SetupHookFunction*>;
	}
	
	setup_hooks->insert(std::make_pair(phase, func));
}

void REHex::App::unregister_setup_hook(SetupPhase phase, const SetupHookFunction *func)
{
	auto i = std::find_if(
		setup_hooks->begin(), setup_hooks->end(),
		[&](const std::pair<SetupPhase, const SetupHookFunction*> &elem) { return elem.first == phase && elem.second == func; });
	
	setup_hooks->erase(i);
	
	if(setup_hooks->empty())
	{
		delete setup_hooks;
		setup_hooks = NULL;
	}
}

void REHex::App::call_setup_hooks(SetupPhase phase)
{
	if(setup_hooks == NULL)
	{
		/* No hooks registered. */
		return;
	}
	
	for(auto i = setup_hooks->begin(); i != setup_hooks->end(); ++i)
	{
		if(i->first == phase)
		{
			const SetupHookFunction &func = *(i->second);
			func();
		}
	}
}

REHex::App::SetupHookRegistration::SetupHookRegistration(SetupPhase phase, const SetupHookFunction &func):
	phase(phase),
	func(func)
{
	App::register_setup_hook(phase, &(this->func));
}

REHex::App::SetupHookRegistration::~SetupHookRegistration()
{
	App::unregister_setup_hook(phase, &func);
}
