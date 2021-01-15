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
#include <wx/stdpaths.h>

#include "app.hpp"
#include "ArtProvider.hpp"
#include "Events.hpp"
#include "mainwindow.hpp"
#include "Palette.hpp"
#include "../res/version.h"

/* These MUST come after any wxWidgets headers. */
#ifdef _WIN32
#include <objbase.h>
#endif

IMPLEMENT_APP(REHex::App);

bool REHex::App::OnInit()
{
	locale = new wxLocale(wxLANGUAGE_DEFAULT);
	console = new ConsoleBuffer();
	
	call_setup_hooks(SetupPhase::EARLY);
	
	#ifdef _WIN32
	/* Needed for shell API calls. */
	CoInitialize(NULL);
	#endif
	
	wxImage::AddHandler(new wxPNGHandler);
	
	ArtProvider::init();
	
	config = new wxConfig("REHex");
	
	config->SetPath("/");
	last_directory = config->Read("last-directory", "");
	font_size_adjustment = config->ReadLong("font-size-adjustment", 0);
	
	/* Display default tool panels if a default view hasn't been configured. */
	if(!config->HasGroup("/default-view/"))
	{
		config->SetPath("/default-view/vtools/panels/0/tab/0");
		config->Write("name", "DecodePanel");
		config->Write("selected", true);
		config->Write("big-endian", false);
		
		config->SetPath("/default-view/vtools/panels/0/tab/1");
		config->Write("name", "CommentTree");
		config->Write("selected", false);
	}
	
	recent_files = new wxFileHistory();
	
	config->SetPath("/recent-files/");
	recent_files->Load(*config);
	
	config->SetPath("/");
	
	std::string theme = config->Read("theme", "system").ToStdString();
	if(theme == "light")
	{
		active_palette = Palette::create_light_palette();
	}
	else if(theme == "dark")
	{
		active_palette = Palette::create_dark_palette();
	}
	else /* if(theme == "system") */
	{
		active_palette = Palette::create_system_palette();
	}
	
	call_setup_hooks(SetupPhase::READY);
	
	wxSize windowSize(740, 540);
	
	#ifndef __APPLE__
	config->Read("/default-view/window-width", &windowSize.x, windowSize.x);
	config->Read("/default-view/window-height", &windowSize.y, windowSize.y);
	#endif
	
	REHex::MainWindow *window = new REHex::MainWindow(windowSize);
	
	#ifndef __APPLE__
	bool maximise = config->ReadBool("/default-view/window-maximised", false);
	window->Maximize(maximise);
	#endif
	
	window->Show(true);
	
	if(argc > 1)
	{
		for(int i = 1; i < argc; ++i)
		{
			window->open_file(argv[i].ToStdString());
		}
	}
	else{
		window->new_file();
	}
	
	call_setup_hooks(SetupPhase::DONE);
	
	return true;
}

int REHex::App::OnExit()
{
	call_setup_hooks(SetupPhase::SHUTDOWN);
	
	config->SetPath("/recent-files/");
	recent_files->Save(*config);
	
	config->SetPath("/");
	config->Write("last-directory", wxString(last_directory));
	
	delete active_palette;
	delete recent_files;
	delete config;
	
	#ifdef _WIN32
	CoUninitialize();
	#endif
	
	
	call_setup_hooks(SetupPhase::SHUTDOWN_LATE);
	
	delete console;
	console = NULL;
	
	delete locale;
	locale = NULL;
	
	return 0;
}

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
			plugin_directories.push_back(exe_path.substr((exe_path.length() - REPLACE.length())) + REPLACE_WITH);
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
		
		plugin_directories.push_back(std::string(REHEX_LIBDIR) + "/rehex/");
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
