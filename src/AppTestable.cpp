/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2022 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <wx/version.h>

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

#ifdef BUILD_HELP
REHex::HelpController *REHex::App::get_help_controller(wxWindow *error_parent)
{
	if(help_controller == NULL)
	{
		help_controller = new HelpController;
	}
	
	if(help_controller != NULL && !help_loaded)
	{
		#if defined(_WIN32)
		wxString chm_path = wxStandardPaths::Get().GetResourcesDir() + "/rehex.chm";
		
		/* Delete the "Zone.Identifier" NTFS alternate stream if present on the help file.
		 *
		 * The Zone.Identifier stream is added for files that come from an untrusted
		 * source (like the Internet) and causes Windows to restrict access to them. In
		 * particular, the help viewer will display a blank page with no explanation as to
		 * why if this isn't done.
		 *
		 * The "Unblock" tickbox under the file's Properties dialog does the same thing.
		*/
		DeleteFile((chm_path + ":Zone.Identifier").wc_str());
		
		help_loaded = help_controller->Initialize(chm_path);
		
		#elif defined(__APPLE__)
		help_loaded = help_controller->AddBook(wxStandardPaths::Get().GetResourcesDir() + "/rehex.htb", false);
		
		#elif defined(REHEX_APPIMAGE)
		const char *APPDIR = getenv("APPDIR");
		if(APPDIR != NULL)
		{
			help_loaded = help_controller->AddBook(std::string(APPDIR) + "/" + REHEX_DATADIR + "/rehex/rehex.htb");
		}
		
		#else /* Linux/UNIX */
		help_loaded = help_controller->AddBook(std::string(REHEX_DATADIR) + "/rehex/rehex.htb");
		#endif
	}
	
	if(!help_loaded)
	{
		wxMessageBox("Unable to load help file", "Error", wxOK | wxICON_ERROR, error_parent);
		return NULL;
	}
	
	return help_controller;
}

void REHex::App::show_help_contents(wxWindow *error_parent)
{
	HelpController *help = get_help_controller(error_parent);
	if(help)
	{
		#ifndef _WIN32
		wxHtmlHelpWindow *help_window = help_controller->GetHelpWindow();
		#endif
		
		help->DisplayContents();
		
		#ifndef _WIN32
		if(help_window == NULL)
		{
			help_window = help_controller->GetHelpWindow();
			assert(help_window != NULL);
			
			help_window->Bind(wxEVT_HTML_LINK_CLICKED, [&](wxHtmlLinkEvent &event)
			{
				const wxHtmlLinkInfo &linkinfo = event.GetLinkInfo();
				
				if(linkinfo.GetTarget() == "_blank")
				{
					/* External link - display it in the web browser. */
					wxLaunchDefaultBrowser(linkinfo.GetHref());
				}
				else{
					/* Internal link - let the help viewer deal with it. */
					event.Skip();
				}
			});
		}
		#endif
	}
}
#endif

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

static const int FALLBACK_CARET_BLINK = 500;

#if wxCHECK_VERSION(3,1,3)
int REHex::App::get_caret_on_time_ms()
{
	int value = wxSystemSettings::GetMetric(wxSYS_CARET_ON_MSEC);
	if(value >= 0)
	{
		return value;
	}
	else{
		return FALLBACK_CARET_BLINK;
	}
}

int REHex::App::get_caret_off_time_ms()
{
	int value = wxSystemSettings::GetMetric(wxSYS_CARET_OFF_MSEC);
	if(value >= 0)
	{
		return value;
	}
	else{
		return FALLBACK_CARET_BLINK;
	}
}
#elif defined(_WIN32)
int REHex::App::get_caret_on_time_ms()
{
	const UINT blinkTime = ::GetCaretBlinkTime();
	
	if ( blinkTime == 0 ) // error
	{
		return FALLBACK_CARET_BLINK;
	}
	else if ( blinkTime == INFINITE ) // caret does not blink
	{
		return 0;
	}
	else{
		return blinkTime;
	}
}

int REHex::App::get_caret_off_time_ms()
{
	return get_caret_on_time_ms();
}
#elif defined(__WXGTK__)
#include <gtk/gtk.h>

int REHex::App::get_caret_on_time_ms()
{
	gboolean should_blink = true;
	gint blink_time = -1;
	g_object_get(gtk_settings_get_default(),
		"gtk-cursor-blink", &should_blink,
		"gtk-cursor-blink-time", &blink_time,
		NULL);
	
	if(!should_blink)
	{
		return 0;
	}
	else if (blink_time > 0)
	{
		return blink_time / 2;
	}
	else{
		return FALLBACK_CARET_BLINK;
	}
}

int REHex::App::get_caret_off_time_ms()
{
	return get_caret_on_time_ms();
}
#elif defined(__APPLE__) /* Implemented in AppMac.mm */
#else
int REHex::App::get_caret_on_time_ms()
{
	return FALLBACK_CARET_BLINK;
}

int REHex::App::get_caret_off_time_ms()
{
	return FALLBACK_CARET_BLINK;
}
#endif

#ifdef __APPLE__
void REHex::App::MacOpenFiles(const wxArrayString &filenames)
{
	size_t n_files = filenames.GetCount();
	
	for(size_t i = 0; i < n_files; ++i)
	{
		window->open_file(filenames[i].ToStdString());
	}
}
#endif
