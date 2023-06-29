/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2023 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <string>
#include <vector>
#include <wx/event.h>
#include <wx/filesys.h>
#include <wx/fontutil.h>
#include <wx/fs_zip.h>
#include <wx/log.h>
#include <wx/stdpaths.h>

#include "App.hpp"
#include "ArtProvider.hpp"
#include "DiffWindow.hpp"
#include "IPC.hpp"
#include "mainwindow.hpp"
#include "Palette.hpp"
#include "profile.hpp"
#include "../res/version.h"

/* These MUST come after any wxWidgets headers. */
#ifdef _WIN32
#include <objbase.h>
#endif

IMPLEMENT_APP(REHex::App);

bool REHex::App::OnInit()
{
	bulk_updates_freeze_count = 0;
	quick_exit = false;
	
	#ifdef BUILD_HELP
	help_controller = NULL;
	help_loaded = false;
	#endif
	
	locale = new wxLocale(wxLANGUAGE_DEFAULT);
	console = new ConsoleBuffer();
	thread_pool = new ThreadPool(std::thread::hardware_concurrency());
	
	bool process_switches = true;
	bool compare_mode = false;
	
	std::vector<std::string> open_filenames;
	
	for(int i = 1; i < argc; ++i)
	{
		if(process_switches)
		{
			if(argv[i] == "--")
			{
				process_switches = false;
				continue;
			}
			else if(argv[i] == "--compare")
			{
				if(compare_mode)
				{
					fprintf(stderr, "WARNING: Ignoring duplicate '--compare' switch\n");
				}
				
				compare_mode = true;
				continue;
			}
			else if(argv[i][0] == '-')
			{
				fprintf(stderr, "Unknown command line switch: %s\n", argv[i].ToStdString().c_str());
				fprintf(stderr, "Usage: %s [--compare] [--] [<filename(s)>]\n", argv[0].ToStdString().c_str());
				return false;
			}
		}
		
		/* If the filename ends in .rehex-meta and stripping it off points to an existing
		 * file, then assume they mean to open that file - the meta file being considered
		 * like a "project".
		*/
		
		std::string filename = argv[i].ToStdString();
		std::string meta_extension = ".rehex-meta";
		
		if(filename.length() >= meta_extension.length()
			&& filename.substr(filename.length() - meta_extension.length()) == meta_extension
			&& wxFileExists(filename.substr(0, filename.length() - meta_extension.length())))
		{
			filename = filename.substr(0, filename.length() - meta_extension.length());
		}
		
		open_filenames.push_back(filename);
	}
	
	if(compare_mode && open_filenames.size() < 2)
	{
		fprintf(stderr, "At least two filenames must be given with --compare switch\n");
		fprintf(stderr, "Usage: %s [--compare] [--] [<filename(s)>]\n", argv[0].ToStdString().c_str());
		return false;
	}
	
	bool ipc_params_ok = false;
	std::string ipc_host;
	std::string ipc_service;
	std::string ipc_topic;
	
	try {
		ipc_host      = get_ipc_host();
		ipc_service   = get_ipc_service();
		ipc_topic     = get_ipc_topic();
		ipc_params_ok = true;
	}
	catch(const std::exception &e)
	{
		fprintf(stderr, "Unable to get IPC parameters: %s\n", e.what());
	}
	
	if(ipc_params_ok)
	{
		/* wxDDEClient logs if it can't connect, which comes out as a messagebox. Failing
		 * to connect is normal if we are the first instance of rehex, so just turn off
		 * logging while we try to connect to an existing instance...
		*/
		wxLogNull bequiet;
		
		IPCClient ipc_client;
		
		wxConnectionBase *ipc = ipc_client.MakeConnection(ipc_host, ipc_service, ipc_topic);
		if(ipc != NULL)
		{
			quick_exit = true;
			quick_exit_code = 0;
			
			if(compare_mode)
			{
				std::vector<std::string> command = { "compare" };
				
				for(auto filename = open_filenames.begin(); filename != open_filenames.end(); ++filename)
				{
					command.push_back(*filename);
				}
				
				std::string encoded_command = encode_command(command);
				bool ok = ipc->Execute(encoded_command);
				
				if(!ok)
				{
					quick_exit_code = 1;
				}
			}
			else{
				for(auto filename = open_filenames.begin(); filename != open_filenames.end(); ++filename)
				{
					std::vector<std::string> command = { "open", *filename };
					std::string encoded_command = encode_command(command);
					
					ipc->Execute(encoded_command);
				}
			}
			
			ipc->Disconnect();
			
			return true;
		}
	}
	
	call_setup_hooks(SetupPhase::EARLY);
	
	#ifdef _WIN32
	/* Needed for shell API calls. */
	CoInitialize(NULL);
	#endif
	
	wxImage::AddHandler(new wxPNGHandler);
	wxFileSystem::AddHandler(new wxZipFSHandler);
	
	ArtProvider::init();
	
	config = new wxConfig("REHex");
	config->SetPath("/");
	
	wxConfig::Set(config);
	
	settings = new AppSettings(config);
	
	last_directory = config->Read("last-directory", "");
	font_size_adjustment = config->ReadLong("font-size-adjustment", 0);
	
	{
		wxFont default_font(wxFontInfo().Family(wxFONTFAMILY_MODERN));
		
		#ifdef __APPLE__
		/* wxWidgets 3.1 on Mac returns an empty string from wxFont::GetFaceName() at this
		 * point for whatever reason, but it works fine later on....
		*/
		font_name = default_font.GetNativeFontInfo()->GetFaceName();
		#else
		font_name = default_font.GetFaceName();
		#endif
		
		set_font_name(config->Read("font-name", font_name).ToStdString());
	}
	
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
	
	Bind(EVT_PAGE_DROPPED, &REHex::App::OnTabDropped, this);
	
	call_setup_hooks(SetupPhase::READY);
	
	wxSize windowSize(740, 540);
	
	#ifndef __APPLE__
	config->Read("/default-view/window-width", &windowSize.x, windowSize.x);
	config->Read("/default-view/window-height", &windowSize.y, windowSize.y);
	#endif
	
	window = new REHex::MainWindow(windowSize);
	
	#ifndef __APPLE__
	bool maximise = config->ReadBool("/default-view/window-maximised", false);
	window->Maximize(maximise);
	#endif
	
	if(compare_mode)
	{
		DiffWindow::instance = new DiffWindow(NULL);
		DiffWindow::instance->set_invisible_owner_window(window);
		DiffWindow::instance->Show(true);
	}
	else{
		window->Show();
	}
	
	bool opened_a_file = false;
	
	for(auto filename = open_filenames.begin(); filename != open_filenames.end(); ++filename)
	{
		Tab *tab = window->open_file(*filename);
		if(compare_mode)
		{
			if(tab != NULL)
			{
				DiffWindow::instance->add_range(DiffWindow::Range(tab->doc, tab->doc_ctrl, 0, tab->doc->buffer_length()));
			}
			else{
				/* Failed to open a file with --compare specified. */
				return false;
			}
		}
		
		if(tab != NULL)
		{
			opened_a_file = true;
		}
	}
	
	if(!opened_a_file)
	{
		window->new_file();
	}
	
	if(ipc_params_ok)
	{
		ipc_server = new IPCServer;
		bool ipc_ok = ipc_server->Create(ipc_service);
		
		if(ipc_ok)
		{
			printf_info("IPC service created (%s)\n", ipc_service.c_str());
		}
		else{
			printf_error("Unable to create IPC service (%s)\n", ipc_service.c_str());
			
			delete ipc_server;
			ipc_server = NULL;
		}
	}
	
	#ifdef REHEX_PROFILE
	ProfilingWindow *pw = new ProfilingWindow(window);
	pw->Show();
	#endif
	
	call_setup_hooks(SetupPhase::DONE);
	
	return true;
}

int REHex::App::OnExit()
{
	if(quick_exit)
	{
		return 0;
	}
	
	call_setup_hooks(SetupPhase::SHUTDOWN);
	
	config->SetPath("/recent-files/");
	recent_files->Save(*config);
	
	config->SetPath("/");
	config->Write("last-directory", wxString(last_directory));
	
	settings->write(config);
	
	delete ipc_server;
	delete active_palette;
	#ifdef BUILD_HELP
	delete help_controller;
	#endif
	delete recent_files;
	delete settings;
	
	#ifdef _WIN32
	CoUninitialize();
	#endif
	
	call_setup_hooks(SetupPhase::SHUTDOWN_LATE);
	
	delete thread_pool;
	thread_pool = NULL;
	
	delete console;
	console = NULL;
	
	delete locale;
	locale = NULL;
	
	return 0;
}

int REHex::App::OnRun()
{
	if(quick_exit)
	{
		return quick_exit_code;
	}
	else{
		return wxApp::OnRun();
	}
}

void REHex::App::OnTabDropped(DetachedPageEvent &event)
{
	/* We get triggered by DetachableNotebook when a document tab is detached from a
	 * MainWindow and then dropped elsewhere, wherein we set up a new MainWindow to own it.
	*/
	
	wxPoint mouse_position = wxGetMousePosition();
	
	Tab *tab = dynamic_cast<Tab*>(event.page);
	assert(tab != NULL);
	
	MainWindow *window = new MainWindow(wxDefaultSize);
	window->SetClientSize(tab->GetParent()->GetSize());
	window->SetPosition(mouse_position);
	window->insert_tab(tab, -1);
	window->Show();
}
