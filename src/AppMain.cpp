/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2026 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <numeric>
#include <string>
#include <tuple>
#include <vector>
#include <wx/event.h>
#include <wx/filename.h>
#include <wx/filesys.h>
#include <wx/fontutil.h>
#include <wx/fs_zip.h>
#include <wx/log.h>
#include <wx/stdpaths.h>
#include <wx/wfstream.h>

#include "App.hpp"
#include "ArtProvider.hpp"
#include "DataType.hpp"
#include "DiffWindow.hpp"
#include "IPC.hpp"
#include "mainwindow.hpp"
#include "MathUtils.hpp"
#include "Palette.hpp"
#include "profile.hpp"
#include "../res/version.h"

/* These MUST come after any wxWidgets headers. */
#ifdef _WIN32
#include <objbase.h>
#endif

#ifdef __WXGTK__
#include <glib.h>
#endif

IMPLEMENT_APP(REHex::App);

bool REHex::App::Initialize(int& argc, wxChar **argv)
{
	/* We override wxApp::Initialize() and process the --data-types argument here so that it can be
	 * used to build the manual when running 'make' in environments without an X display set up.
	*/

	for(int i = 1; i < argc; ++i)
	{
		if(wxStrcmp(argv[i], "--data-types") == 0)
		{
			if(argc != 2)
			{
				fprintf(stderr, "--data-types cannot be used with any other option\n");
				_Exit(1);
			}

			/* Need to execute setup hooks so that character sets, instruction sets, etc
			 * supported by libraries on the system are probed.
			*/

			call_setup_hooks(SetupPhase::EARLY);

			auto types = DataTypeRegistry::sorted_by_group();

			std::vector<std::string> current_groups;

			for(auto t = types.begin(); t != types.end(); ++t)
			{
				if((*t)->configurable())
				{
					/* Skip over configurable types at this point since they can't be instantiated
					 * without providing configuration and there's no API for plugins to do that.
					*/
					continue;
				}
				
				while(current_groups.size() > (*t)->groups.size() || current_groups != std::vector<std::string>((*t)->groups.begin(), std::next((*t)->groups.begin(), current_groups.size())))
				{
					current_groups.pop_back();
				}

				while(current_groups.size() < (*t)->groups.size())
				{
					current_groups.push_back((*t)->groups[current_groups.size()]);
					printf("%*s* %s\n",
						(int)((current_groups.size() - 1) * 4), "",
						current_groups.back().c_str());
				}

				static constexpr int LABEL_COLUMN = 22;
				int label_pad = std::max((LABEL_COLUMN - (int)((*t)->name.length())), 4);

				printf("%*s* %s%*s%s\n",
					(int)(current_groups.size() * 4), "",
					(*t)->name.c_str(),
					label_pad, "",
					(*t)->label.c_str());
			}

			fflush(stdout);

			call_setup_hooks(SetupPhase::SHUTDOWN_LATE);

			/* Using exit() here results in recursion and a stack overflow when destroying an
			 * apparently-uninitialised static wxMutex (i.e. in global destruction) under RHEL 8...
			 * could be a bug specific to wxWidgets 3.0, or it could just happen to be the previous
			 * contents of memory, so let's just be "safe" and bypass C library cleanup.
			*/
			_Exit(0);
		}
	}

	return wxApp::Initialize(argc, argv);
}

bool REHex::App::OnInit()
{
	#ifdef REHEX_PROFILE
	ProfilingCollector::set_thread_group(ProfilingCollector::ThreadGroup::MAIN);
	#endif
	
	SetAppName("rehex");
	SetAppDisplayName("REHex");
	SetClassName("rehex");

	#ifdef __WXGTK__
	/* Ensure X11 window class is correctly set. */
	g_set_prgname("rehex");
	#endif
	
	bulk_updates_freeze_count = 0;
	quick_exit = false;
	
	#ifdef BUILD_HELP
	help_controller = NULL;
	help_loaded = false;
	#endif
	
	active_palette = Palette::create_light_palette();
	
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
		
		wxFileName filename(argv[i]);
		filename.MakeAbsolute();
		
		/* If the filename ends in .rehex-meta and stripping it off points to an existing
		 * file, then assume they mean to open that file - the meta file being considered
		 * like a "project".
		*/
		
		if(filename.GetExt() == "rehex-meta")
		{
			wxFileName nometa_fn(filename);
			nometa_fn.ClearExt();
			
			if(nometa_fn.FileExists())
			{
				filename = nometa_fn;
			}
		}
		
		open_filenames.push_back(filename.GetFullPath().ToStdString());
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

	if(config->HasEntry("font-name"))
	{
		config->Write("primary-font-name", config->Read("font-name"));
		config->DeleteEntry("font-name");
	}

	if(config->HasEntry("font-size-adjustment"))
	{
		int font_size_adjustment = config->ReadLong("font-size-adjustment", 0);
		float scale = decimal_round(pow(1.2f, font_size_adjustment), 2);

		config->Write("primary-font-scale", scale);
		config->DeleteEntry("font-size-adjustment");
	}
	
	settings = new AppSettings(config);
	
	last_directory = config->Read("last-directory", "");
	
	/* Display default tool panels if a default view hasn't been configured. */
	if(!config->HasGroup("/default-view/"))
	{
		config->SetPath("/default-view/tools/right/0");
		config->Write("name", "DecodePanel");
		config->Write("selected", true);
		config->Write("big-endian", false);
		
		config->SetPath("/default-view/tools/right/1");
		config->Write("name", "CommentTree");
		config->Write("selected", false);
	}
	
	/* Migrate open tools from the saved default view of rehex <0.63.0 */
	
	if(config->HasGroup("/default-view/htools/panels/0"))
	{
		config_copy(config, "/default-view/tools/bottom", *config, "/default-view/htools/panels/0/tab");
		config->DeleteGroup("/default-view/htools/panels/0");
	}
	
	if(config->HasGroup("/default-view/vtools/panels/0"))
	{
		config_copy(config, "/default-view/tools/right", *config, "/default-view/vtools/panels/0/tab");
		config->DeleteGroup("/default-view/vtools/panels/0");
	}
	
	#ifdef __APPLE__
	recent_files = new MacFileHistory();
	#else
	recent_files = new wxFileHistory();
	#endif
	
	config->SetPath("/recent-files/");
	recent_files->Load(*config);
	
	config->SetPath("/");
	
	std::string theme = config->Read("theme", "system").ToStdString();
	if(theme == "light")
	{
		delete active_palette;
		active_palette = Palette::create_light_palette();
	}
	else if(theme == "dark")
	{
		delete active_palette;
		active_palette = Palette::create_dark_palette();
	}
	else /* if(theme == "system") */
	{
		delete active_palette;
		active_palette = Palette::create_system_palette();
	}
	
	{
		wxCommandEvent pc_event(PALETTE_CHANGED);
		ProcessEvent(pc_event);
	}
	
	Bind(EVT_PAGE_DROPPED, &REHex::App::OnTabDropped, this);
	Bind(wxEVT_END_SESSION, &REHex::App::OnEndSession, this);
	
	call_setup_hooks(SetupPhase::READY);

	/* Split out any *.rehex-workspace filenames into a separate list. */

	std::vector<std::string> workspace_filenames;
	std::copy_if(
		open_filenames.begin(), open_filenames.end(), std::back_inserter(workspace_filenames),
		[](const std::string &filename)
		{
			return wxFileName(filename).GetExt().IsSameAs("rehex-workspace", false);
		});

	open_filenames.erase(
		std::remove_if(
			open_filenames.begin(), open_filenames.end(),
			[](const std::string &filename)
			{
				return wxFileName(filename).GetExt().IsSameAs("rehex-workspace", false);
			}),
		open_filenames.end());

	std::vector<MainWindow*> windows;
	std::vector<std::string> missing_files;

	auto load_workspace = [&](const std::string &filename)
	{
		FileReader fr(filename.c_str());

		std::vector<MainWindow*> ws_windows;
		std::vector<std::string> ws_missing_files;

		std::tie(ws_windows, ws_missing_files) = MainWindow::deserialise_windows(&fr);

		windows.insert(windows.end(), ws_windows.begin(), ws_windows.end());
		missing_files.insert(missing_files.end(), ws_missing_files.begin(), ws_missing_files.end());
	};

	wxFileName auto_workspace = get_auto_workspace();
	bool restored_workspace = false;

	if(auto_workspace.FileExists())
	{
		try {
			load_workspace(auto_workspace.GetFullPath().ToStdString());
			unlink(auto_workspace.GetFullPath().mb_str());
		}
		catch(const std::exception &e)
		{
			printf_error("Error restoring session: %s\n", e.what());
		}
	}

	for(auto w = workspace_filenames.begin(); w != workspace_filenames.end(); ++w)
	{
		try {
			load_workspace(*w);
		}
		catch(const std::exception &e)
		{
			wxMessageBox(
				std::string("Error loading workspace ") + *w + ": " + e.what(),
				"Error", wxICON_ERROR, NULL);
		}
	}

	for(auto i = windows.begin(); i != windows.end(); ++i)
	{
		(*i)->Show();
		restored_workspace = true;
	}

	if(!(missing_files.empty()))
	{
		std::string message = std::accumulate<std::vector<std::string>::iterator, std::string>(
			missing_files.begin(), missing_files.end(),
			"Unable to re-open the following files:\n",
			[](const std::string &a, const std::string &b)
			{
				return a + "\n" + b;
			});

		wxMessageBox(message, "Error", wxICON_ERROR, (windows.empty() ? NULL : windows.back()));
	}
	
	if(!restored_workspace || !(open_filenames.empty()))
	{
		wxSize windowSize = MainWindow::DEFAULT_SIZE;
		
		#ifndef __APPLE__
		config->Read("/default-view/window-width", &windowSize.x, windowSize.x);
		config->Read("/default-view/window-height", &windowSize.y, windowSize.y);
		#endif
		
		window = new REHex::MainWindow(wxDefaultPosition, windowSize);
		
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
			Tab *tab = window->open_file(wxFileName(*filename));
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
	config->Flush();
	
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
	
	MainWindow *window = new MainWindow(wxDefaultPosition, wxDefaultSize);
	window->SetClientSize(tab->GetParent()->GetSize());
	window->SetPosition(mouse_position);
	window->insert_tab(tab, -1);
	window->Show();
}

void REHex::App::OnEndSession(wxCloseEvent &event)
{
	std::list<MainWindow*> all_windows = MainWindow::get_instances();

	wxFileName workspace_path = get_auto_workspace();

	if(wxFileName::Mkdir(workspace_path.GetPath(), wxS_DIR_DEFAULT, wxPATH_MKDIR_FULL))
	{
		try {
			FileWriter workspace(workspace_path.GetFullPath().mb_str());
			MainWindow::serialise_windows(std::vector<MainWindow*>(all_windows.begin(), all_windows.end()), true, &workspace);

			workspace.commit();
		}
		catch(const std::exception &e)
		{
			printf_error("Error saving session: %s\n", e.what());
		}
	}

	for(auto w = all_windows.begin(); w != all_windows.end(); ++w)
	{
		(*w)->Destroy();
	}
	
	event.Skip();
}
