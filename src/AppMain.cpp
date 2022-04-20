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

#include <string>
#include <vector>
#include <wx/event.h>
#include <wx/filesys.h>
#include <wx/fontutil.h>
#include <wx/fs_zip.h>
#include <wx/stdpaths.h>

#include "App.hpp"
#include "ArtProvider.hpp"
#include "DiffWindow.hpp"
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
	help_controller = NULL;
	help_loaded = false;
	
	locale = new wxLocale(wxLANGUAGE_DEFAULT);
	console = new ConsoleBuffer();
	
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
		
		open_filenames.push_back(argv[i].ToStdString());
	}
	
	if(compare_mode && open_filenames.size() < 2)
	{
		fprintf(stderr, "At least two filenames must be given with --compare switch\n");
		fprintf(stderr, "Usage: %s [--compare] [--] [<filename(s)>]\n", argv[0].ToStdString().c_str());
		return false;
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
		DiffWindow::instance->Show(true);
		
		/* Special hacky handlers to deal with DiffWindow being the only visible window...
		 * see the comments in them.
		*/
		window->Bind(wxEVT_SHOW, &REHex::App::OnMainWindowShow, this);
		DiffWindow::instance->Bind(wxEVT_CLOSE_WINDOW, &REHex::App::OnDiffWindowClose, this);
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
	delete help_controller;
	delete recent_files;
	delete settings;
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

void REHex::App::OnMainWindowShow(wxShowEvent &event)
{
	/* This handler gets called if the MainWindow is shown because of an action in the
	 * DiffWindow when the --compare switch was used.
	 *
	 * We remove our hacky handlers and let things go as normal now.
	*/
	
	if(event.IsShown())
	{
		DiffWindow::instance->Unbind(wxEVT_CLOSE_WINDOW, &REHex::App::OnDiffWindowClose, this);
		window->Unbind(wxEVT_SHOW, &REHex::App::OnMainWindowShow, this);
	}
	
	event.Skip();
}

void REHex::App::OnDiffWindowClose(wxCloseEvent &event)
{
	/* This handler gets called if the DiffWindow created as the sole visible top-level window
	 * when using the --compare switch was closed. We destroy the (invisible) MainWindow so the
	 * program will exit.
	*/
	
	if(event.GetEventObject() == DiffWindow::instance)
	{
		window->Destroy();
		event.Skip();
	}
}
