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

#include "App.hpp"
#include "ArtProvider.hpp"
#include "mainwindow.hpp"
#include "Palette.hpp"

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
