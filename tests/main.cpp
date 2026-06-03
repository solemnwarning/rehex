/* Reverse Engineer's Hex Editor
 * Copyright (C) 2019-2026 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "../src/platform.hpp"
#include <gtest/gtest.h>
#include <wx/app.h>
#include <wx/fontutil.h>
#include <wx/init.h>

#include "../src/App.hpp"
#include "../src/ArtProvider.hpp"
#include "../src/Palette.hpp"

REHex::App &wxGetApp()
{
	return *(REHex::App*)(wxTheApp);
}

void REHex::App::_test_setup_hooks(SetupPhase phase)
{
	call_setup_hooks(phase);
}

int main(int argc, char **argv)
{
	REHex::App *app = new REHex::App();
	
	wxApp::SetInstance(app);
	wxInitializer wxinit;
	
	app->bulk_updates_freeze_count = 0;
	app->console = new REHex::ConsoleBuffer();
	app->thread_pool = new REHex::ThreadPool(8);
	app->config = new wxConfig("REHex-qwertyuiop"); /* Should be a name that won't load anything. */
	app->settings = new REHex::AppSettings();
	
	#ifdef __APPLE__
	app->recent_files = new REHex::MacFileHistory();
	#else
	app->recent_files = new wxFileHistory();
	#endif
	
	app->_test_setup_hooks(REHex::App::SetupPhase::EARLY);
	
	wxImage::AddHandler(new wxPNGHandler);
	REHex::ArtProvider::init();
	
	REHex::active_palette = REHex::Palette::create_system_palette();
	
	testing::InitGoogleTest(&argc, argv);
	
	app->_test_setup_hooks(REHex::App::SetupPhase::SHUTDOWN_LATE);
	
	int result = RUN_ALL_TESTS();

	app->CleanUp();
	app->OnExit();
	
	wxApp::SetInstance(NULL);
	delete app;

	return result;
}

bool REHex::App::Initialize(int& argc, wxChar **argv)
{
	return wxApp::Initialize(argc, argv);
}

bool REHex::App::OnInit()
{
	return true;
}

int REHex::App::OnExit()
{
	delete active_palette;
	delete recent_files;
	delete settings;
	delete config;
	delete console;

	return wxApp::OnExit();
}

int REHex::App::OnRun()
{
	return wxApp::OnRun();
}
