/* Reverse Engineer's Hex Editor
 * Copyright (C) 2019-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

struct Cleanup
{
	~Cleanup()
	{
		delete REHex::active_palette;
		delete wxGetApp().recent_files;
		delete wxGetApp().settings;
		delete wxGetApp().config;
		delete wxGetApp().console;
	}
};

int main(int argc, char **argv)
{
	REHex::App *app = new REHex::App();
	
	wxApp::SetInstance(app);
	wxInitializer wxinit;
	
	wxFont default_font(wxFontInfo().Family(wxFONTFAMILY_MODERN));
	
	#ifdef __APPLE__
	/* wxWidgets 3.1 on Mac returns an empty string from wxFont::GetFaceName() at this
	 * point for whatever reason, but it works fine later on....
	*/
	app->set_font_name(default_font.GetNativeFontInfo()->GetFaceName().ToStdString());
	#else
	app->set_font_name(default_font.GetFaceName().ToStdString());
	#endif
	
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
	Cleanup cleanup;
	
	testing::InitGoogleTest(&argc, argv);
	
	app->_test_setup_hooks(REHex::App::SetupPhase::SHUTDOWN_LATE);
	
	return RUN_ALL_TESTS();
}

bool REHex::App::OnInit()
{
	return true;
}

int REHex::App::OnExit()
{
	return 0;
}

int REHex::App::OnRun()
{
	return wxApp::OnRun();
}
