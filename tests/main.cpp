/* Reverse Engineer's Hex Editor
 * Copyright (C) 2019 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <wx/init.h>

#include "../src/App.hpp"
#include "../src/ArtProvider.hpp"
#include "../src/Palette.hpp"

REHex::App &wxGetApp()
{
	return *(REHex::App*)(wxTheApp);
}

struct Cleanup
{
	~Cleanup()
	{
		delete REHex::active_palette;
		delete wxGetApp().recent_files;
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
	app->set_font_name(default_font.GetFaceName().ToStdString());
	
	app->console = new REHex::ConsoleBuffer();
	app->config = new wxConfig("REHex-qwertyuiop"); /* Should be a name that won't load anything. */
	app->recent_files = new wxFileHistory();
	
	wxImage::AddHandler(new wxPNGHandler);
	REHex::ArtProvider::init();
	
	REHex::active_palette = REHex::Palette::create_system_palette();
	Cleanup cleanup;
	
	testing::InitGoogleTest(&argc, argv);
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
