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

#include "../src/app.hpp"
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
	}
};

int main(int argc, char **argv)
{
	wxApp::SetInstance(new REHex::App());
	wxInitializer wxinit;
	
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

int REHex::App::get_font_size_adjustment() const
{
	return 0;
}

void REHex::App::set_font_size_adjustment(int font_size_adjustment) {}
