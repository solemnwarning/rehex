/* Reverse Engineer's Hex Editor
 * Copyright (C) 2021 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <stdexcept>

#include "../src/App.hpp"
#include "../src/LuaPluginLoader.hpp"
#include "../src/mainwindow.hpp"

using namespace REHex;

static void pump_events()
{
	wxFrame frame(NULL, wxID_ANY, "REHex Tests");
	wxTimer *timer = new wxTimer(&frame, wxID_ANY);
	
	frame.Bind(wxEVT_IDLE, [](wxIdleEvent &event)
	{
		wxTheApp->ExitMainLoop();
	});
	
	frame.Bind(wxEVT_TIMER, [](wxTimerEvent &event)
	{
		wxTheApp->ExitMainLoop();
	});
	
	timer->Start(1000, wxTIMER_ONE_SHOT);
	
	wxTheApp->OnRun();
	
	timer->Stop();
}

TEST(LuaPluginLoader, LoadPlugin)
{
	LuaPluginLoader::init();
	
	App &app = wxGetApp();
	app.console->clear();
	
	{
		LuaPlugin p = LuaPluginLoader::load_plugin("tests/stub-plugin.lua");
		
		EXPECT_EQ(app.console->get_messages_text(), "stub plugin loaded\n");
		app.console->clear();
	}
	
	EXPECT_EQ(app.console->get_messages_text(), "stub plugin unloaded\n");
	
	LuaPluginLoader::shutdown();
}

TEST(LuaPluginLoader, ErrorPlugin)
{
	LuaPluginLoader::init();
	
	App &app = wxGetApp();
	app.console->clear();
	
	EXPECT_THROW(
		{
			try {
				LuaPluginLoader::load_plugin("tests/error-plugin.lua");
			}
			catch(const std::runtime_error &e)
			{
				std::string what = e.what();
				
				EXPECT_NE(what.find("hello"), std::string::npos);
				EXPECT_NE(what.find("oh no"), std::string::npos);
				EXPECT_EQ(what.find("bye"),   std::string::npos);
				
				throw;
			}
		},
		std::runtime_error);
	
	EXPECT_EQ(app.console->get_messages_text(), "");
	
	LuaPluginLoader::shutdown();
}

TEST(LuaPluginLoader, ReadData)
{
	LuaPluginLoader::init();
	
	App &app = wxGetApp();
	app.console->clear();
	
	{
		LuaPlugin p = LuaPluginLoader::load_plugin("tests/read-test-1.lua");
		
		MainWindow window(wxDefaultSize);
		window.open_file("tests/bin-data.bin");
		
		pump_events();
		
		char expect[2048];
		size_t x = 0;
		
		for(unsigned i = 0; i < 256; ++i) { sprintf(expect + x, "%02x\n", i); x += 3; }
		for(unsigned i = 0; i < 256; ++i) { sprintf(expect + x, "%02x\n", i); x += 3; }
		
		EXPECT_EQ(app.console->get_messages_text(), expect);
	}
	
	LuaPluginLoader::shutdown();
}

TEST(LuaPluginLoader, ReadDataOffset)
{
	LuaPluginLoader::init();
	
	App &app = wxGetApp();
	app.console->clear();
	
	{
		LuaPlugin p = LuaPluginLoader::load_plugin("tests/read-test-2.lua");
		
		MainWindow window(wxDefaultSize);
		window.open_file("tests/bin-data.bin");
		
		pump_events();
		
		char expect[2048];
		size_t x = 0;
		
		for(unsigned i = 128; i < 256; ++i) { sprintf(expect + x, "%02x\n", i); x += 3; }
		for(unsigned i = 0; i < 256; ++i) { sprintf(expect + x, "%02x\n", i); x += 3; }
		
		EXPECT_EQ(app.console->get_messages_text(), expect);
	}
	
	LuaPluginLoader::shutdown();
}

TEST(LuaPluginLoader, ReadDataLimitLength)
{
	LuaPluginLoader::init();
	
	App &app = wxGetApp();
	app.console->clear();
	
	{
		LuaPlugin p = LuaPluginLoader::load_plugin("tests/read-test-3.lua");
		
		MainWindow window(wxDefaultSize);
		window.open_file("tests/bin-data.bin");
		
		pump_events();
		
		char expect[2048];
		size_t x = 0;
		
		for(unsigned i = 0; i < 128; ++i) { sprintf(expect + x, "%02x\n", i); x += 3; }
		
		EXPECT_EQ(app.console->get_messages_text(), expect);
	}
	
	LuaPluginLoader::shutdown();
}
