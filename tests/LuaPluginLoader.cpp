/* Reverse Engineer's Hex Editor
 * Copyright (C) 2021-2022 Daniel Collins <solemnwarning@solemnwarning.net>
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
	wxTimer timer(&frame, wxID_ANY);
	
	frame.Bind(wxEVT_IDLE, [](wxIdleEvent &event)
	{
		wxTheApp->ExitMainLoop();
	});
	
	frame.Bind(wxEVT_TIMER, [](wxTimerEvent &event)
	{
		wxTheApp->ExitMainLoop();
	});
	
	timer.Start(1000, wxTIMER_ONE_SHOT);
	
	wxTheApp->OnRun();
	
	timer.Stop();
}

class LuaPluginLoaderInitialiser
{
	public:
		LuaPluginLoaderInitialiser()
		{
			LuaPluginLoader::init();
		}
		
		~LuaPluginLoaderInitialiser()
		{
			LuaPluginLoader::shutdown();
		}
};

TEST(LuaPluginLoader, LoadPlugin)
{
	LuaPluginLoaderInitialiser lpl_init;
	
	App &app = wxGetApp();
	app.console->clear();
	
	{
		LuaPlugin p = LuaPluginLoader::load_plugin("tests/stub-plugin.lua");
		
		EXPECT_EQ(app.console->get_messages_text(), "stub plugin loaded\n");
		app.console->clear();
	}
	
	EXPECT_EQ(app.console->get_messages_text(), "stub plugin unloaded\n");
}

TEST(LuaPluginLoader, ErrorPlugin)
{
	LuaPluginLoaderInitialiser lpl_init;
	
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
}

TEST(LuaPluginLoader, ReadData)
{
	LuaPluginLoaderInitialiser lpl_init;
	
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
}

TEST(LuaPluginLoader, ReadDataOffset)
{
	LuaPluginLoaderInitialiser lpl_init;
	
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
}

TEST(LuaPluginLoader, ReadDataLimitLength)
{
	LuaPluginLoaderInitialiser lpl_init;
	
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
}

TEST(LuaPluginLoader, BitOffsetBindings)
{
	LuaPluginLoaderInitialiser lpl_init;
	
	App &app = wxGetApp();
	app.console->clear();
	
	{
		LuaPlugin p = LuaPluginLoader::load_plugin("tests/bitoffset-test.lua");
		
		EXPECT_EQ(app.console->get_messages_text(),
			/* Constructors */
			
			"rehex.BitOffset():byte() = 0\n"
			"rehex.BitOffset():bit() = 0\n"
			
			"rehex.BitOffset(10, 0):byte() = 10\n"
			"rehex.BitOffset(10, 0):bit() = 0\n"
			
			"rehex.BitOffset(10, 2):byte() = 10\n"
			"rehex.BitOffset(10, 2):bit() = 2\n"
			
			/* Accessors */
			
			"rehex.BitOffset(0, 0):total_bits() = 0\n"
			"rehex.BitOffset(10, 0):total_bits() = 80\n"
			"rehex.BitOffset(10, 3):total_bits() = 83\n"
			"rehex.BitOffset(-10, 0):total_bits() = -80\n"
			"rehex.BitOffset(-10, -3):total_bits() = -83\n"
			
			"rehex.BitOffset(0, 0):byte_aligned() = true\n"
			"rehex.BitOffset(10, 0):byte_aligned() = true\n"
			"rehex.BitOffset(10, 3):byte_aligned() = false\n"
			"rehex.BitOffset(-10, 0):byte_aligned() = true\n"
			"rehex.BitOffset(-10, -3):byte_aligned() = false\n"
			
			"rehex.BitOffset(0, 0):byte_round_up() = 0\n"
			"rehex.BitOffset(10, 0):byte_round_up() = 10\n"
			"rehex.BitOffset(10, 3):byte_round_up() = 11\n"
			
			/* Comparison operators */
			
			"rehex.BitOffset(10, 0) == rehex.BitOffset(10, 0) = true\n"
			"rehex.BitOffset(10, 0) ~= rehex.BitOffset(10, 0) = false\n"
			
			"rehex.BitOffset(10, 0) == rehex.BitOffset(20, 0) = false\n"
			"rehex.BitOffset(10, 0) ~= rehex.BitOffset(20, 0) = true\n"
			
			"rehex.BitOffset(10, 0) < rehex.BitOffset(10, 0) = false\n"
			"rehex.BitOffset(10, 0) <= rehex.BitOffset(10, 0) = true\n"
			"rehex.BitOffset(10, 0) > rehex.BitOffset(10, 0) = false\n"
			"rehex.BitOffset(10, 0) >= rehex.BitOffset(10, 0) = true\n"
			
			"rehex.BitOffset(10, 0) < rehex.BitOffset(20, 0) = true\n"
			"rehex.BitOffset(10, 0) <= rehex.BitOffset(20, 0) = true\n"
			"rehex.BitOffset(10, 0) > rehex.BitOffset(20, 0) = false\n"
			"rehex.BitOffset(10, 0) >= rehex.BitOffset(20, 0) = false\n"
			
			/* Binary operators */
			
			"rehex.BitOffset(1, 0) + rehex.BitOffset(1, 0) = { 2, 0 }\n"
			"rehex.BitOffset(1, 2) + rehex.BitOffset(2, 4) = { 3, 6 }\n"
			
			"rehex.BitOffset(1, 0) - rehex.BitOffset(1, 0) = { 0, 0 }\n"
			"rehex.BitOffset(1, 2) - rehex.BitOffset(2, 4) = { -1, -2 }\n"
			
			/* Unary operators */
			
			"-(rehex.BitOffset(0, 0)) = { 0, 0 }\n"
			"-(rehex.BitOffset(10, 0)) = { -10, 0 }\n"
			"-(rehex.BitOffset(10, 7)) = { -10, -7 }\n"
			"-(rehex.BitOffset(-10, -7)) = { 10, 7 }\n"
		);
	}
}
