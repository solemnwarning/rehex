/* Reverse Engineer's Hex Editor
 * Copyright (C) 2021-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "testutil.hpp"

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
		
		char expect[2048] = "Warning: Calling rehex.Document:read_data() with a numeric offset is deprecated\n";
		size_t x = strlen(expect);
		
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

TEST(LuaPluginLoader, SetComment)
{
	LuaPluginLoaderInitialiser lpl_init;
	
	App &app = wxGetApp();
	app.console->clear();
	
	{
		const char *SCRIPT =
			"rehex.OnTabCreated(function(window, tab)\n"
			"	local doc = tab.doc\n"
			"	\n"
			"	doc:set_comment(0, 10, rehex.Comment.new(\"Hello world\"))\n"
			"end);\n";
		
		TempFilename script_file;
		write_file(script_file.tmpfile, std::vector<unsigned char>((unsigned char*)(SCRIPT), (unsigned char*)(SCRIPT) + strlen(SCRIPT)));
		
		LuaPlugin p = LuaPluginLoader::load_plugin(script_file.tmpfile);
		
		MainWindow window(wxDefaultSize);
		Tab *tab = window.open_file("tests/bin-data.bin");
		
		pump_events();
		
		const BitRangeTree<Document::Comment> comments = tab->doc->get_comments();
		
		BitRangeTree<Document::Comment> expected_comments;
		expected_comments.set(BitOffset(0, 0), BitOffset(10, 0), Document::Comment("Hello world"));
		
		EXPECT_EQ(comments, expected_comments);
	}
	
	EXPECT_EQ(app.console->get_messages_text(), "Warning: Calling rehex.Document:set_comment() with a numeric offset/length is deprecated\n");
}

TEST(LuaPluginLoader, SetCommentBitAligned)
{
	LuaPluginLoaderInitialiser lpl_init;
	
	App &app = wxGetApp();
	app.console->clear();
	
	{
		const char *SCRIPT =
			"rehex.OnTabCreated(function(window, tab)\n"
			"	local doc = tab.doc\n"
			"	\n"
			"	doc:set_comment(rehex.BitOffset(0, 4), rehex.BitOffset(10, 2), rehex.Comment.new(\"Hello world\"))\n"
			"end);\n";
		
		TempFilename script_file;
		write_file(script_file.tmpfile, std::vector<unsigned char>((unsigned char*)(SCRIPT), (unsigned char*)(SCRIPT) + strlen(SCRIPT)));
		
		LuaPlugin p = LuaPluginLoader::load_plugin(script_file.tmpfile);
		
		MainWindow window(wxDefaultSize);
		Tab *tab = window.open_file("tests/bin-data.bin");
		
		pump_events();
		
		const BitRangeTree<Document::Comment> comments = tab->doc->get_comments();
		
		BitRangeTree<Document::Comment> expected_comments;
		expected_comments.set(BitOffset(0, 4), BitOffset(10, 2), Document::Comment("Hello world"));
		
		EXPECT_EQ(comments, expected_comments);
	}
	
	EXPECT_EQ(app.console->get_messages_text(), "");
}

TEST(LuaPluginLoader, SetDataType)
{
	LuaPluginLoaderInitialiser lpl_init;
	
	App &app = wxGetApp();
	app.console->clear();
	
	{
		const char *SCRIPT =
			"rehex.OnTabCreated(function(window, tab)\n"
			"	local doc = tab.doc\n"
			"	\n"
			"	doc:set_data_type(0, 2, \"u16le\")\n"
			"end);\n";
		
		TempFilename script_file;
		write_file(script_file.tmpfile, std::vector<unsigned char>((unsigned char*)(SCRIPT), (unsigned char*)(SCRIPT) + strlen(SCRIPT)));
		
		LuaPlugin p = LuaPluginLoader::load_plugin(script_file.tmpfile);
		
		MainWindow window(wxDefaultSize);
		Tab *tab = window.open_file("tests/bin-data.bin");
		
		pump_events();
		
		const BitRangeMap<Document::TypeInfo> types = tab->doc->get_data_types();
		
		BitRangeMap<Document::TypeInfo> expected_types;
		expected_types.set_range(BitOffset(0, 0), BitOffset(2, 0), Document::TypeInfo("u16le", NULL));
		expected_types.set_range(BitOffset(2, 0), BitOffset(510, 0), Document::TypeInfo("", NULL));
		
		EXPECT_EQ(types, expected_types);
	}
	
	EXPECT_EQ(app.console->get_messages_text(), "Warning: Calling rehex.Document:set_data_type() with a numeric offset/length is deprecated\n");
}

TEST(LuaPluginLoader, SetDataTypeBitAligned)
{
	LuaPluginLoaderInitialiser lpl_init;
	
	App &app = wxGetApp();
	app.console->clear();
	
	{
		const char *SCRIPT =
			"rehex.OnTabCreated(function(window, tab)\n"
			"	local doc = tab.doc\n"
			"	\n"
			"	doc:set_data_type(rehex.BitOffset(0, 4), rehex.BitOffset(1, 4), \"bitarray\")\n"
			"end);\n";
		
		TempFilename script_file;
		write_file(script_file.tmpfile, std::vector<unsigned char>((unsigned char*)(SCRIPT), (unsigned char*)(SCRIPT) + strlen(SCRIPT)));
		
		LuaPlugin p = LuaPluginLoader::load_plugin(script_file.tmpfile);
		
		MainWindow window(wxDefaultSize);
		Tab *tab = window.open_file("tests/bin-data.bin");
		
		pump_events();
		
		const BitRangeMap<Document::TypeInfo> types = tab->doc->get_data_types();
		
		BitRangeMap<Document::TypeInfo> expected_types;
		expected_types.set_range(BitOffset(0, 0), BitOffset(0, 4), Document::TypeInfo("", NULL));
		expected_types.set_range(BitOffset(0, 4), BitOffset(1, 4), Document::TypeInfo("bitarray", NULL));
		expected_types.set_range(BitOffset(2, 0), BitOffset(510, 0), Document::TypeInfo("", NULL));
		
		EXPECT_EQ(types, expected_types);
	}
	
	EXPECT_EQ(app.console->get_messages_text(), "");
}