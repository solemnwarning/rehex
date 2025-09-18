/* Reverse Engineer's Hex Editor
 * Copyright (C) 2021-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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
	AutoFrame frame(NULL, wxID_ANY, "REHex Tests");
	wxTimer timer(frame, wxID_ANY);
	
	frame->Bind(wxEVT_IDLE, [](wxIdleEvent &event)
	{
		wxTheApp->ExitMainLoop();
	});
	
	frame->Bind(wxEVT_TIMER, [](wxTimerEvent &event)
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
		
		for(unsigned i = 0; i < 256; ++i) { snprintf((expect + x), (sizeof(expect) - x), "%02x\n", i); x += 3; }
		for(unsigned i = 0; i < 256; ++i) { snprintf((expect + x), (sizeof(expect) - x), "%02x\n", i); x += 3; }
		
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
		
		for(unsigned i = 128; i < 256; ++i) { snprintf((expect + x), (sizeof(expect) - x), "%02x\n", i); x += 3; }
		for(unsigned i = 0; i < 256; ++i) { snprintf((expect + x), (sizeof(expect) - x), "%02x\n", i); x += 3; }
		
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
		
		for(unsigned i = 0; i < 128; ++i) { snprintf((expect + x), (sizeof(expect) - x), "%02x\n", i); x += 3; }
		
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

TEST(LuaPluginLoader, SetCommentBulk)
{
	LuaPluginLoaderInitialiser lpl_init;
	
	App &app = wxGetApp();
	app.console->clear();
	
	{
		const char *SCRIPT =
			"rehex.OnTabCreated(function(window, tab)\n"
			"	local doc = tab.doc\n"
			"	\n"
			"	doc:set_comment_bulk({\n"
			"		{ 0, 0, 0, 0, \"fear\" },\n"
			"		{ 2, 0, 8, 0, \"home\" },\n"
			"	})\n"
			"end);\n";
		
		TempFilename script_file;
		write_file(script_file.tmpfile, std::vector<unsigned char>((unsigned char*)(SCRIPT), (unsigned char*)(SCRIPT) + strlen(SCRIPT)));
		
		LuaPlugin p = LuaPluginLoader::load_plugin(script_file.tmpfile);
		
		MainWindow window(wxDefaultSize);
		Tab *tab = window.open_file("tests/bin-data.bin");
		
		pump_events();
		
		const BitRangeTree<Document::Comment> comments = tab->doc->get_comments();
		
		BitRangeTree<Document::Comment> expected_comments;
		expected_comments.set(BitOffset(0, 0), BitOffset(0, 0), Document::Comment("fear"));
		expected_comments.set(BitOffset(2, 0), BitOffset(8, 0), Document::Comment("home"));
		
		EXPECT_EQ(comments, expected_comments);
	}
	
	EXPECT_EQ(app.console->get_messages_text(), "");
}

TEST(LuaPluginLoader, SetCommentBulkBitAligned)
{
	LuaPluginLoaderInitialiser lpl_init;
	
	App &app = wxGetApp();
	app.console->clear();
	
	{
		const char *SCRIPT =
			"rehex.OnTabCreated(function(window, tab)\n"
			"	local doc = tab.doc\n"
			"	\n"
			"	doc:set_comment_bulk({\n"
			"		{ 0, 4, 0, 0, \"sticks\" },\n"
			"		{ 2, 2, 8, 6, \"billowy\" },\n"
			"	})\n"
			"end);\n";
		
		TempFilename script_file;
		write_file(script_file.tmpfile, std::vector<unsigned char>((unsigned char*)(SCRIPT), (unsigned char*)(SCRIPT) + strlen(SCRIPT)));
		
		LuaPlugin p = LuaPluginLoader::load_plugin(script_file.tmpfile);
		
		MainWindow window(wxDefaultSize);
		Tab *tab = window.open_file("tests/bin-data.bin");
		
		pump_events();
		
		const BitRangeTree<Document::Comment> comments = tab->doc->get_comments();
		
		BitRangeTree<Document::Comment> expected_comments;
		expected_comments.set(BitOffset(0, 4), BitOffset(0, 0), Document::Comment("sticks"));
		expected_comments.set(BitOffset(2, 2), BitOffset(8, 6), Document::Comment("billowy"));
		
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

TEST(LuaPluginLoader, SetDataTypeBulk)
{
	LuaPluginLoaderInitialiser lpl_init;
	
	App &app = wxGetApp();
	app.console->clear();
	
	{
		const char *SCRIPT =
			"rehex.OnTabCreated(function(window, tab)\n"
			"	local doc = tab.doc\n"
			"	\n"
			"	doc:set_data_type_bulk({\n"
			"		{ 0, 0,  2, 0, \"u16le\" },\n"
			"		{ 2, 0, 12, 0, \"u32le\" },\n"
			"	})\n"
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
		expected_types.set_range(BitOffset(2, 0), BitOffset(12, 0), Document::TypeInfo("u32le", NULL));
		expected_types.set_range(BitOffset(14, 0), BitOffset(498, 0), Document::TypeInfo("", NULL));
		
		EXPECT_EQ(types, expected_types);
	}
	
	EXPECT_EQ(app.console->get_messages_text(), "");
}

TEST(LuaPluginLoader, SetDataTypeBulkBitAligned)
{
	LuaPluginLoaderInitialiser lpl_init;
	
	App &app = wxGetApp();
	app.console->clear();
	
	{
		const char *SCRIPT =
			"rehex.OnTabCreated(function(window, tab)\n"
			"	local doc = tab.doc\n"
			"	\n"
			"	doc:set_data_type_bulk({\n"
			"		{ 0, 4,  2, 2, \"bitarray\" },\n"
			"		{ 3, 6, 12, 0, \"u32le\" },\n"
			"	})\n"
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
		expected_types.set_range(BitOffset(0, 4), BitOffset(2, 2), Document::TypeInfo("bitarray", NULL));
		expected_types.set_range(BitOffset(2, 6), BitOffset(1, 0), Document::TypeInfo("", NULL));
		expected_types.set_range(BitOffset(3, 6), BitOffset(12, 0), Document::TypeInfo("u32le", NULL));
		expected_types.set_range(BitOffset(15, 6), BitOffset(496, 2), Document::TypeInfo("", NULL));
		
		EXPECT_EQ(types, expected_types);
	}
	
	EXPECT_EQ(app.console->get_messages_text(), "");
}

#ifndef __SANITIZE_ADDRESS__
TEST(LuaPluginLoader, SetDataTypeBulkNotTable)
{
	LuaPluginLoaderInitialiser lpl_init;
	
	App &app = wxGetApp();
	app.console->clear();
	
	{
		const char *SCRIPT =
			"rehex.OnTabCreated(function(window, tab)\n"
			"	local doc = tab.doc\n"
			"	\n"
			"	doc:set_data_type_bulk(1234)\n"
			"end);\n";
		
		TempFilename script_file;
		write_file(script_file.tmpfile, std::vector<unsigned char>((unsigned char*)(SCRIPT), (unsigned char*)(SCRIPT) + strlen(SCRIPT)));
		
		LuaPlugin p = LuaPluginLoader::load_plugin(script_file.tmpfile);
		
		MainWindow window(wxDefaultSize);
		Tab *tab = window.open_file("tests/bin-data.bin");
		
		pump_events();
		
		const BitRangeMap<Document::TypeInfo> types = tab->doc->get_data_types();
		
		BitRangeMap<Document::TypeInfo> expected_types;
		expected_types.set_range(BitOffset(0, 0), BitOffset(512, 0), Document::TypeInfo("", NULL));
		
		EXPECT_EQ(types, expected_types);
	}
	
	EXPECT_NE(app.console->get_messages_text().find("wxLua: Expected a table of tables for parameter 2"), std::string::npos);
}

TEST(LuaPluginLoader, SetDataTypeBulkNotInnerTable)
{
	LuaPluginLoaderInitialiser lpl_init;
	
	App &app = wxGetApp();
	app.console->clear();
	
	{
		const char *SCRIPT =
			"rehex.OnTabCreated(function(window, tab)\n"
			"	local doc = tab.doc\n"
			"	\n"
			"	doc:set_data_type_bulk({ 1234 })\n"
			"end);\n";
		
		TempFilename script_file;
		write_file(script_file.tmpfile, std::vector<unsigned char>((unsigned char*)(SCRIPT), (unsigned char*)(SCRIPT) + strlen(SCRIPT)));
		
		LuaPlugin p = LuaPluginLoader::load_plugin(script_file.tmpfile);
		
		MainWindow window(wxDefaultSize);
		Tab *tab = window.open_file("tests/bin-data.bin");
		
		pump_events();
		
		const BitRangeMap<Document::TypeInfo> types = tab->doc->get_data_types();
		
		BitRangeMap<Document::TypeInfo> expected_types;
		expected_types.set_range(BitOffset(0, 0), BitOffset(512, 0), Document::TypeInfo("", NULL));
		
		EXPECT_EQ(types, expected_types);
	}
	
	EXPECT_NE(app.console->get_messages_text().find("wxLua: Expected a table of tables for parameter 2"), std::string::npos);
}

TEST(LuaPluginLoader, SetDataTypeBulkBadOffset)
{
	LuaPluginLoaderInitialiser lpl_init;
	
	App &app = wxGetApp();
	app.console->clear();
	
	{
		const char *SCRIPT =
			"rehex.OnTabCreated(function(window, tab)\n"
			"	local doc = tab.doc\n"
			"	\n"
			"	doc:set_data_type_bulk({\n"
			"		{ 0, 4,  2, 2, \"bitarray\" },\n"
			"		{ \"potato\", 6, 12, 0, \"u32le\" },\n"
			"	})\n"
			"end);\n";
		
		TempFilename script_file;
		write_file(script_file.tmpfile, std::vector<unsigned char>((unsigned char*)(SCRIPT), (unsigned char*)(SCRIPT) + strlen(SCRIPT)));
		
		LuaPlugin p = LuaPluginLoader::load_plugin(script_file.tmpfile);
		
		MainWindow window(wxDefaultSize);
		Tab *tab = window.open_file("tests/bin-data.bin");
		
		pump_events();
		
		const BitRangeMap<Document::TypeInfo> types = tab->doc->get_data_types();
		
		BitRangeMap<Document::TypeInfo> expected_types;
		expected_types.set_range(BitOffset(0, 0), BitOffset(512, 0), Document::TypeInfo("", NULL));
		
		EXPECT_EQ(types, expected_types);
	}
	
	EXPECT_NE(app.console->get_messages_text().find("wxLua: Expected a 'number' for parameter"), std::string::npos);
}

TEST(LuaPluginLoader, SetDataTypeBulkMissingParameter)
{
	LuaPluginLoaderInitialiser lpl_init;
	
	App &app = wxGetApp();
	app.console->clear();
	
	{
		const char *SCRIPT =
			"rehex.OnTabCreated(function(window, tab)\n"
			"	local doc = tab.doc\n"
			"	\n"
			"	doc:set_data_type_bulk({\n"
			"		{ 0, 4,  2, 2, \"bitarray\" },\n"
			"		{ 10, 6, 12, 0 },\n"
			"	})\n"
			"end);\n";
		
		TempFilename script_file;
		write_file(script_file.tmpfile, std::vector<unsigned char>((unsigned char*)(SCRIPT), (unsigned char*)(SCRIPT) + strlen(SCRIPT)));
		
		LuaPlugin p = LuaPluginLoader::load_plugin(script_file.tmpfile);
		
		MainWindow window(wxDefaultSize);
		Tab *tab = window.open_file("tests/bin-data.bin");
		
		pump_events();
		
		const BitRangeMap<Document::TypeInfo> types = tab->doc->get_data_types();
		
		BitRangeMap<Document::TypeInfo> expected_types;
		expected_types.set_range(BitOffset(0, 0), BitOffset(512, 0), Document::TypeInfo("", NULL));
		
		EXPECT_EQ(types, expected_types);
	}
	
	EXPECT_NE(app.console->get_messages_text().find("wxLua: Expected a table of tables for parameter 2"), std::string::npos);
}
#endif

/* Test key #1:
 *
 * -----BEGIN PRIVATE KEY-----
 * MC4CAQAwBQYDK2VwBCIEIKQeiyDyz4VwmJkWYlHgFMmr1/AZT5sCB1dxi6swrv2b
 * -----END PRIVATE KEY-----
 * ED25519 Private-Key:
 * priv:
 *     a4:1e:8b:20:f2:cf:85:70:98:99:16:62:51:e0:14:
 *     c9:ab:d7:f0:19:4f:9b:02:07:57:71:8b:ab:30:ae:
 *     fd:9b
 * pub:
 *     96:79:8e:fc:7b:04:03:c0:f0:15:9d:d9:d4:59:f7:
 *     0c:c2:92:7f:1c:c1:3d:0d:ec:5a:cb:65:db:5e:a1:
 *     8c:e9
 *
 * Test key #2:
 *
 * -----BEGIN PRIVATE KEY-----
 * MC4CAQAwBQYDK2VwBCIEIDLPbYJLZNTVUZM1U2BS4Usm8/KxNqE5iAE+yUEZV35F
 * -----END PRIVATE KEY-----
 * ED25519 Private-Key:
 * priv:
 *     32:cf:6d:82:4b:64:d4:d5:51:93:35:53:60:52:e1:
 *     4b:26:f3:f2:b1:36:a1:39:88:01:3e:c9:41:19:57:
 *     7e:45
 * pub:
 *     0d:93:ff:7c:92:48:ec:19:5e:52:38:55:c8:d8:3f:
 *     21:46:8f:af:e6:e8:c9:a5:a1:8f:bc:3a:23:f8:28:
 *     f4:18
*/

#define PUBKEY1 "96798efc7b0403c0f0159dd9d459f70cc2927f1cc13d0dec5acb65db5ea18ce9"
#define PUBKEY2 "0d93ff7c9248ec195e523855c8d83f21468fafe6e8c9a5a18fbc3a23f828f418"

/* Test message #1 and signature for each key. */
#define MSG1 "\\135\\8\\135\\240\\218\\60\\46\\189\\231\\175\\70\\92\\85\\178\\187\\121\\33\\135\\57\\224\\171\\116\\105\\94\\101\\230\\143\\151\\58\\56\\45\\247\\57\\144\\104\\59\\147\\164\\151\\199\\100\\121\\216\\137\\122\\0\\42\\217\\135\\86\\22\\230\\184\\82\\4\\121\\219\\122\\101\\137\\93\\240\\169\\167\\126\\29\\106\\93\\34\\90\\207\\255\\140\\96\\9\\40\\62\\240\\250\\100\\240\\13\\252\\22\\252\\217\\168\\40\\206\\74\\51\\240\\253\\248\\91\\145\\171\\147\\52\\105\\168\\51\\38\\163\\154\\103\\125\\60\\200\\82\\60\\232\\202\\82\\201\\185\\34\\60\\179\\164\\246\\129\\160\\16\\172\\87\\41\\243"
#define MSG1_SIG1 "\\143\\65\\16\\35\\5\\15\\56\\84\\191\\111\\20\\124\\131\\17\\133\\28\\197\\130\\35\\229\\34\\17\\123\\219\\211\\109\\207\\1\\209\\141\\247\\37\\231\\33\\156\\191\\73\\11\\84\\190\\240\\185\\15\\150\\152\\144\\45\\220\\160\\236\\240\\92\\65\\145\\96\\39\\26\\224\\46\\90\\197\\50\\129\\11"
#define MSG1_SIG2 "\\74\\181\\194\\119\\32\\58\\233\\91\\22\\115\\162\\108\\177\\61\\175\\108\\46\\52\\27\\255\\208\\65\\129\\64\\39\\164\\27\\228\\248\\185\\21\\16\\193\\211\\102\\191\\116\\235\\16\\175\\94\\54\\228\\149\\163\\93\\118\\151\\99\\148\\159\\215\\200\\154\\80\\84\\131\\223\\45\\133\\155\\183\\33\\3"

/* Test message #2 and signature for each key. */
#define MSG2 "\\92\\195\\38\\106\\114\\189\\123\\15\\74\\166\\210\\17\\186\\216\\33\\118\\134\\46\\128\\42\\255\\201\\120\\46\\155\\51\\184\\80\\217\\148\\248\\100\\85\\199\\90\\221\\157\\172\\74\\175\\255\\51\\19\\104\\165\\176\\166\\95\\133\\163\\22\\82\\25\\23\\91\\82\\107\\224\\70\\127\\124\\196\\47\\120\\211\\52\\97\\62\\253\\218\\203\\72\\30\\162\\237\\163\\86\\198\\50\\167\\15\\34\\245\\10\\185\\196\\118\\211\\177\\53\\246\\93\\136\\192\\253\\28\\80\\204\\125\\117\\122\\185\\127\\237\\25\\182\\66\\208\\82\\247\\226\\4\\114\\236\\84\\161\\9\\74\\248\\226\\68\\100\\68\\218\\189\\162\\195\\211"
#define MSG2_SIG1 "\\5\\227\\208\\188\\94\\87\\39\\130\\191\\216\\79\\189\\134\\247\\15\\201\\136\\161\\201\\244\\154\\152\\139\\176\\6\\35\\45\\212\\32\\140\\107\\231\\30\\93\\41\\136\\123\\117\\67\\27\\238\\233\\204\\208\\184\\173\\57\\19\\185\\192\\174\\227\\96\\246\\196\\93\\68\\122\\151\\158\\99\\60\\17\\6"
#define MSG2_SIG2 "\\13\\95\\18\\131\\27\\28\\247\\15\\60\\119\\102\\166\\57\\41\\199\\156\\145\\116\\163\\67\\50\\117\\134\\25\\152\\183\\133\\172\\170\\45\\195\\201\\254\\179\\118\\28\\232\\11\\162\\68\\34\\222\\15\\46\\243\\191\\253\\64\\3\\231\\205\\9\\198\\89\\207\\223\\95\\26\\215\\85\\144\\32\\42\\10"

/* Test messages with bytes swapped. */
#define BADMSG1 "\\135\\8\\240\\135\\218\\60\\46\\189\\231\\175\\70\\92\\85\\178\\187\\121\\33\\135\\57\\224\\171\\116\\105\\94\\101\\230\\143\\151\\58\\56\\45\\247\\57\\144\\104\\59\\147\\164\\151\\199\\100\\121\\216\\137\\122\\0\\42\\217\\135\\86\\22\\230\\184\\82\\4\\121\\219\\122\\101\\137\\93\\240\\169\\167\\126\\29\\106\\93\\34\\90\\207\\255\\140\\96\\9\\40\\62\\240\\250\\100\\240\\13\\252\\22\\252\\217\\168\\40\\206\\74\\51\\240\\253\\248\\91\\145\\171\\147\\52\\105\\168\\51\\38\\163\\154\\103\\125\\60\\200\\82\\60\\232\\202\\82\\201\\185\\34\\60\\179\\164\\246\\129\\160\\16\\172\\87\\41\\243"
#define BADMSG2 "\\92\\195\\38\\106\\114\\189\\123\\74\\15\\166\\210\\17\\186\\216\\33\\118\\134\\46\\128\\42\\255\\201\\120\\46\\155\\51\\184\\80\\217\\148\\248\\100\\85\\199\\90\\221\\157\\172\\74\\175\\255\\51\\19\\104\\165\\176\\166\\95\\133\\163\\22\\82\\25\\23\\91\\82\\107\\224\\70\\127\\124\\196\\47\\120\\211\\52\\97\\62\\253\\218\\203\\72\\30\\162\\237\\163\\86\\198\\50\\167\\15\\34\\245\\10\\185\\196\\118\\211\\177\\53\\246\\93\\136\\192\\253\\28\\80\\204\\125\\117\\122\\185\\127\\237\\25\\182\\66\\208\\82\\247\\226\\4\\114\\236\\84\\161\\9\\74\\248\\226\\68\\100\\68\\218\\189\\162\\195\\211"

TEST(LuaPluginLoader, VerifySignature)
{
	auto try_verify = [](const char *msg, const char *sig, const char *pubkey)
	{
		LuaPluginLoaderInitialiser lpl_init;
		
		App &app = wxGetApp();
		app.console->clear();
		
		{
			std::string SCRIPT =
				std::string("")
				+ "if rehex._verify_signature(\"" + msg + "\", \"" + sig + "\", \"" + pubkey + "\")\n"
				+ "then\n"
				+ "    print(\"Signature OK\")\n"
				+ "else\n"
				+ "    print(\"Signature verification failed\")\n"
				+ "end\n";
			
			TempFile script_file(SCRIPT);
			
			LuaPlugin p = LuaPluginLoader::load_plugin(script_file.tmpfile);
			pump_events();
		}

		return app.console->get_messages_text();
	};

	EXPECT_EQ(try_verify(MSG1, MSG1_SIG1, PUBKEY1), "Signature OK\n");
	EXPECT_EQ(try_verify(MSG1, MSG1_SIG2, PUBKEY2), "Signature OK\n");
	EXPECT_EQ(try_verify(MSG2, MSG2_SIG1, PUBKEY1), "Signature OK\n");
	EXPECT_EQ(try_verify(MSG2, MSG2_SIG2, PUBKEY2), "Signature OK\n");

	EXPECT_EQ(try_verify(MSG1, MSG1_SIG1, PUBKEY2), "Signature verification failed\n") << "Signature signed by the wrong key is rejected";
	EXPECT_EQ(try_verify(MSG1, MSG1_SIG2, PUBKEY1), "Signature verification failed\n") << "Signature signed by the wrong key is rejected";

	EXPECT_EQ(try_verify(MSG1, MSG2_SIG1, PUBKEY1), "Signature verification failed\n") << "Signature for wrong message is rejected";
	EXPECT_EQ(try_verify(MSG1, MSG2_SIG2, PUBKEY2), "Signature verification failed\n") << "Signature for wrong message is rejected";

	EXPECT_EQ(try_verify(BADMSG1, MSG1_SIG1, PUBKEY1), "Signature verification failed\n") << "Signature for tainted message is rejected";
	EXPECT_EQ(try_verify(BADMSG2, MSG2_SIG1, PUBKEY1), "Signature verification failed\n") << "Signature for tainted message is rejected";

	EXPECT_EQ(try_verify(MSG1, "potato", PUBKEY1), "Signature verification failed\n") << "Malformed signature is rejected";
	EXPECT_EQ(try_verify(MSG2, "potato", PUBKEY2), "Signature verification failed\n") << "Malformed signature is rejected";
}

TEST(LuaPluginLoader, ChecksumAlgorithms)
{
	LuaPluginLoaderInitialiser lpl_init;
	
	App &app = wxGetApp();
	app.console->clear();
	
	{
		std::string SCRIPT =
			std::string("")
			+ "local algos = rehex.Checksum.algorithms()\n"
			+ "for _, algo in ipairs(algos)\n"
			+ "do\n"
			+ "  print(\"name = '\" .. algo.name .. \"' group = '\" .. algo.group .. \"' label = '\" .. algo.label .. \"'\")\n"
			+ "end\n";
		
		TempFile script_file(SCRIPT);
		
		LuaPlugin p = LuaPluginLoader::load_plugin(script_file.tmpfile);
		pump_events();

		EXPECT_NE(app.console->get_messages_text().find("name = 'CRC-16-ARC' group = 'CRC' label = 'CRC-16 ARC (aka CRC-16 IBM, CRC-16 LHA)'"), std::string::npos);
		EXPECT_NE(app.console->get_messages_text().find("name = 'MD5' group = '' label = 'MD5'"), std::string::npos);
	}
}

TEST(LuaPluginLoader, ChecksumMD5Text)
{
	LuaPluginLoaderInitialiser lpl_init;
	
	App &app = wxGetApp();
	app.console->clear();
	
	{
		std::string SCRIPT =
			std::string("")
			+ "local md5 = rehex.Checksum(\"MD5\")\n"
			+ "md5:update(\"Hello\")\n"
			+ "md5:update(\" world\")\n"
			+ "md5:finish()\n"
			+ "print(md5:checksum_hex())\n";
		
		TempFile script_file(SCRIPT);
		
		LuaPlugin p = LuaPluginLoader::load_plugin(script_file.tmpfile);
		pump_events();

		EXPECT_EQ(app.console->get_messages_text(), "3E25960A79DBC69B674CD4EC67A72C62\n");
	}
}

TEST(LuaPluginLoader, ChecksumMD5BinaryData)
{
	LuaPluginLoaderInitialiser lpl_init;
	
	App &app = wxGetApp();
	app.console->clear();
	
	{
		std::string SCRIPT =
			std::string("")
			+ "local md5 = rehex.Checksum(\"MD5\")\n"
			+ "md5:update(\"\\0\\1\\2\\3\")\n"
			+ "md5:update(\"\\4\\5\\6\\7\\8\\9\")\n"
			+ "md5:finish()\n"
			+ "print(md5:checksum_hex())\n";
		
		TempFile script_file(SCRIPT);
		
		LuaPlugin p = LuaPluginLoader::load_plugin(script_file.tmpfile);
		pump_events();

		EXPECT_EQ(app.console->get_messages_text(), "C56BD5480F6E5413CB62A0AD9666613A\n");
	}
}
