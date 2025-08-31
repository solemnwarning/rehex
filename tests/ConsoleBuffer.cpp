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
#include <list>
#include <string>
#include <vector>
#include <wx/app.h>
#include <wx/frame.h>
#include <wx/timer.h>

#include "../src/ConsoleBuffer.hpp"
#include "testutil.hpp"

using namespace REHex;

#define EXPECT_MESSAGES(...) \
{ \
	const std::list<ConsoleBuffer::Message> EXPECT = { __VA_ARGS__ }; \
	EXPECT_EQ(cbuffer.get_messages(), EXPECT); \
}

#define EXPECT_EVENTS(...) \
{ \
	const std::vector<std::string> EXPECT = { __VA_ARGS__ }; \
	EXPECT_EQ(events, EXPECT); \
	events.clear(); \
}

class ConsoleBufferTest: public ::testing::Test
{
	protected:
		ConsoleBuffer cbuffer;
		std::vector<std::string> events;
		
		AutoFrame frame;
		wxTimer timer;
		
		ConsoleBufferTest():
			cbuffer(64),
			frame(NULL, wxID_ANY, "REHex Tests")
		{
			frame->Bind(wxEVT_IDLE, [](wxIdleEvent &event)
			{
				wxTheApp->ExitMainLoop();
			});
			
			timer.Bind(wxEVT_TIMER, [](wxTimerEvent &event)
			{
				wxTheApp->ExitMainLoop();
			});
			
			cbuffer.Bind(CONSOLE_PRINT, [&](ConsolePrintEvent &event)
			{
				std::string level_s;
				switch(event.level)
				{
					case ConsoleBuffer::Level::DEBUG:
						level_s = "DEBUG";
						break;
						
					case ConsoleBuffer::Level::INFO:
						level_s = "INFO";
						break;
						
					case ConsoleBuffer::Level::ERROR:
						level_s = "ERROR";
						break;
				}
				
				events.push_back("PRINT(" + level_s + ", '" + event.text + "')");
			});
			
			cbuffer.Bind(CONSOLE_ERASE, [&](ConsoleEraseEvent &event)
			{
				events.push_back("ERASE(" + std::to_string(event.count) + ")");
			});
		}
		
		void pump_events()
		{
			timer.Start(1000, wxTIMER_ONE_SHOT);
			
			wxTheApp->OnRun();
			
			timer.Stop();
		}
};

TEST_F(ConsoleBufferTest, Basic)
{
	cbuffer.print(ConsoleBuffer::Level::INFO, "Hello world\n");
	pump_events();
	
	EXPECT_MESSAGES(
		ConsoleBuffer::Message(ConsoleBuffer::Level::INFO, "Hello world\n"),
	);
	
	EXPECT_EQ(cbuffer.get_messages_text(),
		"Hello world\n");
	
	EXPECT_EVENTS(
		"PRINT(INFO, 'Hello world\n')",
	);
	
	cbuffer.print(ConsoleBuffer::Level::ERROR, "Goodbye world\n");
	cbuffer.print(ConsoleBuffer::Level::DEBUG, "Insignificant string\n");
	pump_events();
	
	EXPECT_MESSAGES(
		ConsoleBuffer::Message(ConsoleBuffer::Level::INFO, "Hello world\n"),
		ConsoleBuffer::Message(ConsoleBuffer::Level::ERROR, "Goodbye world\n"),
		ConsoleBuffer::Message(ConsoleBuffer::Level::DEBUG, "Insignificant string\n"),
	);
	
	EXPECT_EQ(cbuffer.get_messages_text(),
		"Hello world\n"
		"Goodbye world\n"
		"Insignificant string\n");
	
	EXPECT_EVENTS(
		"PRINT(ERROR, 'Goodbye world\n')",
		"PRINT(DEBUG, 'Insignificant string\n')",
	);
	
	cbuffer.clear();
	pump_events();
	
	EXPECT_MESSAGES();
	EXPECT_EQ(cbuffer.get_messages_text(), "");
	
	EXPECT_EVENTS(
		"ERASE(47)",
	);
}

TEST_F(ConsoleBufferTest, Printf)
{
	cbuffer.printf(ConsoleBuffer::Level::DEBUG, "foo %d5678\n", 1234);
	cbuffer.printf(ConsoleBuffer::Level::INFO,  "bar %s%lld\n", "baz", 5000000000LL);
	cbuffer.printf(ConsoleBuffer::Level::ERROR, "qux %hu\n", (unsigned short)(42));
	pump_events();
	
	EXPECT_MESSAGES(
		ConsoleBuffer::Message(ConsoleBuffer::Level::DEBUG, "foo 12345678\n"),
		ConsoleBuffer::Message(ConsoleBuffer::Level::INFO,  "bar baz5000000000\n"),
		ConsoleBuffer::Message(ConsoleBuffer::Level::ERROR, "qux 42\n"),
	);
	
	EXPECT_EVENTS(
		"PRINT(DEBUG, 'foo 12345678\n')",
		"PRINT(INFO, 'bar baz5000000000\n')",
		"PRINT(ERROR, 'qux 42\n')",
	);
}

TEST_F(ConsoleBufferTest, SizeLimit)
{
	cbuffer.print(ConsoleBuffer::Level::INFO, "lying alive road pencil overjoyed\n");
	cbuffer.print(ConsoleBuffer::Level::INFO, "small bat receptive spiffy\n");
	pump_events();
	
	ASSERT_EQ(cbuffer.get_messages_text(),
		"lying alive road pencil overjoyed\n"
		"small bat receptive spiffy\n");
	
	events.clear();
	
	/* buffer at 51 characters, append a message that would take it up to 65 and exceed the
	 * set limit of 64 characters - first whole message should be erased.
	*/
	
	cbuffer.print(ConsoleBuffer::Level::INFO, "resolute zoom\n");
	pump_events();
	
	EXPECT_EQ(cbuffer.get_messages_text(),
		"small bat receptive spiffy\n"
		"resolute zoom\n");
	
	EXPECT_EVENTS(
		"ERASE(34)",
		"PRINT(INFO, 'resolute zoom\n')",
	);
	
	/* buffer at 41 characters, push several long messages with no newlines onto the buffer
	 * which will push it over the size limit.
	 *
	 * The existing messages with a terminating newline should be removed, but the new ones
	 * should remain even beyond the size limit, since there aren't terminated (yet).
	*/
	
	cbuffer.print(ConsoleBuffer::Level::INFO, "title redundant depend dream existence difficult beneficial spiteful certain");
	cbuffer.print(ConsoleBuffer::Level::INFO, "disarm blushing actor");
	pump_events();
	
	EXPECT_EQ(cbuffer.get_messages_text(),
		"title redundant depend dream existence difficult beneficial spiteful certain"
		"disarm blushing actor");
	
	EXPECT_EVENTS(
		"ERASE(41)",
		"PRINT(INFO, 'title redundant depend dream existence difficult beneficial spiteful certain')",
		"PRINT(INFO, 'disarm blushing actor')",
	);
	
	/* buffer at 97 characters, push a message with a terminating newline, finally ending the
	 * saga of the above messages, which shouldn't be deleted *yet*.
	*/
	
	cbuffer.print(ConsoleBuffer::Level::INFO, "suspect wave\n");
	pump_events();
	
	EXPECT_EQ(cbuffer.get_messages_text(),
		"title redundant depend dream existence difficult beneficial spiteful certain"
		"disarm blushing actor"
		"suspect wave\n");
	
	EXPECT_EVENTS(
		"PRINT(INFO, 'suspect wave\n')",
	);
	
	/* buffer at 110 characters, push another short message which should clear the whole above
	 * block up to the terminating newline.
	*/
	
	cbuffer.print(ConsoleBuffer::Level::INFO, "flagrant\n");
	pump_events();
	
	EXPECT_EQ(cbuffer.get_messages_text(),
		"flagrant\n");
	
	EXPECT_EVENTS(
		"ERASE(110)",
		"PRINT(INFO, 'flagrant\n')",
	);
}
