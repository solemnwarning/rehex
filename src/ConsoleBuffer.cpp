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

#include "platform.hpp"

#include <stdarg.h>
#include <vector>

#include "ConsoleBuffer.hpp"

REHex::ConsoleBuffer::ConsoleBuffer(size_t total_text_max):
	total_text_max(total_text_max),
	total_text(0) {}

const std::list<REHex::ConsoleBuffer::Message> &REHex::ConsoleBuffer::get_messages() const
{
	return messages;
}

std::string REHex::ConsoleBuffer::get_messages_text() const
{
	std::string all_text;
	all_text.reserve(total_text);
	
	for(auto m = messages.begin(); m != messages.end(); ++m)
	{
		all_text += m->text;
	}
	
	return all_text;
}

void REHex::ConsoleBuffer::print(Level level, const std::string &text)
{
	if(text.empty())
	{
		/* Don't want zero-length messages in the list. */
		return;
	}
	
	if((total_text + text.length()) > total_text_max)
	{
		/* We don't want to erase to the middle of a line, so erase sequences of messages
		 * up to the first one with a terminating newline until we have enough to keep the
		 * buffer under the size limit, or there are none left.
		*/
		
		auto erase_end = messages.begin();
		size_t erase_total = 0;
		
		while(erase_end != messages.end() && erase_total < text.length())
		{
			auto line_end = erase_end;
			size_t line_total = 0;
			
			while(line_end != messages.end())
			{
				line_total += line_end->text.length();
				
				if(line_end->text.back() == '\n')
				{
					break;
				}
				
				++line_end;
			}
			
			if(line_end != messages.end())
			{
				/* Found a message with a terminating newline, add it and any
				 * preceeding ones to the range to be erased.
				*/
				erase_end = std::next(line_end);
				erase_total += line_total;
			}
			else{
				/* No more messages with terminating newlines, stop. */
				break;
			}
		}
		
		if(erase_total > 0)
		{
			/* Erase the messages and raise a CONSOLE_ERASE event. */
			
			messages.erase(messages.begin(), erase_end);
			total_text -= erase_total;
			
			ConsoleEraseEvent event(this, erase_total);
			wxPostEvent(this, event);
		}
	}
	
	messages.push_back(Message(level, text));
	total_text += text.length();
	
	ConsolePrintEvent event(this, level, text);
	wxPostEvent(this, event);
}

void REHex::ConsoleBuffer::printf(Level level, const char *fmt, ...)
{
	va_list argv;
	va_start(argv, fmt);
	
	vprintf(level, fmt, argv);
	
	va_end(argv);
}

void REHex::ConsoleBuffer::vprintf(Level level, const char *fmt, va_list argv)
{
	/* vsnprintf() invalidates argv, so we must make a copy for the first call. */
	va_list argv_c;
	va_copy(argv_c, argv);
	int n_chars = vsnprintf(NULL, 0, fmt, argv_c);
	va_end(argv_c);
	
	std::vector<char> buf(n_chars + 1);
	vsnprintf(buf.data(), buf.size(), fmt, argv);
	
	print(level, buf.data());
}

void REHex::ConsoleBuffer::clear()
{
	if(total_text == 0)
	{
		/* Don't raise zero-length CONSOLE_ERASE events. */
		return;
	}
	
	size_t old_total_text = total_text;
	
	messages.clear();
	total_text = 0;
	
	ConsoleEraseEvent event(this, old_total_text);
	wxPostEvent(this, event);
}

REHex::ConsoleBuffer::Message::Message(Level level, const std::string &text):
	level(level), text(text) {}

bool REHex::ConsoleBuffer::Message::operator==(const Message &rhs) const
{
	return level == rhs.level && text == rhs.text;
}

wxDEFINE_EVENT(REHex::CONSOLE_PRINT, REHex::ConsolePrintEvent);

REHex::ConsolePrintEvent::ConsolePrintEvent(ConsoleBuffer *source, ConsoleBuffer::Level &level, const std::string &text):
	wxEvent(wxID_ANY, CONSOLE_PRINT), level(level), text(text)
{
	SetEventObject(source);
}

wxEvent *REHex::ConsolePrintEvent::Clone() const
{
	return new ConsolePrintEvent(*this);
}

wxDEFINE_EVENT(REHex::CONSOLE_ERASE, REHex::ConsoleEraseEvent);

REHex::ConsoleEraseEvent::ConsoleEraseEvent(ConsoleBuffer *source, size_t count):
	wxEvent(wxID_ANY, CONSOLE_ERASE), count(count)
{
	SetEventObject(source);
}

wxEvent *REHex::ConsoleEraseEvent::Clone() const
{
	return new ConsoleEraseEvent(*this);
}
