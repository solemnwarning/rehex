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

#include "ConsoleBuffer.hpp"

REHex::ConsoleBuffer::ConsoleBuffer():
	total_text(0) {}

const std::list<REHex::ConsoleBuffer::Message> &REHex::ConsoleBuffer::get_messages() const
{
	return messages;
}

void REHex::ConsoleBuffer::print(Level level, const std::string &text)
{
	/* TODO: Limit number of entries in data. */
	
	messages.push_back(Message(level, text));
	total_text += text.length();
}

void REHex::ConsoleBuffer::clear()
{
	messages.clear();
}

REHex::ConsoleBuffer::Message::Message(Level level, const std::string &text):
	level(level), text(text) {}

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
