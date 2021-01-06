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

#ifndef REHEX_CONSOLEBUFFER_HPP
#define REHEX_CONSOLEBUFFER_HPP

#include <list>
#include <string>
#include <wx/event.h>

namespace REHex {
	class ConsoleBuffer: public wxEvtHandler
	{
		public:
			enum class Level
			{
				DEBUG,
				INFO,
				ERROR,
			};
			
			struct Message
			{
				Level level;
				std::string text;
				
				Message(Level level, const std::string &text);
			};
			
			ConsoleBuffer();
			
			const std::list<Message> &get_messages() const;
			
			void print(Level level, const std::string &text);
			void clear();
			
		private:
			size_t total_text;
			std::list<Message> messages;
	};
	
	class ConsolePrintEvent: public wxEvent
	{
		public:
			const ConsoleBuffer::Level level;
			const std::string text;
			
			ConsolePrintEvent(ConsoleBuffer *source, ConsoleBuffer::Level &level, const std::string &text);
			
			virtual wxEvent *Clone() const override;
	};
	
	wxDECLARE_EVENT(CONSOLE_PRINT, ConsolePrintEvent);
}

#endif /* !REHEX_CONSOLEBUFFER_HPP */
