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
#include <stdarg.h>
#include <string>
#include <wx/event.h>

namespace REHex {
	/**
	 * @brief Console output message buffer.
	*/
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
				
				bool operator==(const Message &rhs) const;
			};
			
			/**
			 * @brief Construct a new ConsoleBuffer.
			 *
			 * The total_text_max parameter specifies a soft limit for the number of
			 * characters to hold in the buffer - only complete messages with a
			 * terminating newline will be erased to keep the buffer under this size.
			*/
			ConsoleBuffer(size_t total_text_max = 16384 /* 16KiB */);
			
			/**
			 * @brief Get a reference to the list of messages in the buffer.
			*/
			const std::list<Message> &get_messages() const;
			
			/**
			 * @brief Get the text of all messages in the buffer.
			*/
			std::string get_messages_text() const;
			
			/**
			 * @brief Append a message to the buffer.
			 *
			 * Appends a message to the buffer, raising a CONSOLE_PRINT event to notify
			 * any consumers.
			 *
			 * If any messages need to be erased to make room, a CONSOLE_ERASE event
			 * will also be raised.
			*/
			void print(Level level, const std::string &text);
			
			/**
			 * @brief Append a printf format message to the buffer.
			 * @see print()
			*/
			void printf(Level level, const char *fmt, ...);
			
			/**
			 * @brief Append a printf format message to the buffer.
			 * @see print()
			*/
			void vprintf(Level level, const char *fmt, va_list argv);
			
			/**
			 * @brief Clear all messages from the buffer.
			 *
			 * Clears all messages from the buffer, raising a CONSOLE_ERASE event if
			 * the buffer wasn't already empty.
			*/
			void clear();
			
		private:
			const size_t total_text_max;  /**< Buffer character limit (soft). */
			
			size_t total_text;            /**< Number of characters in the buffer. */
			std::list<Message> messages;  /**< Messages in the buffer. */
	};
	
	/**
	 * @brief Event signalling a message has been appended to the buffer.
	*/
	class ConsolePrintEvent: public wxEvent
	{
		public:
			const ConsoleBuffer::Level level;  /**< Priority of message. */
			const std::string text;            /**< Text of message. */
			
			ConsolePrintEvent(ConsoleBuffer *source, ConsoleBuffer::Level &level, const std::string &text);
			
			virtual wxEvent *Clone() const override;
	};
	
	/**
	 * @brief Event signalling characters have been erased from the buffer.
	 *
	 * This event is fired when one or more characters is erased from the start of the buffer
	 * to make room for a new message.
	*/
	class ConsoleEraseEvent: public wxEvent
	{
		public:
			const size_t count;  /**< Number of characters erased. */
			
			ConsoleEraseEvent(ConsoleBuffer *source, size_t count);
			
			virtual wxEvent *Clone() const override;
	};
	
	wxDECLARE_EVENT(CONSOLE_PRINT, ConsolePrintEvent);
	wxDECLARE_EVENT(CONSOLE_ERASE, ConsoleEraseEvent);
}

#endif /* !REHEX_CONSOLEBUFFER_HPP */
