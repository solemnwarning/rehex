/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <functional>
#include <memory>
#include <stack>
#include <wx/event.h>

#include "document.hpp"

#ifndef REHEX_SHAREDDOCUMENTPOINTER_HPP
#define REHEX_SHAREDDOCUMENTPOINTER_HPP

namespace REHex
{
	/**
	 * @brief Wrapper around a shared_ptr<Document> with some convenience methods.
	*/
	class SharedDocumentPointer
	{
		private:
			std::shared_ptr<Document> document;
			
			std::stack< std::function<void()> > cleanups;
			
			SharedDocumentPointer(std::shared_ptr<Document> &document):
				document(document) {}
			
		public:
			/**
			 * Sets up a binding with document->Bind() that is automatically undone
			 * using document->Unbind() when the SharedDocumentPointer is destroyed.
			*/
			template <typename EventTag, typename Class, typename EventArg, typename EventHandler>
				void auto_cleanup_bind(const EventTag &eventType, void (Class::*method)(EventArg &), EventHandler *handler)
			{
				document->Bind(eventType, method, handler);
				
				cleanups.push([this, eventType, method, handler]()
				{
					document->Unbind(eventType, method, handler);
				});
			}
			
			SharedDocumentPointer(const SharedDocumentPointer &document):
				document(document.document) {}
			
			~SharedDocumentPointer()
			{
				while(!cleanups.empty())
				{
					cleanups.top()();
					cleanups.pop();
				}
			}
			
			operator Document*() const
			{
				return document.get();
			}
			
			Document* operator->() const
			{
				return document.get();
			}
			
			/* Equality just checks Document pointers match. */
			bool operator==(const SharedDocumentPointer &rhs) const
			{
				return document == rhs.document;
			}
			
			/**
			 * @brief Construct a new Document and return a SharedDocumentPointer.
			*/
			static SharedDocumentPointer make()
			{
				std::shared_ptr<Document> s = std::make_shared<Document>();
				return SharedDocumentPointer(s);
			}
			
			/**
			 * @brief Construct a new Document and return a SharedDocumentPointer.
			*/
			static SharedDocumentPointer make(const std::string &filename)
			{
				std::shared_ptr<Document> s = std::make_shared<Document>(filename);
				return SharedDocumentPointer(s);
			}
	};
}

#endif /* !REHEX_SHAREDDOCUMENTPOINTER_HPP */
