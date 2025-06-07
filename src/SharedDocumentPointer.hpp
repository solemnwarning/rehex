/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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
	template<typename T> class SharedDocumentPointerImpl
	{
		private:
			std::shared_ptr<T> document;
			
			std::stack< std::function<void()> > cleanups;
			
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
			
			const std::shared_ptr<T> &_get_shared_ptr() const
			{
				return document;
			}
			
			SharedDocumentPointerImpl(const SharedDocumentPointerImpl<T> &document):
				document(document.document) {}
			
			SharedDocumentPointerImpl(const std::shared_ptr<T> &document):
				document(document) {}
			
			SharedDocumentPointerImpl &operator=(const SharedDocumentPointerImpl<T>&) = delete;
			
			/* Allow conversion of SharedDocumentPointerImpl<T> to SharedDocumentPointerImpl<Base> */
			template<typename U> SharedDocumentPointerImpl(const SharedDocumentPointerImpl<U> &document):
				document(document._get_shared_ptr()) {}
			
			~SharedDocumentPointerImpl()
			{
				while(!cleanups.empty())
				{
					cleanups.top()();
					cleanups.pop();
				}
			}
			
			operator T*() const
			{
				return document.get();
			}
			
			T* operator->() const
			{
				return document.get();
			}
			
			/* Equality just checks Document pointers match. */
			bool operator==(const SharedDocumentPointerImpl<T> &rhs) const
			{
				return document == rhs.document;
			}
			
			/**
			 * @brief Construct a new Document and return a SharedDocumentPointer.
			*/
			template<typename... Args> static SharedDocumentPointerImpl<T> make(Args&&... args)
			{
				std::shared_ptr<T> s = std::make_shared<T>(std::forward<Args>(args)...);
				return SharedDocumentPointerImpl<T>(s);
			}
	};
	
	using SharedDocumentPointer = SharedDocumentPointerImpl<Document>;
	
	template<typename T> using SharedEvtHandler = SharedDocumentPointerImpl<T>;
}

#endif /* !REHEX_SHAREDDOCUMENTPOINTER_HPP */
