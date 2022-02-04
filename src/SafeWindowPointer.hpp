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

#include <assert.h>
#include <functional>
#include <stack>
#include <wx/event.h>

#ifndef REHEX_SAFEWINDOWPOINTER_HPP
#define REHEX_SAFEWINDOWPOINTER_HPP

namespace REHex
{
	/**
	 * @brief Smart pointer container for weak references to a wxWindow
	 *
	 * This class holds a pointer of a type derived from wxWindow. If the
	 * window is destroyed (raises a wxEVT_DESTROY event), the pointer will
	 * be set to NULL.
	*/
	template<typename T> class SafeWindowPointer
	{
		private:
			T *window;
			
			std::stack< std::function<void()> > cleanups;
			
			void OnWindowDestroyed(wxWindowDestroyEvent &event)
			{
				if(event.GetEventObject() == window)
				{
					window = NULL;
				}
				
				event.Skip();
			}
			
		public:
			/**
			 * Sets up a binding with window->Bind() that is automatically undone using
			 * window->Unbind() when the SafeWindowPointer is destroyed.
			*/
			template <typename EventTag, typename Class, typename EventArg, typename EventHandler>
				void auto_cleanup_bind(const EventTag &eventType, void (Class::*method)(EventArg &), EventHandler *handler)
			{
				if(window == NULL)
				{
					/* Window has already been destroyed. */
					return;
				}
				
				window->Bind(eventType, method, handler);
				
				cleanups.push([this, eventType, method, handler]()
				{
					window->Unbind(eventType, method, handler);
				});
			}
			
			SafeWindowPointer(T *window):
				window(window)
			{
				auto_cleanup_bind(wxEVT_DESTROY, &SafeWindowPointer<T>::OnWindowDestroyed, this);
			}
			
			SafeWindowPointer(const SafeWindowPointer &src):
				window(src.window)
			{
				auto_cleanup_bind(wxEVT_DESTROY, &SafeWindowPointer<T>::OnWindowDestroyed, this);
			}
			
			SafeWindowPointer() = delete;
			SafeWindowPointer &operator=(const SafeWindowPointer&) = delete;
			
			~SafeWindowPointer()
			{
				if(window == NULL)
				{
					/* Window has already been destroyed. */
					return;
				}
				
				while(!cleanups.empty())
				{
					cleanups.top()();
					cleanups.pop();
				}
			}
			
			operator T*() const
			{
				return window;
			}
			
			T* operator->() const
			{
				assert(window != NULL);
				return window;
			}
			
			/* Equality just checks window pointers match. */
			bool operator==(const SafeWindowPointer<T> &rhs) const
			{
				return window == rhs.window;
			}
	};
}

#endif /* !REHEX_SAFEWINDOWPOINTER_HPP */
