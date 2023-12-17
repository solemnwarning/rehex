/* Reverse Engineer's Hex Editor
 * Copyright (C) 2023 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_SHARED_MUTEX_HPP
#define REHEX_SHARED_MUTEX_HPP

/* The implementation of std::shared_mutex in MinGW seems to be broken in some
 * subtle way possibly related to memory barriers and causes unpredictable
 * crashes and memory corruption, so carry on using my implementation there.
 *
 * std::shared_mutex under Linux seems just fine in my testing.
*/

#if __cplusplus >= 201402L && !(defined(__MINGW32__))

#include <shared_mutex>

namespace REHex
{
	using shared_mutex = std::shared_mutex;
	using shared_lock = std::shared_lock<std::shared_mutex>;
}

#else

#include <assert.h>
#include <atomic>
#include <condition_variable>
#include <mutex>

namespace REHex
{
	/**
	 * @brief Partial implementation of C++14's shared_mutex.
	*/
	class shared_mutex
	{
		private:
			std::mutex write_lock;
			
			std::mutex readers_lock;
			std::condition_variable readers_cv;
			volatile unsigned int readers;
			
		public:
			shared_mutex():
				readers(0) {}
			
			void lock()
			{
				write_lock.lock();
				
				std::unique_lock<std::mutex> rl(readers_lock);
				readers_cv.wait(rl, [&]()
				{
					return readers == 0;
				});
			}
			
			void unlock()
			{
				write_lock.unlock();
			}
			
			void lock_shared()
			{
				std::lock_guard<std::mutex> wl(write_lock);
				std::lock_guard<std::mutex> rl(readers_lock);
				++readers;
			}
			
			void unlock_shared()
			{
				{
					std::lock_guard<std::mutex> rl(readers_lock);
					--readers;
				}
				
				readers_cv.notify_one();
			}
	};
	
	/**
	 * @brief Partial implementation of C++14's shared_lock.
	*/
	class shared_lock
	{
		private:
			shared_mutex &mutex;
			
		public:
			shared_lock(shared_mutex &mutex):
				mutex(mutex)
			{
				lock();
			}
			
			~shared_lock()
			{
				unlock();
			}
			
			void lock()
			{
				mutex.lock_shared();
			}
			
			void unlock()
			{
				mutex.unlock_shared();
			}
	};
};

#endif

#endif /* !REHEX_SHARED_MUTEX_HPP */
