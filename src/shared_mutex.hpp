/* Reverse Engineer's Hex Editor
 * Copyright (C) 2023-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <thread>
#include <vector>

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
			unsigned int readers;
			
			#ifndef NDEBUG
			/* Store the threads which hold the mutex for debugging. */
			std::thread::id writer_thread;
			std::vector<std::thread::id> reader_threads;
			#endif
			
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
				
				#ifndef NDEBUG
				writer_thread = std::this_thread::get_id();
				#endif
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
				
				#ifndef NDEBUG
				assert(std::find(reader_threads.begin(), reader_threads.end(), std::this_thread::get_id()) == reader_threads.end());
				reader_threads.push_back(std::this_thread::get_id());
				#endif
			}
			
			void unlock_shared()
			{
				{
					std::lock_guard<std::mutex> rl(readers_lock);
					--readers;
					
					#ifndef NDEBUG
					auto it = std::find(reader_threads.begin(), reader_threads.end(), std::this_thread::get_id());
					assert(it != reader_threads.end());
					reader_threads.erase(it);
					#endif
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
			bool locked;
			
		public:
			shared_lock(shared_mutex &mutex):
				mutex(mutex), locked(false)
			{
				lock();
			}
			
			shared_lock(shared_mutex &mutex, std::defer_lock_t t):
				mutex(mutex), locked(false) {}
			
			~shared_lock()
			{
				if(locked)
				{
					unlock();
				}
			}
			
			void lock()
			{
				assert(!locked);
				mutex.lock_shared();
				locked = true;
			}
			
			void unlock()
			{
				assert(locked);
				mutex.unlock_shared();
				locked = false;
			}
	};
};

#endif

#endif /* !REHEX_SHARED_MUTEX_HPP */
