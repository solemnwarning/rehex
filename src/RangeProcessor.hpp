/* Reverse Engineer's Hex Editor
 * Copyright (C) 2022-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_RANGEPROCESSOR_HPP
#define REHEX_RANGEPROCESSOR_HPP

#include <atomic>
#include <condition_variable>
#include <functional>
#include <list>
#include <mutex>
#include <stddef.h>
#include <thread>

#include "ByteRangeSet.hpp"
#include "ThreadPool.hpp"

namespace REHex
{
	/**
	 * @brief Helper class for processing a range of data in chunks on worker threads.
	 *
	 * This class breaks up one or more ranges of bytes to be processed into smaller blocks
	 * and processes them using a callback function on worker threads.
	*/
	class RangeProcessor
	{
		public:
			/**
			 * @brief Construct a new RangeProcessor instance.
			 *
			 * Constructs a new RangeProcessor that will call the provided callback for
			 * each block of data to be processed, with no more than max_window_size
			 * bytes in any given block.
			*/
			RangeProcessor(const std::function<void(off_t, off_t)> &work_func, size_t max_window_size);
			
			/**
			 * @brief Destroy a RangeProcessor instance.
			 *
			 * All worker threads will exit once their work function has returned and
			 * any work remaining in the queue is discarded.
			*/
			~RangeProcessor();
			
			/**
			 * @brief Get the currently queued/processing ranges.
			*/
			ByteRangeSet get_queue() const;
			
			/**
			 * @brief Check if any ranges are queued or processing.
			*/
			REHEX_NODISCARD bool queue_empty() const;
			
			/**
			 * @brief Add a range of bytes to the work queue.
			 *
			 * If the given range intersects with a range that is already being
			 * processed, processing of the intersection will be deferred until the
			 * work callback for that range has finished. Any data not intersecting
			 * will be dispatched as soon as a worker is free.
			*/
			void queue_range(off_t offset, off_t length);
			
			/**
			 * @brief Add a range of bytes to the work queue.
			 *
			 * This is basically the same as queue_range(), except this one should be
			 * called from within the work callback function rather than from the main
			 * thread.
			*/
			void queue_range_in_worker(off_t offset, off_t length);
			
			/**
			 * @brief Remove a range of bytes from the work queue.
			 *
			 * Once this function returns, no more blocks from the given range will be
			 * processed, however any blocks within it that are already being processed
			 * on a background thread will continue until their work function returns.
			*/
			void unqueue_range(off_t offset, off_t length);
			
			/**
			 * @brief Clear the work queue.
			 *
			 * Clears the work queue. Any workers already processing a block will
			 * continue until the work function returns.
			*/
			void clear_queue();
			
			/**
			 * @brief Adjust the queue for data being erased from file.
			 *
			 * Ranges after the section erased will be moved back by the size of the
			 * insertion. Ranges wholly within the erased section will be lost. Ranges
			 * on either side of the erase will be truncated and merged as necessary.
			 *
			 * NOTE: The RangeProcessor *MUST* be paused before calling this method.
			*/
			void data_inserted(off_t offset, off_t length);
			
			/**
			 * @brief Adjust the queue for data being erased from file.
			 *
			 * Ranges after the section erased will be moved back by the size of the
			 * insertion. Ranges wholly within the erased section will be lost. Ranges
			 * on either side of the erase will be truncated and merged as necessary.
			 *
			 * NOTE: The RangeProcessor *MUST* be paused before calling this method.
			*/
			void data_erased(off_t offset, off_t length);
			
			/**
			 * @brief Pause worker threads.
			 *
			 * Pauses any worker threads. Will not return until any work functions
			 * have returned and the queue has settled.
			*/
			void pause_threads();
			
			/**
			 * @brief Resume paused worker threads.
			*/
			void resume_threads();
			
			/**
			 * @brief Check if this RangeProcessor is paused.
			*/
			REHEX_NODISCARD bool paused() const;
			
			/**
			 * @brief Wait for work queue to be empty.
			 *
			 * This is mostly intended for unit tests. This should not be used from the
			 * application UI thread.
			*/
			void wait_for_completion();
			
			void set_max_threads(unsigned int max_threads);
			
		private:
			const std::function<void(off_t, off_t)> work_func;
			const size_t max_window_size;
			unsigned int max_threads;
			
			ThreadPool::TaskHandle task;
			bool task_paused;
			
			mutable std::mutex pause_lock;      /**< Mutex protecting access to this block of members: */
			std::condition_variable paused_cv;  /**< Notifies pause_threads() that a thread has paused. */
			std::condition_variable resume_cv;  /**< Notifies paused threads that they should resume. */
			std::condition_variable idle_cv;    /**< Notifies wait_for_completion() that a thread has gone idle. */
			ByteRangeSet queued;                /**< Ranges which are queued, but already being worked. */
			ByteRangeSet pending;               /**< Ranges waiting to be processed. */
			ByteRangeSet working;               /**< Ranges currently being processed. */
			
			#ifndef NDEBUG
			static thread_local bool in_work_func;
			#endif
			
			void queue_range_locked(off_t offset, off_t length);
			void mark_work_done(off_t offset, off_t length);
			
			bool task_function();
			void start_threads();
			void stop_threads();
			
			unsigned int calc_max_threads() const;
	};
}

#endif /* !REHEX_RANGEPROCESSOR_HPP */
