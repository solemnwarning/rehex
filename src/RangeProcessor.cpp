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

#include "platform.hpp"

#include <assert.h>
#include <numeric>

#include "App.hpp"
#include "RangeProcessor.hpp"

#ifndef NDEBUG
thread_local bool REHex::RangeProcessor::in_work_func = false;
#endif

REHex::RangeProcessor::RangeProcessor(const std::function<void(off_t, off_t)> &work_func, size_t max_window_size):
	work_func(work_func),
	max_window_size(max_window_size),
	max_threads(0),
	task_paused(false)
{}

REHex::RangeProcessor::~RangeProcessor()
{
	stop_threads();
}

REHex::ByteRangeSet REHex::RangeProcessor::get_queue() const
{
	assert(!in_work_func);
	
	std::lock_guard<std::mutex> pl(pause_lock);
	
	/* Merge the all the ranges in queued, pending and working. */
	
	ByteRangeSet merged;
	merged.set_ranges(queued.begin(),  queued.end());
	merged.set_ranges(pending.begin(), pending.end());
	merged.set_ranges(working.begin(), working.end());
	
	return merged;
}

bool REHex::RangeProcessor::queue_empty() const
{
	assert(!in_work_func);
	
	std::lock_guard<std::mutex> pl(pause_lock);
	return queued.empty() && pending.empty() && working.empty();
}

void REHex::RangeProcessor::queue_range(off_t offset, off_t length)
{
	assert(!in_work_func);
	
	std::lock_guard<std::mutex> pl(pause_lock);
	
	queue_range_locked(offset, length);
	
	if(!pending.empty() && task)
	{
		/* Notify any sleeping workers that there is now work to be done. */
		task.restart();
	}
	
	start_threads();
}

void REHex::RangeProcessor::queue_range_in_worker(off_t offset, off_t length)
{
	assert(in_work_func);
	
	std::lock_guard<std::mutex> pl(pause_lock);
	
	queue_range_locked(offset, length);
}

void REHex::RangeProcessor::unqueue_range(off_t offset, off_t length)
{
	assert(!in_work_func);
	
	std::lock_guard<std::mutex> pl(pause_lock);
	pending.clear_range(offset, length);
	queued.clear_range(offset, length);
}

void REHex::RangeProcessor::clear_queue()
{
	assert(!in_work_func);
	
	std::lock_guard<std::mutex> pl(pause_lock);
	pending.clear_all();
	queued.clear_all();
}

void REHex::RangeProcessor::data_inserted(off_t offset, off_t length)
{
	assert(task_paused);
	pending.data_inserted(offset, length);
}

void REHex::RangeProcessor::data_erased(off_t offset, off_t length)
{
	assert(task_paused);
	pending.data_erased(offset, length);
}

void REHex::RangeProcessor::queue_range_locked(off_t offset, off_t length)
{
	ByteRangeSet to_pending;
	to_pending.set_range(offset, length);
	
	ByteRangeSet to_queued = ByteRangeSet::intersection(to_pending, working);
	
	to_pending.clear_ranges(to_queued.begin(), to_queued.end());
	
	queued .set_ranges( to_queued.begin(),  to_queued.end());
	pending.set_ranges(to_pending.begin(), to_pending.end());
}

void REHex::RangeProcessor::mark_work_done(off_t offset, off_t length)
{
	ByteRangeSet work_done;
	work_done.set_range(offset, length);
	
	ByteRangeSet to_pending = ByteRangeSet::intersection(work_done, queued);
	
	working.clear_range(offset, length);
	
	queued.clear_ranges(to_pending.begin(), to_pending.end());
	pending.set_ranges(to_pending.begin(), to_pending.end());
}

bool REHex::RangeProcessor::task_function()
{
	std::unique_lock<std::mutex> pl(pause_lock);
	
	/* Take up to WINDOW_SIZE bytes from the next range in the pending pool to be
	 * processed in this thread.
	*/
	
	auto next_dirty_range = pending.begin();
	if(next_dirty_range == pending.end())
	{
		if(queued.empty())
		{
			/* All ranges processed. */
			idle_cv.notify_all();
			return true;
		}
		else{
			/* A range currently being processed in another thread has been queued
			 * for processing again, don't let the task go to sleep.
			*/
			
			return false;
		}
	}
	
	off_t  window_base   = next_dirty_range->offset;
	size_t window_length = next_dirty_range->length;
	
	window_length = std::min<off_t>(window_length, max_window_size);
	
	pending.clear_range(window_base, window_length);
	working.set_range(  window_base, window_length);
	
	#ifndef NDEBUG
	in_work_func = true;
	#endif
	
	pl.unlock();
	work_func(window_base, window_length);
	pl.lock();
	
	#ifndef NDEBUG
	in_work_func = false;
	#endif
	
	mark_work_done(window_base, window_length);
	
	idle_cv.notify_all();
	
	return pending.empty() && queued.empty();
}

void REHex::RangeProcessor::start_threads()
{
	ByteRangeSet merged;
	merged.set_ranges(queued.begin(),  queued.end());
	merged.set_ranges(pending.begin(), pending.end());
	merged.set_ranges(working.begin(), working.end());
	
	off_t working_total = merged.total_bytes();
	
	if(working_total > 0)
	{
		#if 0
		if(dirty_total >= (off_t)(UI_THREAD_THRESH))
		{
		#endif
			/* There is more than one "window" worth of data to process, either we are
			 * still initialising, or a huge amount of data has just changed. We shall
			 * do our processing in background threads.
			*/
			
			unsigned int max_threads  = calc_max_threads();
			unsigned int want_threads = working_total / max_window_size;
			
			if(want_threads == 0)
			{
				want_threads = 1;
			}
			else if(want_threads > max_threads)
			{
				want_threads = max_threads;
			}
			
			if(task)
			{
				task.change_concurrency(want_threads);
				task.restart();
			}
			else if(!task_paused)
			{
				task = wxGetApp().thread_pool->queue_task([this]() { return task_function(); }, want_threads);
			}
		#if 0
		}
		else{
			/* There is very little data to analyse, do it in the UI thread to avoid
			 * starting and stopping background threads on every changed nibble since
			 * the context switching gets expensive.
			*/
			
			// TODO
			thread_main();
		}
		#endif
	}
}

void REHex::RangeProcessor::stop_threads()
{
	if(task)
	{
		task.finish();
		task.join();
	}
}

void REHex::RangeProcessor::pause_threads()
{
	assert(!in_work_func);
	
	if(task && !task_paused)
	{
		task.pause();
	}
	
	task_paused = true;
}

void REHex::RangeProcessor::resume_threads()
{
	assert(!in_work_func);
	
	std::unique_lock<std::mutex> pl(pause_lock);
	
	if(task_paused)
	{
		task_paused = false;
		
		if(task)
		{
			task.resume();
		}
		else{
			start_threads();
		}
	}
}

bool REHex::RangeProcessor::paused() const
{
	assert(!in_work_func);
	return task_paused;
}

void REHex::RangeProcessor::wait_for_completion()
{
	std::unique_lock<std::mutex> pl(pause_lock);
	idle_cv.wait(pl, [&]() { return queued.empty() && pending.empty() && working.empty(); });
}

void REHex::RangeProcessor::set_max_threads(unsigned int max_threads)
{
	this->max_threads = max_threads;
}

unsigned int REHex::RangeProcessor::calc_max_threads() const
{
	if(max_threads > 0)
	{
		return max_threads;
	}
	else{
		unsigned int hardware_concurrency = std::thread::hardware_concurrency();
		
		if(hardware_concurrency > 0)
		{
			return hardware_concurrency;
		}
		else{
			return 1;
		}
	}
}
