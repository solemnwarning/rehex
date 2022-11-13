/* Reverse Engineer's Hex Editor
 * Copyright (C) 2022 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "../src/platform.hpp"

#include <gtest/gtest.h>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <thread>
#include <vector>

#include "../src/RangeProcessor.hpp"

using namespace REHex;

TEST(RangeProcessorTest, RunOneWorker)
{
	std::mutex lock;
	unsigned int current_calls = 0;
	unsigned int max_calls = 0;
	unsigned int total_calls = 0;
	
	auto func = [&](off_t window_base, off_t window_size)
	{
		lock.lock();
		
		if(++current_calls > max_calls)
		{
			max_calls = current_calls;
		}
		
		++total_calls;
		
		lock.unlock();
		
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		
		lock.lock();
		--current_calls;
		lock.unlock();
	};
	
	RangeProcessor rp(func, 1024 /* 1KiB window */);
	rp.set_max_threads(1);
	
	rp.queue_range(0, 1024 * 10);
	rp.wait_for_completion();
	
	EXPECT_EQ(current_calls, 0U);
	EXPECT_EQ(max_calls, 1U);
	EXPECT_EQ(total_calls, 10U);
}

TEST(RangeProcessorTest, RunFourWorkers)
{
	std::mutex lock;
	unsigned int current_calls = 0;
	unsigned int max_calls = 0;
	unsigned int total_calls = 0;
	
	auto func = [&](off_t window_base, off_t window_size)
	{
		lock.lock();
		
		if(++current_calls > max_calls)
		{
			max_calls = current_calls;
		}
		
		++total_calls;
		
		lock.unlock();
		
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		
		lock.lock();
		--current_calls;
		lock.unlock();
	};
	
	RangeProcessor rp(func, 1024 /* 1KiB window */);
	rp.set_max_threads(4);
	
	rp.queue_range(0, 1024 * 20);
	rp.wait_for_completion();
	
	EXPECT_EQ(current_calls, 0U);
	EXPECT_EQ(max_calls, 4U);
	EXPECT_EQ(total_calls, 20U);
}

TEST(RangeProcessorTest, ProcessSingleRange)
{
	std::mutex lock;
	std::vector< std::pair<off_t, off_t> > got_calls;
	
	auto func = [&](off_t window_base, off_t window_size)
	{
		lock.lock();
		got_calls.push_back( std::make_pair(window_base, window_size) );
		lock.unlock();
	};
	
	RangeProcessor rp(func, 1024 /* 1KiB window */);
	
	rp.queue_range(512, 1024 * 10);
	rp.wait_for_completion();
	
	std::sort(got_calls.begin(), got_calls.end());
	
	const std::vector< std::pair<off_t, off_t> > EXPECT_CALLS = {
		std::make_pair(512 + (1024 * 0), 1024),
		std::make_pair(512 + (1024 * 1), 1024),
		std::make_pair(512 + (1024 * 2), 1024),
		std::make_pair(512 + (1024 * 3), 1024),
		std::make_pair(512 + (1024 * 4), 1024),
		std::make_pair(512 + (1024 * 5), 1024),
		std::make_pair(512 + (1024 * 6), 1024),
		std::make_pair(512 + (1024 * 7), 1024),
		std::make_pair(512 + (1024 * 8), 1024),
		std::make_pair(512 + (1024 * 9), 1024),
	};
	
	EXPECT_EQ(got_calls, EXPECT_CALLS);
}

TEST(RangeProcessorTest, ProcessMultipleRanges)
{
	std::mutex lock;
	std::vector< std::pair<off_t, off_t> > got_calls;
	
	auto func = [&](off_t window_base, off_t window_size)
	{
		lock.lock();
		got_calls.push_back( std::make_pair(window_base, window_size) );
		lock.unlock();
	};
	
	RangeProcessor rp(func, 1024 /* 1KiB window */);
	
	rp.queue_range(512, 1024 * 10);
	rp.queue_range(20480, 512  * 10);
	rp.wait_for_completion();
	
	std::sort(got_calls.begin(), got_calls.end());
	
	const std::vector< std::pair<off_t, off_t> > EXPECT_CALLS = {
		std::make_pair(512 + (1024 * 0), 1024),
		std::make_pair(512 + (1024 * 1), 1024),
		std::make_pair(512 + (1024 * 2), 1024),
		std::make_pair(512 + (1024 * 3), 1024),
		std::make_pair(512 + (1024 * 4), 1024),
		std::make_pair(512 + (1024 * 5), 1024),
		std::make_pair(512 + (1024 * 6), 1024),
		std::make_pair(512 + (1024 * 7), 1024),
		std::make_pair(512 + (1024 * 8), 1024),
		std::make_pair(512 + (1024 * 9), 1024),
		
		std::make_pair(20480 + (1024 * 0), 1024),
		std::make_pair(20480 + (1024 * 1), 1024),
		std::make_pair(20480 + (1024 * 2), 1024),
		std::make_pair(20480 + (1024 * 3), 1024),
		std::make_pair(20480 + (1024 * 4), 1024),
	};
	
	EXPECT_EQ(got_calls, EXPECT_CALLS);
}

TEST(RangeProcessorTest, ProcessOverlappingRanges)
{
	std::mutex lock;
	std::vector< std::pair<off_t, off_t> > got_calls;
	
	auto func = [&](off_t window_base, off_t window_size)
	{
		lock.lock();
		got_calls.push_back( std::make_pair(window_base, window_size) );
		lock.unlock();
	};
	
	RangeProcessor rp(func, 1024 /* 1KiB window */);
	
	rp.pause_threads();
	rp.queue_range(512,  1024 * 10);
	rp.queue_range(1024, 1024 * 10);
	rp.queue_range(1536, 1024 * 10);
	rp.resume_threads();
	rp.wait_for_completion();
	
	std::sort(got_calls.begin(), got_calls.end());
	
	const std::vector< std::pair<off_t, off_t> > EXPECT_CALLS = {
		std::make_pair(512 + (1024 * 0), 1024),
		std::make_pair(512 + (1024 * 1), 1024),
		std::make_pair(512 + (1024 * 2), 1024),
		std::make_pair(512 + (1024 * 3), 1024),
		std::make_pair(512 + (1024 * 4), 1024),
		std::make_pair(512 + (1024 * 5), 1024),
		std::make_pair(512 + (1024 * 6), 1024),
		std::make_pair(512 + (1024 * 7), 1024),
		std::make_pair(512 + (1024 * 8), 1024),
		std::make_pair(512 + (1024 * 9), 1024),
		std::make_pair(512 + (1024 * 10), 1024),
	};
	
	EXPECT_EQ(got_calls, EXPECT_CALLS);
}

TEST(RangeProcessorTest, ProcessRangeNotMultipleOfWindow)
{
	std::mutex lock;
	std::vector< std::pair<off_t, off_t> > got_calls;
	
	auto func = [&](off_t window_base, off_t window_size)
	{
		lock.lock();
		got_calls.push_back( std::make_pair(window_base, window_size) );
		lock.unlock();
	};
	
	RangeProcessor rp(func, 1024 /* 1KiB window */);
	
	rp.queue_range(512,  1024 * 10 + 100);
	rp.wait_for_completion();
	
	std::sort(got_calls.begin(), got_calls.end());
	
	const std::vector< std::pair<off_t, off_t> > EXPECT_CALLS = {
		std::make_pair(512 + (1024 * 0), 1024),
		std::make_pair(512 + (1024 * 1), 1024),
		std::make_pair(512 + (1024 * 2), 1024),
		std::make_pair(512 + (1024 * 3), 1024),
		std::make_pair(512 + (1024 * 4), 1024),
		std::make_pair(512 + (1024 * 5), 1024),
		std::make_pair(512 + (1024 * 6), 1024),
		std::make_pair(512 + (1024 * 7), 1024),
		std::make_pair(512 + (1024 * 8), 1024),
		std::make_pair(512 + (1024 * 9), 1024),
		std::make_pair(512 + (1024 * 10), 100),
	};
	
	EXPECT_EQ(got_calls, EXPECT_CALLS);
}

TEST(RangeProcessorTest, QueueRangeWhileBeingProcessed)
{
	std::mutex lock;
	std::vector< std::pair<off_t, off_t> > got_calls;
	std::condition_variable cv;
	bool hit = false, resume = false;
	
	auto func = [&](off_t window_base, off_t window_size)
	{
		std::unique_lock<std::mutex> l(lock);
		
		got_calls.push_back( std::make_pair(window_base, window_size) );
		
		if(window_base == 0 && window_size == 1024)
		{
			hit = true;
			cv.notify_all();
			
			cv.wait(l, [&]() { return resume; });
		}
	};
	
	RangeProcessor rp(func, 1024 /* 1KiB window */);
	
	rp.queue_range(0, 1024 * 10);
	
	/* Wait for our work function to be called with the window 0,1024... */
	std::unique_lock<std::mutex> l(lock);
	cv.wait(l, [&]() { return hit; });
	
	/* Re-queue the window currently being processed... */
	rp.queue_range(0, 1024);
	
	/* Unblock the worker and let it continue as normal. */
	resume = true;
	l.unlock();
	cv.notify_all();
	
	rp.wait_for_completion();
	
	std::sort(got_calls.begin(), got_calls.end());
	
	const std::vector< std::pair<off_t, off_t> > EXPECT_CALLS = {
		std::make_pair(1024 * 0, 1024),
		std::make_pair(1024 * 0, 1024), /* Note this window got processed TWICE */
		std::make_pair(1024 * 1, 1024),
		std::make_pair(1024 * 2, 1024),
		std::make_pair(1024 * 3, 1024),
		std::make_pair(1024 * 4, 1024),
		std::make_pair(1024 * 5, 1024),
		std::make_pair(1024 * 6, 1024),
		std::make_pair(1024 * 7, 1024),
		std::make_pair(1024 * 8, 1024),
		std::make_pair(1024 * 9, 1024),
	};
	
	EXPECT_EQ(got_calls, EXPECT_CALLS);
}

TEST(RangeProcessorTest, DestructorDiscardsQueue)
{
	std::mutex lock;
	std::vector< std::pair<off_t, off_t> > got_calls;
	
	auto func = [&](off_t window_base, off_t window_size)
	{
		std::unique_lock<std::mutex> l(lock);
		got_calls.push_back( std::make_pair(window_base, window_size) );
		
		/* Should be enough time for the main thread to enter ~RangeProcessor() */
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	};
	
	{
		RangeProcessor rp(func, 1024 /* 1KiB window */);
		rp.set_max_threads(1);
		
		rp.queue_range(0, 1024 * 10);
		
		/* Should be enough time for worker thread to enter func() */
		std::this_thread::sleep_for(std::chrono::milliseconds(250));
	}
	
	std::sort(got_calls.begin(), got_calls.end());
	
	const std::vector< std::pair<off_t, off_t> > EXPECT_CALLS = {
		std::make_pair(1024 * 0, 1024),
	};
	
	EXPECT_EQ(got_calls, EXPECT_CALLS);
}

TEST(RangeProcessorTest, GetQueue)
{
	std::mutex lock;
	std::condition_variable cv;
	bool hit = false, resume = false;
	
	auto func = [&](off_t window_base, off_t window_size)
	{
		std::unique_lock<std::mutex> l(lock);
		
		if((window_base == 0 && window_size == 1024) || (window_base == 2048 && window_size == 1024))
		{
			resume = false;
			hit = true;
			cv.notify_all();
			
			cv.wait(l, [&]() { return resume; });
		}
	};
	
	RangeProcessor rp(func, 1024 /* 1KiB window */);
	rp.set_max_threads(1);
	
	rp.queue_range(0, 1024 * 10);
	
	/* Wait for our work function to be called with the window 0,1024... */
	std::unique_lock<std::mutex> l(lock);
	cv.wait(l, [&]() { return hit; });
	
	{
		/* Check the result of RangeProcessor::get_queue() */
		
		ByteRangeSet queue = rp.get_queue();
		
		std::vector< std::pair<off_t, off_t> > got_queue;
		for(auto i = queue.begin(); i != queue.end(); ++i)
		{
			got_queue.push_back( std::make_pair(i->offset, i->length) );
		}
		
		const std::vector< std::pair<off_t, off_t> > EXPECT_QUEUE = {
			std::make_pair(0, 1024 * 10),
		};
		
		EXPECT_EQ(got_queue, EXPECT_QUEUE);
	}
	
	/* Unblock the worker and let it continue until it hits 2048,1024... */
	hit = false;
	resume = true;
	cv.notify_all();
	cv.wait(l, [&]() { return hit; });
	
	{
		/* Check the result of RangeProcessor::get_queue() */
		
		ByteRangeSet queue = rp.get_queue();
		
		std::vector< std::pair<off_t, off_t> > got_queue;
		for(auto i = queue.begin(); i != queue.end(); ++i)
		{
			got_queue.push_back( std::make_pair(i->offset, i->length) );
		}
		
		const std::vector< std::pair<off_t, off_t> > EXPECT_QUEUE = {
			std::make_pair(2048, 1024 * 8),
		};
		
		EXPECT_EQ(got_queue, EXPECT_QUEUE);
	}
	
	/* Unblock the worker and let it continue until it finishes the queue... */
	resume = true;
	cv.notify_all();
	l.unlock();
	
	rp.wait_for_completion();
	
	{
		/* Check the result of RangeProcessor::get_queue() */
		
		ByteRangeSet queue = rp.get_queue();
		
		std::vector< std::pair<off_t, off_t> > got_queue;
		for(auto i = queue.begin(); i != queue.end(); ++i)
		{
			got_queue.push_back( std::make_pair(i->offset, i->length) );
		}
		
		const std::vector< std::pair<off_t, off_t> > EXPECT_QUEUE = {};
		
		EXPECT_EQ(got_queue, EXPECT_QUEUE);
	}
}
