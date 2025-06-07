/* Reverse Engineer's Hex Editor
 * Copyright (C) 2024-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <chrono>
#include <gtest/gtest.h>
#include <mutex>
#include <thread>

#include "../src/ThreadPool.hpp"

using namespace REHex;

TEST(ThreadPool, RunTask)
{
	ThreadPool pool(8);
	
	std::mutex mutex;
	unsigned int times_called = 0; 
	unsigned int num_active = 0;
	unsigned int max_active = 0;
	
	ThreadPool::TaskHandle task = pool.queue_task([&]()
	{
		std::unique_lock<std::mutex> lock(mutex);
		
		++times_called;
		if(++num_active > max_active)
		{
			max_active = num_active;
		}
		
		lock.unlock();
		
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
		
		lock.lock();
		
		--num_active;
		return times_called >= 10;
	}, 1);
	
	task.join(); /* Wait for task to complete. */
	
	EXPECT_EQ(times_called, 10U) << "Task function was called correct number of times";
	EXPECT_EQ(max_active, 1U) << "Task function was not called in parallel";
}

TEST(ThreadPool, RunTaskParallel)
{
	ThreadPool pool(8);
	
	std::mutex mutex;
	unsigned int times_called = 0; 
	unsigned int num_active = 0;
	unsigned int max_active = 0;
	
	ThreadPool::TaskHandle task = pool.queue_task([&]()
	{
		std::unique_lock<std::mutex> lock(mutex);
		
		++times_called;
		if(++num_active > max_active)
		{
			max_active = num_active;
		}
		
		lock.unlock();
		
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
		
		lock.lock();
		
		--num_active;
		return times_called >= 10;
	}, 4);
	
	task.join(); /* Wait for task to complete. */
	
	/* Parallel tasks can inherently race here, so we test it was called at least as many as
	 * expected and not excessively so.
	*/
	EXPECT_GE(times_called, 10U) << "Task function was called correct number of times";
	EXPECT_LT(times_called, 14U) << "Task function was called correct number of times";
	
	EXPECT_EQ(max_active, 4U) << "Task function was not called in parallel";
}

TEST(ThreadPool, PauseTask)
{
	ThreadPool pool(8);
	
	std::mutex mutex;
	unsigned int times_called = 0; 
	unsigned int num_active = 0;
	bool finished = false;
	
	ThreadPool::TaskHandle task = pool.queue_task([&]()
	{
		std::unique_lock<std::mutex> lock(mutex);
		
		++times_called;
		++num_active;
		
		lock.unlock();
		
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		
		lock.lock();
		
		--num_active;
		return finished;
	}, 4);
	
	/* Yield for a moment so the workers can wake up. */
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	
	/* Verify some threads started. */
	mutex.lock();
	EXPECT_GT(times_called, 0U);
	EXPECT_GT(num_active, 0U);
	mutex.unlock();
	
	task.pause();
	
	/* Verify all workers stopped being called. */
	
	mutex.lock();
	unsigned int paused_times_called = times_called;
	EXPECT_EQ(num_active, 0U) << "Task function is not called when task is paused";
	mutex.unlock();
	
	/* Yield for a moment in case the workers are still running. */
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	
	mutex.lock();
	EXPECT_EQ(times_called, paused_times_called) << "Task function is not called when task is paused";
	EXPECT_EQ(num_active, 0U) << "Task function is not called when task is paused";
	mutex.unlock();
	
	task.resume();
	
	/* Yield for a moment so the workers can wake up. */
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	
	/* Verify workers are working again. */
	
	mutex.lock();
	EXPECT_GT(times_called, paused_times_called) << "Task function is called after task is resumed";
	EXPECT_GT(num_active, 0U) << "Task function is called after task is resumed";
	mutex.unlock();
	
	finished = true;
	task.join(); /* Wait for task to complete. */
}

TEST(ThreadPool, FinishTaskEarly)
{
	ThreadPool pool(8);
	
	std::mutex mutex;
	unsigned int times_called = 0; 
	unsigned int num_active = 0;
	bool finished = false;
	
	ThreadPool::TaskHandle task = pool.queue_task([&]()
	{
		std::unique_lock<std::mutex> lock(mutex);
		
		++times_called;
		++num_active;
		
		lock.unlock();
		
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		
		lock.lock();
		
		--num_active;
		return finished;
	}, 4);
	
	/* Yield for a moment so the workers can wake up. */
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	
	/* Verify some threads started. */
	mutex.lock();
	EXPECT_GT(times_called, 0U);
	EXPECT_GT(num_active, 0U);
	mutex.unlock();
	
	task.finish();
	
	/* Give the workers some time to stop. */
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	
	mutex.lock();
	unsigned int finished_times_called = times_called;
	EXPECT_EQ(num_active, 0U) << "Task function is not called when task has been finished early";
	mutex.unlock();
	
	/* Yield for a moment in case the workers are still running. */
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	
	mutex.lock();
	EXPECT_EQ(times_called, finished_times_called) << "Task function is not called when task has been finished early";
	EXPECT_EQ(num_active, 0U) << "Task function is not called when task has been finished early";
	mutex.unlock();
	
	finished = true;
	task.join(); /* Wait for task to complete. */
}

TEST(ThreadPool, RestartTask)
{
	ThreadPool pool(8);
	
	std::mutex mutex;
	unsigned int times_called = 0; 
	unsigned int num_active = 0;
	
	ThreadPool::TaskHandle task = pool.queue_task([&]()
	{
		std::unique_lock<std::mutex> lock(mutex);
		
		++times_called;
		++num_active;
		
		lock.unlock();
		
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		
		lock.lock();
		
		--num_active;
		return true;
	}, 1);
	
	/* Yield for a moment so the workers can wake up. */
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	
	mutex.lock();
	EXPECT_EQ(times_called, 1U) << "Task function was called";
	EXPECT_EQ(num_active, 0U) << "Task function is not running";
	EXPECT_TRUE(task.finished()) << "Task is finished";
	mutex.unlock();
	
	/* Yield for a moment in case the workers are still running. */
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	
	mutex.lock();
	EXPECT_EQ(times_called, 1U) << "Task function was called";
	EXPECT_EQ(num_active, 0U) << "Task function is not running";
	EXPECT_TRUE(task.finished()) << "Task is finished";
	mutex.unlock();
	
	/* Restart the task. */
	task.restart();
	
	/* Yield for a moment so the workers can wake up. */
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	
	mutex.lock();
	EXPECT_EQ(times_called, 2U) << "Task function was called";
	EXPECT_EQ(num_active, 0U) << "Task function is not running";
	EXPECT_TRUE(task.finished()) << "Task is finished";
	mutex.unlock();
	
	/* Yield for a moment in case the workers are still running. */
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	
	mutex.lock();
	EXPECT_EQ(times_called, 2U) << "Task function was called";
	EXPECT_EQ(num_active, 0U) << "Task function is not running";
	EXPECT_TRUE(task.finished()) << "Task is finished";
	mutex.unlock();
	
	task.join(); /* Wait for task to complete. */
}

TEST(ThreadPool, RestartPausedTask)
{
	ThreadPool pool(8);
	
	std::mutex mutex;
	unsigned int times_called = 0;
	unsigned int num_active = 0;
	
	ThreadPool::TaskHandle task = pool.queue_task([&]()
	{
		std::unique_lock<std::mutex> lock(mutex);
		
		++times_called;
		++num_active;
		
		lock.unlock();
		
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		
		lock.lock();
		
		--num_active;
		return true;
	}, 1);
	
	/* Yield for a moment so the workers can wake up. */
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	
	mutex.lock();
	EXPECT_EQ(times_called, 1U) << "Task function was called";
	EXPECT_EQ(num_active, 0U) << "Task function is not running";
	EXPECT_TRUE(task.finished()) << "Task is finished";
	mutex.unlock();
	
	/* Yield for a moment in case the workers are still running. */
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	
	mutex.lock();
	EXPECT_EQ(times_called, 1U) << "Task function was called";
	EXPECT_EQ(num_active, 0U) << "Task function is not running";
	EXPECT_TRUE(task.finished()) << "Task is finished";
	mutex.unlock();
	
	/* Pause and restart the task. */
	task.pause();
	task.restart();
	
	/* Yield for a moment so the workers can wake up. */
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	
	mutex.lock();
	EXPECT_EQ(times_called, 1U) << "Task function was called";
	EXPECT_EQ(num_active, 0U) << "Task function is not running";
	EXPECT_FALSE(task.finished()) << "Task is not finished";
	mutex.unlock();
	
	/* Resume the restarted task, execution will finally resume. */
	task.resume();
	
	/* Yield for a moment so the workers can wake up. */
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	
	mutex.lock();
	EXPECT_EQ(times_called, 2U) << "Task function was called";
	EXPECT_EQ(num_active, 0U) << "Task function is not running";
	EXPECT_TRUE(task.finished()) << "Task is finished";
	mutex.unlock();
	
	/* Yield for a moment in case the workers are still running. */
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	
	mutex.lock();
	EXPECT_EQ(times_called, 2U) << "Task function was called";
	EXPECT_EQ(num_active, 0U) << "Task function is not running";
	EXPECT_TRUE(task.finished()) << "Task is finished";
	mutex.unlock();
	
	task.join(); /* Wait for task to complete. */
}

TEST(ThreadPool, ParallelTasks)
{
	ThreadPool pool(8);
	
	std::mutex mutex;
	unsigned int t1_times_called = 0, t2_times_called = 0;
	unsigned int t1_num_active = 0, t2_num_active = 0;
	unsigned int t1_max_active = 0, t2_max_active = 0;
	bool t1_finished = false, t2_finished = false;
	
	ThreadPool::TaskHandle task1 = pool.queue_task([&]()
	{
		std::unique_lock<std::mutex> lock(mutex);
		
		++t1_times_called;
		if(++t1_num_active > t1_max_active)
		{
			t1_max_active = t1_num_active;
		}
		
		lock.unlock();
		
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		
		lock.lock();
		
		--t1_num_active;
		return t1_finished;
	}, -1);
	
	ThreadPool::TaskHandle task2 = pool.queue_task([&]()
	{
		std::unique_lock<std::mutex> lock(mutex);
		
		++t2_times_called;
		if(++t2_num_active > t2_max_active)
		{
			t2_max_active = t2_num_active;
		}
		
		lock.unlock();
		
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		
		lock.lock();
		
		--t2_num_active;
		return t2_finished;
	}, -1);
	
	/* Yield for a moment so the workers can wake up. */
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	
	mutex.lock();
	EXPECT_GT(t1_times_called, 0U) << "Task 1 function was called";
	EXPECT_GT(t1_max_active, 2U) << "Task 1 function was given at least 25% of worker time";
	EXPECT_GT(t2_times_called, 0U) << "Task 2 function was called";
	EXPECT_GT(t2_max_active, 2U) << "Task 2 function was given at least 25% of worker time";
	mutex.unlock();
	
	t1_finished = true;
	t2_finished = true;
	
	task1.join(); /* Wait for task to complete. */
	task2.join(); /* Wait for task to complete. */
}

TEST(ThreadPool, ParallelTasksPriority)
{
	ThreadPool pool(8);
	
	std::mutex mutex;
	unsigned int t1_times_called = 0, t2_times_called = 0;
	unsigned int t1_num_active = 0, t2_num_active = 0;
	unsigned int t1_max_active = 0, t2_max_active = 0;
	bool t1_finished = false, t2_finished = false;
	
	ThreadPool::TaskHandle task1 = pool.queue_task([&]()
	{
		std::unique_lock<std::mutex> lock(mutex);
		
		++t1_times_called;
		if(++t1_num_active > t1_max_active)
		{
			t1_max_active = t1_num_active;
		}
		
		lock.unlock();
		
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		
		lock.lock();
		
		--t1_num_active;
		return t1_finished;
	}, -1, ThreadPool::TaskPriority::HIGH);
	
	ThreadPool::TaskHandle task2 = pool.queue_task([&]()
	{
		std::unique_lock<std::mutex> lock(mutex);
		
		++t2_times_called;
		if(++t2_num_active > t2_max_active)
		{
			t2_max_active = t2_num_active;
		}
		
		lock.unlock();
		
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		
		lock.lock();
		
		--t2_num_active;
		return t2_finished;
	}, -1, ThreadPool::TaskPriority::NORMAL);
	
	/* Yield for a moment so the workers can wake up. */
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	
	mutex.lock();
	EXPECT_GT(t1_times_called, 0U) << "High priority function was called";
	EXPECT_EQ(t1_max_active, 8U) << "High priority task was given 100% of worker threads";
	EXPECT_EQ(t2_times_called, 0U) << "Normal priority function wasn't called while high priority task was active";
	EXPECT_EQ(t2_max_active, 0U) << "Normal priority function wasn't called while high priority task was active";
	mutex.unlock();
	
	/* Finish the high priority task. */
	t1_finished = true;
	task1.join();
	
	/* Yield for a moment so the workers can service task 2 for a bit. */
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	
	mutex.lock();
	EXPECT_GT(t2_times_called, 0U) << "Normal priority function was called once high priority task finished";
	EXPECT_EQ(t2_max_active, 8U) << "Normal priority task was given 100% of worker threads";
	mutex.unlock();
	
	t2_finished = true;
	task2.join();
}

TEST(ThreadPool, ParallelTasksPrioritySpareThreads)
{
	ThreadPool pool(8);
	
	std::mutex mutex;
	unsigned int t1_times_called = 0, t2_times_called = 0;
	unsigned int t1_num_active = 0, t2_num_active = 0;
	unsigned int t1_max_active = 0, t2_max_active = 0;
	bool t1_finished = false, t2_finished = false;
	
	ThreadPool::TaskHandle task1 = pool.queue_task([&]()
	{
		std::unique_lock<std::mutex> lock(mutex);
		
		++t1_times_called;
		if(++t1_num_active > t1_max_active)
		{
			t1_max_active = t1_num_active;
		}
		
		lock.unlock();
		
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		
		lock.lock();
		
		--t1_num_active;
		return t1_finished;
	}, 6, ThreadPool::TaskPriority::HIGH);
	
	ThreadPool::TaskHandle task2 = pool.queue_task([&]()
	{
		std::unique_lock<std::mutex> lock(mutex);
		
		++t2_times_called;
		if(++t2_num_active > t2_max_active)
		{
			t2_max_active = t2_num_active;
		}
		
		lock.unlock();
		
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		
		lock.lock();
		
		--t2_num_active;
		return t2_finished;
	}, -1, ThreadPool::TaskPriority::NORMAL);
	
	/* Yield for a moment so the workers can wake up. */
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	
	mutex.lock();
	EXPECT_GT(t1_times_called, 0U) << "High priority function was called";
	EXPECT_EQ(t1_max_active, 6U) << "High priority task was executed with requested concurrency";
	EXPECT_GT(t2_times_called, 0U) << "Normal priority function was called";
	EXPECT_LE(t2_max_active, 2U) << "Normal priority function was executed on threads not required by high priority task only";
	mutex.unlock();
	
	/* Finish the high priority task. */
	t1_finished = true;
	task1.join();
	
	/* Yield for a moment so the workers can service task 2 for a bit. */
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	
	mutex.lock();
	EXPECT_GT(t2_times_called, 0U) << "Normal priority function was called once high priority task finished";
	EXPECT_EQ(t2_max_active, 8U) << "Normal priority task was given 100% of worker threads";
	mutex.unlock();
	
	t2_finished = true;
	task2.join();
}

TEST(ThreadPool, ChangeTaskConcurrency)
{
	ThreadPool pool(8);
	
	std::mutex mutex;
	unsigned int num_active = 0;
	unsigned int max_active = 0;
	bool finished = false;
	
	ThreadPool::TaskHandle task = pool.queue_task([&]()
	{
		std::unique_lock<std::mutex> lock(mutex);
		
		if(++num_active > max_active)
		{
			max_active = num_active;
		}
		
		lock.unlock();
		
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		
		lock.lock();
		
		--num_active;
		return finished;
	}, 1);
	
	/* Yield for a moment so the workers can wake up. */
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	
	mutex.lock();
	EXPECT_EQ(max_active, 1U) << "Task function was not called in parallel";
	mutex.unlock();
	
	/* Scale task up. */
	task.change_concurrency(4);
	
	/* Wait for task to run a bit... */
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	
	mutex.lock();
	EXPECT_EQ(max_active, 4U) << "Task function was executed in parallel";
	mutex.unlock();
	
	/* Scale down. */
	task.change_concurrency(2);
	
	/* Wait for the workers to settle... */
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	
	mutex.lock();
	max_active = 0;
	mutex.unlock();
	
	/* Wait for max_active to settle... */
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	
	mutex.lock();
	EXPECT_EQ(max_active, 2U) << "Task function was executed in parallel";
	mutex.unlock();
	
	finished = true;
	task.join();
}
