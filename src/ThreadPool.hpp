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

#ifndef REHEX_THREADPOOL_HPP
#define REHEX_THREADPOOL_HPP

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

#include "shared_mutex.hpp"

namespace REHex
{
	/**
	 * @brief A thread pool manager for background processing.
	*/
	class ThreadPool
	{
		public:
			enum class TaskPriority
			{
				UI = 0,
				
				HIGH = 1,
				NORMAL = 2,
				LOW = 3,
			};
			
		private:
			struct Task
			{
				std::function<bool()> func;
				
				std::atomic<int> max_concurrency;
				
				/* TODO: Use a semaphore under C++20. */
				int current_concurrency;
				std::mutex concurrency_mutex;
				
				shared_mutex task_mutex;
				std::condition_variable_any finished_cv;
				std::atomic<bool> finished;
				std::atomic<bool> paused;
				unsigned int restart_count;
				
				Task(const std::function<bool()> &func, int max_concurrency):
					func(func),
					max_concurrency(max_concurrency),
					current_concurrency(0),
					finished(false),
					paused(false),
					restart_count(0) {}
			};
			
			shared_mutex task_queues_mutex;
			std::condition_variable_any task_queues_cv;
			std::vector<Task*> task_queues[4];
			
			volatile bool stopping;
			std::vector<std::thread> workers;
		
		public:
			/**
			 * @brief A handle to a running task.
			 *
			 * Once created, a background task MUST be cleaned up (using join()) before
			 * the TaskHandle is destroyed.
			*/
			class TaskHandle
			{
				friend ThreadPool;
				
				private:
					Task *task;
					
					ThreadPool *pool;
					TaskPriority priority;
					size_t task_idx;
					
					TaskHandle(Task *task, ThreadPool *pool, TaskPriority priority, size_t task_idx);
					
				public:
					TaskHandle();
					
					TaskHandle(TaskHandle&&);
					TaskHandle(const TaskHandle&) = delete;
					
					TaskHandle &operator=(TaskHandle&&);
					TaskHandle &operator=(const TaskHandle&) = delete;
					
					~TaskHandle();
					
					operator bool() const;
					
					/**
					 * @brief Wait for the task to finish and clean up.
					 *
					 * This method will block until the associated task has
					 * finished and clean up the associated data structures in
					 * the ThreadPool object.
					 *
					 * No other methods on this object should be called after
					 * calling this.
					*/
					void join();
					
					/* Not implemented yet... */
					// void detach();
					
					/**
					 * @brief Check if the task has finished.
					*/
					bool finished() const;
					
					/**
					 * @brief Pause the task.
					 *
					 * This method will mark the task as paused, preventing the
					 * registered function from being called.
					 *
					 * If any workers are currently running the task's function
					 * then the method will block until they finish.
					*/
					void pause();
					
					/**
					 * @brief Undo the effects of pause().
					*/
					void resume();
					
					/**
					 * @brief Check if the task is paused.
					*/
					bool paused() const;
					
					/**
					 * @brief Finish the task early.
					 *
					 * This method will mark the task as finished, preventing
					 * the registered function from being called again and
					 * allowing it to be destroyed before it finishes.
					 *
					 * This method does not block and calling join() afterwards
					 * may still block until any in-progress calls finish.
					*/
					void finish();
					
					/**
					 * @brief Restart the task.
					 *
					 * This method will ensure the task is eligible to run,
					 * even if it has finished.
					 *
					 * When this method is called, any already-active task
					 * functions returning true will be ignored - this is to
					 * avoid any race conditions between the main thread
					 * restarting a task and the task finishing, tasks must be
					 * safe to call again after returning true if you use this
					 * method.
					 *
					 * Paused tasks will remain paused.
					*/
					void restart();
					
					void change_concurrency(int max_concurrency);
			};
			
			friend TaskHandle;
			
			/**
			 * @brief Construct a new ThreadPool and start worker threads.
			 *
			 * @param num_threads Number of worker threads to start.
			*/
			ThreadPool(unsigned int num_threads);
			
			~ThreadPool();
			
			/**
			 * @brief Change the number of worker threads.
			 *
			 * @param num_threads Number of worker threads to start.
			 *
			 * Stops all workers, then spins up the new desired number of workers.
			*/
			void rescale(unsigned int num_threads);
			
			/**
			 * @brief Queue a task to be run on one or more worker threads.
			 *
			 * @param func             The function to run in the worker thread(s).
			 * @param max_concurrency  Maximum number of instances to run in parallel.
			 * @param priority         Priority level for the task.
			 *
			 * This method adds a task to the queue to be run in any available worker
			 * threads.
			 *
			 * Ideally, tasks should perform a small chunk of work and then yield back
			 * to the worker thread by returning so other tasks can be serviced. The
			 * task function will keep getting called until it returns true to indicate
			 * it has finished its work.
			 *
			 * Long-running tasks can potentially hang the application while the UI
			 * thread tries to synchronise with other blocked tasks.
			 *
			 * If max_concurrency is >1, then the function will be called in multiple
			 * threads at the same time and it must deal with synchronising any shared
			 * resources itself.
			 *
			 * Tasks will be run in order of priority - so long as a higher-priority
			 * task exists, lower-priority ones will not run until the higher-priority
			 * one(s) are finished.
			 *
			 * The returned TaskHandle object may be used to poll the task state or
			 * block until completion. You MUST wait for the task or detach it before
			 * the TaskHandle object is destroyed.
			*/
			TaskHandle queue_task(const std::function<bool()> &func, int max_concurrency = 1, TaskPriority priority = TaskPriority::NORMAL);
			
			/**
			 * @brief Queue a one-shot function to run in a worker thread.
			 *
			 * @param func      The function to run in the worker thread.
			 * @param priority  Priority level for the task.
			 *
			 * This is a specialisation of queue_task() mainly intended for running
			 * concurrent workloads for the UI thread which may run in parallel, but
			 * not themselves be broken up into parallel chunks.
			 *
			 * The function will only be called once and the task will finish once it
			 * returns.
			 */
			TaskHandle queue_task(const std::function<void()> &func, TaskPriority priority = TaskPriority::NORMAL);
			
		private:
			void worker_main();
			void clear_threads();
			
			#ifndef NDEBUG
			/**
			 * @brief Check if the caller is running in a worker thread.
			 *
			 * This method returns true if called from one of the worker threads.
			 *
			 * This method is only available in debug builds.
			*/
			bool in_worker_thread() const;
			#endif
	};
}

#endif /* !REHEX_THREADPOOL_HPP */
