/* Reverse Engineer's Hex Editor
 * Copyright (C) 2023-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <algorithm>
#include <assert.h>

#include "profile.hpp"
#include "ThreadPool.hpp"

REHex::ThreadPool::ThreadPool(unsigned int num_threads):
	stopping(false)
{
	rescale(num_threads);
}

REHex::ThreadPool::~ThreadPool()
{
	assert(!in_worker_thread());
	clear_threads();
}

void REHex::ThreadPool::rescale(unsigned int num_threads)
{
	assert(!in_worker_thread());
	
	clear_threads();
	
	workers.reserve(num_threads);
	
	/* Ensure no threads can start executing tasks, which could try invoking a TaskHandle
	 * method that needs to examine the workers array before it is fully populated.
	*/
	std::unique_lock<shared_mutex> lock(task_queues_mutex);
	
	while(workers.size() < num_threads)
	{
		workers.emplace_back([&]() { worker_main(); });
	}
}

void REHex::ThreadPool::clear_threads()
{
	task_queues_mutex.lock();
	stopping = true;
	task_queues_mutex.unlock();
	task_queues_cv.notify_all();
	
	for(auto t = workers.begin(); t != workers.end(); ++t)
	{
		t->join();
	}
	
	workers.clear();
	
	stopping = false;
}

REHex::ThreadPool::TaskHandle REHex::ThreadPool::queue_task(const std::function<bool()> &func, int max_concurrency, TaskPriority priority)
{
	assert(!in_worker_thread());
	
	std::vector<Task*> &queue = task_queues[ (size_t)(priority) ];
	
	Task *task = new Task(func, max_concurrency);
	size_t task_idx;
	
	task_queues_mutex.lock();
	
	auto null_iter = std::find(queue.begin(), queue.end(), nullptr);
	if(null_iter != queue.end())
	{
		*null_iter = task;
		task_idx = std::distance(queue.begin(), null_iter);
	}
	else{
		task_idx = queue.size();
		queue.push_back(task);
	}
	
	task_queues_mutex.unlock();
	task_queues_cv.notify_all();
	
	return TaskHandle(task, this, priority, task_idx);
}

REHex::ThreadPool::TaskHandle REHex::ThreadPool::queue_task(const std::function<void()> &func, TaskPriority priority)
{
	assert(!in_worker_thread());
	
	return queue_task([func]()
	{
		func();
		return true;
	}, 1, priority);
}

void REHex::ThreadPool::worker_main()
{
	PROFILE_SET_THREAD_GROUP(POOL);
	
	bool work_available = true;
	
	shared_lock task_queues_lock(task_queues_mutex);
	
	size_t task_indices[] = { 0, 0, 0, 0 };
	
	while(!stopping)
	{
		if(!work_available)
		{
			PROFILE_BLOCK("ThreadPool worker idle");
			task_queues_cv.wait(task_queues_lock);
		}
		
		work_available = false;
		
		for(int i = 0; i < 4 && !work_available; ++i)
		{
			std::vector<Task*> &queue = task_queues[i];
			
			/* Loop over all the tasks at this priority level until we find one that
			 * is ready to ber serviced, starting after the last task we serviced at
			 * the same priority to ensure even distribution of worker time between
			 * high numbers of tasks.
			 *
			 * We return to the outer loop after servicing a single task so that any
			 * higher-priority tasks which have become ready since the loop began will
			 * preempt any further processing of lower-priority ones.
			*/
			
			for(size_t j = 0; j < queue.size() && !work_available; ++j, ++(task_indices[i]))
			{
				assert(task_indices[i] <= queue.size());
				
				if(task_indices[i] == queue.size())
				{
					task_indices[i] = 0;
				}
				
				Task *task = queue[ task_indices[i] ];
				if(task == NULL)
				{
					continue;
				}
				
				shared_lock task_lock(task->task_mutex);
				
				if(task->finished.load() || task->paused.load())
				{
					continue;
				}
				
				int max_concurrency = task->max_concurrency.load();
				
				{
					std::unique_lock<std::mutex> cc_lock(task->concurrency_mutex);
					
					if(++(task->current_concurrency) > max_concurrency && max_concurrency >= 0)
					{
						--(task->current_concurrency);
						continue;
					}
				}
				
				unsigned int old_restart_count = task->restart_count;
				
				task_queues_lock.unlock();
				
				bool now_finished;
				{
					PROFILE_BLOCK("ThreadPool task function");
					now_finished = task->func();
				}
				
				task_queues_lock.lock();
				
				unsigned int new_restart_count = task->restart_count;
				
				if(new_restart_count == old_restart_count)
				{
					if(now_finished)
					{
						task->finished = true;
						task->finished_cv.notify_all();
					}
					else{
						task->finished = false;
					}
				}
				
				work_available = true;
				
				{
					std::unique_lock<std::mutex> cc_lock(task->concurrency_mutex);
					--(task->current_concurrency);
				}
			}
		}
	}
}

#ifndef NDEBUG
bool REHex::ThreadPool::in_worker_thread() const
{
	return std::find_if(workers.begin(), workers.end(),
		[](const std::thread &t) { return t.get_id() == std::this_thread::get_id(); }) != workers.end();
}
#endif

REHex::ThreadPool::TaskHandle::TaskHandle(Task *task, ThreadPool *pool, TaskPriority priority, size_t task_idx):
	task(task),
	pool(pool),
	priority(priority),
	task_idx(task_idx) {}

REHex::ThreadPool::TaskHandle::TaskHandle():
	task(NULL),
	pool(NULL),
	task_idx(-1) {}

REHex::ThreadPool::TaskHandle::TaskHandle(TaskHandle &&handle):
	task(handle.task),
	pool(handle.pool),
	priority(handle.priority),
	task_idx(handle.task_idx)
{
	handle.task = NULL;
	handle.pool = NULL;
	handle.task_idx = -1;
}

REHex::ThreadPool::TaskHandle &REHex::ThreadPool::TaskHandle::operator=(TaskHandle &&handle)
{
	assert(task == NULL);
	
	task = handle.task;
	pool = handle.pool;
	priority = handle.priority;
	task_idx = handle.task_idx;
	
	handle.task = NULL;
	handle.pool = NULL;
	handle.task_idx = -1;
	
	return *this;
}

REHex::ThreadPool::TaskHandle::~TaskHandle()
{
	/* Ensure join() was called. */
	assert(task == NULL);
}

REHex::ThreadPool::TaskHandle::operator bool() const
{
	return task != NULL;
}

bool REHex::ThreadPool::TaskHandle::finished() const
{
	assert(task != NULL);
	return task->finished.load();
}

void REHex::ThreadPool::TaskHandle::join()
{
	PROFILE_BLOCK("REHex::ThreadPool::TaskHandle::join");
	
	assert(task != NULL);
	assert(!pool->in_worker_thread());
	
	{
		PROFILE_INNER_BLOCK("waiting for task to finish");
		
		std::unique_lock<shared_mutex> lock(pool->task_queues_mutex);
		task->finished_cv.wait(lock, [&]()
		{
			return task->finished.load();
		});
	}
	
	{
		PROFILE_INNER_BLOCK("removing task from queue");
		
		std::unique_lock<shared_mutex> lock(pool->task_queues_mutex);
		
		assert(pool->task_queues[ (size_t)(priority) ][task_idx] == task);
		pool->task_queues[ (size_t)(priority) ][task_idx] = NULL;
	}
	
	/* worker_main claims a shared lock on task_mutex before releasing its lock on
	 * task_queues_mutex, since we held that exclusively while removing the Task from the
	 * queue, we just need to exclusively cycle the lock on task_mutex to know no workers
	 * still hold it.
	*/
	
	{
		PROFILE_INNER_BLOCK("destroying task");
		
		task->task_mutex.lock();
		task->task_mutex.unlock();
		delete task;
	}
	
	task = NULL;
	pool = NULL;
	task_idx = -1;
}

void REHex::ThreadPool::TaskHandle::pause()
{
	assert(task != NULL);
	assert(!pool->in_worker_thread());
	assert(!task->paused.load());
	
	pool->task_queues_mutex.lock();
	task->paused = true;
	pool->task_queues_mutex.unlock();
	
	task->task_mutex.lock();
	task->task_mutex.unlock();
}

void REHex::ThreadPool::TaskHandle::resume()
{
	assert(task != NULL);
	assert(!pool->in_worker_thread());
	assert(task->paused.load());
	
	pool->task_queues_mutex.lock();
	task->paused = false;
	pool->task_queues_mutex.unlock();
	
	pool->task_queues_cv.notify_all();
}

bool REHex::ThreadPool::TaskHandle::paused() const
{
	assert(task != NULL);
	
	return task->paused.load();
}

void REHex::ThreadPool::TaskHandle::finish()
{
	assert(task != NULL);
	assert(!pool->in_worker_thread());
	
	pool->task_queues_mutex.lock();
	++(task->restart_count);
	task->finished = true;
	pool->task_queues_mutex.unlock();
	
	task->finished_cv.notify_all();
}

void REHex::ThreadPool::TaskHandle::restart()
{
	assert(task != NULL);
	assert(!pool->in_worker_thread());
	
	pool->task_queues_mutex.lock();
	++(task->restart_count);
	task->finished = false;
	pool->task_queues_mutex.unlock();
	
	pool->task_queues_cv.notify_all();
}

void REHex::ThreadPool::TaskHandle::change_concurrency(int max_concurrency)
{
	assert(task != NULL);
	assert(!pool->in_worker_thread());
	
	pool->task_queues_mutex.lock();
	task->max_concurrency = max_concurrency;
	pool->task_queues_mutex.unlock();
	
	pool->task_queues_cv.notify_all();
}
