/* Reverse Engineer's Hex Editor
 * Copyright (C) 2022-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_PROFILECOLLECTOR_HPP
#define REHEX_PROFILECOLLECTOR_HPP

#ifdef REHEX_PROFILE

#include <list>
#include <map>
#include <mutex>
#include <stdint.h>
#include <string>
#include <wx/dataview.h>
#include <wx/frame.h>
#include <wx/longlong.h>
#include <wx/timer.h>
#include <wx/window.h>

#define PROFILE_SET_THREAD_GROUP(group) \
	ProfilingCollector::set_thread_group(ProfilingCollector::ThreadGroup::group);

#define PROFILE_BLOCK(name) \
	static ProfilingCollector block_collector(name); \
	AutoBlockProfiler abp(&block_collector);

#define PROFILE_INNER_BLOCK(name) \
	static ProfilingCollector *block_collector_parent = &block_collector; \
	static ProfilingCollector block_collector(name, block_collector_parent); \
	AutoBlockProfiler abp(&block_collector);

namespace REHex
{
	class ProfilingCollector
	{
		public:
			enum class ThreadGroup
			{
				MAIN,
				POOL,
				
				UNKNOWN, /* This must remain at the end of the valid groups. */
				NONE, /**< Thread is excluded from profiling. */
			};
			
			struct Stats
			{
				uint64_t min_time, max_time, total_time;
				unsigned int num_samples;
				
				Stats();
				
				uint64_t get_avg_time() const;
				
				void record_time(uint64_t duration);
				void reset();
				
				Stats &operator+=(const Stats &rhs);
			};
			
		private:
			static std::list<ProfilingCollector*> *collectors;
			static thread_local ThreadGroup thread_group;
			
			std::list<ProfilingCollector*>::iterator this_iter;
			
			std::string key;
			
			static const uint64_t SLOT_DURATION_MS = 1000;
			static const size_t NUM_SLOTS = 60;
			
			struct ThreadGroupStats
			{
				mutable std::mutex mutex;
				
				Stats slots[NUM_SLOTS];
				uint64_t head_time_bucket;
				
				ThreadGroupStats():
					head_time_bucket(0) {}
				
				void reset(const std::unique_lock<std::mutex> &mutex_guard, size_t begin_idx = 0, size_t end_idx = NUM_SLOTS);
			};
			
			ThreadGroupStats tg_stats[ (size_t)(ThreadGroup::UNKNOWN) ];
			
			void reset(size_t begin_idx = 0, size_t end_idx = NUM_SLOTS);
			
		public:
			ProfilingCollector(const std::string &key, ProfilingCollector *parent = NULL);
			~ProfilingCollector();
			
			ProfilingCollector* const parent;
			
			const std::string &get_key() const;
			
			Stats accumulate_stats(ThreadGroup group, unsigned int window_duration_ms) const;
			
			void record_time(uint64_t begin_time, uint64_t duration);
			
			static void set_thread_group(ThreadGroup thread_group);
			
			static std::list<ProfilingCollector*> get_collectors(ThreadGroup group);
			static void reset_collectors();
			
			static uint64_t get_monotonic_us();
	};
	
	class AutoBlockProfiler
	{
		private:
			ProfilingCollector *collector;
			uint64_t start_time;
			
		public:
			AutoBlockProfiler(ProfilingCollector *collector);
			~AutoBlockProfiler();
	};
	
	class ProfilingDataViewModel: public wxDataViewModel
	{
		private:
			typedef std::pair<ProfilingCollector* const, ProfilingCollector::Stats> stats_elem_t;
			
			std::map<ProfilingCollector*, ProfilingCollector::Stats> stats;
			unsigned int duration_ms;
			ProfilingCollector::ThreadGroup thread_group;
			
			static stats_elem_t *dv_item_to_stats_elem(const wxDataViewItem &item);
			
		public:
			ProfilingDataViewModel();
			
			void set_duration(unsigned int duration_ms);
			void set_thread_group(ProfilingCollector::ThreadGroup group);
			void update();
			
			virtual int Compare(const wxDataViewItem &item1, const wxDataViewItem &item2, unsigned int column, bool ascending) const override;
			virtual unsigned int GetChildren(const wxDataViewItem &item, wxDataViewItemArray &children) const override;
			virtual unsigned int GetColumnCount() const override;
			virtual wxString GetColumnType(unsigned int col) const override;
			virtual wxDataViewItem GetParent(const wxDataViewItem &item) const override;
			virtual void GetValue(wxVariant &variant, const wxDataViewItem &item, unsigned int col) const override;
			virtual bool IsContainer(const wxDataViewItem &item) const override;
			virtual bool SetValue(const wxVariant &variant, const wxDataViewItem &item, unsigned int col) override;
			virtual bool HasContainerColumns(const wxDataViewItem &item) const override;
	};
	
	class ProfilingWindow: public wxFrame
	{
		public:
			ProfilingWindow(wxWindow *parent);
			
		private:
			wxTimer update_timer;
	};
}

#else /* REHEX_PROFILE */

/* Stub out profiling hook when profiling is disabled. */
#define PROFILE_SET_THREAD_GROUP(group)
#define PROFILE_BLOCK(name)
#define PROFILE_INNER_BLOCK(name)

#endif /* !REHEX_PROFILE */

#endif /* !REHEX_PROFILECOLLECTOR_HPP */
