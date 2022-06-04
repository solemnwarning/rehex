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

#ifndef REHEX_PROFILECOLLECTOR_HPP
#define REHEX_PROFILECOLLECTOR_HPP

#ifdef REHEX_PROFILE

#include <list>
#include <set>
#include <string>
#include <wx/dataview.h>
#include <wx/frame.h>
#include <wx/longlong.h>
#include <wx/timer.h>
#include <wx/window.h>

#define PROFILE_BLOCK(name) \
	static ProfilingCollector block_collector(name); \
	AutoBlockProfiler abp(&block_collector);

namespace REHex
{
	class ProfilingCollector
	{
		private:
			static std::list<ProfilingCollector*> *collectors;
			
			std::list<ProfilingCollector*>::iterator this_iter;
			
			std::string key;
			wxLongLong min_time, max_time, total_time;
			unsigned int num_samples;
			
		public:
			ProfilingCollector(const std::string &key);
			~ProfilingCollector();
			
			const std::string &get_key() const;
			wxLongLong get_min_time() const;
			wxLongLong get_max_time() const;
			wxLongLong get_total_time() const;
			wxLongLong get_avg_time() const;
			unsigned int get_num_samples() const;
			
			void record_time(wxLongLong t);
			void reset();
			
			static std::list<ProfilingCollector*> get_collectors();
			static void reset_collectors();
	};
	
	class AutoBlockProfiler
	{
		private:
			ProfilingCollector *collector;
			wxLongLong start_time;
			
		public:
			AutoBlockProfiler(ProfilingCollector *collector);
			~AutoBlockProfiler();
	};
	
	class ProfilingDataViewModel: public wxDataViewModel
	{
		private:
			std::set<ProfilingCollector*> added;
			
		public:
			void update();
			
			static ProfilingCollector *dv_item_to_collector(const wxDataViewItem &item);
			
			virtual int Compare(const wxDataViewItem &item1, const wxDataViewItem &item2, unsigned int column, bool ascending) const override;
			virtual unsigned int GetChildren(const wxDataViewItem &item, wxDataViewItemArray &children) const override;
			virtual unsigned int GetColumnCount() const override;
			virtual wxString GetColumnType(unsigned int col) const override;
			virtual wxDataViewItem GetParent(const wxDataViewItem &item) const override;
			virtual void GetValue(wxVariant &variant, const wxDataViewItem &item, unsigned int col) const override;
			virtual bool IsContainer(const wxDataViewItem &item) const override;
			virtual bool SetValue(const wxVariant &variant, const wxDataViewItem &item, unsigned int col) override;
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
#define PROFILE_BLOCK(name)

#endif /* !REHEX_PROFILE */

#endif /* !REHEX_PROFILECOLLECTOR_HPP */
