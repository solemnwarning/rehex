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

#include "platform.hpp"

#include <wx/button.h>
#include <wx/checkbox.h>
#include <wx/radiobut.h>
#include <wx/sizer.h>
#include <wx/time.h>

#include "profile.hpp"

#ifdef REHEX_PROFILE

std::list<REHex::ProfilingCollector*> *REHex::ProfilingCollector::collectors = NULL;
thread_local REHex::ProfilingCollector::ThreadGroup REHex::ProfilingCollector::thread_group = REHex::ProfilingCollector::ThreadGroup::UNKNOWN;

void REHex::ProfilingCollector::set_thread_group(ThreadGroup thread_group)
{
	/* Thread group may only be set once per thread. */
	if(REHex::ProfilingCollector::thread_group != REHex::ProfilingCollector::ThreadGroup::UNKNOWN)
	{
		abort();
	}
	
	REHex::ProfilingCollector::thread_group = thread_group;
}

std::list<REHex::ProfilingCollector*> REHex::ProfilingCollector::get_collectors(ThreadGroup group)
{
	std::list<ProfilingCollector*> result;
	
	if(collectors != NULL)
	{
		for(auto it = collectors->begin(); it != collectors->end(); ++it)
		{
			if((*it)->tg_stats[ (size_t)(group) ].head_time_bucket != 0)
			{
				result.push_back(*it);
			}
		}
	}
	
	return result;
}

void REHex::ProfilingCollector::reset_collectors()
{
	if(collectors != NULL)
	{
		for(auto c = collectors->begin(); c != collectors->end(); ++c)
		{
			(*c)->reset();
		}
	}
}

uint64_t REHex::ProfilingCollector::get_monotonic_us()
{
	// TODO: Actually use a monotonic time source.
	return wxGetUTCTimeUSec().GetValue();
}

REHex::ProfilingCollector::ProfilingCollector(const std::string &key, ProfilingCollector *parent):
	key(key),
	parent(parent)
{
	reset();
	
	if(collectors == NULL)
	{
		collectors = new std::list<ProfilingCollector*>();
	}
	
	collectors->emplace_back(this);
	this_iter = std::prev(collectors->end());
}

REHex::ProfilingCollector::~ProfilingCollector()
{
	collectors->erase(this_iter);
	
	if(collectors->empty())
	{
		delete collectors;
		collectors = NULL;
	}
}

const std::string &REHex::ProfilingCollector::get_key() const
{
	return key;
}

REHex::ProfilingCollector::Stats REHex::ProfilingCollector::accumulate_stats(ThreadGroup group, unsigned int window_duration_ms) const
{
	const ThreadGroupStats &tgs = tg_stats[ (size_t)(group) ];
	std::unique_lock<std::mutex> tgs_lock(tgs.mutex);
	
	uint64_t now_time_bucket = get_monotonic_us() / (SLOT_DURATION_MS * 1000);
	assert(now_time_bucket >= tgs.head_time_bucket);
	
	Stats acc;
	
	const Stats *stats_begin = tgs.slots + (now_time_bucket == tgs.head_time_bucket);
	const Stats *stats_end = std::min((stats_begin + (window_duration_ms / SLOT_DURATION_MS)), (tgs.slots + NUM_SLOTS));
	
	stats_end -= std::min((uint64_t)(stats_end - stats_begin), (now_time_bucket - tgs.head_time_bucket));
	
	for(auto s = stats_begin; s != stats_end; ++s)
	{
		acc += *s;
	}
	
	return acc;
}

void REHex::ProfilingCollector::record_time(uint64_t begin_time, uint64_t duration)
{
	uint64_t now_time_bucket = get_monotonic_us() / (SLOT_DURATION_MS * 1000);
	
	if(thread_group == ThreadGroup::UNKNOWN)
	{
		abort();
	}
	else if(thread_group == ThreadGroup::NONE)
	{
		return;
	}
	
	ThreadGroupStats &tgs = tg_stats[ (size_t)(thread_group) ];
	std::unique_lock<std::mutex> tgs_lock(tgs.mutex);
	
	if(now_time_bucket != tgs.head_time_bucket)
	{
		assert(now_time_bucket > tgs.head_time_bucket);
		uint64_t shift_by = now_time_bucket - tgs.head_time_bucket;
		
		size_t slots_to_keep = 0;
		if(shift_by < NUM_SLOTS)
		{
			slots_to_keep = NUM_SLOTS - shift_by;
			memmove(tgs.slots + shift_by, tgs.slots, sizeof(*(tgs.slots)) * slots_to_keep);
		}
		
		tgs.reset(tgs_lock, 0, NUM_SLOTS - slots_to_keep);
		
		tgs.head_time_bucket = now_time_bucket;
	}
	
	uint64_t begin_time_bucket = begin_time / (SLOT_DURATION_MS * 1000);
	
	if(begin_time_bucket <= tgs.head_time_bucket && (begin_time_bucket + NUM_SLOTS) > tgs.head_time_bucket)
	{
		size_t slot_idx = tgs.head_time_bucket - begin_time_bucket;
		tgs.slots[slot_idx].record_time(duration);
	}
}

void REHex::ProfilingCollector::reset(size_t begin_idx, size_t end_idx)
{
	for(size_t t = 0; t < (size_t)(ThreadGroup::UNKNOWN); ++t)
	{
		std::unique_lock<std::mutex> tgs_lock(tg_stats[t].mutex);
		tg_stats[t].reset(tgs_lock, begin_idx, end_idx);
	}
}

void REHex::ProfilingCollector::ThreadGroupStats::reset(const std::unique_lock<std::mutex> &mutex_guard, size_t begin_idx, size_t end_idx)
{
	for(size_t i = begin_idx; i < end_idx; ++i)
	{
		slots[i].reset();
	}
}

REHex::ProfilingCollector::Stats::Stats():
	min_time(0),
	max_time(0),
	total_time(0),
	num_samples(0) {}

void REHex::ProfilingCollector::Stats::reset()
{
	min_time    = 0;
	max_time    = 0;
	total_time  = 0;
	num_samples = 0;
}

uint64_t REHex::ProfilingCollector::Stats::get_avg_time() const
{
	if(num_samples > 0)
	{
		return total_time / num_samples;
	}
	else{
		return 0;
	}
}

void REHex::ProfilingCollector::Stats::record_time(uint64_t duration)
{
	if(num_samples == 0)
	{
		min_time    = duration;
		max_time    = duration;
		total_time  = duration;
	}
	else{
		if(min_time > duration)
		{
			min_time = duration;
		}
		
		if(max_time < duration)
		{
			max_time = duration;
		}
		
		total_time += duration;
	}
	
	++num_samples;
}

REHex::ProfilingCollector::Stats &REHex::ProfilingCollector::Stats::operator+=(const Stats &rhs)
{
	if(rhs.num_samples > 0)
	{
		if(num_samples == 0 || min_time > rhs.min_time)
		{
			min_time = rhs.min_time;
		}
		
		if(num_samples == 0 || max_time < rhs.max_time)
		{
			max_time = rhs.max_time;
		}
		
		total_time += rhs.total_time;
		num_samples += rhs.num_samples;
	}
	
	return *this;
}

REHex::AutoBlockProfiler::AutoBlockProfiler(ProfilingCollector *collector):
	collector(collector)
{
	start_time = ProfilingCollector::get_monotonic_us();
}

REHex::AutoBlockProfiler::~AutoBlockProfiler()
{
	uint64_t end_time = ProfilingCollector::get_monotonic_us();
	uint64_t duration = end_time - start_time;
	
	collector->record_time(start_time, duration);
}

enum {
	COLLECTOR_MODEL_COLUMN_NAME = 0,
	COLLECTOR_MODEL_COLUMN_TOTAL,
	COLLECTOR_MODEL_COLUMN_SAMPLES,
	COLLECTOR_MODEL_COLUMN_MIN,
	COLLECTOR_MODEL_COLUMN_MAX,
	COLLECTOR_MODEL_COLUMN_AVG,
	COLLECTOR_MODEL_COLUMN_COUNT,
};

enum {
	ID_UPDATE_TIMER = 1,
	ID_RESET,
};

REHex::ProfilingWindow::ProfilingWindow(wxWindow *parent):
	wxFrame(parent, wxID_ANY, "Profiling counters", wxDefaultPosition, wxSize(800, 400)),
	update_timer(this, ID_UPDATE_TIMER)
{
	update_timer.Start(1000, wxTIMER_CONTINUOUS);
	
	ProfilingDataViewModel *model = new ProfilingDataViewModel();
	
	wxDataViewCtrl *dvc = new wxDataViewCtrl(this, wxID_ANY, wxDefaultPosition, wxDefaultSize);
	
	wxDataViewColumn *name_col = dvc->AppendTextColumn("Name", COLLECTOR_MODEL_COLUMN_NAME);
	name_col->SetSortable(true);
	
	wxDataViewColumn *total_col = dvc->AppendTextColumn(wxString::FromUTF8("total time (\xC2\xB5s)"), COLLECTOR_MODEL_COLUMN_TOTAL);
	total_col->SetSortable(true);
	
	wxDataViewColumn *samples_col = dvc->AppendTextColumn("# calls", COLLECTOR_MODEL_COLUMN_SAMPLES);
	samples_col->SetSortable(true);
	
	wxDataViewColumn *avg_col = dvc->AppendTextColumn(wxString::FromUTF8("avg duration (\xC2\xB5s)"), COLLECTOR_MODEL_COLUMN_AVG);
	avg_col->SetSortable(true);
	
	wxDataViewColumn *min_col = dvc->AppendTextColumn(wxString::FromUTF8("min duration (\xC2\xB5s)"), COLLECTOR_MODEL_COLUMN_MIN);
	min_col->SetSortable(true);
	
	wxDataViewColumn *max_col = dvc->AppendTextColumn(wxString::FromUTF8("max duration (\xC2\xB5s)"), COLLECTOR_MODEL_COLUMN_MAX);
	max_col->SetSortable(true);
	
	dvc->AssociateModel(model);
	model->update();
	
	/* NOTE: This has to come after AssociateModel, or it will segfault. */
	name_col->SetSortOrder(true);
	
	wxButton *reset_btn = new wxButton(this, wxID_ANY, "Reset");
	reset_btn->Bind(wxEVT_BUTTON, [](wxCommandEvent &event)
	{
		ProfilingCollector::reset_collectors();
	});
	
	Bind(wxEVT_TIMER, [=](wxTimerEvent &event)
	{
		model->update();
	}, ID_UPDATE_TIMER, ID_UPDATE_TIMER);
	
	wxBoxSizer *duration_sizer = new wxBoxSizer(wxHORIZONTAL);
	
	auto add_duration_btn = [&](const char *label, unsigned int duration_ms, bool enable = false)
	{
		wxRadioButton *btn = new wxRadioButton(this, wxID_ANY, label, wxDefaultPosition, wxDefaultSize, (enable ? wxRB_GROUP : 0));
		btn->SetValue(enable);
		
		Bind(wxEVT_RADIOBUTTON, [=](wxCommandEvent &event)
		{
			model->set_duration(duration_ms);
		}, btn->GetId(), btn->GetId());
		
		duration_sizer->Add(btn);
	};
	
	add_duration_btn( "5s",  5000, true);
	add_duration_btn("15s", 15000);
	add_duration_btn("30s", 30000);
	add_duration_btn("1m",  60000);
	
	wxBoxSizer *thread_group_sizer = new wxBoxSizer(wxHORIZONTAL);
	
	auto add_tg_button = [&](const char *label, ProfilingCollector::ThreadGroup group, bool enable = false)
	{
		wxRadioButton *btn = new wxRadioButton(this, wxID_ANY, label, wxDefaultPosition, wxDefaultSize, (enable ? wxRB_GROUP : 0));
		btn->SetValue(enable);
		
		Bind(wxEVT_RADIOBUTTON, [=](wxCommandEvent &event)
		{
			model->set_thread_group(group);
		}, btn->GetId(), btn->GetId());
		
		thread_group_sizer->Add(btn);
	};
	
	add_tg_button("Main thread",  ProfilingCollector::ThreadGroup::MAIN, true);
	add_tg_button("Thread pool",  ProfilingCollector::ThreadGroup::POOL);
	
	wxCheckBox *pause_btn = new wxCheckBox(this, wxID_ANY, "Pause");
	
	Bind(wxEVT_CHECKBOX, [=](wxCommandEvent &event)
	{
		if(event.IsChecked())
		{
			update_timer.Stop();
		}
		else{
			model->update();
			update_timer.Start(-1, wxTIMER_CONTINUOUS);
		}
	}, pause_btn->GetId(), pause_btn->GetId());
	
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);
	sizer->Add(dvc, 1, wxEXPAND);
	sizer->Add(reset_btn);
	sizer->Add(duration_sizer);
	sizer->Add(thread_group_sizer);
	sizer->Add(pause_btn);
	SetSizer(sizer);
}

REHex::ProfilingDataViewModel::ProfilingDataViewModel():
	duration_ms(5000) {}

void REHex::ProfilingDataViewModel::set_duration(unsigned int duration_ms)
{
	this->duration_ms = duration_ms;
	update();
}

void REHex::ProfilingDataViewModel::set_thread_group(ProfilingCollector::ThreadGroup group)
{
	this->thread_group = group;
	
	stats.clear();
	Cleared();
	
	update();
}

void REHex::ProfilingDataViewModel::update()
{
	auto collectors = ProfilingCollector::get_collectors(thread_group);
	
	for(auto c = collectors.begin(); c != collectors.end(); ++c)
	{
		ProfilingCollector *collector = *c;
		
		auto s = stats.find(collector);
		if(s != stats.end())
		{
			/* Update for existing collector. */
			
			s->second = s->first->accumulate_stats(thread_group, duration_ms);
			
			stats_elem_t *collector_stats = &(*s);
			ItemChanged(wxDataViewItem(collector_stats));
		}
		else{
			/* Add new collector and stats. */
			
			stats_elem_t *parent_collector_stats = NULL;
			
			if(collector->parent != NULL)
			{
				auto ps = stats.find(collector->parent);
				if(ps == stats.end())
				{
					/* Parent not added yet - skip for now. */
					continue;
				}
				
				parent_collector_stats = &(*ps);
			}
			
			bool inserted;
			std::tie(s, inserted) = stats.emplace(collector, collector->accumulate_stats(thread_group, duration_ms));
			assert(inserted);
			
			stats_elem_t *collector_stats = &(*s);
			ItemAdded(wxDataViewItem(parent_collector_stats), wxDataViewItem(collector_stats));
		}
	}
}

REHex::ProfilingDataViewModel::stats_elem_t *REHex::ProfilingDataViewModel::dv_item_to_stats_elem(const wxDataViewItem &item)
{
	return (stats_elem_t*)(item.GetID());
}

template<typename T> int cmp_value(const T &a, const T &b)
{
	if(a < b)
	{
		return -1;
	}
	else if(a > b)
	{
		return 1;
	}
	else{
		return 0;
	}
}

int REHex::ProfilingDataViewModel::Compare(const wxDataViewItem &item1, const wxDataViewItem &item2, unsigned int column, bool ascending) const
{
	stats_elem_t *collector_stats1 = dv_item_to_stats_elem(item1);
	stats_elem_t *collector_stats2 = dv_item_to_stats_elem(item2);
	int result;
	
	switch(column)
	{
		case COLLECTOR_MODEL_COLUMN_NAME:
			result = cmp_value(collector_stats1->first->get_key(), collector_stats2->first->get_key());
			break;
			
		case COLLECTOR_MODEL_COLUMN_TOTAL:
			result = cmp_value(collector_stats1->second.total_time, collector_stats2->second.total_time);
			break;
			
		case COLLECTOR_MODEL_COLUMN_SAMPLES:
			result = cmp_value(collector_stats1->second.num_samples, collector_stats2->second.num_samples);
			break;
			
		case COLLECTOR_MODEL_COLUMN_MIN:
			result = cmp_value(collector_stats1->second.min_time, collector_stats2->second.min_time);
			break;
			
		case COLLECTOR_MODEL_COLUMN_MAX:
			result = cmp_value(collector_stats1->second.max_time, collector_stats2->second.max_time);
			break;
			
		case COLLECTOR_MODEL_COLUMN_AVG:
			result = cmp_value(collector_stats1->second.get_avg_time(), collector_stats2->second.get_avg_time());
			break;
			
		default:
			abort();
	}
	
	if(result == 0)
	{
		/* Compare by address if values are equal.
		 * Returning zero here can lead to corruption and crashing under wxGTK.
		*/
		result = cmp_value(collector_stats1, collector_stats2);
	}
	
	if(!ascending)
	{
		result = -1 * result;
	}
	
	return result;
}

unsigned int REHex::ProfilingDataViewModel::GetChildren(const wxDataViewItem &item, wxDataViewItemArray &children) const
{
	stats_elem_t *parent_collector_stats = dv_item_to_stats_elem(item);
	ProfilingCollector *parent_collector = parent_collector_stats != NULL
		? parent_collector_stats->first
		: NULL;
	
	children.Alloc(stats.size());
	unsigned int count = 0;
	
	for(auto s = stats.begin(); s != stats.end(); ++s)
	{
		if(s->first->parent == parent_collector)
		{
			const stats_elem_t *collector_stats = &(*s);
			children.Add(wxDataViewItem((void*)(collector_stats)));
			++count;
		}
	}
	
	return count;
}

unsigned int REHex::ProfilingDataViewModel::GetColumnCount() const
{
	return COLLECTOR_MODEL_COLUMN_COUNT;
}

wxString REHex::ProfilingDataViewModel::GetColumnType(unsigned int col) const
{
	return "string";
}

wxDataViewItem REHex::ProfilingDataViewModel::GetParent(const wxDataViewItem &item) const
{
	stats_elem_t *collector_stats = dv_item_to_stats_elem(item);
	ProfilingCollector *collector = collector_stats->first;
	
	if(collector->parent != NULL)
	{
		auto ps = stats.find(collector->parent);
		const stats_elem_t *parent_collector_stats = &(*ps);
		
		return wxDataViewItem((void*)(parent_collector_stats));
	}
	else{
		return wxDataViewItem(NULL);
	}
}

void REHex::ProfilingDataViewModel::GetValue(wxVariant &variant, const wxDataViewItem &item, unsigned int col) const
{
	auto collector_stats = dv_item_to_stats_elem(item);
	
	switch(col)
	{
		case COLLECTOR_MODEL_COLUMN_NAME:
			variant = collector_stats->first->get_key();
			break;
			
		case COLLECTOR_MODEL_COLUMN_TOTAL:
			variant = std::to_string(collector_stats->second.total_time);
			break;
			
		case COLLECTOR_MODEL_COLUMN_SAMPLES:
			variant = std::to_string(collector_stats->second.num_samples);
			break;
			
		case COLLECTOR_MODEL_COLUMN_MIN:
			variant = std::to_string(collector_stats->second.min_time);
			break;
			
		case COLLECTOR_MODEL_COLUMN_MAX:
			variant = std::to_string(collector_stats->second.max_time);
			break;
			
		case COLLECTOR_MODEL_COLUMN_AVG:
			variant = std::to_string(collector_stats->second.get_avg_time());
			break;
			
		default:
			abort();
	}
}

bool REHex::ProfilingDataViewModel::IsContainer(const wxDataViewItem &item) const
{
	return true;
}

bool REHex::ProfilingDataViewModel::SetValue(const wxVariant &variant, const wxDataViewItem &item, unsigned int col)
{
	/* Base implementation is pure virtual, but I don't think we need this... */
	abort();
}

bool REHex::ProfilingDataViewModel::HasContainerColumns(const wxDataViewItem &item) const
{
	return true;
}

#endif /* !REHEX_PROFILE */
