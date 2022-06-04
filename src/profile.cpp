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

#include "platform.hpp"

#include <wx/button.h>
#include <wx/sizer.h>
#include <wx/time.h>

#include "profile.hpp"

#ifdef REHEX_PROFILE

std::list<REHex::ProfilingCollector*> *REHex::ProfilingCollector::collectors = NULL;

std::list<REHex::ProfilingCollector*> REHex::ProfilingCollector::get_collectors()
{
	if(collectors != NULL)
	{
		return *collectors;
	}
	else{
		return std::list<ProfilingCollector*>();
	}
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

REHex::ProfilingCollector::ProfilingCollector(const std::string &key):
	key(key),
	min_time(0),
	max_time(0),
	total_time(0),
	num_samples(0)
{
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

wxLongLong REHex::ProfilingCollector::get_min_time() const
{
	return min_time;
}

wxLongLong REHex::ProfilingCollector::get_max_time() const
{
	return max_time;
}

wxLongLong REHex::ProfilingCollector::get_total_time() const
{
	return total_time;
}

wxLongLong REHex::ProfilingCollector::get_avg_time() const
{
	if(num_samples > 0)
	{
		return total_time / num_samples;
	}
	else{
		return 0;
	}
}

unsigned int REHex::ProfilingCollector::get_num_samples() const
{
	return num_samples;
}

void REHex::ProfilingCollector::record_time(wxLongLong t)
{
	if(num_samples == 0)
	{
		min_time   = t;
		max_time   = t;
		total_time = t;
	}
	else{
		if(min_time > t)
		{
			min_time = t;
		}
		
		if(max_time < t)
		{
			max_time = t;
		}
		
		total_time += t;
	}
	
	++num_samples;
}

void REHex::ProfilingCollector::reset()
{
	min_time    = 0;
	max_time    = 0;
	total_time  = 0;
	num_samples = 0;
}

REHex::AutoBlockProfiler::AutoBlockProfiler(ProfilingCollector *collector):
	collector(collector)
{
	start_time = wxGetUTCTimeUSec();
}

REHex::AutoBlockProfiler::~AutoBlockProfiler()
{
	wxLongLong end_time = wxGetUTCTimeUSec();
	wxLongLong this_time = end_time - start_time;
	
	collector->record_time(this_time);
}

enum {
	COLLECTOR_MODEL_COLUMN_NAME = 0,
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
	wxFrame(parent, wxID_ANY, "Profiling counters", wxDefaultPosition, wxSize(600, 400)),
	update_timer(this, ID_UPDATE_TIMER)
{
	update_timer.Start(1000, wxTIMER_CONTINUOUS);
	
	ProfilingDataViewModel *model = new ProfilingDataViewModel();
	
	wxDataViewCtrl *dvc = new wxDataViewCtrl(this, wxID_ANY, wxDefaultPosition, wxDefaultSize);
	
	wxDataViewColumn *name_col = dvc->AppendTextColumn("Name", COLLECTOR_MODEL_COLUMN_NAME);
	name_col->SetSortable(true);
	
	wxDataViewColumn *samples_col = dvc->AppendTextColumn("# samples", COLLECTOR_MODEL_COLUMN_SAMPLES);
	samples_col->SetSortable(true);
	
	wxDataViewColumn *min_col = dvc->AppendTextColumn("min (µs)", COLLECTOR_MODEL_COLUMN_MIN);
	min_col->SetSortable(true);
	
	wxDataViewColumn *max_col = dvc->AppendTextColumn("max (µs)", COLLECTOR_MODEL_COLUMN_MAX);
	max_col->SetSortable(true);
	
	wxDataViewColumn *avg_col = dvc->AppendTextColumn("avg (µs)", COLLECTOR_MODEL_COLUMN_AVG);
	avg_col->SetSortable(true);
	
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
	
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);
	sizer->Add(dvc, 1, wxEXPAND);
	sizer->Add(reset_btn);
	SetSizer(sizer);
}

void REHex::ProfilingDataViewModel::update()
{
	auto collectors = ProfilingCollector::get_collectors();
	
	for(auto c = collectors.begin(); c != collectors.end(); ++c)
	{
		if(added.find(*c) == added.end())
		{
			added.insert(*c);
			ItemAdded(wxDataViewItem(NULL), wxDataViewItem(*c));
		}
		else{
			ItemChanged(wxDataViewItem(*c));
		}
	}
}

REHex::ProfilingCollector *REHex::ProfilingDataViewModel::dv_item_to_collector(const wxDataViewItem &item)
{
	return (ProfilingCollector*)(item.GetID());
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
	ProfilingCollector *collector1 = dv_item_to_collector(item1);
	ProfilingCollector *collector2 = dv_item_to_collector(item2);
	
	switch(column)
	{
		case COLLECTOR_MODEL_COLUMN_NAME:
			return cmp_value(collector1->get_key(), collector2->get_key());
			
		case COLLECTOR_MODEL_COLUMN_SAMPLES:
			return cmp_value(collector1->get_num_samples(), collector2->get_num_samples());
			
		case COLLECTOR_MODEL_COLUMN_MIN:
			return cmp_value(collector1->get_min_time(), collector2->get_min_time());
			
		case COLLECTOR_MODEL_COLUMN_MAX:
			return cmp_value(collector1->get_max_time(), collector2->get_max_time());
			
		case COLLECTOR_MODEL_COLUMN_AVG:
			return cmp_value(collector1->get_avg_time(), collector2->get_avg_time());
			
		default:
			abort();
	}
}

unsigned int REHex::ProfilingDataViewModel::GetChildren(const wxDataViewItem &item, wxDataViewItemArray &children) const
{
	auto collectors = ProfilingCollector::get_collectors();
	children.Alloc(collectors.size());
	
	for(auto c = collectors.begin(); c != collectors.end(); ++c)
	{
		children.Add(wxDataViewItem(*c));
	}
	
	return collectors.size();
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
	return wxDataViewItem(NULL);
}

void REHex::ProfilingDataViewModel::GetValue(wxVariant &variant, const wxDataViewItem &item, unsigned int col) const
{
	ProfilingCollector *collector = dv_item_to_collector(item);
	
	switch(col)
	{
		case COLLECTOR_MODEL_COLUMN_NAME:
			variant = collector->get_key();
			break;
			
		case COLLECTOR_MODEL_COLUMN_SAMPLES:
			variant = std::to_string(collector->get_num_samples());
			break;
			
		case COLLECTOR_MODEL_COLUMN_MIN:
			variant = std::to_string(collector->get_min_time().GetValue());
			break;
			
		case COLLECTOR_MODEL_COLUMN_MAX:
			variant = std::to_string(collector->get_max_time().GetValue());
			break;
			
		case COLLECTOR_MODEL_COLUMN_AVG:
			variant = std::to_string(collector->get_avg_time().GetValue());
			break;
			
		default:
			abort();
	}
}

bool REHex::ProfilingDataViewModel::IsContainer(const wxDataViewItem &item) const
{
	return false;
}

bool REHex::ProfilingDataViewModel::SetValue(const wxVariant &variant, const wxDataViewItem &item, unsigned int col)
{
	/* Base implementation is pure virtual, but I don't think we need this... */
	abort();
}

#endif /* !REHEX_PROFILE */
