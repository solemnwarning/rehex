/////////////////////////////////////////////////////////////////////////////
// Name:    ganttsimpledataset.cpp
// Purpose: gantt simple dataset implementation
// Author:    Moskvichev Andrey V.
// Created:    2009/11/25
// Copyright:    (c) 2009 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/gantt/ganttsimpledataset.h>

#include "wx/arrimpl.cpp"

WX_DEFINE_OBJARRAY(GanttSerieArray);

GanttSerie::GanttSerie(TaskTime *taskTimes, size_t taskTimesCount, const wxString &name)
{
    m_taskTimes = new TaskTime[taskTimesCount];
    for (size_t n = 0; n < taskTimesCount; n++) {
        m_taskTimes[n].start = taskTimes[n].start;
        m_taskTimes[n].end = taskTimes[n].end;
    }

    m_taskTimesCount = taskTimesCount;

    m_name = name;
}

GanttSerie::~GanttSerie()
{
    wxDELETEA(m_taskTimes);
}

time_t GanttSerie::GetStart(size_t index)
{
    wxCHECK(index < m_taskTimesCount, 0);
    return m_taskTimes[index].start;
}

time_t GanttSerie::GetEnd(size_t index)
{
    wxCHECK(index < m_taskTimesCount, 0);
    return m_taskTimes[index].end;
}

const wxString &GanttSerie::GetName()
{
    return m_name;
}

//
// GanttSimpleDataset
//

GanttSimpleDataset::GanttSimpleDataset(size_t dateCount, const wxChar **taskNames, size_t taskNamesCount)
: GanttDataset(dateCount)
{
    m_taskNames.Alloc(taskNamesCount);
    for (size_t n = 0; n < taskNamesCount; n++) {
        m_taskNames.Add(wxString(taskNames[n]));
    }
}

GanttSimpleDataset::~GanttSimpleDataset()
{
    for (size_t n = 0; n < m_series.Count(); n++) {
        wxDELETE(m_series[n]);
    }
}

void GanttSimpleDataset::AddSerie(GanttSerie *serie)
{
    m_series.Add(serie);
    DatasetChanged();
}

wxString GanttSimpleDataset::GetName(size_t index)
{
    return m_taskNames[index];
}

double GanttSimpleDataset::GetValue(size_t WXUNUSED(index), size_t WXUNUSED(serie))
{
    return 0; // dummy
}

size_t GanttSimpleDataset::GetSerieCount()
{
    return m_series.Count();
}

wxString GanttSimpleDataset::GetSerieName(size_t serie)
{
    wxCHECK(serie < m_series.Count(), wxEmptyString);
    return m_series[serie]->GetName();
}

size_t GanttSimpleDataset::GetCount()
{
    return m_taskNames.Count();
}

time_t GanttSimpleDataset::GetStart(size_t index, size_t serie)
{
    wxCHECK(serie < m_series.Count(), 0);
    return m_series[serie]->GetStart(index);
}

time_t GanttSimpleDataset::GetEnd(size_t index, size_t serie)
{
    wxCHECK(serie < m_series.Count(), 0);
    return m_series[serie]->GetEnd(index);
}
