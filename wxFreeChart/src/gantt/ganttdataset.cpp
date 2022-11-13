/////////////////////////////////////////////////////////////////////////////
// Name:    ganttdataset.cpp
// Purpose: gantt dataset implementation
// Author:    Moskvichev Andrey V.
// Created:    2009/03/23
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/gantt/ganttdataset.h>

IMPLEMENT_CLASS(GanttDataset, CategoryDataset)

GanttDatasetDateHelper::GanttDatasetDateHelper(GanttDataset *ganttDataset)
{
    m_ganttDataset = ganttDataset;
}

GanttDatasetDateHelper::~GanttDatasetDateHelper()
{
}

time_t GanttDatasetDateHelper::GetDate(size_t index)
{
    return m_ganttDataset->GetMinStart() + index * m_ganttDataset->GetDateInterval();
}

size_t GanttDatasetDateHelper::GetCount()
{
    return m_ganttDataset->GetDateCount();
}


GanttDataset::GanttDataset(size_t dateCount)
: m_dateHelper(this)
{
    m_dateCount = dateCount;
}

GanttDataset::~GanttDataset()
{
}

size_t GanttDataset::GetCount(size_t WXUNUSED(serie))
{
    // Gannt Dataset has equal number of elements in all series.
    return GetCount();
}

time_t GanttDataset::GetMinStart()
{
    time_t minStart = 0;

    FOREACH_SERIE(serie, this) {
        for (size_t index = 0; index < GetCount(); index++) {
            time_t start = GetStart(index, serie);

            if (serie == 0 && index == 0) {
                minStart = start;
            }
            else {
                minStart = wxMin(minStart, start);
            }
        }
    }
    return minStart;
}

time_t GanttDataset::GetMaxEnd()
{
    time_t maxEnd = 0;

    FOREACH_SERIE(serie, this) {
        for (size_t index = 0; index < GetCount(); index++) {
            time_t end = GetEnd(index, serie);

            if (serie == 0 && index == 0) {
                maxEnd = end;
            }
            else {
                maxEnd = wxMax(maxEnd, end);
            }
        }
    }
    return maxEnd;
}

time_t GanttDataset::GetDateInterval()
{
    time_t minStart = GetMinStart();
    time_t maxEnd = GetMaxEnd();

    return (maxEnd - minStart) / m_dateCount;
}

size_t GanttDataset::GetDateCount()
{
    return m_dateCount;
}

DateTimeDataset *GanttDataset::AsDateTimeDataset()
{
    return &m_dateHelper;
}
