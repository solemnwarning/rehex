/////////////////////////////////////////////////////////////////////////////
// Name:    ganttsimpledataset.h
// Purpose: gantt simple dataset declaration
// Author:    Moskvichev Andrey V.
// Created:    2009/11/25
// Copyright:    (c) 2009 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef GANTTSIMPLEDATASET_H_
#define GANTTSIMPLEDATASET_H_

#include <wx/gantt/ganttdataset.h>

#include <wx/dynarray.h>

class WXDLLIMPEXP_FREECHART GanttSerie
{
public:
    struct TaskTime
    {
        time_t start;
        time_t end;
    };

    GanttSerie(TaskTime *tasks, size_t taskCount, const wxString &name);
    virtual ~GanttSerie();

    time_t GetStart(size_t index);

    time_t GetEnd(size_t index);

    const wxString &GetName();

private:
    TaskTime *m_taskTimes;
    size_t m_taskTimesCount;

    wxString m_name;
};

WX_DECLARE_OBJARRAY(GanttSerie *, GanttSerieArray);

/**
 * Gantt simple dataset.
 */
class WXDLLIMPEXP_FREECHART GanttSimpleDataset : public GanttDataset
{
public:
    /**
     * Construct new gantt demo dataset.
     * @param dateCount
     * @param taskNames names for tasks
     * @param taskNamesCount count of names
     */
    GanttSimpleDataset(size_t dateCount, const wxChar **taskNames, size_t taskNamesCount);
    virtual ~GanttSimpleDataset();

    /**
     * Add new serie to dataset.
     * @param serie new serie
     */
    void AddSerie(GanttSerie *serie);

    virtual wxString GetName(size_t index);

    virtual double GetValue(size_t index, size_t serie);

    virtual size_t GetSerieCount();

    virtual wxString GetSerieName(size_t serie);

    virtual size_t GetCount();

    virtual time_t GetStart(size_t index, size_t serie);

    virtual time_t GetEnd(size_t index, size_t serie);

private:
    wxArrayString m_taskNames;
    GanttSerieArray m_series;
};

#endif /* GANTTSIMPLEDATASET_H_ */
