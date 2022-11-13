/////////////////////////////////////////////////////////////////////////////
// Name:    ganttdataset.h
// Purpose: gantt dataset declaration
// Author:    Moskvichev Andrey V.
// Created:    2009/03/23
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef GANTTDATASET_H_
#define GANTTDATASET_H_

//#include <wx/dataset.h>
#include <wx/category/categorydataset.h>

class GanttRenderer;
class GanttDataset;

/**
 * Helper used to access gantt dataset as datetime dataset.
 * Internal class, don't use from programs.
 */
class WXDLLIMPEXP_FREECHART GanttDatasetDateHelper : public DateTimeDataset
{
public:
    GanttDatasetDateHelper(GanttDataset *ganttDataset);
    virtual ~GanttDatasetDateHelper();

    virtual time_t GetDate(size_t index);

    virtual size_t GetCount();

private:
    GanttDataset *m_ganttDataset;
};

/**
 * Gantt chart dataset base class.
 */
class WXDLLIMPEXP_FREECHART GanttDataset : public CategoryDataset
{
    DECLARE_CLASS(GanttDataset)
public:
    /**
     * Constructs new gantt dataset.
     * @param dateCount count of dates for date axis. TODO: this looks bad:
     *   date count must be set to axis, not to dataset.
     */
    GanttDataset(size_t dateCount);
    virtual ~GanttDataset();

    virtual DateTimeDataset *AsDateTimeDataset();

    /**
     * Returns task count.
     * @return task count
     */
    virtual size_t GetCount() = 0;

    /**
     * Returns task start time.
     * @param index task index
     * @param serie serie index
     * @return task start time
     */
    virtual time_t GetStart(size_t index, size_t serie) = 0;

    /**
     * Returns task end time.
     * @param index task index
     * @param serie serie index
     * @return task end time
     */
    virtual time_t GetEnd(size_t index, size_t serie) = 0;

    /**
     * Returns task count in specified serie.
     * @param serie serie index
     * @return task count
     */
    virtual size_t GetCount(size_t serie);

    virtual time_t GetMinStart();

    virtual time_t GetMaxEnd();

    time_t GetDateInterval();

    size_t GetDateCount();

    GanttRenderer *GetRenderer()
    {
        return (GanttRenderer *) m_renderer;
    }

private:
    GanttDatasetDateHelper m_dateHelper;

    size_t m_dateCount;
};

#endif /* GANTTDATASET_H_ */
