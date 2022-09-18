/////////////////////////////////////////////////////////////////////////////
// Name:    ganttplot.h
// Purpose: gantt plot declaration
// Author:    Moskvichev Andrey V.
// Created:    2009/03/23
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////


#ifndef GANTTPLOT_H_
#define GANTTPLOT_H_

#include <wx/axisplot.h>

/**
 * Plot to draw gantt charts.
 */
class WXDLLIMPEXP_FREECHART GanttPlot : public AxisPlot
{
public:
    GanttPlot();
    virtual ~GanttPlot();

protected:
    virtual bool AcceptAxis(Axis *axis);

    virtual bool AcceptDataset(Dataset *dataset);

    virtual void DrawDatasets(wxDC &dc, wxRect rc);
};

#endif /* GANTTPLOT_H_ */
