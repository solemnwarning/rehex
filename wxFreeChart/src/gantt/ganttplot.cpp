/////////////////////////////////////////////////////////////////////////////
// Name:    ganttplot.cpp
// Purpose: gantt plot implementation
// Author:    Moskvichev Andrey V.
// Created:    2009/03/23
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/gantt/ganttplot.h>
#include <wx/gantt/ganttdataset.h>
#include <wx/gantt/ganttrenderer.h>

#include <wx/axis/dateaxis.h>
#include <wx/axis/categoryaxis.h>

GanttPlot::GanttPlot()
{
}

GanttPlot::~GanttPlot()
{
}

bool GanttPlot::AcceptAxis(Axis *axis)
{
    return (wxDynamicCast(axis, DateAxis) != NULL && !axis->IsVertical()) ||
            (wxDynamicCast(axis, CategoryAxis) != NULL && axis->IsVertical());
}

bool GanttPlot::AcceptDataset(Dataset *dataset)
{
    return (wxDynamicCast(dataset, GanttDataset) != NULL);
}

void GanttPlot::DrawDatasets(wxDC &dc, wxRect rc)
{
    for (size_t nData = 0; nData < GetDatasetCount(); nData++) {
        GanttDataset *dataset = (GanttDataset *) GetDataset(nData);
        GanttRenderer *renderer = dataset->GetRenderer();
        wxCHECK_RET(renderer != NULL, wxT("no renderer for data"));

        CategoryAxis *vertAxis = wxDynamicCast(GetDatasetVerticalAxis(dataset), CategoryAxis);
        DateAxis *horizAxis = wxDynamicCast(GetDatasetHorizontalAxis(dataset), DateAxis);

        wxCHECK_RET(vertAxis != NULL, wxT("no axis for data"));
        wxCHECK_RET(horizAxis != NULL, wxT("no axis for data"));

        renderer->Draw(dc, rc, horizAxis, vertAxis, dataset);
    }
}
