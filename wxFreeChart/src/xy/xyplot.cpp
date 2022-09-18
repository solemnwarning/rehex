/////////////////////////////////////////////////////////////////////////////
// Name:    xyplot.cpp
// Purpose: xy plot implementation
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/xy/xyplot.h>

XYPlot::XYPlot()
{
}

XYPlot::~XYPlot()
{
}

bool XYPlot::AcceptAxis(Axis *WXUNUSED(axis))
{
    return true;
}

bool XYPlot::AcceptDataset(Dataset *dataset)
{
    return (wxDynamicCast(dataset, XYDataset) != NULL);
}

void XYPlot::DrawDatasets(wxDC &dc, wxRect rc)
{
    for (size_t nData = 0; nData < GetDatasetCount(); nData++) {
        XYDataset *dataset = (XYDataset *) GetDataset(nData);
        DrawXYDataset(dc, rc, dataset);
    }
}

void XYPlot::DrawXYDataset(wxDC &dc, wxRect rc, XYDataset *dataset)
{
    XYRenderer *renderer = dataset->GetRenderer();
    wxCHECK_RET(renderer != NULL, wxT("no renderer for data"));

    Axis *vertAxis = GetDatasetVerticalAxis(dataset);
    Axis *horizAxis = GetDatasetHorizontalAxis(dataset);

    wxCHECK_RET(vertAxis != NULL, wxT("no axis for data"));
    wxCHECK_RET(horizAxis != NULL, wxT("no axis for data"));

    renderer->Draw(dc, rc, horizAxis, vertAxis, dataset);
}

