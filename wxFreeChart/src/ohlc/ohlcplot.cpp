/////////////////////////////////////////////////////////////////////////////
// Name:    ohlcplot.cpp
// Purpose: OHLC plot implementation
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/ohlc/ohlcplot.h>

#include <wx/axis/dateaxis.h>
#include <wx/axis/numberaxis.h>
#include <wx/axis/compdateaxis.h>

OHLCPlot::OHLCPlot()
{
}

OHLCPlot::~OHLCPlot()
{
}

bool OHLCPlot::AcceptAxis(Axis *axis)
{
    if (axis->IsVertical()) {
        return (wxDynamicCast(axis, NumberAxis) != NULL);
    }
    else {
        return ((wxDynamicCast(axis, DateAxis) != NULL) ||
                (wxDynamicCast(axis, CompDateAxis) != NULL));
    }
}

bool OHLCPlot::AcceptDataset(Dataset *dataset)
{
    return (wxDynamicCast(dataset, OHLCDataset) != NULL ||
            wxDynamicCast(dataset, XYDataset) != NULL);
}

void OHLCPlot::DrawDatasets(wxDC &dc, wxRect rc)
{
    for (size_t nData = 0; nData < GetDatasetCount(); nData++) {
        Dataset *dataset = GetDataset(nData);

        OHLCDataset *ohlcDataset = wxDynamicCast(dataset, OHLCDataset);
        if (ohlcDataset != NULL) {
            DrawOHLCDataset(dc, rc, ohlcDataset);
        }
        else {
            XYDataset *xyDataset = wxDynamicCast(dataset, XYDataset);
            if (xyDataset != NULL) {
                DrawXYDataset(dc, rc, xyDataset);
            }
        }
    }
}

void OHLCPlot::DrawOHLCDataset(wxDC &dc, wxRect rc, OHLCDataset *dataset)
{
    OHLCRenderer *renderer = dataset->GetRenderer();
    wxCHECK_RET(renderer != NULL, wxT("no renderer for data"));

    Axis *vertAxis = GetDatasetVerticalAxis(dataset);
    Axis *horizAxis = GetDatasetHorizontalAxis(dataset);

    wxCHECK_RET(vertAxis != NULL, wxT("no axis for data"));
    wxCHECK_RET(horizAxis != NULL, wxT("no axis for data"));

    // draw OHLC items
    for (size_t n = 0; n < dataset->GetCount(); n++) {
        OHLCItem *item = dataset->GetItem(n);

        wxCoord open = vertAxis->ToGraphics(dc, rc.y, rc.height, item->open);
        wxCoord high = vertAxis->ToGraphics(dc, rc.y, rc.height, item->high);
        wxCoord low = vertAxis->ToGraphics(dc, rc.y, rc.height, item->low);
        wxCoord close = vertAxis->ToGraphics(dc, rc.y, rc.height, item->close);

        wxCoord x = horizAxis->ToGraphics(dc, rc.x, rc.width, n);//item->date);

        renderer->DrawItem(dc, x, open, high, low, close);
    }
}
