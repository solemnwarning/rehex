/////////////////////////////////////////////////////////////////////////////
// Name:    bubbleplot.cpp
// Purpose: bubble plot implementation
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/xyz/bubbleplot.h>
#include <wx/xyz/xyzdataset.h>
#include <wx/xyz/xyzrenderer.h>

BubblePlot::BubblePlot()
{
}

BubblePlot::~BubblePlot()
{
}

bool BubblePlot::AcceptAxis(Axis *WXUNUSED(axis))
{
    // TODO FIXIT: accepts all axes. 
    return true;
}

bool BubblePlot::AcceptDataset(Dataset *dataset)
{
    return (wxDynamicCast(dataset, XYZDataset) != NULL);
}

void BubblePlot::DrawDatasets(wxDC &dc, wxRect rc)
{
    for (size_t nData = 0; nData < GetDatasetCount(); nData++) {
        XYZDataset *dataset = (XYZDataset *) GetDataset(nData);
        XYZRenderer *renderer = dataset->GetRenderer();
        wxCHECK_RET(renderer != NULL, wxT("no renderer for data"));

        Axis *vertAxis = GetDatasetVerticalAxis(dataset);
        Axis *horizAxis = GetDatasetHorizontalAxis(dataset);

        wxCHECK_RET(vertAxis != NULL, wxT("no axis for data"));
        wxCHECK_RET(horizAxis != NULL, wxT("no axis for data"));

        renderer->Draw(dc, rc, horizAxis, vertAxis, dataset);
    }
}
