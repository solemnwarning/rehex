/////////////////////////////////////////////////////////////////////////////
// Name:    bubbleplot.h
// Purpose: bubble plot declarations
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef BUBBLEPLOT_H_
#define BUBBLEPLOT_H_

#include <wx/axisplot.h>

/**
 * Used to draw bubble charts.
 */
class WXDLLIMPEXP_FREECHART BubblePlot : public AxisPlot
{
public:
    BubblePlot();
    virtual ~BubblePlot();

protected:
    virtual bool AcceptAxis(Axis *axis);

    virtual bool AcceptDataset(Dataset *dataset);

    virtual void DrawDatasets(wxDC &dc, wxRect rc);
};

#endif /*BUBBLEPLOT_H_*/
