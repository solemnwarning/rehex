/////////////////////////////////////////////////////////////////////////////
// Name:    xyplot.h
// Purpose: XY plot declaration
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef XYPLOT_H_
#define XYPLOT_H_

#include <wx/axisplot.h>
#include <wx/axis/numberaxis.h>

#include <wx/xy/xydataset.h>
#include <wx/xy/xyrenderer.h>

/**
 * An plot for displaying XY data values.
 */
class WXDLLIMPEXP_FREECHART XYPlot : public AxisPlot
{
public:
    XYPlot();
    virtual ~XYPlot();

protected:
    //
    // AxisPlot
    //
    virtual bool AcceptAxis(Axis *axis);

    virtual bool AcceptDataset(Dataset *dataset);

    virtual void DrawDatasets(wxDC &dc, wxRect rc);

    /**
     * Draw single XY dataset.
     * @param dc device context
     * @param rc rectangle where to draw
     * @param dataset XY dataset to draw
     */
    void DrawXYDataset(wxDC &dc, wxRect rc, XYDataset *dataset);
};

#endif /*XYPLOT_H_*/
