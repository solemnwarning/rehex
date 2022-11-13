/////////////////////////////////////////////////////////////////////////////
// Name:    ohlcplot.h
// Purpose: OHLC plot declaration.
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef OHLCPLOT_H_
#define OHLCPLOT_H_

#include <wx/xy/xyplot.h>
#include <wx/ohlc/ohlcdataset.h>

/**
 * Open-High-Low-Close plot.
 *
 * TODO:
 *  - technical indicators support
 *  - grapical objects support, like levels, fibo-retracements, fractals, etc.
 */
class WXDLLIMPEXP_FREECHART OHLCPlot : public XYPlot
{
public:
    OHLCPlot();
    virtual ~OHLCPlot();

protected:
    virtual bool AcceptAxis(Axis *axis);

    virtual bool AcceptDataset(Dataset *dataset);

    virtual void DrawDatasets(wxDC &dc, wxRect rc);

    /**
     * Draw single OHLC dataset.
     * @param dc device context
     * @param rc rectangle where to draw
     * @param dataset OHLC dataset to draw
     */
    virtual void DrawOHLCDataset(wxDC &dc, wxRect rc, OHLCDataset *dataset);
};

#endif /*OHLCPLOT_H_*/
