/////////////////////////////////////////////////////////////////////////////
// Name:    ohlcrenderer.h
// Purpose: OHLC renderers base class declaration.
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef OHLCRENDERER_H_
#define OHLCRENDERER_H_

#include <wx/chartrenderer.h>

/**
 * Class that controls bars/candlesticks colour.
 * It's used to implement bar colo
 */ 
class WXDLLIMPEXP_FREECHART OHLCColourer
{
public:
    // IY: Virtual destructor needed otherwise behaviour is undefined.
    virtual ~OHLCColourer() {}
    virtual wxColor GetColour(int step) = 0;
};

/**
 * Base class for rendering OHLC data.
 */
class WXDLLIMPEXP_FREECHART OHLCRenderer : public Renderer
{
public:
    OHLCRenderer();
    virtual ~OHLCRenderer();

    /**
     * Draws item.
     * @param dc device context
     * @param x coordinate
     * @param open open value in graphical coordinates
     * @param high high value in graphical coordinates
     * @param low low value in graphical coordinates
     * @param close close value in graphical coordinates
     */
    virtual void DrawItem(wxDC &dc, wxCoord x, wxCoord open, wxCoord high, wxCoord low, wxCoord close) = 0;

    void SetColourer(OHLCColourer *colourer);
    OHLCColourer *GetColourer();

protected:
    OHLCColourer *m_colourer;
};

#endif /*OHLCRENDERER_H_*/
