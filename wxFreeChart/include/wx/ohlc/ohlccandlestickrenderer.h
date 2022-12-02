/////////////////////////////////////////////////////////////////////////////
// Name:    ohlccandlestickrenderer.h
// Purpose: OHLC candlestick renderer declarations
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef OHLCCANDDLESTICKRENDERER_H_
#define OHLCCANDDLESTICKRENDERER_H_

#include <wx/ohlc/ohlcrenderer.h>

/**
 * OHLC renderer for displaying japanese candles.
 */
class WXDLLIMPEXP_FREECHART OHLCCandlestickRenderer : public OHLCRenderer
{
public:
    OHLCCandlestickRenderer();
    virtual ~OHLCCandlestickRenderer();

    virtual void DrawItem(wxDC &dc, wxCoord x, wxCoord open, wxCoord high, wxCoord low, wxCoord close);

    /**
     * Sets pen to draw candle outline.
     * @param outlinePen pen to draw candle outline
     */
    void SetOutlinePen(wxPen outlinePen)
    {
        m_outlinePen = outlinePen;
        FireNeedRedraw();
    }

    /**
     * Returns pen to draw candle outline.
     * @return outlinePen pen to draw candle outline
     */
    const wxPen &GetOutlinePen()
    {
        return m_outlinePen;
    }

    /**
     * Sets brush to draw lower (bear) candles.
     * @param lowerBrush brush to draw lower (bear) candles
     */
    void SetLowerBrush(wxBrush lowerBrush)
    {
        m_lowerBrush = lowerBrush;
        FireNeedRedraw();
    }

    /**
     * Returns brush to draw lower (bear) candles.
     * @return brush to draw lower (bear) candles
     */
    const wxBrush &GetLowerBrush()
    {
        return m_lowerBrush;
    }

    /**
     * Sets brush to draw higher (bull) candles.
     * @param higherBrush brush to draw higher (bear) candles
     */
    void SetHigherBrush(wxBrush higherBrush)
    {
        m_higherBrush = higherBrush;
        FireNeedRedraw();
    }

    /**
     * Return brush to draw higher (bull) candles.
     * @return brush to draw higher (bear) candles
     */
    const wxBrush &GetHigherBrush()
    {
        return m_higherBrush;
    }

private:
    wxCoord m_candleRadius;

    wxPen m_outlinePen;
    wxBrush m_lowerBrush;
    wxBrush m_higherBrush;
};

#endif /*OHLCCANDDLESTICKRENDERER_H_*/
