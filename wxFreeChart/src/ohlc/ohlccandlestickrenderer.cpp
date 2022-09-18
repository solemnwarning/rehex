/////////////////////////////////////////////////////////////////////////////
// Name:    ohlccandlestickrenderer.cpp
// Purpose: OHLC candlestick renderer implementation
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/ohlc/ohlccandlestickrenderer.h>

OHLCCandlestickRenderer::OHLCCandlestickRenderer()
{
    // defaults
    m_outlinePen = *wxBLACK_PEN;
    m_lowerBrush = *wxBLACK_BRUSH;
    m_higherBrush = *wxWHITE_BRUSH;
    m_candleRadius = 5;
}

OHLCCandlestickRenderer::~OHLCCandlestickRenderer()
{
}

void OHLCCandlestickRenderer::DrawItem(wxDC &dc, wxCoord x, wxCoord open, wxCoord high, wxCoord low, wxCoord close)
{
    wxCoord leftX = x - m_candleRadius;
    wxCoord centerX = x;

    dc.SetPen(m_outlinePen);
    dc.DrawLine(centerX, low, centerX, high);

    wxCoord height;
    wxCoord y;

    if (open > close) {
        height = open - close;
        y = close;
        dc.SetBrush(m_higherBrush);
    }
    else {
        height = close - open;
        y = open;
        dc.SetBrush(m_lowerBrush);
    }

    if (height > 1) {
        dc.DrawRectangle(leftX, y, 2 * m_candleRadius, height);
    }
    else {
        dc.DrawLine(leftX, y, leftX + 2 * m_candleRadius, y);
    }
}
