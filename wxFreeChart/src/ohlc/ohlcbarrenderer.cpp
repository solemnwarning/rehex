/////////////////////////////////////////////////////////////////////////////
// Name:    ohlcbarrenderer.cpp
// Purpose: OHLC bar renderer implementation
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/ohlc/ohlcbarrenderer.h>

OHLCBarRenderer::OHLCBarRenderer()
{
    m_barPen = *wxThePenList->FindOrCreatePen(*wxBLACK, 2, wxPENSTYLE_SOLID);
}

OHLCBarRenderer::~OHLCBarRenderer()
{
}

void OHLCBarRenderer::DrawItem(wxDC &dc, wxCoord x, wxCoord open, wxCoord high, wxCoord low, wxCoord close)
{
    wxCoord leftX = x - 5;
    wxCoord centerX = x;
    wxCoord rightX = x + 5;

    dc.SetPen(m_barPen);

    dc.DrawLine(leftX, open, centerX, open);
    dc.DrawLine(centerX, low, centerX, high);
    dc.DrawLine(centerX, close, rightX, close);
}
