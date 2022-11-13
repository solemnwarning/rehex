/////////////////////////////////////////////////////////////////////////////
// Name:    crosshair.cpp
// Purpose: Crosshair implementation
// Author:    Moskvichev Andrey V.
// Created:    14.04.2010
// Copyright:    (c) 2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/crosshair.h"

Crosshair::Crosshair(int WXUNUSED(style), wxPen *WXUNUSED(pen))
{

}

Crosshair::~Crosshair()
{

}

void Crosshair::Draw(wxDC& WXUNUSED(dc), wxRect WXUNUSED(rcData))//, wxCoord x, wxCoord y)
{
    // TODO
    /*
    dc.SetPen(*m_pen);

    dc.DrawLine(rcData.x, y,
            rcData.x + rcData.width, y);
    */
}

void Crosshair::ChartMouseDown(wxPoint& WXUNUSED(pt), int WXUNUSED(key))
{
}

void Crosshair::ChartMouseUp(wxPoint& WXUNUSED(pt), int WXUNUSED(key))
{
}

void Crosshair::ChartMouseMove(wxPoint& WXUNUSED(pt))
{
}
