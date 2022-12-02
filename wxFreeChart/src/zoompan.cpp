/////////////////////////////////////////////////////////////////////////////
// Name:    zoompan.h
// Purpose: Zoom/pan support implementation
// Author:    Moskvichev Andrey V.
// Created:    2010/09/13
// Copyright:    (c) 2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/zoompan.h>

//
// ZoomMode
//
ZoomMode::ZoomMode()
{
    m_allowHorizontalZoom = true;
    m_allowVerticalZoom = true;
}

ZoomMode::~ZoomMode()
{
}

void ZoomMode::SetAllowHorizontalZoom(bool allowHorizontalZoom)
{
    m_allowHorizontalZoom = allowHorizontalZoom;
}

void ZoomMode::SetAllowVertialZoom(bool allowVerticalZoom)
{
    m_allowVerticalZoom = allowVerticalZoom;
}

void ZoomMode::ChartEnterWindow()
{
}

void ZoomMode::ChartMouseDown(wxPoint& WXUNUSED(pt), int WXUNUSED(key))
{
}

void ZoomMode::ChartMouseUp(wxPoint& WXUNUSED(pt), int WXUNUSED(key))
{
}

void ZoomMode::ChartMouseMove(wxPoint& WXUNUSED(pt))
{
}

void ZoomMode::ChartMouseDrag(wxPoint& WXUNUSED(pt))
{
}

void ZoomMode::ChartMouseWheel(int WXUNUSED(rotation))
{
}


//
// PanMode
//
PanMode::PanMode()
{

}

PanMode::~PanMode()
{

}

void PanMode::ChartMouseDown(wxPoint& WXUNUSED(pt))
{

}

void PanMode::ChartMouseUp(wxPoint& WXUNUSED(pt))
{

}

void PanMode::ChartMouseMove(wxPoint& WXUNUSED(pt))
{

}
