/////////////////////////////////////////////////////////////////////////////
// Name:    marker.cpp
// Purpose: markers implementation
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/marker.h>
#include <wx/axis/axis.h>

#include "wx/arrimpl.cpp"

WX_DEFINE_EXPORTED_OBJARRAY(MarkerArray);

Marker::Marker()
{
}

Marker::~Marker()
{
}

#if 0
//
// PointMarker
//

PointMarker::PointMarker()
{
}

PointMarker::~PointMarker()
{
}

void PointMarker::Draw(wxDC &dc, wxRect rcData, Axis *horizAxis, Axis *vertAxis)
{
    // TODO not implemented!
    //wxCoord x = horizAxis->ToGraphics()
}
#endif

//
// LineMarker
//

LineMarker::LineMarker(wxPen linePen)
{
    m_linePen = linePen;
    m_value = 0;
    m_horizontal = true;
}

LineMarker::LineMarker(wxColour lineColour, int lineWidth)
{
    m_linePen = *wxThePenList->FindOrCreatePen(lineColour, lineWidth, wxPENSTYLE_SOLID);
    m_value = 0;
    m_horizontal = true;
}

LineMarker::~LineMarker()
{
}

void LineMarker::Draw(wxDC &dc, wxRect rcData, Axis *horizAxis, Axis *vertAxis)
{
    wxCoord x0, y0;
    wxCoord x1, y1;

    if (m_horizontal) {
        if (!vertAxis->IsVisible(m_value)) {
            return ;
        }

        x0 = rcData.x;
        x1 = rcData.x + rcData.width;
        y0 = y1 = vertAxis->ToGraphics(dc, rcData.y, rcData.height, m_value);
    }
    else {
        if (!horizAxis->IsVisible(m_value)) {
            return ;
        }

        x0 = x1 = horizAxis->ToGraphics(dc, rcData.x, rcData.width, m_value);
        y0 = rcData.y;
        y1 = rcData.y + rcData.height;
    }

    dc.SetPen(m_linePen);
    dc.DrawLine(x0, y0, x1, y1);
}

void LineMarker::SetVerticalLine(double value)
{
    SetValue(value, false);
}

void LineMarker::SetHorizontalLine(double value)
{
    SetValue(value, true);
}

void LineMarker::SetValue(double value, bool horizontal)
{
    m_value = value;
    m_horizontal = horizontal;
    FireNeedRedraw();
}

//
// RangeMarker
//
RangeMarker::RangeMarker(AreaDraw *rangeAreaDraw)
{
    m_rangeAreaDraw = rangeAreaDraw;
    m_minValue = 0;
    m_maxValue =0;
    m_horizontal = true;
}

RangeMarker::~RangeMarker()
{
    wxDELETE(m_rangeAreaDraw);
}

void RangeMarker::Draw(wxDC &dc, wxRect rcData, Axis *horizAxis, Axis *vertAxis)
{
    wxRect rcRange;

    if (m_horizontal) {
        if (!vertAxis->IsVisible(m_minValue) && !vertAxis->IsVisible(m_maxValue)) {
            return ;
        }

        wxCoord y0, y1;

        y0 = vertAxis->ToGraphics(dc, rcData.y, rcData.height, m_minValue);
        y1 = vertAxis->ToGraphics(dc, rcData.y, rcData.height, m_maxValue);

        rcRange.x = rcData.x;
        rcRange.width = rcData.width;
        rcRange.y = wxMin(y0, y1);
        rcRange.height = wxMax(y0, y1) - rcRange.y;
    }
    else {
        if (!horizAxis->IsVisible(m_minValue) && !horizAxis->IsVisible(m_maxValue)) {
            return ;
        }
        wxCoord x0, x1;

        x0 = horizAxis->ToGraphics(dc, rcData.x, rcData.width, m_minValue);
        x1 = horizAxis->ToGraphics(dc, rcData.x, rcData.width, m_maxValue);

        rcRange.x = wxMin(x0, x1);
        rcRange.width = wxMax(x0, x1) - rcRange.x;
        rcRange.y = rcData.y;
        rcRange.height = rcData.height;
    }

    m_rangeAreaDraw->Draw(dc, rcRange);
}

void RangeMarker::SetVerticalRange(double minValue, double maxValue)
{
    SetRange(minValue, maxValue, false);
}

void RangeMarker::SetHorizontalRange(double minValue, double maxValue)
{
    SetRange(minValue, maxValue, true);
}

void RangeMarker::SetRange(double minValue, double maxValue, bool horizontal)
{
    m_minValue = minValue;
    m_maxValue = maxValue;
    m_horizontal = horizontal;
    FireNeedRedraw();
}

void RangeMarker::SetRangeAreaDraw(AreaDraw *rangeAreaDraw)
{
    wxREPLACE(m_rangeAreaDraw, rangeAreaDraw);
    FireNeedRedraw();
}
