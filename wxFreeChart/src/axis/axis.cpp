/////////////////////////////////////////////////////////////////////////////
// Name:    axis.cpp
// Purpose: axis base class implementation
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/axis/axis.h>

#include "wx/arrimpl.cpp"

IMPLEMENT_CLASS(Axis, wxObject)


AxisObserver::AxisObserver()
{
}

AxisObserver::~AxisObserver()
{
}

Axis::Axis(AXIS_LOCATION location)
{
    m_location = location;

    m_majorGridlinePen = *wxThePenList->FindOrCreatePen(DEFAULT_MAJOR_GRIDLINE_PEN_COLOUR, 1, wxPENSTYLE_SOLID); // wxPENSTYLE_DOT);//wxPENSTYLE_SHORT_DASH);
    m_minorGridlinePen = *wxThePenList->FindOrCreatePen(DEFAULT_MINOR_GRIDLINE_PEN_COLOUR, 1, wxPENSTYLE_SOLID); // wxPENSTYLE_DOT);//wxPENSTYLE_SHORT_DASH);

    m_winPos = 0;
    m_winWidth = 0;
    m_useWin = false;

    m_marginMin = 5;
    m_marginMax = 5;

    m_shareCount = 0; // counter for AxisShare
}

Axis::~Axis()
{
}

void Axis::SetMargins(wxCoord marginMin, wxCoord marginMax)
{
    if (m_marginMin != marginMin || m_marginMax != marginMax) {
        m_marginMin = marginMin;
        m_marginMax = marginMax;
        FireAxisChanged();
    }
}

size_t Axis::GetDatasetCount()
{
    return m_datasets.Count();
}

Dataset *Axis::GetDataset(size_t index)
{
    return m_datasets[index];
}

bool Axis::IsVisible(double value)
{
    if (m_useWin) {
        return (value >= m_winPos && value <= (m_winPos + m_winWidth));
    }
    else {
        double minValue, maxValue;
        GetDataBounds(minValue, maxValue);

        return (value >= minValue && value <= maxValue);
    }
}

bool Axis::IntersectsWindow(double v0, double v1)
{
    if (m_useWin) {
        return ((v0 >= v1 && v0 >= m_winPos && v1 <= m_winPos)
                || (v0 < v1 && v1 >= m_winPos && v0 <= m_winPos));
    }
    else {
        return IsVisible(v0) || IsVisible(v1);
    }
}

double Axis::BoundValue(double value)
{
    if (m_useWin) {
        if (value <= m_winPos) {
            return m_winPos;
        }
        else if (value >= (m_winPos + m_winWidth)) {
            return m_winPos + m_winWidth;
        }
        else {
            return value;
        }
    }
    else {
      double min, max;
      GetDataBounds(min, max);

    double bound = wxMin(max, wxMax(min, value));
    return bound;
    }
}

wxCoord Axis::ToGraphics(wxDC& WXUNUSED(dc), int minCoord, int gRange, double value)
{
    double minValue, maxValue;
    GetDataBounds(minValue, maxValue);

    minCoord += m_marginMin;
    gRange -= (m_marginMin + m_marginMax);
    if (gRange < 0) {
        gRange = 0;
    }

    if (m_useWin) {
        minValue = m_winPos;
        maxValue = m_winPos + m_winWidth;
    }

    return ::ToGraphics(minCoord, gRange, minValue, maxValue, 0/*textMargin*/, IsVertical(), value);
}

double Axis::ToData(wxDC& WXUNUSED(dc), int minCoord, int gRange, wxCoord g)
{
    double minValue, maxValue;
    GetDataBounds(minValue, maxValue);

    minCoord += m_marginMin;
    gRange -= (m_marginMin + m_marginMax);
    if (gRange < 0) {
        gRange = 0;
    }

    if (m_useWin) {
        minValue = m_winPos;
        maxValue = m_winPos + m_winWidth;
    }

    double value = ::ToData(minCoord, gRange, minValue, maxValue, 0/*textMargin*/, IsVertical(), g);
    return value;
}

//
// AxisShare
//
AxisShare::AxisShare(Axis *axis)
: Axis(axis->GetLocation())
{
    m_axis = axis;
    m_axis->m_shareCount++;

    // share is invisible by default
    m_shareVisible = false;
}

AxisShare::~AxisShare()
{
    m_axis->m_shareCount--;

    if (m_axis->m_shareCount <= 0) {
        wxDELETE(m_axis);
    }
}

void AxisShare::SetShareVisible(bool shareVisible)
{
    if (m_shareVisible != shareVisible) {
        m_shareVisible = shareVisible;
        FireAxisChanged();
    }
}

void AxisShare::GetDataBounds(double &minValue, double &maxValue) const
{
    m_axis->GetDataBounds(minValue, maxValue);
}

wxCoord AxisShare::GetExtent(wxDC &dc)
{
    if (!m_shareVisible) {
        return 0;
    }
    return m_axis->GetExtent(dc);
}

bool AxisShare::IsVisible(double value)
{
    return m_axis->IsVisible(value);
}

double AxisShare::BoundValue(double value)
{
    return m_axis->BoundValue(value);
}

wxCoord AxisShare::ToGraphics(wxDC &dc, int minCoord, int gRange, double value)
{
    return m_axis->ToGraphics(dc, minCoord, gRange, value);
}

double AxisShare::ToData(wxDC &dc, int minCoord, int gRange, wxCoord g)
{
    return m_axis->ToData(dc, minCoord, gRange, g);
}

bool AxisShare::UpdateBounds()
{
    return m_axis->UpdateBounds();
}

void AxisShare::Draw(wxDC &dc, wxRect rc)
{
    if (m_shareVisible) {
        m_axis->Draw(dc, rc);
    }
}

void AxisShare::DrawGridLines(wxDC &dc, wxRect rcData)
{
    m_axis->DrawGridLines(dc, rcData);
}

bool AxisShare::AcceptDataset(Dataset *dataset)
{
    return m_axis->AcceptDataset(dataset);
}


wxCoord ToGraphics(int minCoord, int gRange, double minValue, double maxValue, wxCoord margin, bool vertical, double value)
{
    double k;
    double valueRange = maxValue - minValue;

    minCoord += margin / 2;
    gRange -= margin;

    if (gRange <= 0) {
        return minCoord;
    }

    if (vertical) {
        k = (maxValue - value) / valueRange;
    }
    else {
        k = (value - minValue) / valueRange;
    }

    return (wxCoord) (k * gRange + minCoord);
}

double ToData(int minCoord, int gRange, double minValue, double maxValue, wxCoord margin, bool vertical, wxCoord g)
{
    double valueRange = maxValue - minValue;

    minCoord += margin / 2;
    gRange -= margin;

    if (gRange <= 0) {
        return 0;
    }

    if (vertical) {
        return maxValue - ((g - minCoord) * valueRange / gRange);
    }
    else {
        return minValue + ((g - minCoord) * valueRange / gRange);
    }
}

WX_DEFINE_EXPORTED_OBJARRAY(AxisArray)
