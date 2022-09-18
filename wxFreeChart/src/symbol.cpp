/////////////////////////////////////////////////////////////////////////////
// Name:    symbol.cpp
// Purpose: symbols implementation
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/symbol.h>

Symbol::Symbol()
{
}

Symbol::~Symbol()
{
}

MaskedSymbol::MaskedSymbol(const char **maskData, wxCoord size)
{
    m_maskBmp = wxBitmap(maskData);
    m_size = size;

    m_initialized = false;
}

MaskedSymbol::~MaskedSymbol()
{
}

wxSize MaskedSymbol::GetExtent()
{
    return wxSize(m_size, m_size);
}

void MaskedSymbol::Draw(wxDC &dc, wxCoord x, wxCoord y, wxColour color)
{
    wxImage tmpImage = m_maskBmp.ConvertToImage();
    tmpImage.Replace((unsigned char) -1, (unsigned char) -1, (unsigned char)  -1, color.Red(), color.Green(), color.Blue());
    tmpImage.Rescale(m_size, m_size, wxIMAGE_QUALITY_HIGH);

    m_symbolBitmap = wxBitmap(tmpImage);
    m_symbolBitmap.SetMask(new wxMask(wxBitmap(tmpImage), *wxBLACK));

    wxSize extent = GetExtent();
    wxMemoryDC symbolDC(m_symbolBitmap);

    dc.Blit(x - extent.x / 2, y - extent.y / 2, extent.x, extent.y, &symbolDC, 0, 0, wxCOPY, true);
}

ShapeSymbol::ShapeSymbol(wxCoord size)
{
    m_size = size;
}

ShapeSymbol::~ShapeSymbol()
{
}

wxSize ShapeSymbol::GetExtent()
{
    return wxSize(m_size, m_size);
}

CircleSymbol::CircleSymbol(wxCoord size)
: ShapeSymbol(size)
{
}

CircleSymbol::~CircleSymbol()
{
}

void CircleSymbol::Draw(wxDC &dc, wxCoord x, wxCoord y, wxColour color)
{
    dc.SetPen(*wxThePenList->FindOrCreatePen(color, 1, wxPENSTYLE_SOLID));
    dc.SetBrush(*wxTheBrushList->FindOrCreateBrush(color));

    dc.DrawCircle(x, y, m_size / 2);
}


SquareSymbol::SquareSymbol(wxCoord size)
: ShapeSymbol(size)
{
}

SquareSymbol::~SquareSymbol()
{
}

void SquareSymbol::Draw(wxDC &dc, wxCoord x, wxCoord y, wxColour color)
{
    dc.SetBrush(*wxTheBrushList->FindOrCreateBrush(color));
    dc.SetPen(*wxThePenList->FindOrCreatePen(color, 1, wxPENSTYLE_SOLID));

    dc.DrawRectangle(x - m_size / 2, y - m_size / 2, m_size, m_size);
}

CrossSymbol::CrossSymbol(wxCoord size)
: ShapeSymbol(size)
{
}

CrossSymbol::~CrossSymbol()
{
}

void CrossSymbol::Draw(wxDC &dc, wxCoord x, wxCoord y, wxColour color)
{
    dc.SetPen(*wxThePenList->FindOrCreatePen(color, 1, wxPENSTYLE_SOLID));

    dc.DrawLine(x - m_size / 2, y, x + m_size / 2, y);
    dc.DrawLine(x, y - m_size / 2, x, y + m_size / 2);
}

TriangleSymbol::TriangleSymbol(wxCoord size)
: ShapeSymbol(size)
{
}

TriangleSymbol::~TriangleSymbol()
{
}

void TriangleSymbol::Draw(wxDC &dc, wxCoord x, wxCoord y, wxColour color)
{
    dc.SetBrush(*wxTheBrushList->FindOrCreateBrush(color));
    dc.SetPen(*wxThePenList->FindOrCreatePen(color, 1, wxPENSTYLE_SOLID));

    const double COS_30 = 0.866158094;
    const double SIN_30 = 0.5;

    double r = m_size / 2;
    wxPoint pts[] = {
        wxPoint(x, (wxCoord) ( y - r)),
        wxPoint((wxCoord) (x + r * COS_30), (wxCoord) (y + r * SIN_30)),
        wxPoint((wxCoord) (x - r * COS_30), (wxCoord) (y + r * SIN_30)),
    };

    dc.DrawPolygon(3, pts);
}
