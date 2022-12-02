/////////////////////////////////////////////////////////////////////////////
// Name:    categoryrenderer.cpp
// Purpose:     Category renderer (for legend rendering)
// Author:    Grgory Soutad
// Created:    2010/05/24
// Copyright:    (c) 2010 Grgory Soutad
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/category/categoryrenderer.h>

IMPLEMENT_CLASS(CategoryRenderer, Renderer)

CategoryRenderer::CategoryRenderer(ColorScheme& colorScheme) 
: m_colorScheme(colorScheme)
{
}

CategoryRenderer::~CategoryRenderer()
{
}

void CategoryRenderer::DrawLegendSymbol(wxDC &dc, wxRect rcSymbol, size_t serie)
{
  wxColour colour = m_colorScheme.GetColor(serie);

    dc.SetBrush(*wxTheBrushList->FindOrCreateBrush(colour));
    dc.SetPen(*wxThePenList->FindOrCreatePen(colour, 1, wxPENSTYLE_SOLID));

    dc.DrawRectangle(rcSymbol);

    dc.SetPen(*wxThePenList->FindOrCreatePen(*wxBLACK, 1, wxPENSTYLE_SOLID));
    dc.SetBrush(wxNoBrush);

    dc.DrawRectangle(rcSymbol);
}
