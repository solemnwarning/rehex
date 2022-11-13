/////////////////////////////////////////////////////////////////////////////
// Name:    renderer.cpp
// Purpose: renderer implementation
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/chartrenderer.h>

IMPLEMENT_CLASS(Renderer, wxObject)

Renderer::Renderer()
{
}

Renderer::~Renderer()
{
}

void Renderer::SetSerieColour(size_t serie, wxColour *colour)
{
    m_serieColours[serie] = *colour;
    FireNeedRedraw();
}

wxColour Renderer::GetSerieColour(size_t serie)
{
    if (m_serieColours.find(serie) == m_serieColours.end()) {
        return GetDefaultColour(serie);
    }
    return m_serieColours[serie];
}

void Renderer::SetSerieSymbol(size_t serie, Symbol *symbol)
{
    m_serieSymbols[serie] = symbol;
    FireNeedRedraw();
}

Symbol *Renderer::GetSerieSymbol(size_t serie)
{
    if (m_serieSymbols.find(serie) == m_serieSymbols.end()) {
        return GetDefaultSymbol(serie);
    }
    return m_serieSymbols[serie];
}

void Renderer::DrawLegendSymbol(wxDC &dc, wxRect rcSymbol, size_t serie)
{
    wxColour colour = GetSerieColour(serie);

    dc.SetBrush(*wxTheBrushList->FindOrCreateBrush(colour));
    dc.SetPen(*wxThePenList->FindOrCreatePen(colour, 1, wxPENSTYLE_SOLID));

    dc.DrawRectangle(rcSymbol);
}
