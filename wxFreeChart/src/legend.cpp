/////////////////////////////////////////////////////////////////////////////
// Name:    legend.cpp
// Purpose: legend drawing implementation
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/legend.h>

const wxCoord Legend::labelsSpacing = 2;

Legend::Legend(int vertPosition, int horizPosition, AreaDraw *background, int symbolTextGap, int margin)
{
    m_vertPosition = vertPosition;
    m_horizPosition = horizPosition;
    m_background = background;
    m_symbolTextGap = symbolTextGap;
    m_margin = margin;

    m_font = *wxNORMAL_FONT;
}

Legend::~Legend()
{
    wxDELETE(m_background);
}

void Legend::Draw(wxDC &dc, wxRect rc, DatasetArray &datasets)
{
    dc.SetFont(m_font);

    m_background->Draw(dc, rc);

    wxCoord x = rc.x + m_margin;
    wxCoord y = rc.y + m_margin;

    for (size_t n = 0; n < datasets.Count(); n++) {
        Dataset *dataset = datasets[n];

        FOREACH_SERIE(serie, dataset) {
            wxString serieName = dataset->GetSerieName(serie);
            wxSize textExtent = dc.GetTextExtent(serieName);

            Renderer *renderer = dataset->GetBaseRenderer();

            wxRect rcSymbol(x, y, textExtent.y, textExtent.y);
            renderer->DrawLegendSymbol(dc, rcSymbol, serie);

            wxCoord textX = x + rcSymbol.width + m_symbolTextGap;

            dc.DrawText(serieName, textX, y);

            y += textExtent.y + labelsSpacing;
        }
    }
}

void Legend::Draw(wxDC &dc, wxRect rc, CategoryDataset &dataset)
{
    dc.SetFont(m_font);

    m_background->Draw(dc, rc);

    wxCoord x = rc.x + m_margin;
    wxCoord y = rc.y + m_margin;

    for (size_t n = 0; n < dataset.GetCount(); n++) {
      
      wxString name = dataset.GetName(n);
      wxSize textExtent = dc.GetTextExtent(name);

      Renderer *renderer = dataset.GetBaseRenderer();
      
      wxRect rcSymbol(x, y, textExtent.y, textExtent.y);
      renderer->DrawLegendSymbol(dc, rcSymbol, n);
      
      wxCoord textX = x + rcSymbol.width + m_symbolTextGap;
      
      dc.DrawText(name, textX, y);
      
      y += textExtent.y + labelsSpacing;
    }
}

wxSize Legend::GetExtent(wxDC &dc, DatasetArray &datasets)
{
    wxSize extent(0, 0);

    dc.SetFont(m_font);

    extent.y = 2 * m_margin;

    for (size_t n = 0; n < datasets.Count(); n++) {
        Dataset *dataset = datasets[n];

        FOREACH_SERIE(serie, dataset) {
            wxSize textExtent = dc.GetTextExtent(dataset->GetSerieName(serie));

            wxCoord symbolSize = textExtent.y; // symbol rectangle width and height

            wxCoord width = textExtent.x + symbolSize + m_symbolTextGap + 2 * m_margin;

            extent.x = wxMax(extent.x, width);

            extent.y += textExtent.y;
            if (serie < dataset->GetSerieCount() - 1) {
                extent.y += labelsSpacing;
            }
        }
    }
    return extent;
}

wxSize Legend::GetExtent(wxDC &dc, CategoryDataset &dataset)
{
    wxSize extent(0, 0);

    dc.SetFont(m_font);

    extent.y = 2 * m_margin;

    for (size_t n = 0; n < dataset.GetCount(); n++) {
      wxSize textExtent = dc.GetTextExtent(dataset.GetName(n));

      wxCoord symbolSize = textExtent.y; // symbol rectangle width and height

      wxCoord width = textExtent.x + symbolSize + m_symbolTextGap + 2 * m_margin;

      extent.x = wxMax(extent.x, width);

      extent.y += textExtent.y;
      if (n < dataset.GetCount() - 1) {
        extent.y += labelsSpacing;
      }
    }
    return extent;
}


