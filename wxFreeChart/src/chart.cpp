/////////////////////////////////////////////////////////////////////////////
// Name:    chart.cpp
// Purpose: chart implementation
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/chart.h>
#include <wx/drawutils.h>
#include <wx/dcgraph.h>

ChartObserver::ChartObserver()
{
}

ChartObserver::~ChartObserver()
{
}

Chart::Chart(Plot *plot, const wxString &title)
{
    Init(plot, new Header(TextElement(title, wxALIGN_CENTRE_HORIZONTAL, wxFontInfo(14))));
}

Chart::Chart(Plot* plot, Header* header, Footer* footer)
{
    Init(plot, header, footer);
}

void Chart::Init(Plot* plot, Header* header, Footer* footer)
{
    // defaults
    wxColour bgColor = *wxWHITE;

    m_background = new FillAreaDraw(
            *wxThePenList->FindOrCreatePen(bgColor, 1, wxPENSTYLE_SOLID),
            *wxTheBrushList->FindOrCreateBrush(bgColor));

    m_margin = 5;

    m_plot = plot;
    m_plot->AddObserver(this);
    m_header = header;
    m_footer = footer;
    m_headerGap = 2;

    m_horizScrolledAxis = NULL;
    m_vertScrolledAxis = NULL;
}

Chart::~Chart()
{
    SAFE_REMOVE_OBSERVER(this, m_horizScrolledAxis);
    SAFE_REMOVE_OBSERVER(this, m_vertScrolledAxis);

    SAFE_REMOVE_OBSERVER(this, m_plot);
    wxDELETE(m_plot);
    wxDELETE(m_background);
    wxDELETE(m_header);
    wxDELETE(m_footer);
}

void Chart::PlotNeedRedraw(Plot *WXUNUSED(plot))
{
    FireChartChanged();
}

void Chart::AxisChanged(Axis *WXUNUSED(axis))
{
    // do nothing
}

void Chart::BoundsChanged(Axis *axis)
{
    if (axis == m_horizScrolledAxis || axis == m_vertScrolledAxis) {
        FireChartScrollsChanged();
    }
}

void Chart::SetScrolledAxis(Axis *axis)
{
    if (axis->IsVertical()) {
        if (m_vertScrolledAxis != NULL) {
            m_vertScrolledAxis->RemoveObserver(this);
        }
        m_vertScrolledAxis = axis;
    }
    else {
        if (m_horizScrolledAxis != NULL) {
            m_horizScrolledAxis->RemoveObserver(this);
        }
        m_horizScrolledAxis = axis;
    }

    axis->AddObserver(this);

    FireChartScrollsChanged();
}

Axis *Chart::GetHorizScrolledAxis()
{
    return m_horizScrolledAxis;
}

Axis *Chart::GetVertScrolledAxis()
{
    return m_vertScrolledAxis;
}

wxChartPanel *Chart::GetChartPanel()
{
    return m_chartPanel;
}

void Chart::SetChartPanel(wxChartPanel *chartPanel)
{
    m_chartPanel = chartPanel;
    m_plot->SetChartPanel(chartPanel);
}

// Deprecated?
//wxRect Chart::CalcPlotRect(wxDC &dc, wxRect rc)
//{
//    int topMargin = m_margin;
//    if (m_title.Length() != 0) {
//        dc.SetFont(m_titleFont);
//
//        wxSize textExtent = dc.GetTextExtent(m_title);
//        topMargin += textExtent.y + 2;
//    }
//
//    Margins(rc, m_margin, topMargin, m_margin, m_margin);
//    return rc;
//}

void Chart::Draw(ChartDC &cdc, wxRect &rc, bool WXUNUSED(antialias))
{
    // draw chart background
    m_background->Draw(cdc.GetDC(), rc);

    int topMargin = m_margin;
    int bottomMargin = m_margin;

    if (m_header && !m_header->IsEmpty()) {
        wxRect headerRect = rc;
        Margins(headerRect, m_margin, m_margin, m_margin, m_margin);
        wxSize headerExtent = m_header->CalculateExtent(cdc.GetDC());
        headerRect.height = headerExtent.y + m_headerGap;
        topMargin += headerRect.height;
        m_header->Draw(cdc.GetDC(), headerRect);
    }

    if (m_footer && !m_footer->IsEmpty()) {
        wxRect footerRect = rc;
        Margins(footerRect, m_margin, m_margin, m_margin, m_margin);
        wxSize footerExtent = m_footer->CalculateExtent(cdc.GetDC());
        footerRect.height = footerExtent.y + m_headerGap;
        footerRect.y = rc.height - footerRect.height;
        bottomMargin += footerRect.height;
        m_footer->Draw(cdc.GetDC(), footerRect);
    }
    
    // Shrink the drawing rectangle by the margins.
    Margins(rc, m_margin, topMargin, m_margin, bottomMargin);
   
    m_plot->Draw(cdc, rc, PLOT_DRAW_BACKGROUND);
    
    m_plot->Draw(cdc, rc, PLOT_DRAW_DATA);
}
