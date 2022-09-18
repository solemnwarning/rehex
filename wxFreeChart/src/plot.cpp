/////////////////////////////////////////////////////////////////////////////
// Name:    plot.cpp
// Purpose: plot base class implementation
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/plot.h>
#include <wx/drawutils.h>

PlotObserver::PlotObserver()
{
}

PlotObserver::~PlotObserver()
{
}


Plot::Plot()
{
    m_textNoDataFont = *wxNORMAL_FONT;
    m_textNoData = wxT("No data");

    m_background = new NoAreaDraw();

    m_chartPanel = NULL;
}

Plot::~Plot()
{
    wxDELETE(m_background);
}

void Plot::Draw(ChartDC &cdc, wxRect rc, PlotDrawMode mode)
{
    if (mode == PLOT_DRAW_BACKGROUND || mode == PLOT_DRAW_ALL)
        DrawBackground(cdc, rc);

    if (mode == PLOT_DRAW_DATA || mode == PLOT_DRAW_ALL)
    {
        if (HasData())
            DrawData(cdc,rc);
        else
            DrawNoDataMessage(cdc.GetDC(), rc);
    }
        
}

void Plot::DrawNoDataMessage(wxDC &dc, wxRect rc)
{
    dc.SetFont(m_textNoDataFont);
    DrawTextCenter(dc, rc, m_textNoData);
}

void Plot::SetChartPanel(wxChartPanel *chartPanel)
{
    ChartPanelChanged(m_chartPanel, chartPanel);
    m_chartPanel = chartPanel;
}

wxChartPanel *Plot::GetChartPanel()
{
    return m_chartPanel;
}

void Plot::ChartPanelChanged(wxChartPanel *WXUNUSED(oldPanel), wxChartPanel *WXUNUSED(newPanel))
{
    // default - do nothing
}
