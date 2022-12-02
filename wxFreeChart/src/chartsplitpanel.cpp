/////////////////////////////////////////////////////////////////////////////
// Name:    chartsplitpanel.cpp
// Purpose:
// Author:    Moskvichev Andrey V.
// Created:    28.01.2010
// Copyright:    (c) 2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/chartsplitpanel.h"
#include "wx/chartpanel.h"

wxChartSplitPanel::wxChartSplitPanel(wxWindow *parent, wxWindowID id,
        const wxPoint &pos, const wxSize &size)
: wxPanel(parent, id, pos, size)
{   
    m_auiManager = new wxAuiManager(this);

    m_auiManager->Update();
}

wxChartSplitPanel::~wxChartSplitPanel()
{
}

void wxChartSplitPanel::AddPlot(Plot *plot, int pos, bool allowRemove)
{
    wxChartPanel *chartPanel = new wxChartPanel(this, wxID_ANY, new Chart(plot, wxT("")));

    switch (pos) {
    case wxLEFT:
        pos = wxAUI_DOCK_LEFT;
        break;
    case wxRIGHT:
        pos = wxAUI_DOCK_RIGHT;
        break;
    case wxTOP:
        pos = wxAUI_DOCK_TOP;
        break;
    case wxBOTTOM:
        pos = wxAUI_DOCK_BOTTOM;
        break;
    case wxCENTER:
        pos = wxAUI_DOCK_CENTER;
        break;
    }

    wxAuiPaneInfo paneInfo = wxAuiPaneInfo().CloseButton(allowRemove).DestroyOnClose().Floatable(false).Direction(pos);

    m_auiManager->AddPane(chartPanel, paneInfo);

    m_auiManager->Update();
}

void wxChartSplitPanel::RemovePlot(Plot *WXUNUSED(plot))
{
    // TODO
}

void wxChartSplitPanel::RemovePlot(size_t WXUNUSED(nPlot))
{
    // TODO
}

void wxChartSplitPanel::RemoveAllPlots()
{
    // TODO
    //m_plots->RemoveAll();
}

Plot *wxChartSplitPanel::GetPlot(size_t index)
{
    return m_plots[index];
}
