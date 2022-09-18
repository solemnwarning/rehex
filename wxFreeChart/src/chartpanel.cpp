/////////////////////////////////////////////////////////////////////////////
// Name:    chartpanel.cpp
// Purpose:
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/chartpanel.h>
#include <wx/dcbuffer.h>

#if wxUSE_GRAPHICS_CONTEXT
#include <wx/dcgraph.h>
#endif /* wxUSE_GRAPHICS_CONTEXT */

//
// Events
//

/*// XXX deprecated?!
DEFINE_EVENT_TYPE(wxEVT_FREECHART_LEFT_CLICK)
DEFINE_EVENT_TYPE(wxEVT_FREECHART_RIGHT_CLICK)
DEFINE_EVENT_TYPE(wxEVT_FREECHART_LEFT_DCLICK)
DEFINE_EVENT_TYPE(wxEVT_FREECHART_RIGHT_DCLICK)
DEFINE_EVENT_TYPE(wxEVT_FREECHART_LEFT_DOWN)
DEFINE_EVENT_TYPE(wxEVT_FREECHART_RIGHT_DOWN)
DEFINE_EVENT_TYPE(wxEVT_FREECHART_LEFT_UP)
DEFINE_EVENT_TYPE(wxEVT_FREECHART_RIGHT_UP)
*/

const int scrollPixelStep = 100;
const int stepMult = 100;

void GetAxisScrollParams(Axis *axis, int &noUnits, int &pos)
{
    double minValue, maxValue;
    axis->GetDataBounds(minValue, maxValue);

    noUnits = RoundHigh(stepMult * (maxValue - minValue - axis->GetWindowWidth())) + 10/*XXX dirty hack*/;
    if (noUnits < 0) {
        noUnits = 0;
    }

    pos = (int) (stepMult * (axis->GetWindowPosition() - minValue));
}


//
// ChartPanelObserver
//
void ChartPanelObserver::ChartEnterWindow()
{
}

void ChartPanelObserver::ChartMouseDown(wxPoint &WXUNUSED(pt), int WXUNUSED(key))
{
}

void ChartPanelObserver::ChartMouseUp(wxPoint &WXUNUSED(pt), int WXUNUSED(key))
{
}

void ChartPanelObserver::ChartMouseMove(wxPoint &WXUNUSED(pt))
{
}

void ChartPanelObserver::ChartMouseDrag(wxPoint &WXUNUSED(pt))
{
}

void ChartPanelObserver::ChartMouseWheel(int WXUNUSED(rotation))
{
}

//
// wxChartPanel
//

BEGIN_EVENT_TABLE(wxChartPanel, wxScrolledWindow)
    EVT_PAINT(wxChartPanel::OnPaint)
    EVT_SIZE(wxChartPanel::OnSize)
    EVT_SCROLLWIN(wxChartPanel::OnScrollWin)
    EVT_MOUSE_EVENTS(wxChartPanel::OnMouseEvents)
END_EVENT_TABLE()

wxChartPanel::wxChartPanel(wxWindow *parent, wxWindowID id, Chart *chart, const wxPoint &pos, const wxSize &size)
: wxScrolledWindow(parent, id, pos, size, wxHSCROLL | wxVSCROLL | wxFULL_REPAINT_ON_RESIZE)
{
    SetBackgroundStyle(wxBG_STYLE_CUSTOM);
    EnableScrolling(false, false);

    m_chart = NULL;
    m_antialias = false;

    m_mode = NULL;

    ResizeBackBitmap(size);

    SetScrollRate(1, 1);
    SetChart(chart);
}

wxChartPanel::~wxChartPanel()
{
    SAFE_REMOVE_OBSERVER(this, m_chart);
    wxDELETE(m_chart);
}

void wxChartPanel::SetChart(Chart *chart)
{
    SAFE_REPLACE_OBSERVER(this, m_chart, chart);
    if (m_chart != NULL) {
        m_chart->SetChartPanel(NULL);
    }

    wxREPLACE(m_chart, chart);

    if (m_chart != NULL) {
        m_chart->SetChartPanel(this);
    }

    RecalcScrollbars();

    RedrawBackBitmap();
    Refresh(false);
}

Chart *wxChartPanel::GetChart()
{
    return m_chart;
}

void wxChartPanel::SetMode(ChartPanelMode *mode)
{
    if (m_mode != NULL)
        RemoveObserver(m_mode);
    if (mode != NULL)
        AddObserver(mode);
    wxREPLACE(m_mode, mode);

    if (m_mode != NULL) {
        m_mode->Init(this);
    }
}

void wxChartPanel::SetAntialias(bool antialias)
{
    if (m_antialias != antialias) {
#if wxUSE_GRAPHICS_CONTEXT
#else
        wxASSERT_MSG(!antialias, wxT("Cannot enable antialiasing due to missing wxUSE_GRAPHICS_CONTEXT"));
#endif
        m_antialias = antialias;

        RedrawBackBitmap();
        Refresh(false);
    }
}

bool wxChartPanel::GetAntialias()
{
    return m_antialias;
}

wxBitmap wxChartPanel::CopyBackbuffer()
{
    return wxBitmap(m_backBitmap);
}

void wxChartPanel::ChartChanged(Chart *WXUNUSED(chart))
{
    RedrawBackBitmap();
    Refresh(false);
}

void wxChartPanel::ChartScrollsChanged(Chart *WXUNUSED(chart))
{
    RecalcScrollbars();

    RedrawBackBitmap();
    Refresh(false);
}

void wxChartPanel::RecalcScrollbars()
{
    if (m_chart == NULL) {
        SetScrollbars(1, 1, 0, 0, 0, 0, true);
        return ;
    }

    Axis *horizAxis = m_chart->GetHorizScrolledAxis();
    Axis *vertAxis = m_chart->GetVertScrolledAxis();

    int noUnitsX = 0;
    int noUnitsY = 0;
    int xPos = 0;
    int yPos = 0;

    if (horizAxis != NULL) {
        GetAxisScrollParams(horizAxis, noUnitsX, xPos);
    }

    if (vertAxis != NULL) {
        GetAxisScrollParams(vertAxis, noUnitsY, yPos);
    }

    SetScrollbars(scrollPixelStep, scrollPixelStep, noUnitsX, noUnitsY, xPos, yPos, true);
}

void wxChartPanel::OnPaint(wxPaintEvent &WXUNUSED(ev))
{
    wxPaintDC dc(this);
    const wxRect &rc = GetClientRect();


    if (m_chart != NULL) {
        dc.DrawBitmap(m_backBitmap, 0, 0, false);
    }
    else {
        dc.SetBrush(*wxTheBrushList->FindOrCreateBrush(GetBackgroundColour()));
        dc.SetPen(*wxThePenList->FindOrCreatePen(GetBackgroundColour(), 1, wxPENSTYLE_SOLID));
        dc.DrawRectangle(rc);
    }
}

void wxChartPanel::OnSize(wxSizeEvent &ev)
{
    const wxSize size = ev.GetSize();
    ResizeBackBitmap(size);

    RedrawBackBitmap();
    Refresh();
}

void wxChartPanel::OnScrollWin(wxScrollWinEvent &ev)
{
    if (m_chart == NULL) {
        return ;
    }

    Axis *axis = NULL;

    switch (ev.GetOrientation()) {
    case wxHORIZONTAL:
        axis = m_chart->GetHorizScrolledAxis();
        break;
    case wxVERTICAL:
        axis = m_chart->GetVertScrolledAxis();
        break;
    default: // BUG
        return ;
    }

    if (axis != NULL) {
        double winPos = (double) ev.GetPosition() / (double) stepMult;
        double minValue, maxValue;

        axis->GetDataBounds(minValue, maxValue);
        winPos += minValue;

        axis->SetWindowPosition(winPos);
    }
    ev.Skip();
}

void wxChartPanel::OnMouseEvents(wxMouseEvent &WXUNUSED(ev))
{
    if (m_mode == NULL) {
        return ;
    }

#if 0
    // TODO
    switch (ev.GetEventType()) {
    case wxEVT_ENTER_WINDOW:
        m_mode->ChartEnterWindow();
        break;
    case wxEVT_LEAVE_WINDOW:
        m_mode->ChartLeaveWindow();
        break;
    case wxEVT_LEFT_DOWN:
        m_mode->ChartMouseDown(ev.GetPosition(), wxMOUSE_BTN_LEFT);
        break;
    case wxEVT_LEFT_UP:
        m_mode->ChartMouseUp(ev.GetPosition(), wxMOUSE_BTN_LEFT);
        break;
    //case wxEVT_LEFT_DCLICK:
    case wxEVT_MIDDLE_DOWN:
        m_mode->ChartMouseDown(ev.GetPosition(), wxMOUSE_BTN_MIDDLE);
        break;
    case wxEVT_MIDDLE_UP:
        m_mode->ChartMouseUp(ev.GetPosition(), wxMOUSE_BTN_MIDDLE);
        break;
    //case wxEVT_MIDDLE_DCLICK:
    case wxEVT_RIGHT_DOWN:
        m_mode->ChartMouseDown(ev.GetPosition(), wxMOUSE_BTN_RIGHT);
        break;
    case wxEVT_RIGHT_UP:
        m_mode->ChartMouseUp(ev.GetPosition(), wxMOUSE_BTN_RIGHT);
        break;
    //case wxEVT_RIGHT_DCLICK:
    case wxEVT_MOTION:
        if (ev.Dragging()) {
            m_mode->ChartMouseDrag(ev.GetPosition());
        }
        else {
            m_mode->ChartMouseMove(ev.GetPosition());
        }
        break;
    case wxEVT_MOUSEWHEEL:
        m_mode->ChartMouseWheel(GetWheelRotation());
        break;
    }
#endif
}

void wxChartPanel::ScrollAxis(Axis *axis, int d)
{
    double delta = (double) d / (double) stepMult;
    double minValue, maxValue;

    axis->GetDataBounds(minValue, maxValue);

    double winPos = axis->GetWindowPosition();
    winPos += minValue + delta;

    axis->SetWindowPosition(winPos);
}

void wxChartPanel::RedrawBackBitmap()
{
    if (m_chart != NULL) 
    {
        wxMemoryDC mdc;
        mdc.SelectObject(m_backBitmap);

        const wxRect& rc = GetClientRect();
        
        ChartDC cdc (mdc, m_antialias);
        m_chart->Draw(cdc, (wxRect&)rc, m_antialias);
    }
}

void wxChartPanel::ResizeBackBitmap(wxSize size)
{
    // make sure we do not attempt to create a bitmap 
    // with invalid size (width and/or height < 1)
    size.IncTo(wxSize(1, 1)); 
    
    m_backBitmap.Create(size.GetWidth(), size.GetHeight());
}
