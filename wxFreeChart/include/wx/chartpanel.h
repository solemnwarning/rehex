/////////////////////////////////////////////////////////////////////////////
// Name:    chartpanel.h
// Purpose: wxChartPanel declaration
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef CHARTPANEL_H_
#define CHARTPANEL_H_

#include <wx/wxfreechartdefs.h>
#include <wx/chart.h>

class wxChartPanel;

/**
 * Interface to propagate chart panel mouse events
 * to lower layer classes, for mouse handling objects,
 * such as crosshairs, tooltip generators, etc.
 */
class WXDLLIMPEXP_FREECHART ChartPanelObserver
{
public:
    virtual void ChartEnterWindow();

    virtual void ChartMouseDown(wxPoint &pt, int key);
    virtual void ChartMouseUp(wxPoint &pt, int key);

    virtual void ChartMouseMove(wxPoint &pt);
    virtual void ChartMouseDrag(wxPoint &pt);

    virtual void ChartMouseWheel(int rotation);
};

/**
 * Base class for zoom/pan modes.
 */
class WXDLLIMPEXP_FREECHART ChartPanelMode  : public ChartPanelObserver
{
public:
    // IY: Virtual destructor needed otherwise behaviour is undefined.
    virtual ~ChartPanelMode() {}
    virtual void Init(wxChartPanel *chartPanel) = 0;
};


/**
 * ChartPanel is wxWidgets panel for displaying chart.
 *
 */
class WXDLLIMPEXP_FREECHART wxChartPanel : public wxScrolledWindow, public ChartObserver,
    public Observable<ChartPanelObserver>
{
public:
    wxChartPanel(wxWindow *parent, wxWindowID = wxID_ANY, Chart *chart = NULL,
        const wxPoint &pos = wxDefaultPosition, const wxSize &size = wxDefaultSize);
    virtual ~wxChartPanel();

    /**
     * Sets chart.
     * @param chart new chart
     */
    void SetChart(Chart *chart);

    /**
     * Returns chart.
     * @return chart
     */
    Chart *GetChart();

    /**
     * Sets chart panel mode, eg. zoom, pan, etc.
     * @param mode mode
     */
    void SetMode(ChartPanelMode *mode);

    /**
     * Turn antialiasing on/off.
     * Has effect only when wx wxUSE_GRAPHICS_CONTEXT is set in wxWidgets build.
     * Warning: this feature can dramatically lower rendering performance.
     *
     * @param antialias true to turn on antialiasing.
     */
    void SetAntialias(bool antialias);

    /**
     * Checks whether antialiasing is enabled.
     * @return true if antialiasing is enabled
     */
    bool GetAntialias();

    /**
     * Returns back buffer copy as wxBitmap.
     * Can be used to save chart image to file.
     * @return back buffer copy as wxBitmap
     */
    wxBitmap CopyBackbuffer();

    //
    // ChartObserver
    //
    virtual void ChartChanged(Chart *chart);

    virtual void ChartScrollsChanged(Chart *chart);

private:
    void ResizeBackBitmap(wxSize size);
    void RedrawBackBitmap();
    void RecalcScrollbars();

    //
    // Event handlers
    //
    void OnPaint(wxPaintEvent &ev);
    void OnSize(wxSizeEvent &ev);
    void OnScrollWin(wxScrollWinEvent &ev);
    void OnMouseEvents(wxMouseEvent &ev);

    void ScrollAxis(Axis *axis, int d);

    Chart *m_chart;

    wxBitmap m_backBitmap;

    bool m_antialias;

    ChartPanelMode *m_mode;

    DECLARE_EVENT_TABLE()
};


#endif /*CHARTPANEL_H_*/
