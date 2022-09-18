/////////////////////////////////////////////////////////////////////////////
// Name:    plot.h
// Purpose: plot base class declarations
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef PLOT_H_
#define PLOT_H_

#include <wx/wxfreechartdefs.h>
#include <wx/observable.h>
#include <wx/areadraw.h>
#include <wx/chartdc.h>

class WXDLLIMPEXP_FREECHART Plot;
class WXDLLIMPEXP_FREECHART wxChartPanel;

enum PlotDrawMode
{
    PLOT_DRAW_BACKGROUND,
    PLOT_DRAW_DATA,
    PLOT_DRAW_ALL
};

/**
 * Interface that receives Plot events, such as need redraw condition.
 */
class WXDLLIMPEXP_FREECHART PlotObserver
{
public:
    PlotObserver();

    virtual ~PlotObserver();

    /**
     * Called when plot has been changed and need to be redrawn.
     * @param _plot plot
     */
    virtual void PlotNeedRedraw(Plot *_plot) = 0;
};

/**
 * Base class for all plots.
 *
 */
class WXDLLIMPEXP_FREECHART Plot : public Observable<PlotObserver>
{
public:
    Plot();
    virtual ~Plot();

    /**
     * Draws plot
     * @param dc device context
     * @param rc rectangle where to draw
     */
    virtual void Draw(ChartDC &cdc, wxRect rc, PlotDrawMode mode = PLOT_DRAW_ALL);

    /**
     * Draws "no data" message.
     * Can be overriden by derivative classes.
     * @param dc device context
     * @param rc rectangle where to draw
     */
    virtual void DrawNoDataMessage(wxDC &dc, wxRect rc);

    void SetChartPanel(wxChartPanel *chartPanel);

    /**
     * Returns chart panel (GUI component, at top level) if
     * it
     */
    wxChartPanel *GetChartPanel();


    /**
     * Sets plot background.
     * @param background new background for plot
     */
    void SetBackground(AreaDraw *background)
    {
        wxREPLACE(m_background, background);
        FirePlotNeedRedraw();
    }

    /**
     * Sets text message drawn, when plot has no data to draw
     * @param textNoData text message drawn, when plot has no data to draw
     */
    void SetTextNoData(const wxString &textNoData)
    {
        m_textNoData = textNoData;
        FirePlotNeedRedraw();
    }

protected:
    /**
     * Checks whether plot has data.
     * Must be overriden by derivative classes.
     * @return true if plot has data, false overwise
     */
    virtual bool HasData() = 0;

    /**
     * Draw the plot data, i.e. the lines, bars etc. on top of the background.
     * Must be overriden by derivative classes.
     * @param dc device context
     * @param rc rectangle where to draw
     */
    virtual void DrawData(ChartDC& cdc, wxRect rc) = 0;

    /**
     * Draw the plot's static items (e.g. axis, gridlines, legend etc.).
     * Must be overriden by derivative classes.
     * @param dc device context
     * @param rc rectangle where to draw
     */
    virtual void DrawBackground(ChartDC& cdc, wxRect rc) = 0;

    /**
     * Called when chart panel is changed.
     * @param oldPanel old chart panel
     * @param newPanel new chart panel
     */
    virtual void ChartPanelChanged(wxChartPanel *oldPanel, wxChartPanel *newPanel);

    FIRE_WITH_THIS(PlotNeedRedraw);

    AreaDraw *m_background;

private:
    wxFont m_textNoDataFont;
    wxString m_textNoData;

    wxChartPanel *m_chartPanel;
};

#endif /*PLOT_H_*/
