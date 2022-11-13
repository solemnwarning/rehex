/////////////////////////////////////////////////////////////////////////////
// Name:    crosshair.h
// Purpose: Crosshair decration
// Author:    Moskvichev Andrey V.
// Created:    14.04.2010
// Copyright:    (c) 2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////


#ifndef CROSSHAIR_H_
#define CROSSHAIR_H_

#include <wx/wxfreechartdefs.h>
#include <wx/chartpanel.h>

enum {
    /**
     * Moving crosshair. When user moves mouse on plot, crosshair will
     * move to new position.
     */
    wxCrosshairMoving = 1,
    /**
     * Crosshair moves to new position, when user clicks mouse button.
     */
    wxCrosshairOnClick,
    /**
     * Crosshair has fixed position.
     */
    wxCrosshairFixed,
};

/**
 * Crosshair class.
 * Performs crosshair drawing.
 *
 */
class WXDLLIMPEXP_FREECHART Crosshair : public ChartPanelObserver
{
public:
    Crosshair(int style, wxPen *pen = (wxPen *) wxBLACK_PEN);
    virtual ~Crosshair();

    void Draw(wxDC &dc, wxRect rcData);

    /**
     * Sets horizontal value enabled,
     * @param axisIndex axis index
     * @param enabled <code>true</code> to enable axis value drawing
     */
    void SetHorizontalValueEnabled(int index, bool enabled = true);

    void SetVerticalValueEnabled(int index, bool enabled = true);

    /**
     *
     */
    void SetPoint(double x, double y);

    /**
     * Sets whether to handle mouse moving/clicks to
     * move crosshair.
     * @param handleMouseEvents <code>true</code> to handle mouse events
     */
    void SetHandleMouseEvents(bool handleMouseEvents);

    /**
     * Sets background for value drawn on horizontal axis.
     * @param index horizontal axis index
     * @param bg background
     */
    void SetHorizontalAxisBg(int index, AreaDraw *bg);

    /**
     * Sets background for value drawn on vertical axis.
     * @param index vertical axis index
     * @param bg background
     */
    void SetVerticalAxisBg(int index, AreaDraw *bg);

    //
    // ChartPanelObserver
    //
    virtual void ChartMouseDown(wxPoint &pt, int key);
    virtual void ChartMouseUp(wxPoint &pt, int key);
    virtual void ChartMouseMove(wxPoint &pt);

private:
    int m_style;
    wxPen m_pen;

    AreaDrawCollection m_horizontalAxesBg;
    AreaDrawCollection m_verticalAxesBg;
};

#endif /* CROSSHAIR_H_ */
