/////////////////////////////////////////////////////////////////////////////
// Name:    zoompan.h
// Purpose: Zoom/pan declarations
// Author:    Moskvichev Andrey V.
// Created:    2010/09/13
// Copyright:    (c) 2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef ZOOMPAN_H_
#define ZOOMPAN_H_

#include <wx/wxfreechartdefs.h>
#include <wx/chartpanel.h>


class WXDLLIMPEXP_FREECHART ZoomMode : public ChartPanelMode
{
public:
    ZoomMode();
    virtual ~ZoomMode();

    void SetAllowHorizontalZoom(bool allowHorizontalZoom);
    void SetAllowVertialZoom(bool allowVerticalZoom);

    //
    // ChartPanelObserver
    //
    virtual void ChartEnterWindow();

    virtual void ChartMouseDown(wxPoint &pt, int key);
    virtual void ChartMouseUp(wxPoint &pt, int key);

    virtual void ChartMouseMove(wxPoint &pt);
    virtual void ChartMouseDrag(wxPoint &pt);

    virtual void ChartMouseWheel(int rotation);

private:
    bool m_allowHorizontalZoom;
    bool m_allowVerticalZoom;
};

/**
 * Pan moves chart data when user drags mouse.
 * It's used to implement scrolling.
 */
class WXDLLIMPEXP_FREECHART PanMode : public ChartPanelMode
{
public:
    PanMode();
    virtual ~PanMode();

    void SetAllowHorizontalPan(bool allowHorizontalPan);
    void SetAllowVertialPan(bool allowVerticalPan);

    //
    // ChartPanelObserver
    //
    virtual void ChartMouseDown(wxPoint &pt);
    virtual void ChartMouseUp(wxPoint &pt);
    virtual void ChartMouseMove(wxPoint &pt);
private:


};

#endif /* ZOOMPAN_H_ */
