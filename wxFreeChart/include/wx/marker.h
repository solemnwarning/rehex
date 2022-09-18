/////////////////////////////////////////////////////////////////////////////
// Name:    marker.h
// Purpose: markers declarations
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef MARKER_H_
#define MARKER_H_

#include <wx/wxfreechartdefs.h>
#include <wx/drawobject.h>
#include <wx/areadraw.h>

#include <wx/dynarray.h>

class Axis;

/**
 * Markers base class.
 */
class WXDLLIMPEXP_FREECHART Marker : public DrawObject
{
public:
    Marker();
    virtual ~Marker();

    /**
     * Performs marker drawing.
     * @param dc device context
     * @param rcData data area rectangle
     * @param horizAxis horizontal axis
     * @param vertAxis vertical axis
     */
    virtual void Draw(wxDC &dc, wxRect rcData, Axis *horizAxis, Axis *vertAxis) = 0;
};

WX_DECLARE_USER_EXPORTED_OBJARRAY(Marker *, MarkerArray, WXDLLIMPEXP_FREECHART);

#if 0

/**
 * Point marker. Not Implemented yet
 */
class WXDLLIMPEXP_FREECHART PointMarker : public Marker
{
public:
    PointMarker();
    virtual ~PointMarker();

    virtual void Draw(wxDC &dc, wxRect rcData, Axis *horizAxis, Axis *vertAxis);

    void SetText(const wxString &text)
    {
        m_text = text;
        FireNeedRedraw();
    }

private:
    wxString m_text;
    wxFont m_textFont;
    wxColour m_textColour;
};

#endif // #if 0

/**
 * Marker that marks single value, and drawn as line.
 */
class WXDLLIMPEXP_FREECHART LineMarker : public Marker
{
public:
    LineMarker(wxPen linePen);

    LineMarker(wxColour lineColour, int lineWidth = 1);

    virtual ~LineMarker();

    virtual void Draw(wxDC &dc, wxRect rcData, Axis *horizAxis, Axis *vertAxis);

    /**
     * Sets vertical line value.
     * @param value mark value
     */
    void SetVerticalLine(double value);

    /**
     * Sets horizontal line value.
     * @param value mark value
     */
    void SetHorizontalLine(double value);

    /**
     * Sets line value.
     * @param value mark value
     * @param horizontal true to mark horizontal line, false to mark vertical
     */
    void SetValue(double value, bool horizontal);

private:
    wxPen m_linePen;

    double m_value;
    bool m_horizontal;
};

/**
 * Marker that marks range of data.
 *
 */
class WXDLLIMPEXP_FREECHART RangeMarker : public Marker
{
public:
    RangeMarker(AreaDraw *rangeAreaDraw);
    virtual ~RangeMarker();

    virtual void Draw(wxDC &dc, wxRect rcData, Axis *horizAxis, Axis *vertAxis);

    /**
     * Sets vertical range.
     * @param minValue range minimal value
     * @param maxValue range maximal value
     */
    void SetVerticalRange(double minValue, double maxValue);

    /**
     * Sets horizontal range.
     * @param minValue range minimal value
     * @param maxValue range maximal value
     */
    void SetHorizontalRange(double minValue, double maxValue);

    /**
     * Sets range.
     * @param minValue range minimal value
     * @param maxValue range maximal value
     * @param horizontal true to mark horizontal range, false to mark vertical
     */
    void SetRange(double minValue, double maxValue, bool horizontal);

    /**
     * Sets area draw object to draw marked range.
     * @param rangeArea new range area draw
     */
    void SetRangeAreaDraw(AreaDraw *rangeAreaDraw);

private:
    double m_minValue;
    double m_maxValue;
    bool m_horizontal;

    AreaDraw *m_rangeAreaDraw;
};

#endif /*MARKER_H_*/
