/////////////////////////////////////////////////////////////////////////////
// Name:    compdateaxis.h
// Purpose: comp date axis declarations
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef COMPDATEAXIS_H_
#define COMPDATEAXIS_H_

#include <wx/axis/axis.h>
#include <wx/areadraw.h>

#include <wx/dynarray.h>

WX_DECLARE_USER_EXPORTED_OBJARRAY(wxDateSpan, wxDateSpanArray, WXDLLIMPEXP_FREECHART);
WX_DECLARE_USER_EXPORTED_OBJARRAY(wxTimeSpan, wxTimeSpanArray, WXDLLIMPEXP_FREECHART);

/**
 * Composite date axis.
 * Draws multiple date/time spans (like day, week, month, year),
 * instead of just label as DateAxis does.
 */
class WXDLLIMPEXP_FREECHART CompDateAxis : public Axis
{
    DECLARE_CLASS(CompDateAxis)
public:
    CompDateAxis(AXIS_LOCATION location);
    virtual ~CompDateAxis();

    virtual void Draw(wxDC &dc, wxRect rc);

    virtual void DrawGridLines(wxDC &dc, wxRect rc);

    virtual wxCoord GetExtent(wxDC &dc);

    virtual bool UpdateBounds() wxOVERRIDE;

    virtual void GetDataBounds(double &minValue, double &maxValue) const;

    virtual wxCoord ToGraphics(wxDC &dc, int minCoord, int gRange, double value);

    virtual double ToData(wxDC &dc, int minCoord, int gRange, wxCoord g);

    /**
     * Adds interval.
     */
    void AddInterval(const wxDateSpan &interval);

    void AddInterval(const wxTimeSpan &interval);

    /**
     * Sets area draw to draw spans background.
     * CompDateAxis takes ownership of area draw.
     * @param spanDraw area draw to be set
     */
    void SetSpanDraw(AreaDraw *spanDraw)
    {
        wxREPLACE(m_spanDraw, spanDraw);
        FireAxisChanged();
    }

protected:
    virtual bool AcceptDataset(Dataset *dataset);

private:
    void DrawSpan(wxDC &dc, wxRect rcAxis, int spanNum, wxString spanLabel, double start, double end);

    wxString GetSpanLabel(wxDateTime date, wxDateSpan span);

    wxCoord GetSpanExtent(wxDC &dc);

    bool GetWindowDateBounds(wxDateTime &date0, wxDateTime &date1);

    double DateToDataCoord(wxDateTime &date);

    bool GetFirstDate(wxDateTime &date);
    bool GetLastDate(wxDateTime &date);

    bool GetFirstLastDate(wxDateTime &firstDate, wxDateTime &lastDate);

    bool GetMinSpan(wxDateSpan &span);

    size_t m_dateCount;

    bool m_fillDateGaps;

    wxFont m_labelFont;
    wxColour m_labelColour;

    wxCoord m_minLabelGap; // minimal distance between labels in date/time span
    wxCoord m_labelMargin; // distance between label and span area bounds
    AreaDraw *m_spanDraw;

    wxDateSpanArray m_dateSpans;
};

#endif /* COMPDATEAXIS_H_ */
