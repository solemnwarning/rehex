/////////////////////////////////////////////////////////////////////////////
// Name:    labelaxis.h
// Purpose:    label axis declaration
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef LABELAXIS_H_
#define LABELAXIS_H_

#include <wx/axis/axis.h>

/**
 * Class that used to implement labels with different colours.
 */
class WXDLLIMPEXP_FREECHART LabelColourer
{
public:
    // IY: Virtual destructor needed otherwise behaviour is undefined.
    virtual ~LabelColourer() {}
    virtual wxColor GetColour(int step) = 0;
};

/**
 * Base class for axes for displaying data labels.
 */
class WXDLLIMPEXP_FREECHART LabelAxis : public Axis
{
    DECLARE_CLASS(LabelAxis)
public:
    LabelAxis(AXIS_LOCATION location);
    virtual ~LabelAxis();

    /**
     * Sets axis title.
     * @param new axis title
     */
    void SetTitle(const wxString &title)
    {
        m_title = title;
        FireAxisChanged();
    }

    /**
     * Returns axis title.
     * @return axis title
     */
    const wxString &GetTitle()
    {
        return m_title;
    }

    /**
     * Sets axis title location.
     * @param location new location for axis title,
     * acceptable values wxLEFT, wxCENTER, wxRIGHT for horizontal axes,
     * wxTOP, wxCENTER, wxBOTTOM for vertical axes.
     */
    void SetTitleLocation(int location)
    {
        if (m_titleLocation != location) {
            m_titleLocation = location;
            FireAxisChanged();
        }
    }

    /**
     * Returns axis title location.
     * @return axis title location
     */
    int GetTitleLocation()
    {
        return m_titleLocation;
    }

    /**
     * Sets axis title font.
     * @param axis title font
     */
    void SetTitleFont(wxFont &font)
    {
        m_titleFont = font;
        FireAxisChanged();
    }

    /**
     * Returns axis title font.
     * @return axis title font
     */
    const wxFont &GetTitleFont()
    {
        return m_titleFont;
    }

    /**
     * Sets axis title colour.
     * @param new axis title colour
     */
    void SetTitleColour(wxColour &colour)
    {
        if (m_titleColour != colour) {
            m_titleColour = colour;
            FireAxisChanged();
        }
    }

    /**
     * Returns axis title colour.
     * @return axis title colour
     */
    wxColour GetTitleColour()
    {
        return m_titleColour;
    }

    /**
     * Sets pen for label lines.
     * @param labelPen pen for label lines
     */
    void SetLabelPen(wxPen labelPen)
    {
        m_labelPen = labelPen;
        FireAxisChanged();
    }

    /**
     * Sets colour for labels.
     * @param labelColour color for labels
     */
    void SetLabelTextColour(wxColour labelTextColour)
    {
        m_labelTextColour = labelTextColour;
        FireAxisChanged();
    }

    /**
     * Returns label colour.
     * @return label colour
     */
    wxColour GetLabelTextColour()
    {
        return m_labelTextColour;
    }

    /**
     * Sets font for labels text.
     * @param labelFont font for labels text
     */
    void SetLabelTextFont(wxFont labelTextFont)
    {
        m_labelTextFont = labelTextFont;
        FireAxisChanged();
    }

    /**
     * Returns label font.
     * @return label font
     */
    const wxFont& GetLabelTextFont()
    {
        return m_labelTextFont;
    }

    /**
     * Sets whether to draw labels text vertical.
     * @param verticalLabelText true to draw labels text vertical
     */
    void SetVerticalLabelText(bool verticalLabelText)
    {
        if (m_verticalLabelText != verticalLabelText) {
            m_verticalLabelText = verticalLabelText;
            FireAxisChanged();
        }
    }

    /**
     * Returns whether to draw labels text vertical.
     * @return true if labels text will be drawn vertical
     */
    bool GetVerticalLabelText()
    {
        return m_verticalLabelText;
    }

    /**
     * Sets major label steps.
     * @param step  The step size at which major label should be drawn
     */
    wxDEPRECATED_MSG("Use SetMinorIntervalCount instead.")
    void SetMajorLabelSteps(size_t step)
    {
        if (m_majorLabelStep != step) {
            m_majorLabelStep = step;
            FireAxisChanged();
        }
    }

    /**
     * Set the number of ticks between each label (major interval).
     * @param count The number of minor interval ticks that should appear between each major interval label.
     */
    void SetMinorIntervalCount(size_t count)
    {
        m_minorIntervalCount = count;
        FireAxisChanged();
    }

    /**
     * Get the number of ticks between each label (major interval).
     * @return The number of minor interval ticks that appear between each major interval label.
     */
    size_t GetMinorIntervalCout()
    {
        return m_minorIntervalCount;
    }

    void SetLabelSkip(int blankLabels);

    int GetLabelSkip();

    void SetLabelColourer(LabelColourer *labelColourer)
    {
        wxREPLACE(m_labelColourer, labelColourer);
    }

    LabelColourer *GetLabelColourer()
    {
        return m_labelColourer;
    }

    /**
     * Sets visibility of axis
     * @param bVisible - false if hidden
     */
    void SetAxisVisible(bool bVisible);

    //
    // Axis
    //
    virtual void Draw(wxDC &dc, wxRect rc);

    virtual void DrawGridLines(wxDC &dc, wxRect rc);

    virtual wxCoord GetExtent(wxDC &dc);

protected:
    //
    // Functions that must be implemented by derivative classes
    //

    /**
     * Returns value on step.
     * @param step step index
     * @return value on step
     */
    virtual double GetValue(size_t step) = 0;

    /**
     * Returns label on step.
     * @param step step index
     * @param label output label
     */
    virtual void GetLabel(size_t step, wxString &label) = 0;

    /**
     * Check whether step is last.
     * @param step step
     * @return true if step is last
     */
    virtual bool IsEnd(size_t step) = 0;

    virtual wxSize GetLongestLabelExtent(wxDC &dc) = 0;

    virtual bool HasLabels();

private:
    void DrawLabels(wxDC &dc, wxRect rc);

    void DrawLabel(wxDC &dc, wxRect rc, const wxString &label, double value, bool isMajorLabel);

    void DrawBorderLine(wxDC &dc, wxRect rc);
    
    void DrawGridLine(wxDC& dc, const wxRect& rc, double value);

    wxCoord m_labelLineSize;
    wxCoord m_labelGap;

    // labels properties
    wxFont m_labelTextFont;
    wxColour m_labelTextColour;
    wxPen m_labelPen;
    bool m_verticalLabelText;
    size_t m_majorLabelStep;
    size_t m_minorIntervalCount;

    // label title properties
    wxString m_title;
    wxFont m_titleFont;
    wxColour m_titleColour;
    int m_titleLocation;

    bool m_visible;
    int m_blankLabels;

    LabelColourer *m_labelColourer;
};

#endif /*LABELAXIS_H_*/
