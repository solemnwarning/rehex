/////////////////////////////////////////////////////////////////////////////
// Name:    dateaxis.h
// Purpose: Date/time axis declaration
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef DATEAXIS_H_
#define DATEAXIS_H_

#include <wx/axis/labelaxis.h>


/**
 * An axis for displaying date/time values.
 * TODO:
 * - works with only one dataset.
 */
class WXDLLIMPEXP_FREECHART DateAxis : public LabelAxis
{
    DECLARE_CLASS(DateAxis)
public:
    DateAxis(AXIS_LOCATION location);
    virtual ~DateAxis();

    virtual bool UpdateBounds() wxOVERRIDE;

    /**
     * Sets date format for date labels.
     * @param dateFormat date format in strftime style
     */
    void SetDateFormat(const wxString &dateFormat)
    {
        m_dateFormat = dateFormat;
        FireAxisChanged();
    }

    virtual void GetDataBounds(double &minValue, double &maxValue) const;

protected:
    virtual bool AcceptDataset(Dataset *dataset);

    //
    // LabelAxis
    //
    virtual double GetValue(size_t step);

    virtual void GetLabel(size_t step, wxString &label);

    virtual bool IsEnd(size_t step);

    virtual wxSize GetLongestLabelExtent(wxDC &dc);

private:
    size_t m_dateCount;

    wxString m_dateFormat;
};

#endif /*DATEAXIS_H_*/
