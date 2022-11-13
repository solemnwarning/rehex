/////////////////////////////////////////////////////////////////////////////
// Name:    logarithmicnumberaxis.h
// Purpose: label axis implementation
// Author:    Andreas Kuechler
// Created:    2008/11/07
// Copyright:    (c) 2010 Andreas Kuechler
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef LOGARITHMICNUMBERAXIS_H_INCLUDED
#define LOGARITHMICNUMBERAXIS_H_INCLUDED

#include <wx/axis/numberaxis.h>

/**
 * An axis for displaying and logarithmically scaling numerical data.
 */
class WXDLLIMPEXP_FREECHART LogarithmicNumberAxis : public NumberAxis
{
    DECLARE_CLASS(LogarithmicNumberAxis);
public:
    LogarithmicNumberAxis(AXIS_LOCATION location);
    virtual ~LogarithmicNumberAxis();

  virtual bool UpdateBounds() wxOVERRIDE;
  virtual double BoundValue(double value);
  virtual bool IsVisible(double value);

    /**
     * Sets logarithmic base.
     * @param logBase   A value used as logarithmic base.
     */
    void SetLogBase(double logBase);

    /**
     * Truncates exponent in scientific labels to 2 digits
     */
    void EnableLongLabelExponent(bool enable = true);

    /**
     * Overwrites Axis::ToGraphics to get logarithmic scaling.
     */
    virtual wxCoord ToGraphics(wxDC &dc, int minCoord, int gRange, double value);

    /**
     * Overwrites Axis::ToData to invert logarithmic scaling.
     */
    virtual double ToData(wxDC &dc, int minCoord, int gRange, wxCoord g);

protected:
    virtual void GetLabel(size_t step, wxString& label);
    virtual double GetValue(size_t step);

  double GetMinValue(Dataset* dataset);
  double GetMaxValue(Dataset* dataset);

private:
    bool m_longExponent;

    double m_logBase;
};

#endif // LOGARITHMICNUMBERAXIS_H_INCLUDED
