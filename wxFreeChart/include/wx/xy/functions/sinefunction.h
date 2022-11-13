/////////////////////////////////////////////////////////////////////////////
// Name:    sinefunction.h
// Purpose: sine function dataset declaration
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef SINEFUNCTION_H_
#define SINEFUNCTION_H_

#include <wx/xy/xydataset.h>

/**
 * Sine function of type: y = a * sin(x)
 */
class WXDLLIMPEXP_FREECHART SineFunction : public XYDataset
{
public:
    /**
     * Construct new sine function.
     * @param a y scaling coefficient
     * @param min minimal x
     * @param max maximal x
     * @param step x step
     */
    SineFunction(double a, double minX, double maxX, double step);
    virtual ~SineFunction();

    virtual double GetX(size_t index, size_t serie);

    virtual double GetY(size_t index, size_t serie);

    virtual size_t GetCount(size_t serie);

    virtual size_t GetSerieCount();

    virtual wxString GetSerieName(size_t serie);

private:
    double m_a;

    double m_minX;
    double m_maxX;
    double m_step;
};

#endif /*SINEFUNCTION_H_*/
