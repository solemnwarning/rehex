/////////////////////////////////////////////////////////////////////////////
// Name:    polynom.h
// Purpose: polynom function dataset declaration
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef POLYNOM_H_
#define POLYNOM_H_

#include <wx/xy/xydataset.h>

/**
 * Polynom function of type: y = c0 * x^n + c1 * x^(n-1) + ... + c(n-1) * x + cn
 * where: c0 ... cn - coefficients
 */
class WXDLLIMPEXP_FREECHART Polynom : public XYDataset
{
public:
    /**
     * Constucts new polynom function dataset.
     * @param coefs coefficients for x values
     * @param min minimal x value
     * @param max maximal x value
     * @param step x value step
     */
    Polynom(double *coefs, size_t coefCount, double min, double max, double step);
    virtual ~Polynom();

    virtual double GetX(size_t index, size_t serie);

    virtual double GetY(size_t index, size_t serie);

    virtual size_t GetCount(size_t serie);

    virtual size_t GetSerieCount();

    virtual wxString GetSerieName(size_t serie);

private:
    double CalcY(double x);

    double *m_coefs;
    size_t m_coefCount;
    double m_min;
    double m_max;
    double m_step;
};

#endif /*POLYNOM_H_*/
