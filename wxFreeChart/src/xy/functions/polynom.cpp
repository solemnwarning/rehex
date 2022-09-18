/////////////////////////////////////////////////////////////////////////////
// Name:    polynom.cpp
// Purpose: polynom function implementation
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/xy/functions/polynom.h>

static wxString polynomFunctionName(wxT("Polynom function"));

Polynom::Polynom(double *coefs, size_t coefCount, double min, double max, double step)
{
    m_coefs = new double[coefCount];
    for (size_t n = 0; n < coefCount; n++)
        m_coefs[n] = coefs[n];
    m_coefCount = coefCount;
    m_min = min;
    m_max = max;
    m_step = step;
}

Polynom::~Polynom()
{
    wxDELETEA(m_coefs);
}

double Polynom::GetX(size_t index, size_t WXUNUSED(serie))
{
    return m_min + index * m_step;
}

double Polynom::GetY(size_t index, size_t WXUNUSED(serie))
{
    return CalcY(GetX(index, 0));
}

size_t Polynom::GetCount(size_t WXUNUSED(serie))
{
    return RoundHigh((m_max - m_min) / m_step);
}

size_t Polynom::GetSerieCount()
{
    return 1;
}

double Polynom::CalcY(double x)
{
    double xn = 1;
    double y = 0;

    for (size_t n = m_coefCount - 1; n >= 0; n--) {
        y += xn * m_coefs[n];
        xn *= x;
    }
    return y;
}

wxString Polynom::GetSerieName(size_t WXUNUSED(serie))
{
    return polynomFunctionName;
}
