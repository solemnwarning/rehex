/////////////////////////////////////////////////////////////////////////////
// Name:    sinefunction.cpp
// Purpose: sine function implementation
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/xy/functions/sinefunction.h>

#include <math.h>

static wxString sineFunctionName(wxT("Sine function"));

SineFunction::SineFunction(double a, double minX, double maxX, double step)
{
    m_a = a;
    m_minX = minX;
    m_maxX = maxX;
    m_step = step;
}

SineFunction::~SineFunction()
{
}

double SineFunction::GetX(size_t index, size_t WXUNUSED(serie))
{
    return m_minX + index * m_step;
}

double SineFunction::GetY(size_t index, size_t WXUNUSED(serie))
{
    double x = m_minX + index * m_step;
    return m_a * sin(x);
}

size_t SineFunction::GetCount(size_t WXUNUSED(serie))
{
    return RoundHigh((m_maxX - m_minX) / m_step) + 1;
}

size_t SineFunction::GetSerieCount()
{
    return 1;
}

wxString SineFunction::GetSerieName(size_t WXUNUSED(serie))
{
    return sineFunctionName;
}
