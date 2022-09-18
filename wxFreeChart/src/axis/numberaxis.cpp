/////////////////////////////////////////////////////////////////////////////
// Name:        numberaxis.cpp
// Purpose:     number axis implementation
// Author:      Moskvichev Andrey V.
// Created:     2008/11/07
// Copyright:   (c) 2008-2010 Moskvichev Andrey V.
// Licence:     wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/axis/numberaxis.h>
#include <wx/xy/xydataset.h>
#include <wx/category/categorydataset.h>

#ifdef WIN32
#include <float.h>

bool IsNormalValue(double v)
{
    switch (_fpclass(v)) {
        case _FPCLASS_SNAN:
        case _FPCLASS_QNAN:
        case _FPCLASS_NINF:
        case _FPCLASS_PINF:
            return false;
        default:
            return true;
    }
}
#else
#include <math.h>

bool IsNormalValue(double v)
{
    switch (std::fpclassify(v)) {
        case FP_NAN:
        case FP_INFINITE:
        case FP_SUBNORMAL:
            return false;
        default:
            return true;
    }
}

#endif

IMPLEMENT_CLASS(NumberAxis, Axis)

NumberAxis::NumberAxis(AXIS_LOCATION location)
: LabelAxis(location)
{
    // default values
    m_tickFormat = wxT("%.2f");

    m_minValue = 0;
    m_maxValue = 100;

    m_labelInterval = 10;
    m_labelCount = 0;

    m_intValues = false;
    m_hasLabels = false;
    m_fixedBounds = false;
    m_zeroOrigin = true;
    m_extraMajorInterval = false;

    m_multiplier = 1;
}

NumberAxis::~NumberAxis()
{
}


bool NumberAxis::AcceptDataset(Dataset *WXUNUSED(dataset))
{
    return true;
}

void NumberAxis::SetFixedBounds(double minValue, double maxValue)
{
    m_minValue = minValue;
    m_maxValue = maxValue;
    m_fixedBounds = true;

    UpdateMajorIntervalValues();
    FireBoundsChanged();
}

bool NumberAxis::UpdateBounds()
{
    // No need to update bounds if they are fixed (defined by the user).
    if (m_fixedBounds) 
    {
        m_labelInterval = CalcNiceInterval((m_maxValue - m_minValue) / (DEFAULT_MAJOR_LABEL_COUNT - 1));
        m_labelCount = ((m_maxValue - m_minValue) / m_labelInterval) + 1;
        UpdateMajorIntervalValues();
        return false;
    }

    m_hasLabels = false;

    for (size_t n = 0; n < m_datasets.Count(); n++) 
    {
        bool verticalAxis = IsVertical();

        double minValue = m_datasets[n]->GetMinValue(verticalAxis);
        double maxValue = m_datasets[n]->GetMaxValue(verticalAxis);

        if (n == 0) 
        {
            m_minValue = minValue;
            m_maxValue = maxValue;
        }
        else 
        {
            m_minValue = wxMin(m_minValue, minValue);
            m_maxValue = wxMax(m_maxValue, maxValue);
        }
    }
    
    // Prefer the axis at zero.
    if (m_zeroOrigin && m_minValue > 0)
        m_minValue = 0;

    // Handle horizontal line case. Offset from a zero baseline.
    if (m_minValue == m_maxValue)
    {
        if (m_maxValue > 0)
            m_minValue = 0;
        else
            m_maxValue = 0;
    }

    // Make sure m_maxValue doesn't fall on a boundary for vertical axis (ensures some padding
    // between maximum value and topmost tick).
    if (m_extraMajorInterval && IsVertical())
        m_maxValue += 0.00000001;

    m_labelInterval = CalcNiceInterval((m_maxValue - m_minValue) / (DEFAULT_MAJOR_LABEL_COUNT - 1));
    m_maxValue = ceil(m_maxValue / m_labelInterval) * m_labelInterval;
    m_minValue = floor(m_minValue / m_labelInterval) * m_labelInterval;
    m_labelCount = ((m_maxValue - m_minValue) / m_labelInterval) + 1;
    
    // The following might be a way of formatting the number of relevant decimal places.
    // int nfrac = wxMax(-floor(log10(nice)), 0);
        
    UpdateMajorIntervalValues();
    FireBoundsChanged();
    return true;
}

void NumberAxis::UpdateMajorIntervalValues()
{
    m_hasLabels = false;

    if (!IsNormalValue(m_labelInterval)) 
    {
        // overflow condition bugfix
        m_minValue = 0;
        m_maxValue = 0;
        m_labelInterval = 0;
    }
    else 
    {
        if (m_labelCount)
            m_hasLabels = true;
    }
    FireAxisChanged();
}

wxSize NumberAxis::GetLongestLabelExtent(wxDC &dc)
{
    dc.SetFont(GetLabelTextFont());

    wxSize sizeMinValue = dc.GetTextExtent(wxString::Format(m_tickFormat, m_minValue));
    wxSize sizeMaxValue = dc.GetTextExtent(wxString::Format(m_tickFormat, m_maxValue));

    if (sizeMinValue.x > sizeMaxValue.x) {
        return sizeMinValue;
    }
    else {
        return sizeMaxValue;
    }
}

void NumberAxis::GetDataBounds(double &minValue, double &maxValue) const
{
    minValue = m_minValue;
    maxValue = m_maxValue;
}

double NumberAxis::GetValue(size_t step)
{
    return m_minValue + step * m_labelInterval;
}

void NumberAxis::GetLabel(size_t step, wxString &label)
{
    double value = GetValue(step);

    if (value == -0) {
        value = 0;
    }

    if (m_intValues) {
        // orig : label = wxString::Format(wxT("%i"), (int) value);
        label = wxString::Format(wxT("%i"), int(value * m_multiplier));
    }
    else {
        // orig : label = wxString::Format(m_tickFormat, value);
        label = wxString::Format(m_tickFormat, value * m_multiplier);
    }
}

double NumberAxis::CalcNiceInterval (double value, bool round)
{
    // Get the logarithmic form of the value. 
    double exp = floor(log10(fabs(value)));
    double mant = value / pow(10.0, exp);
    
    // Find a nice value.
    double nice;
    
    if (round)
    {
        if (mant <= 1.5)
            nice = 1.0;
        else if (mant <= 3.0)
            nice = 2.0;
        else if (mant <= 7.0)
            nice = 5.0;
        else
            nice = 10.0;  
    }
    
    else
    {
        if (mant <= 1.0)
            nice = 1.0;
        else if (mant <= 2.0)
            nice = 2.0;
        else if (mant <= 5.0)
            nice = 5.0;
        else
            nice = 10.0;    
    }
    
    return  nice * pow(10, exp);
}

bool NumberAxis::IsEnd(size_t step)
{
    return step >= m_labelCount;
}

bool NumberAxis::HasLabels()
{
    return m_hasLabels;
}

size_t NumberAxis::GetLabelCount() const
{
  return m_labelCount;
}

double NumberAxis::GetMultiplier() const
{
  return m_multiplier;
}

void NumberAxis::SetMultiplier(double multiplier)
{
  m_multiplier = multiplier;
}
