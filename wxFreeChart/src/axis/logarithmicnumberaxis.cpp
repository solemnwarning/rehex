/////////////////////////////////////////////////////////////////////////////
// Name:    logarithmicnumberaxis.cpp
// Purpose: label axis implementation
// Author:    Andreas Kuechler
// Created:    2008/11/07
// Copyright:    (c) 2010 Andreas Kuechler
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/axis/logarithmicnumberaxis.h>
#include <wx/xy/xydataset.h>
#include <math.h>

IMPLEMENT_CLASS(LogarithmicNumberAxis, NumberAxis);

LogarithmicNumberAxis::LogarithmicNumberAxis(AXIS_LOCATION location)
: NumberAxis(location)
, m_longExponent(false)
, m_logBase(10.0)
{
    m_logBase == 10.0 ? SetTickFormat(wxT("%2.2e")) : SetTickFormat(wxT("%2.2f"));
    SetMinorIntervalCount(9); 
}

LogarithmicNumberAxis::~LogarithmicNumberAxis()
{
}

bool LogarithmicNumberAxis::UpdateBounds()
{
    if (m_fixedBounds) 
        return false; // bounds are fixed, so don't update

    m_hasLabels = false;

    for (size_t n = 0; n < m_datasets.Count(); n++) 
    {
        double minValue = GetMinValue(m_datasets[n]);
        double maxValue = GetMaxValue(m_datasets[n]);

        if (n == 0) {
            m_minValue = minValue;
            m_maxValue = maxValue;
        }
        else {
            m_minValue = wxMin(m_minValue, minValue);
            m_maxValue = wxMax(m_maxValue, maxValue);
        }
    }

    if (m_minValue == m_maxValue) 
    {
        if (m_maxValue > 0)
            m_minValue = 0;

        else
            m_maxValue = 0;
    }

    // Note: log_base(n) = log(n) / log(base).

    m_minValue = pow(m_logBase, floor(log(m_minValue) / log(m_logBase)));
    m_maxValue = pow(m_logBase, ceil(log(m_maxValue) / log(m_logBase)));

    m_labelCount = (log(m_maxValue) / log(m_logBase)) - (log(m_minValue) / log(m_logBase)) + 1;

    UpdateMajorIntervalValues();
    FireBoundsChanged();
    return true;
}

double LogarithmicNumberAxis::GetMinValue(Dataset* dataset)
{
  XYDataset* xyds = wxDynamicCast(dataset, XYDataset);
  double min = 0;
  if(IsVertical()) {
    for (size_t serie = 0; serie < xyds->GetSerieCount(); serie++) {
      for (size_t n = 0; n < xyds->GetCount(serie); n++) {
        double y = xyds->GetY(n, serie);

        if(y == 0) continue;

        if (n == 0 && serie == 0)
          min = y;
        else
          min = wxMin(min, y);
      }
    }
  }
  else {
    for (size_t serie = 0; serie < xyds->GetSerieCount(); serie++) {
      for (size_t n = 0; n < xyds->GetCount(serie); n++) {
        double x = xyds->GetX(n, serie);

        if(x == 0) continue;

        if (n == 0 && serie == 0)
          min = x;
        else
          min = wxMin(min, x);
      }
    }
  }

  return min;
}

double LogarithmicNumberAxis::GetMaxValue(Dataset* dataset)
{
  XYDataset* xyds = wxDynamicCast(dataset, XYDataset);
  double max = 0;

  if(IsVertical()) {
    for (size_t serie = 0; serie < xyds->GetSerieCount(); serie++) {
      for (size_t n = 0; n < xyds->GetCount(serie); n++) {
        double y = xyds->GetY(n, serie);

        if(y == 0) continue;

        if (n == 0 && serie == 0)
          max = y;
        else
          max = wxMax(max, y);
      }
    }
  }
  else {
    for (size_t serie = 0; serie < xyds->GetSerieCount(); serie++) {
      for (size_t n = 0; n < xyds->GetCount(serie); n++) {
        double x = xyds->GetX(n, serie);
        if (n == 0 && serie == 0)
          max = x;
        else
          max = wxMax(max, x);
      }
    }
  }

  return max;
}

void LogarithmicNumberAxis::SetLogBase(double logBase)
{
    m_logBase = logBase;
    m_logBase == 10.0 ? SetTickFormat(wxT("%2.2e")) : SetTickFormat(wxT("%2.2f"));
}

void LogarithmicNumberAxis::EnableLongLabelExponent(bool enable)
{
    m_longExponent = enable;
}

double LogarithmicNumberAxis::GetValue(size_t step)
{
    double min, max;
    GetDataBounds(min, max);

    double logMin = log(min) / log(m_logBase);
    double logMax = log(max) / log(m_logBase);

    double logInterval = (logMax - logMin) / (GetLabelCount() - 1);
    return min * pow(m_logBase, step * logInterval);
}

void LogarithmicNumberAxis::GetLabel(size_t step, wxString& label)
{
    NumberAxis::GetLabel(step, label);

#ifdef __WXMSW__
    // Remove trailing zeros on wxMSW.
    if (m_logBase == 10.0 && !m_longExponent) {
        label.erase(label.length() - 3, 1);
    }
#endif // __WXMSW__
}

wxCoord LogarithmicNumberAxis::ToGraphics(wxDC &WXUNUSED(dc), int minCoord, int gRange, double value)
{
    double minValue, maxValue;
    GetDataBounds(minValue, maxValue);

    minCoord += m_marginMin;
    gRange -= (m_marginMin + m_marginMax);

    if (gRange < 0) {
        gRange = 0;
    }

    if (m_useWin) {
        minValue = m_winPos;
        maxValue = m_winPos + m_winWidth;
    }

    double logValue = log(value) / log(m_logBase);
    double logMax = log(maxValue) / log(m_logBase);
    double logMin = log(minValue) / log(m_logBase);

    return ::ToGraphics(minCoord, gRange, logMin, logMax, 0/*textMargin*/, IsVertical(), logValue);
}

double LogarithmicNumberAxis::ToData(wxDC &WXUNUSED(dc), int minCoord, int gRange, wxCoord g)
{
    double minValue, maxValue;
    GetDataBounds(minValue, maxValue);

    minCoord += m_marginMin;
    gRange -= (m_marginMin + m_marginMax);
    if (gRange < 0) {
        gRange = 0;
    }

    if (m_useWin) {
        minValue = m_winPos;
        maxValue = m_winPos + m_winWidth;
    }

    double logMin = log(minValue) / log(m_logBase);
    double logMax = log(minValue) / log(m_logBase);
    return ::ToData(minCoord, gRange, logMin, logMax, 0/*textMargin*/, IsVertical(), g);
}

double LogarithmicNumberAxis::BoundValue(double value)
{
//  double v = abs((double)log10(value));
    if (m_useWin) {
        if (value <= m_winPos) {
            return m_winPos;
        }
        else if (value >= (m_winPos + m_winWidth)) {
            return m_winPos + m_winWidth;
        }
        else {
            return value;
        }
    }
    else {
        return value;
    }
}

bool LogarithmicNumberAxis::IsVisible(double value)
{
  if(value == 0.0) {
    return false;
  }
  else {
    if (m_useWin) {
        return (value >= m_winPos && value <= (m_winPos + m_winWidth));
    }
    else {
      double minValue, maxValue;
      GetDataBounds(minValue, maxValue);

      return (value >= minValue && value <= maxValue);
    }
  }
}

