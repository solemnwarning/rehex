/////////////////////////////////////////////////////////////////////////////
// Name:    timeseriesdataset.cpp
// Purpose: Time series dataset implementation
// Author:    Moskvichev Andrey V.
// Created:    16.02.2012
// RCS-ID:    $Id: wxAdvTable.h,v 1.3 2008/11/07 16:42:58 moskvichev Exp $
// Copyright:    (c) 2012 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/xy/timeseriesdataset.h>

IMPLEMENT_CLASS(TimeSeriesDataset, XYDataset)

TimeSeriesDataset::TimeSeriesDataset(double *data, time_t *times, size_t count)
{
    m_data = new double[count];
    m_times = new time_t[count];
    m_count = count;

    for (size_t n = 0; n < count; n++) {
        m_data[n] = data[n];
        m_times[n] = times[n];
    }
}

TimeSeriesDataset::~TimeSeriesDataset()
{
    m_count = 0;
    wxDELETEA(m_data);
    wxDELETEA(m_times);
}

size_t TimeSeriesDataset::GetSerieCount()
{
    return 1;
}

size_t TimeSeriesDataset::GetCount(size_t WXUNUSED(serie))
{
    return m_count;
}

size_t TimeSeriesDataset::GetCount()
{
    return m_count;
}

wxString TimeSeriesDataset::GetSerieName(size_t WXUNUSED(serie))
{
    return wxT("Time series");
}

double TimeSeriesDataset::GetX(size_t index, size_t WXUNUSED(serie))
{
    return index;
}

double TimeSeriesDataset::GetY(size_t index, size_t WXUNUSED(serie))
{
    return m_data[index];
}

time_t TimeSeriesDataset::GetDate(size_t index)
{
    return m_times[index];
}

DateTimeDataset *TimeSeriesDataset::AsDateTimeDataset()
{
    return this;
}
