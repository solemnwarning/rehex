/////////////////////////////////////////////////////////////////////////////
// Name:    juliantimeseriesdataset.cpp
// Purpose: An XY dataset where the X axis is a Julian Date
// Author:    Carsten Arnholm
// Created:    2010/08/19
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/xy/juliantimeseriesdataset.h"


JulianTimeSeriesDataset::JulianTimeSeriesDataset()
{}

JulianTimeSeriesDataset::JulianTimeSeriesDataset(const vector<TimePair>& data)
: m_data(data)
{}

JulianTimeSeriesDataset::~JulianTimeSeriesDataset()
{}

size_t JulianTimeSeriesDataset::GetSerieCount()
{
    return 1;
}

size_t JulianTimeSeriesDataset::GetCount(size_t WXUNUSED(serie))
{
    return m_data.size();
}

wxString JulianTimeSeriesDataset::GetSerieName(size_t WXUNUSED(serie))
{
    return wxT("JulianTimeSeriesDataset");
}

double JulianTimeSeriesDataset::GetX(size_t index, size_t WXUNUSED(serie))
{
   return m_data[index].first;
}

double JulianTimeSeriesDataset::GetY(size_t index, size_t WXUNUSED(serie))
{
    return m_data[index].second;
}

void JulianTimeSeriesDataset::clear()
{
   m_data.clear();
}

void JulianTimeSeriesDataset::reserve(size_t length)
{
   m_data.reserve(length);
}

void JulianTimeSeriesDataset::push_back(const TimePair& tvpair)
{
   m_data.push_back(tvpair);
}

