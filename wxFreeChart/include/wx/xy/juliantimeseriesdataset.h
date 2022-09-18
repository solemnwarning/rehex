/////////////////////////////////////////////////////////////////////////////
// Name:    JulianTimeSeriesDataset.h
// Purpose: An XY dataset where the X axis is a Julian Date
// Author:    Carsten Arnholm
// Created:    2010/08/19
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef TIMESERIESDATA_H
#define TIMESERIESDATA_H

#include <map> // XXX stl classes must be removed!
#include <vector>
using std::vector;

#include <wx/dataset.h>
#include <wx/xy/xydataset.h>


class JulianTimeSeriesDataset : public XYDataset 
{
public:
    typedef std::pair<double,double> TimePair;  // a pair with time (julian date) and value data

    JulianTimeSeriesDataset();
    JulianTimeSeriesDataset(const vector<TimePair>& data);
    virtual ~JulianTimeSeriesDataset();

    virtual size_t GetSerieCount();

    virtual wxString GetSerieName(size_t serie);

    virtual size_t GetCount(size_t serie);

    virtual double GetX(size_t index, size_t serie);

    virtual double GetY(size_t index, size_t serie);

    void clear();
    void reserve(size_t length);
    void push_back(const TimePair& tvpair);

private:
    vector<TimePair> m_data; // XXX remove this, stl is not allowed
};

#endif // TIMESERIESDATA_H

