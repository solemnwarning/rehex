/////////////////////////////////////////////////////////////////////////////
// Name:    xysimpledataset.cpp
// Purpose: xy simple dataset implementation
// Author:    Moskvichev Andrey V.
// Created:    2009/11/25
// Copyright:    (c) 2009 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/xy/xysimpledataset.h>

#include "wx/arrimpl.cpp"

WX_DEFINE_EXPORTED_OBJARRAY(XYSerieArray);

IMPLEMENT_CLASS(XYSimpleDataset, XYDataset)

//
// XYSerie
//

XYSerie::XYSerie(double *data, size_t count)
{
    for (size_t i = 0; i < count; i++)
        m_newdata.push_back(wxRealPoint(data[i * 2], data[(i * 2) + 1]));
}

XYSerie::XYSerie(const wxVector<wxRealPoint>& seriesData)
{
    m_newdata = seriesData;
}

XYSerie::~XYSerie()
{

}

double XYSerie::GetX(size_t index)
{
    return m_newdata.at(index).x;
}

double XYSerie::GetY(size_t index)
{
    return m_newdata.at(index).y;
}

void XYSerie::UpdateX(size_t index, double x)
{
    m_newdata.at(index).x = x;
}

void XYSerie::UpdateY(size_t index, double y)
{
    m_newdata.at(index).y = y;
}

size_t XYSerie::GetCount()
{
    return m_newdata.size();
}

const wxString &XYSerie::GetName()
{
    return m_name;
}

void XYSerie::SetName(const wxString &name)
{
    m_name = name;
}

void XYSerie::UpdatePoint(size_t index, const wxRealPoint& values)
{
    m_newdata.at(index).x = values.x;
    m_newdata.at(index).y = values.y;
}

void XYSerie::Insert(size_t index, const wxRealPoint& values)
{
    m_newdata.insert(m_newdata.begin() + index, values);
}

void XYSerie::Remove(size_t index)
{
    m_newdata.erase(m_newdata.begin() + index);
}

void XYSerie::Append(const wxRealPoint& values)
{
    m_newdata.push_back(values);
}

//
// XYSimpleDataset
//

XYSimpleDataset::XYSimpleDataset()
{
}

XYSimpleDataset::~XYSimpleDataset()
{
    for (size_t n = 0; n < m_series.Count(); n++) {
        wxDELETE(m_series[n]);
    }
}

void XYSimpleDataset::AddSerie(double *data, size_t count)
{
    wxVector<wxRealPoint> newdata;
    for (size_t i = 0; i < count; i++)
        newdata.push_back(wxRealPoint(data[i * 2], data[(i * 2) + 1]));

    AddSerie(new XYSerie(newdata));
}

void XYSimpleDataset::AddSerie(XYSerie *serie)
{
    m_series.Add(serie);
    DatasetChanged();
}

XYSerie* XYSimpleDataset::GetSerie(size_t series)
{
    wxCHECK(series < m_series.Count(), 0);
    return m_series[series];
}

double XYSimpleDataset::GetX(size_t index, size_t serie)
{
    wxCHECK(serie < m_series.Count(), 0);
    return m_series[serie]->GetX(index);
}

double XYSimpleDataset::GetY(size_t index, size_t serie)
{
    wxCHECK(serie < m_series.Count(), 0);
    return m_series[serie]->GetY(index);
}

size_t XYSimpleDataset::GetSerieCount()
{
    return m_series.Count();
}

size_t XYSimpleDataset::GetCount(size_t serie)
{
    return m_series[serie]->GetCount();
}

wxString XYSimpleDataset::GetSerieName(size_t serie)
{
    wxCHECK(serie < m_series.Count(), wxEmptyString);
    return m_series[serie]->GetName();
}

void XYSimpleDataset::SetSerieName(size_t serie, const wxString &name)
{
    m_series[serie]->SetName(name);
    DatasetChanged();
}
