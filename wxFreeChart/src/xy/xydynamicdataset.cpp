/////////////////////////////////////////////////////////////////////////////
// Name:    xydynamicdataset.cpp
// Purpose: xy dynamic serie and dataset implementation.
// Author:    Mike Sazonov
// E-mail:  msazonov(at)gmail.com
// Created:    2010/01/29
// Copyright:    (c) 2010 Mike Sazonov
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/xy/xydynamicdataset.h"
#include <wx/arrimpl.cpp>

IMPLEMENT_CLASS(XYDynamicSerie, wxObject);
WX_DEFINE_USER_EXPORTED_OBJARRAY(wxRealPointArray);

IMPLEMENT_CLASS(XYDynamicDataset, XYDataset);
WX_DEFINE_USER_EXPORTED_OBJARRAY(XYDynamicSerieArray);

//
// XYDynamicSerie
//

XYDynamicSerie::XYDynamicSerie()
    : wxObject()
{
    m_dataset = NULL;
}

XYDynamicSerie::XYDynamicSerie(const wxRealPointArray& data)
    : wxObject()
    , m_data(data)
{
    m_dataset = NULL;
}

XYDynamicSerie::~XYDynamicSerie()
{
}

double XYDynamicSerie::GetX(size_t index)
{
    wxCHECK_MSG(index < m_data.GetCount()
                    , 0
                    , wxT("XYDynamicSerie::GetX"));

    return m_data[index].x;
}

double XYDynamicSerie::GetY(size_t index)
{
    wxCHECK_MSG(index < m_data.GetCount(),
                0
                , wxT("XYDynamicSerie::GetY"));

    return m_data[index].y;
}

wxRealPoint XYDynamicSerie::GetXY(size_t index)
{
    wxCHECK_MSG(index < m_data.GetCount()
                    , wxRealPoint()
                    , wxT("XYDynamicSerie::GetXY"));

    return m_data[index];
}

size_t XYDynamicSerie::GetCount()
{
    return m_data.GetCount();
}

const wxString &XYDynamicSerie::GetName()
{
    return m_name;
}

void XYDynamicSerie::SetName(const wxString &name)
{
    m_name = name;
}

void XYDynamicSerie::AddXY(double x, double y)
{
    AddXY(wxRealPoint(x, y));
}

void XYDynamicSerie::AddXY(const wxRealPoint& xy)
{
    m_data.Add(xy);

    if (m_dataset != NULL) {
        m_dataset->DatasetChanged();
    }
}

void XYDynamicSerie::AddXY(const wxRealPointArray& data)
{
    WX_APPEND_ARRAY(m_data, data);

    if (m_dataset != NULL) {
        m_dataset->DatasetChanged();
    }
}

void XYDynamicSerie::Insert(size_t index, double x, double y)
{
    Insert(index, wxRealPoint(x, y));
}

void XYDynamicSerie::Insert(size_t index, const wxRealPoint& xy)
{
    m_data.Insert(xy, index);

    if (m_dataset != NULL) {
        m_dataset->DatasetChanged();
    }
}

void XYDynamicSerie::Insert(size_t index, const wxRealPointArray& data)
{
    wxRealPointArray arr = m_data;

    m_data.RemoveAt(index, m_data.GetCount() - index);
    WX_APPEND_ARRAY(m_data, data);

    arr.RemoveAt(0, index);
    WX_APPEND_ARRAY(m_data, arr);

    if (m_dataset != NULL) {
        m_dataset->DatasetChanged();
    }
}

void XYDynamicSerie::Remove(size_t index, size_t count/* = 1*/)
{
    m_data.RemoveAt(index, count);

    if (m_dataset != NULL) {
        m_dataset->DatasetChanged();
    }
}

void XYDynamicSerie::Clear()
{
    m_data.Clear();

    if (m_dataset != NULL) {
        m_dataset->DatasetChanged();
    }
}

void XYDynamicSerie::SetDataset(XYDynamicDataset *dataset)
{
    m_dataset = dataset;
}

//
// XYDynamicDataset
//

XYDynamicDataset::XYDynamicDataset()
    : XYDataset()
{
}

XYDynamicDataset::~XYDynamicDataset()
{
    for (size_t n = 0; n < m_series.Count(); n++) {
        wxDELETE(m_series[n]);
    }
}

void XYDynamicDataset::AddSerie(const wxRealPointArray& data)
{
    AddSerie(new XYDynamicSerie(data));
    DatasetChanged();
}

void XYDynamicDataset::AddSerie(XYDynamicSerie* serie)
{
    serie->SetDataset(this);
    m_series.Add(serie);
    DatasetChanged();
}

size_t XYDynamicDataset::GetSerieCount()
{
    return m_series.Count();
}

wxString XYDynamicDataset::GetSerieName(size_t serie)
{
    wxCHECK(serie < m_series.Count(), wxEmptyString);

    return m_series[serie]->GetName();
}

void XYDynamicDataset::SetSerieName(size_t serie, const wxString &name)
{
    m_series[serie]->SetName(name);
    DatasetChanged();
}

double XYDynamicDataset::GetX(size_t index, size_t serie)
{
    wxCHECK(serie < m_series.Count(), 0);

    return m_series[serie]->GetX(index);
}

double XYDynamicDataset::GetY(size_t index, size_t serie)
{
    wxCHECK(serie <m_series.Count(), 0);

    return m_series[serie]->GetY(index);
}

size_t XYDynamicDataset::GetCount(size_t serie)
{
    return m_series[serie]->GetCount();
}
