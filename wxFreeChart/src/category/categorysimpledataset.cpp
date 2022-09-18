/////////////////////////////////////////////////////////////////////////////
// Name:    categorysimpledataset.cpp
// Purpose: category simple dataset implementation
// Author:    Moskvichev Andrey V.
// Created:    2009/11/26
// Copyright:    (c) 2009 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////


#include <wx/category/categorysimpledataset.h>

#include <wx/arrstr.h>
#include <wx/arrimpl.cpp>


WX_DEFINE_EXPORTED_OBJARRAY(CategorySerieArray);

CategorySerie::CategorySerie(const wxString &name, double *values, size_t count)
{
    m_name = name;

    m_values = new double[count];
    for (size_t n = 0; n < count; n++) {
        m_values[n] = values[n];
    }
    m_count = count;
}

CategorySerie::~CategorySerie()
{
    wxDELETEA(m_values);
}

const wxString &CategorySerie::GetName()
{
    return m_name;
}

double CategorySerie::GetValue(size_t index)
{
    wxCHECK(index < m_count, 0);
    return m_values[index];
}


IMPLEMENT_CLASS(CategorySimpleDataset, CategoryDataset)

CategorySimpleDataset::CategorySimpleDataset(wxString *names, size_t count)
{
    m_names.Alloc(count);
    for (size_t n = 0; n < count; n++) {
        m_names.Add(names[n]);
    }
}

CategorySimpleDataset::~CategorySimpleDataset()
{
    for (size_t n = 0; n < m_series.Count(); n++) {
        wxDELETE(m_series[n]);
    }
}

void CategorySimpleDataset::AddSerie(const wxString &name, double *values, size_t count)
{
    AddSerie(new CategorySerie(name, values, count));
}

void CategorySimpleDataset::AddSerie(CategorySerie *serie)
{
    m_series.Add(serie);
    DatasetChanged();
}

double CategorySimpleDataset::GetValue(size_t index, size_t serie)
{
    wxCHECK(serie < m_series.Count(), 0);
    return m_series[serie]->GetValue(index);
}

size_t CategorySimpleDataset::GetSerieCount()
{
    return m_series.Count();
}

wxString CategorySimpleDataset::GetName(size_t index)
{
    return m_names[index];
}

size_t CategorySimpleDataset::GetCount()
{
    return m_names.Count();
}

wxString CategorySimpleDataset::GetSerieName(size_t serie)
{
    wxCHECK(serie < m_series.Count(), wxEmptyString);
    return m_series[serie]->GetName();
}
