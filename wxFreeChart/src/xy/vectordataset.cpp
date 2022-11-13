/////////////////////////////////////////////////////////////////////////////
// Name:    vectordataset.cpp
// Purpose: vector dataset implementation
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/xy/vectordataset.h>

#include "wx/arrimpl.cpp"

WX_DEFINE_EXPORTED_OBJARRAY(wxDoubleArray);


VectorDataset::VectorDataset()
{
}

VectorDataset::~VectorDataset()
{
}

void VectorDataset::Add(double y)
{
    m_values.Add(y);
    DatasetChanged();
}

void VectorDataset::Replace(size_t index, double y)
{
    if (index < m_values.Count()) {
        m_values[index] = y;

        DatasetChanged();
    }
}

void VectorDataset::RemoveAt(size_t index)
{
    if (index < m_values.Count()) {
        m_values.RemoveAt(index);

        DatasetChanged();
    }
}

void VectorDataset::Clear()
{
    m_values.Clear();
    DatasetChanged();
}

double VectorDataset::GetX(size_t index, size_t WXUNUSED(serie))
{
    return index + 1;
}

double VectorDataset::GetY(size_t index, size_t WXUNUSED(serie))
{
    return m_values[index];
}

size_t VectorDataset::GetCount(size_t WXUNUSED(serie))
{
    return m_values.Count();
}

size_t VectorDataset::GetSerieCount()
{
    return 1;
}

wxString VectorDataset::GetSerieName(size_t WXUNUSED(serie))
{
    return wxEmptyString;
}
