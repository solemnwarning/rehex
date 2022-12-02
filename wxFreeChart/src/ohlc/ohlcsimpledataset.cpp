/////////////////////////////////////////////////////////////////////////////
// Name:    ohlcdataset.cpp
// Purpose: OHLC simple dataset implementation
// Author:    Moskvichev Andrey V.
// Created:    2011/12/25
// Copyright:    (c) 2008-2011 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/ohlc/ohlcsimpledataset.h>

IMPLEMENT_CLASS(OHLCSimpleDataset, OHLCDataset);

OHLCSimpleDataset::OHLCSimpleDataset(OHLCItem *items, size_t count)
{
    m_items = new OHLCItem[count];
    memcpy(m_items, items, count * sizeof(*items));
    m_count = count;
}

OHLCSimpleDataset::~OHLCSimpleDataset()
{
    wxDELETEA(m_items);
}

OHLCItem *OHLCSimpleDataset::GetItem(size_t index)
{
    wxCHECK_MSG(index < m_count, NULL, wxT("GetItem"));
    return &m_items[index];
}

size_t OHLCSimpleDataset::GetCount()
{
    return m_count;
}
