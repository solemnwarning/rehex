/////////////////////////////////////////////////////////////////////////////
// Name:    ohlcdataset.cpp
// Purpose: OHLC dataset implementation
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/ohlc/ohlcdataset.h>

IMPLEMENT_CLASS(OHLCDataset, Dataset)

OHLCDataset::OHLCDataset()
{
    m_serieName = wxT("OHLC");
}

OHLCDataset::~OHLCDataset()
{
}

bool OHLCDataset::AcceptRenderer(Renderer *renderer)
{
    return (wxDynamicCast(renderer, OHLCRenderer) != NULL);
}

double OHLCDataset::GetMaxValue(bool WXUNUSED(unused))
{
    double maxValue = 0;

    for (size_t n = 0; n < GetCount(); n++) {
        OHLCItem *item = GetItem(n);

        if (n == 0)
            maxValue = item->high;
        else
            maxValue = wxMax(maxValue, item->high);
    }
    return maxValue;
}

double OHLCDataset::GetMinValue(bool WXUNUSED(unused))
{
    double minValue = 0;

    for (size_t n = 0; n < GetCount(); n++) {
        OHLCItem *item = GetItem(n);

        if (n == 0)
            minValue = item->low;
        else
            minValue = wxMin(minValue, item->low);
    }
    return minValue;
}


time_t OHLCDataset::GetDate(size_t index)
{
    return GetItem(index)->date;
}


size_t OHLCDataset::GetCount(size_t WXUNUSED(serie))
{
    return GetCount();
}

size_t OHLCDataset::GetSerieCount()
{
    return 1;
}

wxString OHLCDataset::GetSerieName(size_t WXUNUSED(serie))
{
    return m_serieName;
}

DateTimeDataset *OHLCDataset::AsDateTimeDataset()
{
    return this;
}
