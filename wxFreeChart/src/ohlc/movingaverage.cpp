/////////////////////////////////////////////////////////////////////////////
// Name:    movingaverage.cpp
// Purpose: moving average implementation
// Author:    Moskvichev Andrey V.
// Created:    2011/12/25
// Copyright:    (c) 2008-2011 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/ohlc/movingaverage.h>

IMPLEMENT_CLASS(MovingAverage, XYDataset)

MovingAverage::MovingAverage(OHLCDataset *ohlcDataset, int period)
{
    m_ohlcDataset = ohlcDataset;
    m_period = period;

    m_ohlcDataset->AddRef();
    m_ohlcDataset->AddObserver(this);
}

MovingAverage::~MovingAverage()
{
    SAFE_REMOVE_OBSERVER(this, m_ohlcDataset);
    SAFE_UNREF(m_ohlcDataset);
}

size_t MovingAverage::GetSerieCount()
{
    return 1;
}

size_t MovingAverage::GetCount(size_t WXUNUSED(serie))
{
    int count = m_ohlcDataset->GetCount() - m_period + 1;
    if (count < 0) {
        count = 0; // period is larger than OHLC data
    }
    return count;
}

wxString MovingAverage::GetSerieName(size_t WXUNUSED(serie))
{
    return wxT("Moving average");
}

double MovingAverage::GetX(size_t index, size_t WXUNUSED(serie))
{
    return index + m_period - 1;
}

double MovingAverage::GetY(size_t index, size_t WXUNUSED(serie))
{
    wxCHECK_MSG(m_period != 0, 0, wxT("MovingAverage::GetX"));

    double sum = 0;

    for (size_t n = index; n < index + m_period; n++) {
        OHLCItem *item = m_ohlcDataset->GetItem(n);

        sum += item->close;
    }
    return sum / m_period;
}

void MovingAverage::DatasetChanged(Dataset *WXUNUSED(dataset))
{
    Dataset::DatasetChanged();
}
