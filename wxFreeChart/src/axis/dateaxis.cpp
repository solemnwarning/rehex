/////////////////////////////////////////////////////////////////////////////
// Name:    dateaxis.cpp
// Purpose: date axis implementation
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/axis/dateaxis.h>

IMPLEMENT_CLASS(DateAxis, Axis)

DateAxis::DateAxis(AXIS_LOCATION location)
: LabelAxis(location)
{
    m_dateFormat = wxT("%d %m");
    m_dateCount = 0;
}

DateAxis::~DateAxis()
{
}

bool DateAxis::AcceptDataset(Dataset *dataset)
{
    // Accepts only date/time dataset
    // and only one dataset
    return (dataset->AsDateTimeDataset() != NULL)
        && (m_datasets.Count() == 0);
}

bool DateAxis::UpdateBounds()
{
    size_t dateCount = 0;

    for (size_t n = 0; n < m_datasets.Count(); n++) {
        DateTimeDataset *dataset = m_datasets[n]->AsDateTimeDataset();

        size_t count = dataset->GetCount();
        dateCount = wxMax(dateCount, count);
    }

    if (dateCount != m_dateCount) {
        m_dateCount = dateCount;
        FireBoundsChanged();
        return true;
    }
    else
        return false;
}

wxSize DateAxis::GetLongestLabelExtent(wxDC &dc)
{
    dc.SetFont(GetLabelTextFont());

    wxSize maxExtent(0, 0);

    for (int step = 0; !IsEnd(step); step++) {
        wxString label;
        GetLabel(step, label);

        wxSize labelExtent = dc.GetTextExtent(label);
        maxExtent.x = wxMax(maxExtent.x, labelExtent.x);
        maxExtent.y = wxMax(maxExtent.y, labelExtent.y);
    }

    return maxExtent;
}

void DateAxis::GetDataBounds(double &minValue, double &maxValue) const
{
    minValue = 0;
    if (m_dateCount > 1) {
        maxValue = m_dateCount - 1;
    }
    else {
        maxValue = 0;
    }
}

double DateAxis::GetValue(size_t step)
{
    return step;
}

void DateAxis::GetLabel(size_t step, wxString &label)
{
    DateTimeDataset *dataset = m_datasets[0]->AsDateTimeDataset();
    if (dataset == NULL) {
        return ; // BUG
    }

    wxDateTime dt;
    dt.Set(dataset->GetDate(step));
    label = dt.Format(m_dateFormat);
}

bool DateAxis::IsEnd(size_t step)
{
    return step >= m_dateCount;
}
