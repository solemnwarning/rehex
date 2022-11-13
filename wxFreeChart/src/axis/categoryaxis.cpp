/////////////////////////////////////////////////////////////////////////////
// Name:    categoryaxis.cpp
// Purpose: category axis implementation
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/axis/categoryaxis.h>
#include <wx/category/categorydataset.h>

IMPLEMENT_CLASS(CategoryAxis, Axis)

CategoryAxis::CategoryAxis(AXIS_LOCATION location)
: LabelAxis(location)
{
    m_categoryCount = 0;
}

CategoryAxis::~CategoryAxis()
{
}

bool CategoryAxis::AcceptDataset(Dataset *dataset)
{
    //
    // It must be CategoryDataset and this class supports only one
    // dataset
    //
    return ((wxDynamicCast(dataset, CategoryDataset) != NULL)
        && m_datasets.Count() == 0);
}

wxSize CategoryAxis::GetLongestLabelExtent(wxDC &dc)
{
    dc.SetFont(GetLabelTextFont());
    return dc.GetTextExtent(m_longestCategory);
}

void CategoryAxis::GetDataBounds(double &minValue, double &maxValue) const
{
    minValue = 0;
    if (m_categoryCount > 1) {
        maxValue = m_categoryCount - 1;
    }
    else {
        maxValue = 0;
    }
}

bool CategoryAxis::UpdateBounds()
{
    CategoryDataset *dataset = wxDynamicCast(m_datasets[0], CategoryDataset);
    if (dataset == NULL) {
        wxLogError(wxT("CategoryAxis::DataChanged: BUG dataset is not CategoryDataset")); // BUG!
        return false;
    }

    m_categoryCount = dataset->GetCount();

    m_longestCategory = dataset->GetName(0);
    for (size_t nCat = 1; nCat < m_categoryCount; nCat++) {
        wxString catName = dataset->GetName(nCat);

        if (m_longestCategory.Length() < catName.Length()) {
            m_longestCategory = catName;
        }
    }

    FireBoundsChanged();
    return true;
}

double CategoryAxis::GetValue(size_t step)
{
    if (IsVertical()) {
        step = m_categoryCount - 1 - step;
    }
    return step;
}

void CategoryAxis::GetLabel(size_t step, wxString &label)
{
    CategoryDataset *dataset = wxDynamicCast(m_datasets[0], CategoryDataset);
    if (dataset == NULL) {
        label = wxEmptyString;
        return ; // BUG
    }

    if (IsVertical()) {
        step = m_categoryCount - 1 - step;
    }

    label = dataset->GetName(step);
}

bool CategoryAxis::IsEnd(size_t step)
{
    return step >= m_categoryCount;
}
