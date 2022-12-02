/////////////////////////////////////////////////////////////////////////////
// Name:    categorydataset.cpp
// Purpose: category dataset implementation
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/category/categorydataset.h>

IMPLEMENT_CLASS(CategoryDataset, XYDataset);

CategoryDataset::CategoryDataset()
{
}

CategoryDataset::~CategoryDataset()
{
}

bool CategoryDataset::AcceptRenderer(Renderer *renderer)
{
    return (wxDynamicCast(renderer, BarRenderer) != NULL);
}

bool CategoryDataset::HasValue(size_t WXUNUSED(index), size_t WXUNUSED(serie))
{
    return true;
}

double CategoryDataset::GetMinValue(bool WXUNUSED(verticalAxis))
{
    if (GetRenderer() == NULL) {
        return 0;
    }
    return GetRenderer()->GetMinValue(this);
}

double CategoryDataset::GetMaxValue(bool WXUNUSED(verticalAxis))
{
    if (GetRenderer() == NULL) {
        return 0;
    }
    return GetRenderer()->GetMaxValue(this);
}

double CategoryDataset::GetX(size_t index, size_t WXUNUSED(serie))
{
    return index;
}

double CategoryDataset::GetY(size_t index, size_t serie)
{
    return GetValue(index, serie);
}

size_t CategoryDataset::GetCount(size_t WXUNUSED(serie))
{
    return GetCount(); // in category dataset all series has equal count of elements
}
