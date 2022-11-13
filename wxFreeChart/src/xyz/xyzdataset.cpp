/////////////////////////////////////////////////////////////////////////////
// Name:    xyzdataset.cpp
// Purpose: xyz dataset implementation
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/xyz/xyzdataset.h>

XYZDataset::XYZDataset()
{
}

XYZDataset::~XYZDataset()
{
}

double XYZDataset::GetMinZ()
{
    double minZ = 0;

    for (size_t serie = 0; serie < GetSerieCount(); serie++) {
        for (size_t n = 0; n < GetCount(serie); n++) {
            double z = GetZ(n, serie);
            if (n == 0 && serie == 0)
                minZ = z;
            else
                minZ = wxMin(minZ, z);
        }
    }
    return minZ;
}

double XYZDataset::GetMaxZ()
{
    double maxZ = 0;

    for (size_t serie = 0; serie < GetSerieCount(); serie++) {
        for (size_t n = 0; n < GetCount(serie); n++) {
            double z = GetZ(n, serie);
            if (n == 0 && serie == 0)
                maxZ = z;
            else
                maxZ = wxMax(maxZ, z);
        }
    }
    return maxZ;
}
