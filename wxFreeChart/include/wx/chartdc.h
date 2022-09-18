/////////////////////////////////////////////////////////////////////////////
// Name:        chartdc.h
// Purpose:     A DC that is smart enough to know that antialiasing is enabled
// Author:      Moskvichev Andrey V.
// Created:     2008/11/07
// Copyright:   (c) 2008-2010 Moskvichev Andrey V.
// Licence:     wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef CHARTDC_H
#define CHARTDC_H

#include <wx/dcmemory.h>

/**
 * DC that includes a flag to indicate antialiased drawing should be used where appropriate.
 */
class ChartDC
{
public:
    ChartDC (wxDC& dc, bool antialias) : m_DC(dc), m_Antialias(antialias) {}

    wxDC& GetDC()
    {
        return m_DC;
    }
    
    bool AntialiasActive()
    {
        return m_Antialias;
    }

private:
    wxDC& m_DC;
    bool m_Antialias;
};

#endif /* CHARTDC_H */