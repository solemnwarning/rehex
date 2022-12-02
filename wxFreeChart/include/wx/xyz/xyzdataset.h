/////////////////////////////////////////////////////////////////////////////
// Name:    xyzdataset.h
// Purpose: xyz dataset declarations
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef XYZDATASET_H_
#define XYZDATASET_H_

#include <wx/xy/xydataset.h>

class XYZRenderer;

/**
 * Dataset with (x,y,z) coordinate data.
 */
class WXDLLIMPEXP_FREECHART XYZDataset : public XYDataset
{
public:
    XYZDataset();
    virtual ~XYZDataset();

    XYZRenderer *GetRenderer()
    {
        return (XYZRenderer *) m_renderer;
    }

    virtual double GetZ(size_t index, size_t serie) = 0;

    virtual double GetMinZ();

    virtual double GetMaxZ();
};

#endif /*XYZDATASET_H_*/
