/////////////////////////////////////////////////////////////////////////////
// Name:    xydataset.h
// Purpose: xy dataset declarations
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef XYDATASET_H_
#define XYDATASET_H_

#include <wx/dataset.h>
#include <wx/axis/axis.h>

class XYRenderer;

/**
 * Base class for XY datasets.
 */
class WXDLLIMPEXP_FREECHART XYDataset : public Dataset
{
    DECLARE_CLASS(XYDataset)
public:
    XYDataset();
    virtual ~XYDataset();

    XYRenderer *GetRenderer()
    {
        return (XYRenderer *) m_renderer;
    }

    /**
     * Returns x value at index.
     * @param index index
     * @return x value
     */
    virtual double GetX(size_t index, size_t serie) = 0;

    /**
     * Returns y value at index.
     * @param index index
     * @return y value
     */
    virtual double GetY(size_t index, size_t serie) = 0;

    /**
     * Returns maximal y value.
     * @return maximal y value
     */
    virtual double GetMaxY();

    /**
     * Returns minimal y value.
     * @return minimal y value
     */
    virtual double GetMinY();

    /**
     * Returns maximal x value.
     * @return maximal x value
     */
    virtual double GetMaxX();

    /**
     * Returns minimal x value.
     * @return minimal x value
     */
    virtual double GetMinX();

    virtual double GetMinValue(bool verticalAxis);

    virtual double GetMaxValue(bool verticalAxis);


protected:
    virtual bool AcceptRenderer(Renderer *r);

private:
};

//
// Helper functions.
//
void ClipHoriz(Axis *axis, double &x, double &y, double x1, double y1);

void ClipVert(Axis *axis, double &x, double &y, double x1, double y1);

#endif /*XYDATASET_H_*/
