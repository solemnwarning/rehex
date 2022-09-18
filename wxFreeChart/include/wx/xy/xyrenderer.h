/////////////////////////////////////////////////////////////////////////////
// Name:    xyrenderer.h
// Purpose: xy renderer base class declaration
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef XYRENDERER_H_
#define XYRENDERER_H_

#include <wx/chartrenderer.h>
#include <wx/axis/axis.h>
#include <wx/xy/xydataset.h>

/**
 * Base class for all XYDataset renderers.
 */
class WXDLLIMPEXP_FREECHART XYRenderer : public Renderer
{
    DECLARE_CLASS(XYRenderer)
public:
    XYRenderer();
    virtual ~XYRenderer();

    /**
     * Draws dataset.
     * @param dc device context
     * @param rc rectangle where to draw
     * @param horizAxis horizontal axis
     * @param vertAxis vertical axis
     * @param dataset dataset to be drawn
     */
    virtual void Draw(wxDC &dc, wxRect rc, Axis *horizAxis, Axis *vertAxis, XYDataset *dataset) = 0;
};

#endif /*XYRENDERER_H_*/
