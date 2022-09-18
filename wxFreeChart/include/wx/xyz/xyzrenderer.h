/////////////////////////////////////////////////////////////////////////////
// Name:    xyzrenderer.h
// Purpose: xyz renderer declaration
// Author:    Moskvichev Andrey V.
// Created:    2009/04/04
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef XYZRENDERER_H_
#define XYZRENDERER_H_

#include <wx/chartrenderer.h>
#include <wx/axis/axis.h>
#include <wx/xyz/xyzdataset.h>

/**
 * xyz renderer class.
 */
class WXDLLIMPEXP_FREECHART XYZRenderer : public Renderer
{
    DECLARE_CLASS(XYZRenderer)
public:
    XYZRenderer(int minRad, int maxRad);
    virtual ~XYZRenderer();

    void Draw(wxDC &dc, wxRect rc, Axis *horizAxis, Axis *vertAxis, XYZDataset *dataset);

    virtual void SetSerieColor(size_t serie, wxColour *color);

    virtual wxColour GetSerieColor(size_t serie);

    /**
     * Sets pen to draw serie circles.
     * @param serie serie index
     * @param pen pen for serie
     */
    void SetSeriePen(size_t serie, wxPen *pen);

    /**
     * Returns pen, used to draw specified serie lines.
     * @param serie serie index
     * @return pen
     */
    wxPen *GetSeriePen(size_t serie);

    /**
     * Sets brush to fill serie circles.
     * @param serie serie index
     * @param brush brush for serie
     */
    void SetSerieBrush(size_t serie, wxBrush *brush);

    /**
     * Returns brush, used to fill specified serie circles.
     * @param serie serie index
     * @return brush
     */
    wxBrush *GetSerieBrush(size_t serie);


private:
    int m_minRad;
    int m_maxRad;

    PenMap m_seriePens;
    int m_defaultPenWidth;
    wxPenStyle m_defaultPenStyle;

    BrushMap m_serieBrushs;
    wxBrushStyle m_defaultBrushStyle;
};

#endif /* XYZRENDERER_H_ */
