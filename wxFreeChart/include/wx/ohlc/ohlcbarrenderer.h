/////////////////////////////////////////////////////////////////////////////
// Name:    ohlcbarrenderer.h
// Purpose: OHLC bar renderer declarations
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef OHLCBARRENDERER_H_
#define OHLCBARRENDERER_H_

#include <wx/ohlc/ohlcrenderer.h>

/**
 * OHLC renderer for displaying bars.
 */
class WXDLLIMPEXP_FREECHART OHLCBarRenderer : public OHLCRenderer
{
public:
    OHLCBarRenderer();
    virtual ~OHLCBarRenderer();

    virtual void DrawItem(wxDC &dc, wxCoord x, wxCoord open, wxCoord high, wxCoord low, wxCoord close);

    /**
     * Sets pen to draw bars.
     * @param barPen pen to draw bars
     */
    void SetBarPen(wxPen barPen)
    {
        m_barPen = barPen;
        FireNeedRedraw();
    }

    /**
     * Return pen to draw bars.
     * @return pen to draw bars
     */
    const wxPen &GetBarPen()
    {
        return m_barPen;
    }

private:
    wxPen m_barPen;
};

#endif /*OHLCBARRENDERER_H_*/
