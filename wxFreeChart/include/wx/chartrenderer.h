/////////////////////////////////////////////////////////////////////////////
// Name:    chartrenderer.h
// Purpose: Dataset renderer base class declaration.
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef RENDERER_H_
#define RENDERER_H_

#include <wx/wxfreechartdefs.h>
#include <wx/drawobject.h>
#include <wx/refobject.h>
#include <wx/art.h>

/**
 * Base class for all renderers.
 */
class WXDLLIMPEXP_FREECHART Renderer : public wxObject, public DrawObject, public RefObject
{
    DECLARE_CLASS(Renderer)
public:
    Renderer();

    virtual ~Renderer();

    /**
     * Sets color for serie.
     * @param serie serie index
     * @param symbol new color for specified serie
     */
    virtual void SetSerieColour(size_t serie, wxColour *color);

    /**
     * Returns serie color.
     * @return serie color
     */
    virtual wxColour GetSerieColour(size_t serie);

    /**
     * Sets symbol for serie.
     * @param serie serie index
     * @param symbol new symbol for specified serie
     */
    virtual void SetSerieSymbol(size_t serie, Symbol *symbol);

    /**
     * returns symbol for serie.
     * @return symbol for specified serie
     */
    virtual Symbol *GetSerieSymbol(size_t serie);

    /**
     * Draws legend symbol.
     * @param dc device context
     * @param rcSymbol rectangle where to draw
     * @param serie serie index
     */
    virtual void DrawLegendSymbol(wxDC &dc, wxRect rcSymbol, size_t serie);

private:
    ColorMap m_serieColours;
    SymbolMap m_serieSymbols;
};

#endif /*RENDERER_H_*/
