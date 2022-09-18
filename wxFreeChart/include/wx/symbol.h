/////////////////////////////////////////////////////////////////////////////
// Name:    symbol.h
// Purpose: symbols declarations
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef SYMBOL_H_
#define SYMBOL_H_

#include <wx/wxfreechartdefs.h>

/**
 * Symbols base class.
 */
class WXDLLIMPEXP_FREECHART Symbol
{
public:
    Symbol();
    virtual ~Symbol();

    /**
     * Performs symbol drawing.
     * @param dc device context
     * @param x x coordinate
     * @param y y coordinate
     * @param color color to draw symbol
     */
    virtual void Draw(wxDC &dc, wxCoord x, wxCoord y, wxColour color) = 0;

    /**
     * Called to calculate size required for symbol.
     * @return size required for symbol
     */
    virtual wxSize GetExtent() = 0;
};

/**
 * Symbol class, that uses bitmap mask to draw.
 * Masked area will be filled with specified color.
 */
class WXDLLIMPEXP_FREECHART MaskedSymbol : public Symbol
{
public:
    MaskedSymbol(const char **maskData, wxCoord size = 9);

    virtual ~MaskedSymbol();

    virtual void Draw(wxDC &dc, wxCoord x, wxCoord y, wxColour color);

    virtual wxSize GetExtent();

private:
    wxBitmap m_maskBmp;
    wxBitmap m_symbolBitmap;

    bool m_initialized;

    wxCoord m_size;
};

/**
 * Shape symbols base class.
 */
class WXDLLIMPEXP_FREECHART ShapeSymbol : public Symbol
{
public:
    ShapeSymbol(wxCoord size);
    virtual ~ShapeSymbol();

    virtual wxSize GetExtent();

protected:
    wxColour m_color;
    wxCoord m_size;
};

//
// shape symbols
// TODO: add more

/**
 * Circle symbol.
 */
class WXDLLIMPEXP_FREECHART CircleSymbol : public ShapeSymbol
{
public:
    CircleSymbol(wxCoord size = 9);
    virtual ~CircleSymbol();

    virtual void Draw(wxDC &dc, wxCoord x, wxCoord y, wxColour color);
};

/**
 * Square symbol.
 */
class WXDLLIMPEXP_FREECHART SquareSymbol : public ShapeSymbol
{
public:
    SquareSymbol(wxCoord size = 9);
    virtual ~SquareSymbol();

    virtual void Draw(wxDC &dc, wxCoord x, wxCoord y, wxColour color);
};

/**
 * Cross symbol.
 */
class WXDLLIMPEXP_FREECHART CrossSymbol : public ShapeSymbol
{
public:
    CrossSymbol(wxCoord size = 9);
    virtual ~CrossSymbol();

    virtual void Draw(wxDC &dc, wxCoord x, wxCoord y, wxColour color);
};

/**
 * Triangle symbol.
 */
class WXDLLIMPEXP_FREECHART TriangleSymbol : public ShapeSymbol
{
public:
    TriangleSymbol(wxCoord size = 9);
    virtual ~TriangleSymbol();

    virtual void Draw(wxDC &dc, wxCoord x, wxCoord y, wxColour color);
};

#endif /*SYMBOL_H_*/
