/////////////////////////////////////////////////////////////////////////////
// Name:    drawutils.h
// Purpose: Defines some useful drawing utilities.
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef DRAWUTILS_H_
#define DRAWUTILS_H_

/**
 * Draws text, where center defined by [x,y]
 * @param dc device context
 * @param x x coordinate of center
 * @param y y coordinate of center
 * @param text text to draw
 */
inline static void DrawTextCenter(wxDC &dc, wxCoord x, wxCoord y, wxString text)
{
    wxSize textExtent = dc.GetTextExtent(text);

    x -= textExtent.x / 2;
    y -= textExtent.y / 2;

    dc.DrawText(text, x, y);
}

/**
 * Draws text in center of rectangle.
 * @param dc device context
 * @param rc rectangle where to draw text
 * @param text text to draw
 */
inline static void DrawTextCenter(wxDC &dc, wxRect &rc, wxString text)
{
    wxSize textExtent = dc.GetTextExtent(text);

    wxCoord x = rc.x + (rc.GetWidth() - textExtent.x) / 2;
    wxCoord y = rc.y + (rc.GetHeight() - textExtent.y) / 2;

    dc.DrawText(text, x, y);
}

/**
 * Checks and fixes rectangle after arithmetical calculations
 * on it's coordinates and size.
 * It either coordinate or size is negative it will be set to zero.
 * @param rc rectangle
 */
inline static void CheckFixRect(wxRect &rc)
{
    if (rc.x < 0)
        rc.x = 0;
    if (rc.y < 0)
        rc.y = 0;
    if (rc.width < 0)
        rc.width = 0;
    if (rc.height < 0)
        rc.height = 0;
}

/**
 * Substracts margins from rectangle.
 * @param rc rectangle
 * @param left left margin
 * @param top top margin
 * @param right right margin
 * @param bottom bottom margin
 */
inline static void Margins(wxRect &rc, wxCoord left, wxCoord top, wxCoord right, wxCoord bottom)
{
    if ((left + right) > rc.width) {
        rc.x = left;
        rc.width = 0;
    }
    else {
        rc.x += left;
        rc.width -= (left + right);
    }

    if ((top + bottom) > rc.height) {
        rc.y = top;
        rc.height = 0;
    }
    else {
        rc.y += top;
        rc.height -= (top + bottom);
    }

    CheckFixRect(rc);
}

/**
 * Sets rectangle from two points.
 * @param rc rectangle
 * @param x0 first point x
 * @param y0 first point y
 * @param x1 second point x
 * @param y1 second point y
 */
inline static void SetupRect(wxRect &rc, wxCoord x0, wxCoord y0, wxCoord x1, wxCoord y1)
{
    if (x0 < x1) {
        rc.x = x0;
        rc.width = x1 - x0;
    }
    else {
        rc.x = x1;
        rc.width = x0 - x1;
    }

    if (y0 < y1) {
        rc.y = y0;
        rc.height = y1 - y0;
    }
    else {
        rc.y = y1;
        rc.height = y0 - y1;
    }
}

#endif /*DRAWUTILS_H_*/
