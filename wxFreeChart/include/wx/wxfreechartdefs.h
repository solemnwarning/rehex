/////////////////////////////////////////////////////////////////////////////
// Name:    wxfreechartdefs.h
// Purpose: base declarations
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef WXFREECHARTDEFS_H
#define WXFREECHARTDEFS_H

#include <wx/wxprec.h>

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include <wx/wx.h>
#endif

// dll impexp macros. Thanks to Mike Sazonov
#ifdef WXMAKINGDLL_FREECHART
#define WXDLLIMPEXP_FREECHART WXEXPORT
#define WXDLLIMPEXP_DATA_FREECHART(type) WXEXPORT type
#elif defined(WXUSINGDLL) && !defined(_LOCAL_)
#define WXDLLIMPEXP_FREECHART WXIMPORT
#define WXDLLIMPEXP_DATA_FREECHART(type) WXIMPORT type
#else // not making nor using DLL
#define WXDLLIMPEXP_FREECHART
#define WXDLLIMPEXP_DATA_FREECHART(type) type
#endif

#define ABS(a) ((a) < 0) ? (-1*(a)) : (a)

#define wxREPLACE(dst, src) do {                    \
    wxDELETE(dst);                                  \
    dst = src;                                      \
} while (0)


inline static int RoundHigh(double value)
{
    int iv = (int) value;

    if (((double) iv) > value)
        iv++;
    return iv;
}

// Default Colours
#define DEFAULT_LINE_COLOUR_0 wxColour("#5B9BD5")
#define DEFAULT_LINE_COLOUR_1 wxColour("#ED7D31")
#define DEFAULT_LINE_COLOUR_2 wxColour("#FFC000")
#define DEFAULT_LINE_COLOUR_3 wxColour("#4472C4")
#define DEFAULT_LINE_COLOUR_4 wxColour("#70AD47")
#define DEFAULT_LINE_COLOUR_5 wxColour("#9E480E")
#define DEFAULT_LINE_COLOUR_6 wxColour("#997300")
#define DEFAULT_LINE_COLOUR_7 wxColour("#A5A5A5")

#define DEFAULT_BAR_FILL_COLOUR_0 wxColour("#5B9BD5")
#define DEFAULT_BAR_FILL_COLOUR_1 wxColour("#ED7D31")
#define DEFAULT_BAR_FILL_COLOUR_2 wxColour("#FFC000")
#define DEFAULT_BAR_FILL_COLOUR_3 wxColour("#4472C4")
#define DEFAULT_BAR_FILL_COLOUR_4 wxColour("#70AD47")
#define DEFAULT_BAR_FILL_COLOUR_5 wxColour("#9E480E")
#define DEFAULT_BAR_FILL_COLOUR_6 wxColour("#997300")
#define DEFAULT_BAR_FILL_COLOUR_7 wxColour("#A5A5A5")

#define DEFAULT_TEXT_COLOUR wxColour("#686868")

#define DEFAULT_AXIS_LABEL_COLOUR DEFAULT_TEXT_COLOUR 
#define DEFAULT_AXIS_BORDER_COLOUR wxColour("#8B8B8B")
#define DEFAULT_AXIS_TICK_COLOUR wxColour("#8B8B8B")
#define DEFAULT_TITLE_COLOUR DEFAULT_TEXT_COLOUR 

#define DEFAULT_MAJOR_GRIDLINE_PEN_COLOUR wxColour("#DADADA")
#define DEFAULT_MINOR_GRIDLINE_PEN_COLOUR wxColour("#F0F0F0")

// Default Values
#define DEFAULT_MAJOR_LABEL_COUNT 10

#endif /* WXFREECHARTDEFS_H */
