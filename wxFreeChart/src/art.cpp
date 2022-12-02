/////////////////////////////////////////////////////////////////////////////
// Name:    art.cpp
// Purpose:
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/dynarray.h>
#include <wx/arrimpl.cpp>

#include <wx/art.h>

WX_DECLARE_OBJARRAY(Symbol *, SymbolArray);
WX_DEFINE_OBJARRAY(SymbolArray);

SymbolArray defaultSymbols;

wxColour defaultColours[] = 
{
    DEFAULT_BAR_FILL_COLOUR_0,
    DEFAULT_BAR_FILL_COLOUR_1,
    DEFAULT_BAR_FILL_COLOUR_2,
    DEFAULT_BAR_FILL_COLOUR_3,
    DEFAULT_BAR_FILL_COLOUR_4,
    DEFAULT_BAR_FILL_COLOUR_5,
    DEFAULT_BAR_FILL_COLOUR_6,
    DEFAULT_BAR_FILL_COLOUR_7
};

void InitDefaultSymbols()
{
    defaultSymbols.Add(new SquareSymbol());
    defaultSymbols.Add(new TriangleSymbol());
    defaultSymbols.Add(new CircleSymbol());
    defaultSymbols.Add(new CrossSymbol());
}

wxColour GetDefaultColour(size_t index)
{
    if (index >= WXSIZEOF(defaultColours)) {
        index = index % WXSIZEOF(defaultColours);
    }
    return defaultColours[index];
}

Symbol *GetDefaultSymbol(size_t index)
{
    size_t count = defaultSymbols.Count();

    if (count == 0) {
        InitDefaultSymbols();
        count = defaultSymbols.Count();
    }

    if (index >= count) {
        index = index % count;
    }
    return defaultSymbols[index];
}
