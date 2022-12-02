/////////////////////////////////////////////////////////////////////////////
// Name:    art.h
// Purpose:
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

// TODO rename file!
#ifndef ART_H_
#define ART_H_

#include <wx/wx.h>
#include <wx/symbol.h>

#include <wx/hashmap.h>

WX_DECLARE_HASH_MAP(int, wxColor, wxIntegerHash, wxIntegerEqual, ColorMap);
WX_DECLARE_HASH_MAP(int, wxPen, wxIntegerHash, wxIntegerEqual, PenMap);
WX_DECLARE_HASH_MAP(int, wxBrush, wxIntegerHash, wxIntegerEqual, BrushMap);
WX_DECLARE_HASH_MAP(int, Symbol *, wxIntegerHash, wxIntegerEqual, SymbolMap);

wxColour WXDLLIMPEXP_FREECHART GetDefaultColour(size_t index);

Symbol WXDLLIMPEXP_FREECHART *GetDefaultSymbol(size_t index);

#endif /*ART_H_*/
