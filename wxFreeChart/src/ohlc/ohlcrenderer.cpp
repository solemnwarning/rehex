/////////////////////////////////////////////////////////////////////////////
// Name:    ohlcrenderer.cpp
// Purpose: OHLC renderer implementation
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/ohlc/ohlcrenderer.h>

class DefaultOHLCColourer : public OHLCColourer
{
public:
    DefaultOHLCColourer();
    virtual ~DefaultOHLCColourer();

    virtual wxColor GetColour(int step);
};

DefaultOHLCColourer::DefaultOHLCColourer()
{
}

DefaultOHLCColourer::~DefaultOHLCColourer()
{
}

wxColor DefaultOHLCColourer::GetColour(int WXUNUSED(step))
{
    return *wxBLACK;
}

//
// OHLCRenderer
//

OHLCRenderer::OHLCRenderer()
{
    m_colourer = new DefaultOHLCColourer();
}

OHLCRenderer::~OHLCRenderer()
{
    wxDELETE(m_colourer);
}

void OHLCRenderer::SetColourer(OHLCColourer *colourer)
{
    wxREPLACE(m_colourer, colourer);
}

OHLCColourer *OHLCRenderer::GetColourer()
{
    return m_colourer;
}

