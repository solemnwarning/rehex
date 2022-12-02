/////////////////////////////////////////////////////////////////////////////
// Name:    categoryrenderer.h
// Purpose:     Category renderer declarations
// Author:    Grgory Soutad
// Created:    2010/05/24
// Copyright:    (c) 2010 Grgory Soutad
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef CATEGORYRENDERER_H_
#define CATEGORYRENDERER_H_

#include <wx/chartrenderer.h>
#include <wx/colorscheme.h>

class WXDLLIMPEXP_FREECHART CategoryRenderer : public Renderer
{
    DECLARE_CLASS(CategoryRenderer)
public:
    CategoryRenderer(ColorScheme& colorScheme);
    virtual ~CategoryRenderer();

    void DrawLegendSymbol(wxDC &dc, wxRect rcSymbol, size_t serie);

private:
    ColorScheme m_colorScheme;
};

#endif /*CATEGORYRENDERER_H_*/
