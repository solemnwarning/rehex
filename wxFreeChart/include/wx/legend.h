/////////////////////////////////////////////////////////////////////////////
// Name:    legend.h
// Purpose: Legend declaration.
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef LEGEND_H_
#define LEGEND_H_

#include <wx/wxfreechartdefs.h>
#include <wx/dataset.h>
#include <wx/areadraw.h>
#include <wx/category/categorydataset.h>
/**
 * Legend.
 * Performs legend drawing.
 */
class WXDLLIMPEXP_FREECHART Legend
{
public:
    /**
     * Space between serie labels.
     */
    const static wxCoord labelsSpacing;

    /**
     * Constructs new legend.
     * @param vertPosition vertical position, can be wxTOP, wxCENTER, wxBOTTOM
     * @param horizPosition horizontal position, can be wxLEFT, wxCENTER, wxRIGHT
     * @param background background for legend area
     * @param symbolTextGap distance between symbol and text
     * @param margin legend margin
     */
    Legend(int vertPosition, int horizPosition,
            AreaDraw *background = new FillAreaDraw(), int symbolTextGap = 2, int margin = 2);

    virtual ~Legend();

    /**
     * Draw legend.
     * @param dc device context
     * @param rc rectangle where to draw
     * @param datasets datasets array
     */
    void Draw(wxDC &dc, wxRect rc, DatasetArray &datasets);
    void Draw(wxDC &dc, wxRect rc, CategoryDataset &dataset);

    /**
     * Returns legend vertical position.
     * @return legend vertical position
     */
    int GetVertPosition()
    {
        return m_vertPosition;
    }

    /**
     * Returns legend horizontal position.
     * @return legend horizontal position
     */
    int GetHorizPosition()
    {
        return m_horizPosition;
    }

    /**
     * Sets font to draw legend labels.
     * @param font new font to draw legend labels
     */
    void SetTextFont(wxFont font)
    {
        m_font = font;
    }

    /**
     * Returns font to draw legend labels.
     * @return font to draw legend labels
     */
    wxFont GetTextFont()
    {
        return m_font;
    }

    /**
     * Returns size of area to draw legend.
     * @param dc device context
     * @param datasetes dataset array
     * @return size needed for legend area
     */
    wxSize GetExtent(wxDC &dc, DatasetArray &datasets);
    wxSize GetExtent(wxDC &dc, CategoryDataset &dataset);

private:
    int m_vertPosition;
    int m_horizPosition;

    wxFont m_font;

    AreaDraw *m_background;

    int m_symbolTextGap;
    int m_margin;
};

#endif /*LEGEND_H_*/
