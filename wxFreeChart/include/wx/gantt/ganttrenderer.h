/////////////////////////////////////////////////////////////////////////////
// Name:    ganttrenderer.h
// Purpose: gantt renderer declaration
// Author:    Moskvichev Andrey V.
// Created:    2009/03/23
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef GANTTRENDERER_H_
#define GANTTRENDERER_H_

#include <wx/axis/dateaxis.h>
#include <wx/axis/categoryaxis.h>
#include <wx/gantt/ganttdataset.h>

/**
 * Gantt data renderer.
 */
class WXDLLIMPEXP_FREECHART GanttRenderer : public Renderer
{
    DECLARE_CLASS(GanttRenderer)
public:
    /**
     * Constructs new gantt renderer.
     * @param barWidth bar width
     * @param serieGap distance between series
     */
    GanttRenderer(int barWidth = 5, int serieGap = 2);
    virtual ~GanttRenderer();

    //
    // Renderer
    //
    virtual void DrawLegendSymbol(wxDC &dc, wxRect rcSymbol, size_t serie);

    /**
     * Drawn gantt dataset.
     * @param dc device context
     * @param rc rectangle where to draw
     * @param horizAxis horizontal axis
     * @param vertAxis vertical axis
     * @param dataset dataset to draw
     */
    void Draw(wxDC &dc, wxRect rc, DateAxis *horizAxis, CategoryAxis *vertAxis, GanttDataset *dataset);

    /**
     * Sets area draw object to draw specified serie.
     * @param serie serie index
     * @param ad area draw for serie
     */
    void SetSerieDraw(size_t serie, AreaDraw *areaDraw);

    AreaDraw *GetSerieDraw(size_t serie);

    void SetBarWidth(int barWidth)
    {
        if (m_barWidth != barWidth) {
            m_barWidth = barWidth;
            FireNeedRedraw();
        }
    }

private:

    int m_barWidth;
    int m_serieGap;

    AreaDrawCollection m_serieDraws;
};

#endif /* GANTTRENDERER_H_ */
