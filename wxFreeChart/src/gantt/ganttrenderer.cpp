/////////////////////////////////////////////////////////////////////////////
// Name:    ganttrenderer.cpp
// Purpose: gantt renderer implementation
// Author:    Moskvichev Andrey V.
// Created:    2009/03/23
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/gantt/ganttrenderer.h>

IMPLEMENT_CLASS(GanttRenderer, Renderer);

GanttRenderer::GanttRenderer(int barWidth, int serieGap)
{
    m_barWidth = barWidth;
    m_serieGap = serieGap;
}

GanttRenderer::~GanttRenderer()
{
}

void GanttRenderer::Draw(wxDC &dc, wxRect rc, DateAxis *horizAxis, CategoryAxis *vertAxis, GanttDataset *dataset)
{
    const int serieCount = dataset->GetSerieCount();
    const int dateCount = dataset->AsDateTimeDataset()->GetCount() - 1;

    time_t minDate = dataset->GetMinStart();
    time_t maxDate = dataset->GetMaxEnd();

    FOREACH_SERIE(serie, dataset) {
        int shift;

        if (serieCount > 1) {
            shift = serie * (m_barWidth + m_serieGap) - (m_serieGap * (serieCount - 1) + m_barWidth);
        }
        else {
            shift = -m_barWidth / 2;
        }

        AreaDraw *serieDraw = GetSerieDraw(serie);

        FOREACH_DATAITEM(n, serie, dataset) {
            time_t start = dataset->GetStart(n, serie);
            time_t end = dataset->GetEnd(n, serie);

            double dstart = dateCount * (double) (start - minDate) / (double) (maxDate - minDate);
            double dend = dateCount * (double) (end - minDate) / (double) (maxDate - minDate);

            wxRect rcTask;
            rcTask.x = horizAxis->ToGraphics(dc, rc.x, rc.width, dstart);
            rcTask.width = horizAxis->ToGraphics(dc, rc.x, rc.width, dend) - rcTask.x;
            rcTask.y = vertAxis->ToGraphics(dc, rc.y, rc.height, n) + shift;
            rcTask.height = m_barWidth;

            serieDraw->Draw(dc, rcTask);
        }
    }
}

AreaDraw *GanttRenderer::GetSerieDraw(size_t serie)
{
    AreaDraw *serieDraw = m_serieDraws.GetAreaDraw(serie);
    if (serieDraw == NULL) {
        serieDraw = new FillAreaDraw(*wxBLACK_PEN,
                *wxTheBrushList->FindOrCreateBrush(GetDefaultColour(serie), wxBRUSHSTYLE_SOLID));
        m_serieDraws.SetAreaDraw(serie, serieDraw);
    }
    return serieDraw;
}

void GanttRenderer::SetSerieDraw(size_t serie, AreaDraw *areaDraw)
{
    m_serieDraws.SetAreaDraw(serie, areaDraw);
    FireNeedRedraw();
}

void GanttRenderer::DrawLegendSymbol(wxDC &dc, wxRect rcSymbol, size_t serie)
{
    AreaDraw *serieDraw = GetSerieDraw(serie);
    serieDraw->Draw(dc, rcSymbol);
}
