/////////////////////////////////////////////////////////////////////////////
// Name:    multiplot.cpp
// Purpose: multiplot implementation
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/multiplot.h>

#include "wx/arrimpl.cpp"

#define FOREACH_SUBPLOT(index, subPlots) \
    for (size_t index = 0; index < subPlots.Count(); index++)

WX_DEFINE_EXPORTED_OBJARRAY(PlotArray)


MultiPlot::MultiPlot(int rows, int cols, wxCoord horizGap, wxCoord vertGap)
{
    m_rows = rows;
    m_cols = cols;
    m_horizGap = horizGap;
    m_vertGap = vertGap;
}

MultiPlot::~MultiPlot()
{
    FOREACH_SUBPLOT(n, m_subPlots) {
        Plot *plot = m_subPlots[n];
        wxDELETE(plot);
    }
}

void MultiPlot::PlotNeedRedraw(Plot *WXUNUSED(plot))
{
    FirePlotNeedRedraw();
}

bool MultiPlot::HasData()
{
    return (m_subPlots.Count() != 0);
}

void MultiPlot::DrawData(ChartDC& cdc, wxRect rc)
{
    wxCHECK_RET(m_rows != 0 || m_cols != 0, wxT("row and column count = 0"));

    int rows = m_rows;
    int cols = m_cols;
    bool vertical = false;

    if (cols == 0) {
        cols = 1;

        int row = 0;
        FOREACH_SUBPLOT(n, m_subPlots) {
            if (row >= rows) {
                row = 0;
                cols++;
            }
            row++;
        }

        vertical = true;
    }
    if (rows == 0) {
        rows = 1;

        int col = 0;
        FOREACH_SUBPLOT(n, m_subPlots) {
            if (col >= cols) {
                col = 0;

                rows++;
            }
            col++;
        }
    }

    wxCoord subWidth = (rc.width - (cols - 1) * m_horizGap) / cols;
    wxCoord subHeight = (rc.height - (rows - 1) * m_vertGap) / rows;

    wxCoord x = rc.x;
    wxCoord y = rc.y;

    int row = 0;
    int col = 0;
    FOREACH_SUBPLOT(n, m_subPlots) {
        // TODO untested!
        if (vertical) {
            if (row >= rows) {
                row = 0;
                y = rc.y;
                x += subWidth + m_horizGap;

                col++;
                if (col >= cols)
                    break;
            }
        }
        else {
            if (col >= cols) {
                col = 0;
                x = rc.x;
                y += subHeight + m_vertGap;

                row++;
                if (row >= rows)
                    break;
            }
        }

        wxRect subRc(x, y, subWidth, subHeight);

        m_subPlots[n]->Draw(cdc, subRc);

        if (vertical) {
            row++;
            y += subHeight + m_vertGap;
        }
        else {
            col++;
            x += subWidth + m_horizGap;
        }
    }
}
