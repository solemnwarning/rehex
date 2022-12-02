/////////////////////////////////////////////////////////////////////////////
// Name:    pieplot.cpp
// Purpose: pie plot implementation
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/pie/pieplot.h>
#include <wx/drawutils.h>
#include <wx/drawobject.h>

#include <math.h>

/*
 * TODO Initial quick and dirty. Must be rewritten.
 */

void Rotate(wxCoord &x, wxCoord &y, wxCoord xc, wxCoord yc, double rad, double angle)
{
    x = (wxCoord) (rad * cos(angle) + xc);
    y = (wxCoord) (-rad * sin(angle) + yc);
}

void EllipticEgde(wxCoord x, wxCoord y, wxCoord width, wxCoord height, double angle, wxCoord &outX, wxCoord &outY)
{
    double degs = angle * M_PI / 180;

    double w = width;
    double h = height;

    outX = (wxCoord) (w * cos(degs) / 2 + x + w / 2);
    outY = (wxCoord) (-h * sin(degs) / 2 + y + h / 2);
}

PiePlot::PiePlot()
{
    m_dataset = NULL;

    m_use3DView = false;
    m_ellipticAspect = 1.0f;
    //colorScheme = defaultColorScheme;
    m_outlinePen = *wxBLACK_PEN;
    m_labelsFont = *wxSMALL_FONT;

    m_serie = 0; // default behaviour - use first serie

    m_legendPlotGap = 2;
    m_legend = NULL;
}

PiePlot::~PiePlot()
{
    SAFE_REMOVE_OBSERVER(this, m_dataset);
    SAFE_UNREF(m_dataset);
    wxDELETE(m_legend);
}

void PiePlot::SetDataset(CategoryDataset *dataset)
{
    SAFE_REPLACE_OBSERVER(this, m_dataset, dataset);
    SAFE_REPLACE_UNREF(m_dataset, dataset);

    FirePlotNeedRedraw();
}

void PiePlot::SetColorScheme(ColorScheme *colorScheme)
{
    m_colorScheme = *colorScheme;
    FirePlotNeedRedraw();
}

void PiePlot::SetLegend(Legend *legend)
{
    wxREPLACE(m_legend, legend);
    FirePlotNeedRedraw();
}

bool PiePlot::HasData()
{
    return m_dataset != NULL && (m_dataset->GetSerieCount() >= m_serie);
}

void PiePlot::DatasetChanged(Dataset *WXUNUSED(dataset))
{
    FirePlotNeedRedraw();
}

void PiePlot::DrawData(ChartDC& cdc, wxRect rc)
{
    // TODO initial quick and dirty, need cleanup.
    //
    double sum = 0;
    
    wxDC& dc = cdc.GetDC();

    for (size_t n = 0; n < m_dataset->GetCount(); n++) {
        sum += m_dataset->GetValue(n, m_serie);
    }


    wxRect rcLegend;
    if (m_legend != NULL) {
        wxSize legendExtent = m_legend->GetExtent(dc, *m_dataset);

        switch (m_legend->GetHorizPosition()) {
        case wxLEFT:
            rcLegend.x = rc.x;

            rc.x += legendExtent.x + m_legendPlotGap;
            rc.width -= legendExtent.x + m_legendPlotGap;
            break;
        case wxRIGHT:
            rcLegend.x = rc.x + rc.width - legendExtent.x + m_legendPlotGap;

            rc.width -= legendExtent.x + m_legendPlotGap;
            break;
        case wxCENTER:
            rcLegend.x = rc.x + rc.width / 2 - legendExtent.x / 2;
            break;
        default:
            //(wxT("Invalid legend horizontal position"));
            return ;
        }

        switch (m_legend->GetVertPosition()) {
        case wxTOP:
            rcLegend.y = rc.y;

            rc.y += legendExtent.y + m_legendPlotGap;
            rc.height -= legendExtent.y + m_legendPlotGap;
            break;
        case wxBOTTOM:
            rcLegend.y = rc.y + rc.height - legendExtent.y + m_legendPlotGap;

            rc.height -= legendExtent.y + m_legendPlotGap;
            break;
        case wxCENTER:
            rcLegend.y = rc.y + rc.height / 2 - legendExtent.y / 2;
            break;
        default:
            //(wxT("Invalid legend vertical position"));
            return;
        }

        rcLegend.width = legendExtent.x;
        rcLegend.height = legendExtent.y;

        CheckFixRect(rcLegend);

        m_legend->Draw(dc, rcLegend, *m_dataset);
    }

    int radHoriz = (int) (0.8 * wxMin(rc.width, rc.height));
    int radVert  = (int) (radHoriz * m_ellipticAspect);

    wxCoord x0 = rc.x + (rc.width - radHoriz) / 2;
    wxCoord y0 = rc.y + (rc.height - radVert) / 2;

    if (m_use3DView) {
        dc.SetPen(m_outlinePen);
        dc.SetBrush(wxNoBrush);
        dc.DrawEllipticArc(x0, y0 + shift3D, radHoriz, radVert, -180, 0);
        dc.DrawLine(x0, y0 + radVert / 2, x0, y0 + radVert / 2 + shift3D + 1);
        dc.DrawLine(x0 + radHoriz, y0 + radVert / 2, x0 + radHoriz, y0 + radVert / 2 + shift3D + 1);

        double part = 0;
        for (size_t n = 0; ; n++) {
            double angle = 360 * part;

            wxCoord x1, y1, x2, y2;

            if (angle > 180) {
                EllipticEgde(x0, y0, radHoriz, radVert, angle, x1, y1);

                x2 = x1;
                y2 = y1 + shift3D + 1/*XXX*/;

                dc.DrawLine(x1, y1, x2, y2);
            }

            if (n >= m_dataset->GetCount())
                break;

            double v = m_dataset->GetValue(n, m_serie);
            part += v / sum;
        }
    }

    dc.SetPen(m_outlinePen);
    //dc.SetFont(labelsFont);
    double part = 0;
    for (size_t n = 0; n < m_dataset->GetCount(); n++) {
        double v = m_dataset->GetValue(n, m_serie);

        double angle1 = 360 * part;

        part += v / sum;

        double angle2 = 360 * part;

        dc.SetBrush(*wxTheBrushList->FindOrCreateBrush(m_colorScheme.GetColor(n)));
        if(abs(angle2 - angle1) > 0.003) {
          dc.DrawEllipticArc(x0, y0, radHoriz, radVert, angle1, angle2);
        }
    }

    // draw edges
    dc.SetPen(m_outlinePen);
    dc.SetBrush(wxNoBrush);
    part = 0;
    for (size_t n = 0; n < m_dataset->GetCount(); n++) {
        double v = m_dataset->GetValue(n, m_serie);

        double angle = 360 * part;

        wxCoord x1, y1;
        EllipticEgde(x0, y0, radHoriz, radVert, angle, x1, y1);
        dc.DrawLine(x0 + radHoriz / 2, y0 + radVert / 2, x1, y1);

        part += v / sum;
    }

    // fill areas
    if (m_use3DView) {
        double part = 0;
        for (size_t n = 0; n < m_dataset->GetCount(); n++) {
            double angle = 360 * part;
            double v = m_dataset->GetValue(n, m_serie);
            part += v / sum;

            double angle2 = 360 * part;

            if (angle > 180 || angle2 > 180) {
                wxCoord x1, y1;

                double a;
                if (angle <= 180) {
                    a = (180 + angle2) / 2;
                }
                else {
                    a = (angle + angle2) / 2;
                }

                EllipticEgde(x0, y0, radHoriz, radVert, a, x1, y1);

                dc.SetBrush(*wxTheBrushList->FindOrCreateBrush(m_colorScheme.GetColor(n)));
                dc.FloodFill(x1, y1 + shift3D / 2, m_outlinePen.GetColour(), wxFLOOD_BORDER);
            }
        }
    }
}

