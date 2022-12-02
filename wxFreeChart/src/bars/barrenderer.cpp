/////////////////////////////////////////////////////////////////////////////
// Name:    barrenderer.cpp
// Purpose: bar renderer implementation
// Author:    Moskvichev Andrey V.
// Created:    14.11.2008
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/bars/barrenderer.h"
#include "wx/category/categorydataset.h"

//
// bar types
//

BarType::BarType(double base)
{
    m_base = base;
}

BarType::~BarType()
{
}

void BarType::Draw(BarRenderer *barRenderer, wxDC &dc, wxRect rc,
        Axis *horizAxis, Axis *vertAxis,
        bool vertical, size_t item, CategoryDataset *dataset)
{
    FOREACH_SERIE(serie, dataset) {
        // bar geometry params
        int width;
        wxCoord shift;
        double base, value;

        // get bar geometry
        GetBarGeometry(dataset, item, serie, width, shift, base, value);

        double xBase, yBase;
        double xVal, yVal;

        if (vertical) {
            xBase = xVal = item;
            yBase = base;
            yVal = value;
        }
        else {
            xBase = base;
            yBase = yVal = item;
            xVal = value;
        }

        // transform base and value to graphics coordinates
        wxCoord xBaseG = horizAxis->ToGraphics(dc, rc.x, rc.width, xBase);
        wxCoord yBaseG = vertAxis->ToGraphics(dc, rc.y, rc.height, yBase);
        wxCoord xG = horizAxis->ToGraphics(dc, rc.x, rc.width, xVal);
        wxCoord yG = vertAxis->ToGraphics(dc, rc.y, rc.height, yVal);

        wxRect rcBar;
        if (vertical) {
            xBaseG += shift;
            xG += shift;

            rcBar.x = wxMin(xBaseG, xG);
            rcBar.y = wxMin(yBaseG, yG);
            rcBar.width = width;
            rcBar.height = ABS(yBaseG - yG);
        }
        else {
            yBaseG += shift;
            yG += shift;

            rcBar.x = wxMin(xBaseG, xG);
            rcBar.y = wxMin(yBaseG, yG);
            rcBar.width = ABS(xBaseG - xG);
            rcBar.height = width;
        }

        // draw bar
        AreaDraw *barDraw = barRenderer->GetBarDraw(serie);
        barDraw->Draw(dc, rcBar);
    }
}

double BarType::GetMinValue(CategoryDataset *dataset)
{
    if (dataset->GetCount() == 0)
        return 0;

    double minValue = dataset->GetValue(0, 0);

    FOREACH_SERIE(serie, dataset) {
        for (size_t n = 0; n < dataset->GetCount(); n++) {
            minValue = wxMin(minValue, dataset->GetValue(n, serie));
        }
    }
    return wxMin(minValue, m_base);
}

double BarType::GetMaxValue(CategoryDataset *dataset)
{
    if (dataset->GetCount() == 0)
        return 0;

    double maxValue = dataset->GetValue(0, 0);

    FOREACH_SERIE(serie, dataset) {
        for (size_t n = 0; n < dataset->GetCount(); n++) {
            maxValue = wxMax(maxValue, dataset->GetValue(n, serie));
        }
    }
    return maxValue;
}

//
// NormalBarType
//

NormalBarType::NormalBarType(int barWidth, int serieGap, double base)
: BarType(base)
{
    m_barWidth = barWidth;
    m_serieGap = serieGap;
}

NormalBarType::~NormalBarType()
{
}

void NormalBarType::GetBarGeometry(CategoryDataset *dataset, size_t item, size_t serie, int &width, wxCoord &shift, double &base, double &value)
{
    width = m_barWidth;

    const int serieCount = dataset->GetSerieCount();
    if (serieCount > 1) {
        shift = serie * (m_barWidth + m_serieGap) - (m_serieGap * (serieCount - 1) + m_barWidth);
    }
    else {
        shift = -m_barWidth / 2;
    }

    base = m_base;
    value = dataset->GetValue(item, serie);
}

//
// StackedBarType
//

StackedBarType::StackedBarType(int barWidth, double base)
: BarType(base)
{
    m_barWidth = barWidth;
}

StackedBarType::~StackedBarType()
{
}

void StackedBarType::GetBarGeometry(CategoryDataset *dataset, size_t item, size_t serie, int &width, wxCoord &shift, double &base, double &value)
{
    width = m_barWidth;
    shift = -m_barWidth / 2;
    base = (serie >= 1) ? base + dataset->GetValue(item, serie - 1) : m_base;
    value = dataset->GetValue(item, serie);
    if (serie >= 1) {
        value += base;
    }
}

double StackedBarType::GetMinValue(CategoryDataset *WXUNUSED(dataset))
{
    return m_base;
}

double StackedBarType::GetMaxValue(CategoryDataset *dataset)
{
    if (dataset->GetCount() == 0)
        return 0;

    double maxValue = 0;

    for (size_t n = 0; n < dataset->GetCount(); n++) {
        double sum = m_base;

        FOREACH_SERIE(serie, dataset) {
            sum += dataset->GetValue(n, serie);
        }
        maxValue = wxMax(maxValue, sum);
    }
    return maxValue;
}

//
// LayeredBarType
//

LayeredBarType::LayeredBarType(int initialBarWidth, double base)
: BarType(base)
{
    m_initialBarWidth = initialBarWidth;
}

LayeredBarType::~LayeredBarType()
{
}

void LayeredBarType::GetBarGeometry(CategoryDataset *dataset, size_t item, size_t serie, int &width, wxCoord &shift, double &base, double &value)
{
    width = (int) ( m_initialBarWidth * (1 - serie / (double)dataset->GetSerieCount()));
    shift = -width / 2;
    base = m_base;
    value = dataset->GetValue(item, serie);
}

//
// BarRenderer
//

IMPLEMENT_CLASS(BarRenderer, Renderer)

BarRenderer::BarRenderer(BarType *barType)
{
    m_barType = barType;
}

BarRenderer::~BarRenderer()
{
    wxDELETE(m_barType);
}

void BarRenderer::SetBarType(BarType *barType)
{
    wxREPLACE(m_barType, barType);
    FireNeedRedraw();
}

BarType *BarRenderer::GetBarType()
{
    return m_barType;
}

void BarRenderer::DrawLegendSymbol(wxDC &dc, wxRect rcSymbol, size_t serie)
{
    AreaDraw *barDraw = GetBarDraw(serie);
    barDraw->Draw(dc, rcSymbol);
}

void BarRenderer::SetBarDraw(size_t serie, AreaDraw *areaDraw)
{
    m_barDraws.SetAreaDraw(serie, areaDraw);
}

AreaDraw *BarRenderer::GetBarDraw(size_t serie)
{
    AreaDraw *barDraw = m_barDraws.GetAreaDraw(serie);
    if (barDraw == NULL) 
    {
        // barDraw = new FillAreaDraw(GetDefaultColour(serie), GetDefaultColour(serie));
        barDraw = new FillAreaDraw(*wxTRANSPARENT_PEN, GetDefaultColour(serie));

        m_barDraws.SetAreaDraw(serie, barDraw);
    }
    return barDraw;
}

void BarRenderer::Draw(wxDC &dc, wxRect rc, Axis *horizAxis, Axis *vertAxis, bool vertical, CategoryDataset *dataset)
{
    for (size_t n = 0; n < dataset->GetCount(); n++) {
        m_barType->Draw(this, dc, rc, horizAxis, vertAxis, vertical, n, dataset);
    }
}

double BarRenderer::GetMinValue(CategoryDataset *dataset)
{
    return m_barType->GetMinValue(dataset);
}

double BarRenderer::GetMaxValue(CategoryDataset *dataset)
{
    return m_barType->GetMaxValue(dataset);
}
