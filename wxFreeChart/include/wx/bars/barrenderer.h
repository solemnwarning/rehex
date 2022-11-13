/////////////////////////////////////////////////////////////////////////////
// Name:    barrenderer.h
// Purpose: bar renderer and bar types declarations
// Author:    Moskvichev Andrey V.
// Created:    14.11.2008
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef BARRENDERER_H_
#define BARRENDERER_H_

#include "wx/xy/xyrenderer.h"
#include "wx/areadraw.h"

class CategoryDataset;
class BarRenderer;

/**
 * Bar types base class.
 * This class performs bars drawing.
 */
class WXDLLIMPEXP_FREECHART BarType
{
public:
    BarType(double base);
    virtual ~BarType();

    /**
     * Performs bar drawing.
     * @param barRenderer bar renderer
     * @param dc device context
     * @param rc rectangle where to draw
     * @param horizAxis horizontal axis
     * @param vertAxis vertical axis
     * @param vertical true to draw vertical bars
     * @param item dataset item index
     * @param dataset dataset to draw bars
     */
    virtual void Draw(BarRenderer *barRenderer, wxDC &dc, wxRect rc, Axis *horizAxis, Axis *vertAxis, bool vertical, size_t item, CategoryDataset *dataset);

    //
    // Called from BarRenderer. Don't call from programs.
    //
    virtual double GetMinValue(CategoryDataset *dataset);
    virtual double GetMaxValue(CategoryDataset *dataset);

protected:
    /**
     * Called to calculate bar geometry params.
     * Must be implemented by derivate classes.
     * @param dataset dataset
     * @param item item index
     * @param serie serie index
     * @param width output for bar width
     * @param shift output for bar shift
     * @param base output for bar base
     * @param value output for bar value
     */
    virtual void GetBarGeometry(CategoryDataset *dataset, size_t item, size_t serie,
            int &width, wxCoord &shift, double &base, double &value) = 0;

    double m_base;
};

/**
 * Normal bar type. Draws series' bars parallel to each other.
 */
class WXDLLIMPEXP_FREECHART NormalBarType : public BarType
{
public:
    /**
     * Constructs new normal bar type.
     * @param barWidth bar width
     * @param serieGap distance between series bars
     * @param base bars base, point from bars are drawn
     */
    NormalBarType(int barWidth, int serieGap = 1, double base = 0.0);
    virtual ~NormalBarType();

protected:
    virtual void GetBarGeometry(CategoryDataset *dataset, size_t item, size_t serie,
            int &width, wxCoord &shift, double &base, double &value);

private:
    int m_barWidth;
    int m_serieGap;
};

/**
 * Draws series' bars in stack, after each other.
 */
class WXDLLIMPEXP_FREECHART StackedBarType : public BarType
{
public:
    /**
     * Constructs new stacked bar type.
     * @param barWidth bar width
     * @param base bars base, point from bars are drawn
     */
    StackedBarType(int barWidth, double base);
    virtual ~StackedBarType();

    virtual double GetMinValue(CategoryDataset *dataset);
    virtual double GetMaxValue(CategoryDataset *dataset);

protected:
    virtual void GetBarGeometry(CategoryDataset *dataset, size_t item, size_t serie,
            int &width, wxCoord &shift, double &base, double &value);

private:
    int m_barWidth;
};

/**
 * Draws series' bars overlapped.
 */
class WXDLLIMPEXP_FREECHART LayeredBarType : public BarType
{
public:
    /**
     * Constructs new layered bar type.
     * @param initialBarWidth maximal bar width
     * @param base bars base, point from bars are drawn
     */
    LayeredBarType(int initialBarWidth, double base);
    virtual ~LayeredBarType();

protected:
    virtual void GetBarGeometry(CategoryDataset *dataset, size_t item, size_t serie,
            int &width, wxCoord &shift, double &base, double &value);

private:
    int m_initialBarWidth;
};

/**
 * Bar renderer.
 */
class WXDLLIMPEXP_FREECHART BarRenderer : public Renderer
{
    DECLARE_CLASS(BarRenderer)
public:
    /**
     * Constructs new bar renderer.
     * @param barType bar type to be drawn by this renderer,
     * renderer takes ownership for bar type object
     */
    BarRenderer(BarType *barType);
    virtual ~BarRenderer();

    //
    // Renderer
    //
    virtual void DrawLegendSymbol(wxDC &dc, wxRect rcSymbol, size_t serie);

    /**
     * Draws dataset.
     * @param dc device context
     * @param horizAxis horizontal axis
     * @param vertAxis vertical axis
     * @param vertical true to draw vertical bars
     * @param dataset dataset to be drawn
     */
    void Draw(wxDC &dc, wxRect rc, Axis *horizAxis, Axis *vertAxis, bool vertical, CategoryDataset *dataset);

    /**
     * Sets bar type, an object that performs bars drawing.
     * BarRenderer owns this object.
     * @param barType new bar type,
     * renderer takes ownership for bar type object
     */
    void SetBarType(BarType *barType);

    /**
     * Returns bar type.
     * @return bar type
     */
    BarType *GetBarType();

    /**
     * Sets area draw object to draw specified serie.
     * @param serie serie index
     * @param ad area draw for serie
     */
    void SetBarDraw(size_t serie, AreaDraw *areaDraw);

    /**
     * Returns area draw object, used to draw specified serie.
     * @param serie serie index
     * @return area draw object
     */
    AreaDraw *GetBarDraw(size_t serie);

    double GetMinValue(CategoryDataset *dataset);
    double GetMaxValue(CategoryDataset *dataset);

private:
    BarType *m_barType;

    AreaDrawCollection m_barDraws;
};

#endif /*BARRENDERER_H_*/
