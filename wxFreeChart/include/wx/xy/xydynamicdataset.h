/////////////////////////////////////////////////////////////////////////////
// Name:    xydynamidataset.h
// Purpose: xy dynamic serie and dataset declaration.
// Author:    Mike Sazonov
// E-mail:  msazonov(at)gmail.com
// Created:    2010/01/29
// Copyright:    (c) 2010 Mike Sazonov
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef __XYDYNAMICDATASET_H
#define __XYDYNAMICDATASET_H

#include <wx/wx.h>
#include <wx/gdicmn.h>
#include <wx/dynarray.h>

#include "wx/wxfreechartdefs.h"
#include "wx/xy/xydataset.h"

class WXDLLIMPEXP_FREECHART XYDynamicDataset;

WX_DECLARE_USER_EXPORTED_OBJARRAY(wxRealPoint
        , wxRealPointArray
        , WXDLLIMPEXP_FREECHART);

/**
 * XY dynamic serie.
 * Allows dynamic data add/insert/remove.
 */
class WXDLLIMPEXP_FREECHART XYDynamicSerie : public wxObject
{
    // Inherits only for wxWidgets RTTI support
    DECLARE_CLASS(XYDynamicSerie);

public:
    friend class XYDynamicDataset;

    XYDynamicSerie();
    XYDynamicSerie(const wxRealPointArray& data);

    virtual ~XYDynamicSerie();

    /**
     * Returns x coordinate at specified index.
     * @param index index of coordinate
     * @return x coordinate at specified index
     */
    double GetX(size_t index);

    /**
     * Returns y coordinate at specified index.
     * @param index index of coordinate
     * @return y coordinate at specified index
     */
    double GetY(size_t index);

    /**
     * Returns point at specified index.
     * @param index index of point
     * @return point at specified index
     */
    wxRealPoint GetXY(size_t index);

    /**
     * Returns points count.
     * @return points count
     */
    size_t GetCount();

    /**
     * Returns serie name.
     * @return serie name
     */
    const wxString &GetName();

    /**
     * Sets serie name.
     * @param name new serie name
     */
    void SetName(const wxString &name);

    /**
     * Adds XY point to end of data.
     * @param x x coordinate
     * @param y y coordinate
     */
    void AddXY(double x, double y);

    /**
     * Adds XY point to end of data.
     * @param xy point to be inserted
     */
    void AddXY(const wxRealPoint& xy);

    /**
     * Adds XY points to end of data.
     * @param data points array
     */
    void AddXY(const wxRealPointArray& data);

    /**
     * Insert XY point at specified position.
     * @param index index before which to insert point
     * @param x x coordinate
     * @param y y coordinate
     */
    void Insert(size_t index, double x, double y);

    /**
     * Insert XY point at specified position.
     * @param index index before which to insert point
     * @param xy point to be inserted
     */
    void Insert(size_t index, const wxRealPoint& xy);

    /**
     * Insert XY points at specified position.
     * @param index index before which to insert
     * @param data points array to be inserted
     */
    void Insert(size_t index, const wxRealPointArray& data);

    /**
     * Remove number of points from specified index.
     * @param index index from which to remove
     * @param count number of points to remove
     */
    void Remove(size_t index, size_t count = 1);

    /**
     * Remove all points from serie.
     */
    void Clear();

private:
    void SetDataset(XYDynamicDataset *dataset);

    wxRealPointArray    m_data;
    wxString             m_name;
    XYDynamicDataset    *m_dataset;
};

WX_DECLARE_USER_EXPORTED_OBJARRAY(XYDynamicSerie *
        , XYDynamicSerieArray
        , WXDLLIMPEXP_FREECHART);

/**
 * XY dynamic dataset.
 */
class WXDLLIMPEXP_FREECHART XYDynamicDataset : public XYDataset
{
    DECLARE_CLASS(XYDynamicDataset);

public:
    friend class XYDynamicSerie;

    XYDynamicDataset();
    virtual ~XYDynamicDataset();

    /**
     * Add serie to dataset.
     * @param data data for serie to be added
     */
    void AddSerie(const wxRealPointArray& data);

    /**
     * Add serie to dataset.
     * @param serie serie to be added
     */
    void AddSerie(XYDynamicSerie *serie);

    virtual size_t GetSerieCount();

    virtual wxString GetSerieName(size_t serie);
    void SetSerieName(size_t serie, const wxString &name);

    virtual double GetX(size_t index, size_t serie);
    virtual double GetY(size_t index, size_t serie);
    virtual size_t GetCount(size_t serie);

private:
    XYDynamicSerieArray m_series;
};

#endif /* __XYDYNAMICDATASET_H */

