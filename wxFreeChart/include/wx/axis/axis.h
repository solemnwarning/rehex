/////////////////////////////////////////////////////////////////////////////
// Name:    axis.h
// Purpose: axis base class declarations
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef AXIS_H_
#define AXIS_H_

#include <wx/wxfreechartdefs.h>
#include <wx/dataset.h>

#include <wx/dynarray.h>

#include <wx/drawobject.h>
#include <wx/observable.h>

enum AXIS_LOCATION {
    AXIS_LEFT = 1,
    AXIS_RIGHT,
    AXIS_TOP,
    AXIS_BOTTOM,
};

class WXDLLIMPEXP_FREECHART Axis;

/**
 * Interface to receive axis events.
 */
class WXDLLIMPEXP_FREECHART AxisObserver
{
public:
    AxisObserver();
    virtual ~AxisObserver();

    /**
     * Called when axis is changed.
     * @param axis changed axis
     */
    virtual void AxisChanged(Axis *axis) = 0;

    /**
     * Called when axis bounds are changed.
     * @param axis axis that bounds are changed
     */
    virtual void BoundsChanged(Axis *axis) = 0;
};

/**
 * Base class for all axes.
 * Axis has following attributes:
 * <ol>
 *     <li>Location - where axis arranged on plot, can be: AXIS_LEFT, AXIS_RIGHT, AXIS_TOP, AXIS_BOTTOM.</li>
 *     <li>Margins - distance from plot edges to axis labels.</li>
 *     <li>Window - visible subset of data. Window has width and position. Width means how much
 *  data points is visible at once, position is first data item visible.</li>
 * </ol>
 */
class WXDLLIMPEXP_FREECHART Axis : public wxObject, public Observable<AxisObserver>
{
    DECLARE_CLASS(Axis)

    friend class Plot;
    friend class AxisShare;
public:
    /**
     * Constructs new axis.
     * @param location axis location (cannot be changed after axis created)
     */
    Axis(AXIS_LOCATION location);
    virtual ~Axis();

    /**
     * Returns axis location.
     * @return axis location
     */
    AXIS_LOCATION GetLocation()
    {
        return m_location;
    }

    /**
     * Checks whether axis is vertical.
     * @return true if axis is vertical, false - overwise
     */
    bool IsVertical()
    {
        return (m_location == AXIS_LEFT) || (m_location == AXIS_RIGHT);
    }

    /**
     * Checks whether axis is horizontal.
     * @return true if axis is horizontal, false - overwise
     */
    bool IsHorizontal()
    {
        return !IsVertical();
    }

    /**
     * Sets minimal/maximal margins for axis.
     * Eg bottom/top for vertical axes, left/right for horizontal.
     * @param marginMin new minimal margin
     * @param marginMax new maximal margin
     */
    void SetMargins(wxCoord marginMin, wxCoord marginMax);

    /**
     * Sets the pen to be used for drawing major gridlines. A major gridline is a gridline that is associated with a major 
     * axis label.
     * @param majorGridlinePen The pen to be used to draw major gridlines on this axis.
     */
     void SetMajorGridlinePen(const wxPen& pen)
     {
         m_majorGridlinePen = pen;
         FireAxisChanged();
     }
     
    /**
     * Sets the pen to be used for drawing minor gridlines. A minor gridline is a gridline that is associated with a minor 
     * axis label, i.e. any label that is not a major axis label.
     * @param minorGridlinePen The pen to be used to draw minor gridlines on this axis.
     */
     void SetMinorGridlinePen(const wxPen& pen)
     {
         m_minorGridlinePen = pen;
         FireAxisChanged();
     }
     
     /**
      * Gets the pen that is currently used to draw major gridlines on this axis.
      * @return The pen currently used to draw major gridlines.
      */
     const wxPen& GetMajorGridlinePen()
     {
         return m_majorGridlinePen;
     }

     /**
      * Gets the pen that is currently used to draw minor gridlines on this axis.
      * @return The pen currently used to draw minor gridlines.
      */
     const wxPen& GetMinorGridlinePen()
     {
         return m_minorGridlinePen;
     }

    //
    // Dataset functions.
    //
    /**
     * Returns dataset counts, linked with this axis.
     * @return dataset counts, linked with this axis
     */
    size_t GetDatasetCount();

    /**
     * Returns dataset, linked with this axis at specified index.
     * @param index dataset index
     * @return dataset at index
     */
    Dataset *GetDataset(size_t index);

    //
    // Mouse drag behavior
    //
    void SetZoomPanMode();

    //
    // Window functions.
    //

    /**
     * Sets window width. Window width is in data space.
     * @param winWidth new window width
     */
    void SetWindowWidth(double winWidth)
    {
        SetWindow(m_winPos, winWidth);
    }

    /**
     * Returns window width.
     * @return window width
     */
    double GetWindowWidth()
    {
        return m_winWidth;
    }

    /**
     * Sets window position. Window position is in data space.
     * @param winPos new window position
     */
    void SetWindowPosition(double winPos)
    {
        SetWindow(winPos, m_winWidth);
    }

    /**
     * Returns window position.
     * @return window position
     */
    double GetWindowPosition()
    {
        return m_winPos;
    }

    /**
     * Sets whether to use window.
     * @param useWin true to use window
     */
    void SetUseWindow(bool useWin)
    {
        if (m_useWin != useWin) {
            m_useWin = useWin;
            FireAxisChanged();
        }
    }

    /**
     * Sets window params (position and width). Window params are in data space.
     * @param winPos new window position
     * @param winWidth new window width
     */
    void SetWindow(double winPos, double winWidth)
    {
        if (m_winPos != winPos || m_winWidth != winWidth) {
            m_winPos = winPos;
            m_winWidth = winWidth;
            FireAxisChanged();
        }
    }

    /**
     * Checks whether line in data space intersects window.
     * @param v0 line begin in data space
     * @param v0 line end in data space
     * @return true if line intersects window
     */
    bool IntersectsWindow(double v0, double v1);

    /**
     * Returns window bounds.
     * If window is not used, simply returns data bounds.
     * @param winMin out for window minimal
     * @param winMax out for window maximal
     */
    void GetWindowBounds(double &winMin, double &winMax)
    {
        double minValue, maxValue;
        GetDataBounds(minValue, maxValue);

        if (m_useWin) {
            winMin = m_winPos;
            winMax = wxMin(maxValue, winMin + m_winWidth);
        }
        else {
            winMin = minValue;
            winMax = maxValue;
        }
    }

    /**
     * internal. Don't use from programs.
     */
    void AddDataset(Dataset *dataset)
    {
        if (AcceptDataset(dataset)) {
            m_datasets.Add(dataset);
        }
    }

    /**
     * Returns data bounds.
     * @param minValue output minimal data value
     * @param maxValue output maximal data value
     */
    virtual void GetDataBounds(double &minValue, double &maxValue) const = 0;

    /**
     * Used to determine minimal size needed to draw axis contents,
     * minimal width for vertical axes, minimal height for horizontal.
     * @param dc device context
     * @return extent
     */
    virtual wxCoord GetExtent(wxDC &dc) = 0;

    /**
     * Checks whether data value is visible.
     * @param value value in data space
     * @return true if data value is visible
     */
    virtual bool IsVisible(double value);

    /**
     * Returns nearest boundary value.
     * @param value out of bounds value, for which will be returned boundary value
     * @return nearest boundary value
     */
    virtual double BoundValue(double value);

    /**
     * Transforms coordinate from data space to graphics space.
     * @param dc device context
     * @param minCoord minimal graphics space coordinate
     * @param gRange graphics space range
     * @param value value in data space
     * @return value in graphics space
     */
    virtual wxCoord ToGraphics(wxDC &dc, int minCoord, int gRange, double value);

    /**
     * Transforms coordinate from graphics space to data space.
     * @param dc device context
     * @param minCoord minimal graphics space coordinate
     * @param gRange graphics space range
     * @param value value in data space
     * @return coordinate in data space
     */
    virtual double ToData(wxDC &dc, int minCoord, int gRange, wxCoord g);

    /**
     * Performs axis bounds update after dataset/s change.
     */
    virtual bool UpdateBounds() = 0;

    /**
     * Performs axis drawing.
     * @param dc device context
     * @param rc rectangle where to draw
     */
    virtual void Draw(wxDC &dc, wxRect rc) = 0;

    /**
     * Draws grid lines for axis.
     * @param dc device context
     * @param rc data area rectangle of plot
     */
    virtual void DrawGridLines(wxDC &dc, wxRect rcData) = 0;

protected:
    /**
     * Checks whether dataset can be accepted by this axis.
     * Must be implemented by derivative classes.
     * XXX: maybe remove this method later.
     * @param dataset dataset to be checked
     * @return true - if dataset can be accepted, false overwise
     */
    virtual bool AcceptDataset(Dataset *dataset) = 0;

    DatasetArray m_datasets;
	wxPen m_majorGridlinePen;
	wxPen m_minorGridlinePen;

    wxCoord m_marginMin;
    wxCoord m_marginMax;

    double m_winPos;
    double m_winWidth;
    bool m_useWin;

    FIRE_WITH_THIS(AxisChanged);
    FIRE_WITH_THIS(BoundsChanged);

private:
    AXIS_LOCATION m_location;

    size_t m_shareCount;
};

WX_DECLARE_USER_EXPORTED_OBJARRAY(Axis *, AxisArray, WXDLLIMPEXP_FREECHART);

/**
 * Used to combine axes.
 * Shares axis between plots.
 */
class WXDLLIMPEXP_FREECHART AxisShare : public Axis
{
public:
    AxisShare(Axis *axis);
    virtual ~AxisShare();

    /**
     * Sets axis share visible or not.
     * Note: by default axis share is invisible.
     * @param shareVisible true to set share visible
     */
    void SetShareVisible(bool shareVisible);

    //
    // Axis
    //

    virtual void GetDataBounds(double &minValue, double &maxValue) const;

    virtual wxCoord GetExtent(wxDC &dc);

    virtual bool IsVisible(double value);

    virtual double BoundValue(double value);

    virtual wxCoord ToGraphics(wxDC &dc, int minCoord, int gRange, double value);

    virtual double ToData(wxDC &dc, int minCoord, int gRange, wxCoord g);

    virtual bool UpdateBounds() wxOVERRIDE;

    virtual void Draw(wxDC &dc, wxRect rc);

    virtual void DrawGridLines(wxDC &dc, wxRect rcData);

protected:
    virtual bool AcceptDataset(Dataset *dataset);

private:
    bool m_shareVisible;

    Axis *m_axis;
};

wxCoord ToGraphics(int minCoord, int gRange, double minValue, double maxValue, wxCoord margin, bool vertical, double value);
double ToData(int minCoord, int gRange, double minValue, double maxValue, wxCoord margin, bool vertical, wxCoord g);

#endif /*AXIS_H_*/
