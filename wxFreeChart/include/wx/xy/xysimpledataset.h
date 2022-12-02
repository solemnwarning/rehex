/////////////////////////////////////////////////////////////////////////////
// Name:    xysimpledataset.h
// Purpose: xy simple dataset class declaration
// Author:    Moskvichev Andrey V.
// Created:    2009/11/25
// Copyright:    (c) 2009 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef XYSIMPLEDATASET_H_
#define XYSIMPLEDATASET_H_

#include <wx/xy/xydataset.h>

#include <wx/dynarray.h>

/**
 * Holds data for one XY serie.
 */
class WXDLLIMPEXP_FREECHART XYSerie
{
public:
    /**
     * Constructs new xy serie.
     * @param data double [x, y] array
     * @param count point count in data array
     */
    wxDEPRECATED_MSG("Use XYSerie(const wxVector&<wxRealPoint>) instead.")
    XYSerie(double *data, size_t count);
    
    /**
     * Constructs a new XY series using data that is already stored in the prepared vector.
     * @param seriesData The data that will be displayed by this series.
     */
    XYSerie(const wxVector<wxRealPoint>& seriesData);

    virtual ~XYSerie();

    void Append(const wxRealPoint& values);

    void Insert(size_t index, const wxRealPoint& values);
    
    void Remove(size_t index);

    /**
     * Retrieves the X value of an existing data point within the series.
     * @param index The position of the data point within the series.
     * @return The X value for the selected data point.
     */
    double GetX(size_t index);

    /**
     * Retrieves the Y value of an existing data point within the series.
     * @param index The position of the data point within the series.
     * @return The Y value for the selected data point.
     */
    double GetY(size_t index);
    
    /**
     * Updates the X value of an existing data point within the series.
     * @param index The position of the data point within the series.
     * @param values The new values for X.
     */
    void UpdateX(size_t index, double x);
    
    /**
     * Updates the Y value of an existing data point within the series.
     * @param index The position of the data point within the series.
     * @param values The new value for Y.
     */
    void UpdateY(size_t index, double y);

    /**
     * Updates the X and Y values of an existing data point within the series.
     * @param index The position of the data point within the series.
     * @param values The new values for X and Y.
     */
    void UpdatePoint(size_t index, const wxRealPoint& values);
    

    size_t GetCount();

    const wxString &GetName();

    void SetName(const wxString &name);

private:
    wxVector<wxRealPoint> m_newdata;
    wxString m_name;  
};

WX_DECLARE_USER_EXPORTED_OBJARRAY(XYSerie *, XYSerieArray, WXDLLIMPEXP_FREECHART);

/**
 * Simple xy dataset.
 */
class WXDLLIMPEXP_FREECHART XYSimpleDataset : public XYDataset
{
    DECLARE_CLASS(XYSimpleDataset)
public:
    XYSimpleDataset();
    virtual ~XYSimpleDataset();

    /**
     * Adds new xy serie.
     * @param data double [x, y] array
     * @param count point count in data array
     */
    wxDEPRECATED_MSG("Use AddSerie(new XYSerie(const wxVector&<wxRealPoint>)) instead.")
    void AddSerie(double *data, size_t count);

    /**
     * Constructs new xy serie.
     * @param serie new serie
     */
    void AddSerie(XYSerie *serie);

    XYSerie* GetSerie(size_t series);

    virtual double GetX(size_t index, size_t serie) wxOVERRIDE;

    virtual double GetY(size_t index, size_t serie) wxOVERRIDE;

    virtual size_t GetSerieCount();

    virtual size_t GetCount(size_t serie);

    wxDEPRECATED_MSG("Use GetSeries()->GetName() instead.")
    virtual wxString GetSerieName(size_t serie);

    wxDEPRECATED_MSG("Use GetSeries()->SetName() instead.")
    void SetSerieName(size_t serie, const wxString &name);

private:
    XYSerieArray m_series;
    wxVector<wxSharedPtr<XYSerie> > m_series2;
    
    friend XYSerie;
};

#endif /*XYSIMPLEDATASET_H_*/
