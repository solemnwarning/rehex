/////////////////////////////////////////////////////////////////////////////
// Name:    vectordataset.h
// Purpose: vector dataset declarations
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef VECTORDATASET_H_
#define VECTORDATASET_H_

#include <wx/xy/xydataset.h>
#include <wx/dynarray.h>

WX_DECLARE_USER_EXPORTED_OBJARRAY(double, wxDoubleArray, WXDLLIMPEXP_FREECHART);

/**
 * Vector implementation of XYDataset.
 * Where is y values specified, and X values is an index (0....Count)
 * Allows y data addition and removal.
 */
class WXDLLIMPEXP_FREECHART VectorDataset : public XYDataset
{
public:
    /**
     * Construct new VectorDataset instance.
     * @param _name name of dataset
     * @param autoUpdate if true any changes in data will fire dataset updated event
     */
    VectorDataset();
    virtual ~VectorDataset();

    virtual size_t GetSerieCount();

    virtual size_t GetCount(size_t serie);

    virtual wxString GetSerieName(size_t serie);

    virtual double GetX(size_t index, size_t serie);

    virtual double GetY(size_t index, size_t serie);

    /**
     * Adds y values to dataset.
     * @param y y value
     */
    void Add(double y);

    /**
     * Replaces y value at specified index.
     * @param index index of value
     * @param y new y value
     */
    void Replace(size_t index, double y);

    /**
     * Removes value at specified index.
     * @param index of value
     */
    void RemoveAt(size_t index);

    /**
     * Removes all values from dataset.
     */
    void Clear();

private:
    wxDoubleArray m_values;
};

#endif /*VECTORDATASET_H_*/
