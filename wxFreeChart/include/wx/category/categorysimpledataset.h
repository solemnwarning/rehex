/////////////////////////////////////////////////////////////////////////////
// Name:    categorysimpledataset.h
// Purpose: category simple dataset declarations
// Author:    Moskvichev Andrey V.
// Created:    2009/11/26
// Copyright:    (c) 2009 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef CATEGORYSIMPLEDATASET_H_
#define CATEGORYSIMPLEDATASET_H_

#include <wx/category/categorydataset.h>

#include <wx/dynarray.h>

/**
 * Category serie for CategorySimpleDataset.
 */
class WXDLLIMPEXP_FREECHART CategorySerie
{
public:
    /**
     * Constructs new CategorySerie.
     * @param name serie name
     * @param value serie values array
     * @param count values array elements count
     */
    CategorySerie(const wxString &name, double *values, size_t count);
    virtual ~CategorySerie();

    /**
     * Returns serie name.
     * @return serie name
     */
    const wxString &GetName();

    /**
     * Returns value at index.
     * @param index index of value
     * @return value
     */
    double GetValue(size_t index);

private:
    wxString m_name;
    size_t m_count;
    double *m_values;
};

WX_DECLARE_USER_EXPORTED_OBJARRAY(CategorySerie *, CategorySerieArray, WXDLLIMPEXP_FREECHART);

/**
 * Simple category dataset implementation.
 * It's general purpose implementation, and useful for
 * many applications.
 */
class WXDLLIMPEXP_FREECHART CategorySimpleDataset : public CategoryDataset
{
    DECLARE_CLASS(CategorySimpleDataset)
public:
    /**
     * Constructs new category simple dataset.
     * @param names category names array
     * @param count names count
     */
    CategorySimpleDataset(wxString *names, size_t count);
    virtual ~CategorySimpleDataset();

    /**
     * Adds serie.
     * @param name serie name
     * @param value serie values array
     * @param count values array elements count
     */
    void AddSerie(const wxString &name, double *values, size_t count);

    /**
     * Adds serie.
     * @param serie serie to be added
     */
    void AddSerie(CategorySerie *serie);

    //
    // CategoryDataset
    //
    virtual double GetValue(size_t index, size_t serie);

    virtual size_t GetSerieCount();

    virtual wxString GetName(size_t index);

    virtual size_t GetCount();

    virtual wxString GetSerieName(size_t serie);

private:
    wxArrayString m_names;
    CategorySerieArray m_series;
};

#endif /* CATEGORYSIMPLEDATASET_H_ */
