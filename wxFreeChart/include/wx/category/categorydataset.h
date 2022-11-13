/////////////////////////////////////////////////////////////////////////////
// Name:    categorydataset.h
// Purpose: category dataset declarations
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef CATEGORYDATASET_H_
#define CATEGORYDATASET_H_

#include <wx/dataset.h>
#include <wx/bars/barrenderer.h>

/**
 * Dataset for data values in form [category name, value].
 */
class WXDLLIMPEXP_FREECHART CategoryDataset : public XYDataset
{
    DECLARE_CLASS(XYDataset)
public:
    CategoryDataset();
    virtual ~CategoryDataset();

    /**
     * Returns value associated with category at index.
     * @param index value associated with category
     * @return value associated with category
     */
    virtual double GetValue(size_t index, size_t serie) = 0;

    /**
     * Returns category name at index.
     * @param index index of category name
     * @return category name
     */
    virtual wxString GetName(size_t index) = 0;

    /**
     * Returns category count.
     * @return category count
     */
    virtual size_t GetCount() = 0;

    virtual bool HasValue(size_t index, size_t serie);

    virtual double GetMinValue(bool verticalAxis);

    virtual double GetMaxValue(bool verticalAxis);

    //
    // XYDataset
    //
    virtual double GetX(size_t index, size_t serie);

    virtual double GetY(size_t index, size_t serie);

    virtual size_t GetCount(size_t serie);

    BarRenderer *GetRenderer()
    {
        return (BarRenderer *) m_renderer;
    }

protected:
    virtual bool AcceptRenderer(Renderer *r);
};

#endif /*CATEGORYDATASET_H_*/
