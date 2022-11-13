/////////////////////////////////////////////////////////////////////////////
// Name:    ohlcdataset.h
// Purpose: OHLC datasets base class declaration.
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef OHLCDATASET_H_
#define OHLCDATASET_H_

#include <wx/xy/xydataset.h>
#include <wx/ohlc/ohlcrenderer.h>

struct OHLCItem
{
    double open;
    double high;
    double low;
    double close;

    int volume;

    time_t date;
};

/**
 * Open-High-Low-Close datasets base class.
 */
class WXDLLIMPEXP_FREECHART OHLCDataset : public Dataset, public DateTimeDataset
{
    DECLARE_CLASS(OHLCDataset)
public:
    OHLCDataset();
    virtual ~OHLCDataset();

    OHLCRenderer *GetRenderer()
    {
        return (OHLCRenderer *) m_renderer;
    }

    /**
     * Sets serie name. OHLC datasets contains only one serie.
     * @param serieName new serie name
     */
    void SetSerieName(const wxString &serieName)
    {
        m_serieName = serieName;
        DatasetChanged();
    }

    /**
     * Returns item on index.
     * @param index index of item
     */
    virtual OHLCItem *GetItem(size_t index) = 0;

    /**
     * Returns item count.
     * @return item count
     */
    virtual size_t GetCount() = 0;

    //
    // Dataset
    //
    virtual double GetMinValue(bool verticalAxis);

    virtual double GetMaxValue(bool verticalAxis);

    virtual size_t GetSerieCount();

    virtual wxString GetSerieName(size_t serie);

    virtual size_t GetCount(size_t serie);

    virtual DateTimeDataset *AsDateTimeDataset();

    //
    // DateDataset
    //
    virtual time_t GetDate(size_t index);

protected:
    virtual bool AcceptRenderer(Renderer *r);

    wxString m_serieName;
};

#endif /*OHLCDATASET_H_*/
