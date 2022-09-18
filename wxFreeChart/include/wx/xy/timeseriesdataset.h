/////////////////////////////////////////////////////////////////////////////
// Name:    timeseriesdataset.h
// Purpose: Time series dataset declaration
// Author:    Moskvichev Andrey V.
// Created:    16.02.2012
// RCS-ID:    $Id: wxAdvTable.h,v 1.3 2008/11/07 16:42:58 moskvichev Exp $
// Copyright:    (c) 2012 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef TIMESERIESDATASET_H_
#define TIMESERIESDATASET_H_

#include <wx/xy/xydataset.h>

/**
 * Time series dataset.
 */
class WXDLLIMPEXP_FREECHART TimeSeriesDataset : public XYDataset, public DateTimeDataset
{
    DECLARE_CLASS(TimeSeriesDataset)
public:
    TimeSeriesDataset(double *data, time_t *times, size_t count);
    virtual ~TimeSeriesDataset();

    virtual size_t GetSerieCount();

    virtual wxString GetSerieName(size_t serie);

    virtual size_t GetCount(size_t serie);

    virtual double GetX(size_t index, size_t serie);

    virtual double GetY(size_t index, size_t serie);

    virtual DateTimeDataset *AsDateTimeDataset();

    //
    // DateTimeDataset
    //
    virtual time_t GetDate(size_t index);

    virtual size_t GetCount();

private:
    double *m_data;
    time_t *m_times;
    size_t m_count;
};

#endif /* TIMESERIESDATASET_H_ */

