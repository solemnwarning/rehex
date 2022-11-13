/////////////////////////////////////////////////////////////////////////////
// Name:    ohlcdataset.h
// Purpose: OHLC simple dataset declaration.
// Author:    Moskvichev Andrey V.
// Created:    2011/12/25
// Copyright:    (c) 2008-2011 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef OHLCSIMPLEDATASET_H_
#define OHLCSIMPLEDATASET_H_

#include <wx/ohlc/ohlcdataset.h>

class WXDLLIMPEXP_FREECHART OHLCSimpleDataset : public OHLCDataset
{
    DECLARE_CLASS(OHLCSimpleDataset)
public:
    OHLCSimpleDataset(OHLCItem *items, size_t count);
    virtual ~OHLCSimpleDataset();

    virtual OHLCItem *GetItem(size_t index);

    virtual size_t GetCount();

private:
    OHLCItem *m_items;
    size_t m_count;
};

#endif /*OHLCSIMPLEDATASET_H_*/
