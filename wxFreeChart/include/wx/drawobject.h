/////////////////////////////////////////////////////////////////////////////
// Name:    drawobject.h
// Purpose:
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef DRAWOBJECT_H_
#define DRAWOBJECT_H_

#include <wx/observable.h>

#define wxNoBrush *wxTheBrushList->FindOrCreateBrush(*wxBLACK, wxBRUSHSTYLE_TRANSPARENT)
#define wxNoPen *wxThePenList->FindOrCreatePen(*wxBLACK, 1, wxPENSTYLE_TRANSPARENT)

class WXDLLIMPEXP_FREECHART DrawObject;

/**
 * Interface to receive DrawObject events.
 */
class WXDLLIMPEXP_FREECHART DrawObserver
{
public:
    DrawObserver()
    {
    }

    virtual ~DrawObserver()
    {
    }

    /**
     * Called when object is need to be redrawed.
     * @param obj object that need to be redrawed
     */
    virtual void NeedRedraw(DrawObject *obj) = 0;
};

/**
 * Base class for objects drawn on chart or perform drawing of
 * another objects (like renderers, area draws, etc).
 */
class WXDLLIMPEXP_FREECHART DrawObject : public Observable<DrawObserver>
{
public:
    DrawObject()
    {
    }

    virtual ~DrawObject()
    {
    }

protected:
    FIRE_WITH_THIS(NeedRedraw);
};

#endif /*DRAWOBJECT_H_*/
