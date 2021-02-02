/////////////////////////////////////////////////////////////////////////////
// Name:        wxlua/sharedptr.h - copied from wx/sharedptr.h
// Purpose:     Shared pointer based on the counted_ptr<> template, which
//              is in the public domain
// Author:      Robert Roebling, Yonat Sharon
// RCS-ID:      Id: sharedptr.h 67232 2011-03-18 15:10:15Z DS
// Copyright:   Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// This file is copied from 2.9.4's wxWidgets/include/wx/sharedptr.h
// wxLua needs to be able to easily release the pointer from deletion if
// somebody else will take ownership of it. In order to add this feature
// we need to modify the wxSharedPtr class and since its destructor is not
// virtual we cannot derive from it.
// The added functions are : GetWillDelete() and SetWillDelete().

#ifndef _WXLUA_SHAREDPTR_H_
#define _WXLUA_SHAREDPTR_H_

#include <wx/defs.h>
#include "wxlua/atomic.h"

// ----------------------------------------------------------------------------
// wxLuaSharedPtr: A smart pointer with non-intrusive reference counting.
// ----------------------------------------------------------------------------

template <class T>
class wxLuaSharedPtr
{
public:
    typedef T element_type;

    wxEXPLICIT wxLuaSharedPtr( T* ptr = NULL )
        : m_ref(NULL)
    {
        if (ptr)
            m_ref = new reftype(ptr);
    }

    ~wxLuaSharedPtr()                              { Release(); }
    wxLuaSharedPtr(const wxLuaSharedPtr& tocopy)   { Acquire(tocopy.m_ref); }

    wxLuaSharedPtr& operator=( const wxLuaSharedPtr& tocopy )
    {
        if (this != &tocopy)
        {
            Release();
            Acquire(tocopy.m_ref);
        }
        return *this;
    }

    wxLuaSharedPtr& operator=( T* ptr )
    {
        if (get() != ptr)
        {
            Release();
            if (ptr)
                m_ref = new reftype(ptr);
        }
        return *this;
    }

    // test for pointer validity: defining conversion to unspecified_bool_type
    // and not more obvious bool to avoid implicit conversions to integer types
    typedef T *(wxLuaSharedPtr<T>::*unspecified_bool_type)() const;
    operator unspecified_bool_type() const
    {
        if (m_ref && m_ref->m_ptr)
           return  &wxLuaSharedPtr<T>::get;
        else
           return NULL;
    }

    T& operator*() const
    {
        wxASSERT(m_ref != NULL);
        wxASSERT(m_ref->m_ptr != NULL);
        return *(m_ref->m_ptr);
    }

    T* operator->() const
    {
        wxASSERT(m_ref != NULL);
        wxASSERT(m_ref->m_ptr != NULL);
        return m_ref->m_ptr;
    }

    T* get() const
    {
        return m_ref ? m_ref->m_ptr : NULL;
    }

    void reset( T* ptr = NULL )
    {
        Release();
        if (ptr)
            m_ref = new reftype(ptr);
    }

    bool unique()   const    { return (m_ref ? m_ref->m_count == 1 : true); }
    long use_count() const   { return (m_ref ? (long)m_ref->m_count : 0); }

    /// Returns true if this class will delete the wrapped pointer of if
    /// someone else is expected to do so.
    bool GetWillDelete() const { return (m_ref ? m_ref->m_delete : false);  }
    /// Change ownership of who will delete the pointer, this class or someone else.
    void SetWillDelete(bool delete_when_no_more_references)
    {
        wxASSERT(m_ref != NULL);
        m_ref->m_delete = delete_when_no_more_references;
    }

private:

    struct reftype
    {
        reftype( T* ptr = NULL, unsigned count = 1 ) : m_ptr(ptr), m_count(count), m_delete(true) {}
        T*          m_ptr;
        wxAtomicInt m_count;
        bool        m_delete;
    }* m_ref;

    void Acquire(reftype* ref)
    {
        m_ref = ref;
        if (ref)
            wxAtomicInc( ref->m_count );
    }

    void Release()
    {
        if (m_ref)
        {
            wxAtomicDec( m_ref->m_count );
            if ((m_ref->m_count == 0) && m_ref->m_delete)
            {
                delete m_ref->m_ptr;
                delete m_ref;
            }
            m_ref = NULL;
        }
    }
};

template <class T, class U>
bool operator == (wxLuaSharedPtr<T> const &a, wxLuaSharedPtr<U> const &b )
{
    return a.get() == b.get();
}

template <class T, class U>
bool operator != (wxLuaSharedPtr<T> const &a, wxLuaSharedPtr<U> const &b )
{
    return a.get() != b.get();
}

#endif // _WXLUA_SHAREDPTR_H_
