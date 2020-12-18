///////////////////////////////////////////////////////////////////////////////
// Name:        wxlversion.h
// Purpose:     wxLua version information
// Author:      John Labenski
// Created:     5/28/2005
// Copyright:   (c) 2012 John Labenski
// Licence:     wxWidgets licence
///////////////////////////////////////////////////////////////////////////////

#ifndef __WX_WXLVERSION_H__
#define __WX_WXLVERSION_H__

//-----------------------------------------------------------------------------
// The version of wxLua - for convenience we use the current version of
// wxWidgets which wxLua is most compatible with.
//-----------------------------------------------------------------------------

#define wxLUA_MAJOR_VERSION       3
#define wxLUA_MINOR_VERSION       1
#define wxLUA_RELEASE_NUMBER      0
#define wxLUA_SUBRELEASE_NUMBER   0
#define wxLUA_VERSION_STRING      wxT("wxLua 3.1.0.0")

// For non-Unix systems (i.e. when building without a configure script),
// users of this component can use the following macro to check if the
// current version is at least major.minor.release
#define wxLUA_CHECK_VERSION(major,minor,release) \
    (wxLUA_MAJOR_VERSION > (major) || \
    (wxLUA_MAJOR_VERSION == (major) && wxLUA_MINOR_VERSION > (minor)) || \
    (wxLUA_MAJOR_VERSION == (major) && wxLUA_MINOR_VERSION == (minor) && wxLUA_RELEASE_NUMBER >= (release)))

// the same but check the subrelease also
#define wxLUA_CHECK_VERSION_FULL(major,minor,release,subrel) \
    (wxLUA_CHECK_VERSION(major, minor, release) && \
        ((major) != wxLUA_MAJOR_VERSION || \
            (minor) != wxLUA_MINOR_VERSION || \
                (release) != wxLUA_RELEASE_NUMBER || \
                    (subrel) <= wxLUA_SUBRELEASE_NUMBER))

//-----------------------------------------------------------------------------
// This is an internal use binding generator version whose number is
//   incremented every time something changes that requires a regeneration
//   of the bindings. The check is written into the generated bindings to
//   give a compile time error.
// If this number is incremented the variable by the same name must be updated
//   in genwxbind.lua as well.
//-----------------------------------------------------------------------------

#define WXLUA_BINDING_VERSION 41


#endif // __WX_WXLVERSION_H__
