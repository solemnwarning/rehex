///////////////////////////////////////////////////////////////////////////////
// Name:        wxluadebugdefs.h
// Purpose:     definitions for wxLuaDebug module
// Author:      John Labenski, Francesco Montorsi
// Modified by:
// Created:     20/5/2006
// Copyright:   (c) 2012 John Labenski, Francesco Montorsi
// Licence:     wxWidgets licence
///////////////////////////////////////////////////////////////////////////////

#ifndef __WX_WXLUADEBUGDEFS_H__
#define __WX_WXLUADEBUGDEFS_H__

#include <wx/defs.h>

#include "wxlua/wxldefs.h"

// ----------------------------------------------------------------------------
// WXDLLIMPEXP macros
// ----------------------------------------------------------------------------

#ifdef WXMAKINGDLL_WXLUADEBUG
    #define WXDLLIMPEXP_WXLUADEBUG WXEXPORT
    #define WXDLLIMPEXP_DATA_WXLUADEBUG(type) WXEXPORT type
#elif defined(WXUSINGDLL)
    #define WXDLLIMPEXP_WXLUADEBUG WXIMPORT
    #define WXDLLIMPEXP_DATA_WXLUADEBUG(type) WXIMPORT type
#else // not making nor using DLL
    #define WXDLLIMPEXP_WXLUADEBUG
    #define WXDLLIMPEXP_DATA_WXLUADEBUG(type) type
#endif

// Forward declare all wxStEdit classes with this macro
#if defined(HAVE_VISIBILITY) || (defined(__WINDOWS__) && defined(__GNUC__))
    #define WXDLLIMPEXP_FWD_WXLUADEBUG
#else
    #define WXDLLIMPEXP_FWD_WXLUADEBUG WXDLLIMPEXP_WXLUADEBUG
#endif


#endif  // __WX_WXLUADEBUGDEFS_H__
