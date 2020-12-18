///////////////////////////////////////////////////////////////////////////////
// Name:        wxluadebuggerdefs.h
// Purpose:     definitions for wxLuaDebugger module
// Author:      John Labenski, Francesco Montorsi
// Modified by:
// Created:     20/5/2006
// Copyright:   (c) John Labenski, Francesco Montorsi
// Licence:     wxWidgets licence
///////////////////////////////////////////////////////////////////////////////

#ifndef __WX_WXLUADEBUGGERDEFS_H__
#define __WX_WXLUADEBUGGERDEFS_H__

#include "wx/defs.h"

#include "wxlua/wxldefs.h"
#include "wxlua/debug/wxluadebugdefs.h"

// ----------------------------------------------------------------------------
// WXDLLIMPEXP macros
// ----------------------------------------------------------------------------

#ifdef WXMAKINGDLL_WXLUADEBUGGER
    #define WXDLLIMPEXP_WXLUADEBUGGER WXEXPORT
    #define WXDLLIMPEXP_DATA_WXLUADEBUGGER(type) WXEXPORT type
#elif defined(WXUSINGDLL)
    #define WXDLLIMPEXP_WXLUADEBUGGER WXIMPORT
    #define WXDLLIMPEXP_DATA_WXLUADEBUGGER(type) WXIMPORT type
#else // not making nor using DLL
    #define WXDLLIMPEXP_WXLUADEBUGGER
    #define WXDLLIMPEXP_DATA_WXLUADEBUGGER(type) type
#endif

// Forward declare all wxLua classes with this macro
#if defined(HAVE_VISIBILITY) || (defined(__WINDOWS__) && defined(__GNUC__))
    #define WXDLLIMPEXP_FWD_WXLUADEBUGGER
#else
    #define WXDLLIMPEXP_FWD_WXLUADEBUGGER WXDLLIMPEXP_WXLUADEBUGGER
#endif

// ----------------------------------------------------------------------------
// Defines for various things
// ----------------------------------------------------------------------------

#define ID_WXLUA_SERVER          1200
#define ID_WXLUA_SOCKET          1201

#define WXLUA_SOCKET_PORT        1561

#endif  // __WX_WXLUADEBUGGERDEFS_H__
