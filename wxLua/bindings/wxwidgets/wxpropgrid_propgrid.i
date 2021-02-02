// ===========================================================================
// Purpose:     wxPropertyGrid library
// Author:      John Labenski
// Created:     05/01/2013
// Copyright:   (c) 2013 John Labenski. All rights reserved.
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 2.9.5
// ===========================================================================

// NOTE: This file is mostly copied from wxWidget's include/propgrid/*.h headers
// to make updating it easier.

#if wxLUA_USE_wxPropertGrid && %wxchkver_2_9 && wxUSE_PROPGRID

#include "wx/propgrid/propgrid.h"
#include "wx/propgrid/manager.h"
#include "wx/propgrid/editiors.h"
#include "wx/propgrid/advprops.h"
#include "wx/propgrid/props.h"
#include "wx/propgrid/propgridpagestate.h"
#include "wx/propgrid/propgridiface.h"
#include "wx/propgrid/propgriddefs.h"
#include "wx/propgrid/property.h"


#define_string wxPG_LABEL


#endif //wxLUA_USE_wxPropertGrid && %wxchkver_2_9 && wxUSE_PROPGRID
