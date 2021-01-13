#ifndef REHEX_WXLUA_SETUP_H
#define REHEX_WXLUA_SETUP_H

#ifdef wxUSE_FS_INET
#undef wxUSE_FS_INET
#endif

#define wxUSE_FS_INET 0

#ifdef wxUSE_SOUND
#undef wxUSE_SOUND
#endif

#define wxUSE_SOUND 0

#define wxLUA_USE_wxHelpController 0
#define wxLUA_USE_wxJoystick 0
#define wxLUA_USE_wxRegEx 0
#define wxLUA_USE_wxTranslations 0

/* Include base wxluasetup.h to initialise anything we haven't set. */
#include "../wxLua/modules/wxbind/setup/wxluasetup.h"

#endif /* !REHEX_WXLUA_SETUP_H */
