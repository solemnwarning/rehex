/* Reverse Engineer's Hex Editor
 * Copyright (C) 2019-2022 Daniel Collins <solemnwarning@solemnwarning.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "version.h"
#ifdef _MSC_VER
#include "version_msvc.h"
#endif

extern "C" {
	const char *REHEX_VERSION = LONG_VERSION;
	const char *REHEX_SHORT_VERSION = SHORT_VERSION;
	const char *REHEX_BUILD_DATE = __DATE__;
	
	#if !defined(_WIN32) && !defined(__APPLE__)
	const char *REHEX_LIBDIR = LIBDIR;
	const char *REHEX_DATADIR = DATADIR;
	#endif
}
