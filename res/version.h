/* Reverse Engineer's Hex Editor
 * Copyright (C) 2019-2021 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_VERSION_H
#define REHEX_VERSION_H

#ifdef __cplusplus
extern "C" {
#endif

extern const char *REHEX_VERSION;
extern const char *REHEX_BUILD_DATE;

#if !defined(_WIN32) && !defined(__APPLE__)
extern const char *REHEX_LIBDIR;
extern const char *REHEX_DATADIR;
#endif

#ifdef __cplusplus
}
#endif

#endif /* !REHEX_VERSION_H */
