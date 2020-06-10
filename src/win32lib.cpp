/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifdef _WIN32

#include "platform.hpp"
#include <windows.h>
#include <string>

std::string GetLastError_strerror(DWORD errnum)
{
	char buf[1024];
	
	if(!FormatMessageA(
		FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		errnum,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		buf,
		sizeof(buf),
		NULL))
	{
		return "INTERNAL ERROR: Could not resolve error message";
	}
	
	/* Microsoft like to end some of their errors with newlines... */
	
	char *nl = strrchr(buf, '\n');
	char *cr = strrchr(buf, '\r');
	
	if(nl != NULL && nl[1] == '\0') { *nl = '\0'; }
	if(cr != NULL && cr[1] == '\0') { *cr = '\0'; }
	
	return buf;
}

#endif /* !_WIN32 */
