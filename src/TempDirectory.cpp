/* Reverse Engineer's Hex Editor
 * Copyright (C) 2026 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "platform.hpp"

#include <assert.h>
#include <errno.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <wx/filename.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "TempDirectory.hpp"
#include "win32lib.hpp"

REHex::TempDirectory::TempDirectory()
{
	#ifdef _WIN32
	DWORD size = GetTempPathA(0, NULL);
	if(size == 0)
	{
		DWORD err = GetLastError();
		throw std::runtime_error(std::string("Unable to get temporary directory: ") + GetLastError_strerror(err));
	}
	
	std::vector<char> buf(size);
	
	size = GetTempPathA(size, buf.data());
	if(size == 0)
	{
		DWORD err = GetLastError();
		throw std::runtime_error(std::string("Unable to get temporary directory: ") + GetLastError_strerror(err));
	}
	
	assert(size < buf.size());
	buf.resize(size);
	
	if(!(wxFileName::IsPathSeparator(buf.back())))
	{
		buf.push_back(wxFileName::GetPathSeparator());
	}
	
	std::string tmpdir = std::string(buf.data(), buf.size());
	DWORD n = GetTickCount();
	
	while(true)
	{
		char hex_ticks[9];
		snprintf(hex_ticks, sizeof(hex_ticks), "%08x", (unsigned)(n));
		
		m_path = tmpdir + "rehex." + hex_ticks + "\\";
		
		if(CreateDirectoryA(m_path.c_str(), NULL))
		{
			break;
		}
		else{
			DWORD err = GetLastError();
			
			if(err != ERROR_ALREADY_EXISTS)
			{
				throw std::runtime_error(std::string("Unable to create temporary directory: ") + GetLastError_strerror(err));
			}
		}
		
		++n;
	}
	
	#else
	std::vector<char> buf;
	
	const char *tmpdir = getenv("TMPDIR");
	if(tmpdir == NULL)
	{
		tmpdir = P_tmpdir;
	}
	
	buf.insert(buf.end(), tmpdir, (tmpdir + strlen(tmpdir)));
	
	if(!(wxFileName::IsPathSeparator(buf.back())))
	{
		buf.push_back(wxFileName::GetPathSeparator());
	}
	
	static const char TEMPLATE[] = "rehex.XXXXXX";
	buf.insert(buf.end(), TEMPLATE, (TEMPLATE + sizeof(TEMPLATE)));
	
	if(mkdtemp(buf.data()) == buf.data())
	{
		m_path = std::string(buf.data()) + "/";
	}
	else{
		throw std::runtime_error(std::string("Unable to create temporary directory: ") + strerror(errno));
	}
	
	#endif
}

REHex::TempDirectory::~TempDirectory()
{
	wxFileName::Rmdir(m_path, wxPATH_RMDIR_RECURSIVE);
}

std::string REHex::TempDirectory::path() const
{
	return m_path;
}
