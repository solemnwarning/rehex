/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <ctype.h>
#include <string>
#include <vector>
#include <wx/clipbrd.h>
#include <wx/filename.h>
#include <wx/utils.h>

#include "util.hpp"

/* These MUST come after any wxWidgets headers. */
#ifdef _WIN32
#include <shlobj.h>
#endif

REHex::ParseError::ParseError(const char *what):
	runtime_error(what) {}

std::vector<unsigned char> REHex::parse_hex_string(const std::string &hex_string)
{
	std::vector<unsigned char> data;
	
	for(size_t at = 0; at < hex_string.length();)
	{
		char this_char = hex_string.at(at++);
		
		if(isspace(this_char))
		{
			continue;
		}
		else if(isxdigit(this_char) && at < hex_string.length())
		{
			char next_char;
			do {
				next_char = hex_string.at(at++);
			} while(at < hex_string.length() && isspace(next_char));
			
			if(at <= hex_string.length() && isxdigit(next_char))
			{
				unsigned char low_nibble  = parse_ascii_nibble(next_char);
				unsigned char high_nibble = parse_ascii_nibble(this_char);
				
				data.push_back(low_nibble | (high_nibble << 4));
				
				continue;
			}
		}
		
		throw ParseError("Invalid hex string");
	}
	
	return data;
}

unsigned char REHex::parse_ascii_nibble(char c)
{
	switch(c)
	{
		case '0':           return 0x0;
		case '1':           return 0x1;
		case '2':           return 0x2;
		case '3':           return 0x3;
		case '4':           return 0x4;
		case '5':           return 0x5;
		case '6':           return 0x6;
		case '7':           return 0x7;
		case '8':           return 0x8;
		case '9':           return 0x9;
		case 'A': case 'a': return 0xA;
		case 'B': case 'b': return 0xB;
		case 'C': case 'c': return 0xC;
		case 'D': case 'd': return 0xD;
		case 'E': case 'e': return 0xE;
		case 'F': case 'f': return 0xF;
		
		default:
			throw ParseError("Invalid hex character");
	}
}

void REHex::file_manager_show_file(const std::string &filename)
{
	wxFileName wxfn(filename);
	wxfn.MakeAbsolute();
	
	#if defined(_WIN32)
		wxString abs_filename = wxfn.GetFullPath();
		
		PIDLIST_ABSOLUTE pidl;
		SFGAOF flags;
		
		if(SHParseDisplayName(abs_filename.wc_str(), NULL, &pidl, 0, &flags) == S_OK)
		{
			SHOpenFolderAndSelectItems(pidl, 0, NULL, 0);
			CoTaskMemFree(pidl);
		}
	#elif defined(__APPLE__)
		wxString abs_filename = wxfn.GetFullPath();
		
		const char *argv[] = { "open", "-R", abs_filename.c_str(), NULL };
		wxExecute((char**)(argv));
	#else
		wxString dirname = wxfn.GetPath();
		
		const char *argv[] = { "xdg-open", dirname.c_str(), NULL };
		wxExecute((char**)(argv));
	#endif
}

REHex::ClipboardGuard::ClipboardGuard()
{
	open = wxTheClipboard->Open();
}

REHex::ClipboardGuard::~ClipboardGuard()
{
	if(open)
	{
		wxTheClipboard->Close();
	}
}

void REHex::ClipboardGuard::close()
{
	if(open)
	{
		wxTheClipboard->Close();
		open = false;
	}
}
