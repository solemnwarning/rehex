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
#include <inttypes.h>
#include <string>
#include <vector>
#include <wx/clipbrd.h>
#include <wx/filename.h>
#include <wx/utils.h>

#include "document.hpp"
#include "DocumentCtrl.hpp"
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

std::string REHex::format_offset(off_t offset, OffsetBase base, off_t upper_bound)
{
	char fmt_out[24];
	
	if(upper_bound > 0xFFFFFFFF || offset > 0xFFFFFFFF)
	{
		if(base == OFFSET_BASE_HEX)
		{
			snprintf(fmt_out, sizeof(fmt_out), "%08X:%08X",
				(unsigned int)((offset & 0xFFFFFFFF00000000) >> 32),
				(unsigned int)((offset & 0x00000000FFFFFFFF)));
		}
		else if(base == OFFSET_BASE_DEC)
		{
			snprintf(fmt_out, sizeof(fmt_out), "%019" PRId64, (int64_t)(offset));
		}
	}
	else{
		if(base == OFFSET_BASE_HEX)
		{
			snprintf(fmt_out, sizeof(fmt_out), "%04X:%04X",
				(unsigned int)((offset & 0xFFFF0000) >> 16),
				(unsigned int)((offset & 0x0000FFFF)));
		}
		else if(base == OFFSET_BASE_DEC)
		{
			snprintf(fmt_out, sizeof(fmt_out), "%010" PRId64, (int64_t)(offset));
		}
	}
	
	return fmt_out;
}

void REHex::copy_from_doc(REHex::Document *doc, REHex::DocumentCtrl *doc_ctrl, wxWindow *dialog_parent, bool cut)
{
	Document::CursorState cursor_state = doc_ctrl->get_cursor_state();
	
	off_t selection_off, selection_length;
	std::tie(selection_off, selection_length) = doc_ctrl->get_selection();
	
	if(selection_length <= 0)
	{
		/* Nothing selected - nothing to copy. */
		wxBell();
		return;
	}
	
	/* Warn the user this might be a bad idea before dumping silly amounts
	 * of data (>16MiB) into the clipboard.
	*/
	
	static size_t COPY_MAX_SOFT = 16777216;
	
	size_t upper_limit = cursor_state == Document::CSTATE_ASCII
		? selection_length
		: (selection_length * 2);
	
	if(upper_limit > COPY_MAX_SOFT)
	{
		char msg[128];
		snprintf(msg, sizeof(msg),
			"You are about to copy %uMB into the clipboard.\n"
			"This may take a long time and/or crash some applications.",
			(unsigned)(upper_limit / 1000000));
		
		int result = wxMessageBox(msg, "Warning", (wxOK | wxCANCEL | wxICON_EXCLAMATION), dialog_parent);
		if(result != wxOK)
		{
			return;
		}
	}
	
	wxTextDataObject *copy_data = NULL;
	try {
		std::vector<unsigned char> selection_data = doc->read_data(selection_off, selection_length);
		assert((off_t)(selection_data.size()) == selection_length);
		
		if(cursor_state == Document::CSTATE_ASCII)
		{
			std::string ascii_string;
			ascii_string.reserve(selection_data.size());
			
			for(auto c = selection_data.begin(); c != selection_data.end(); ++c)
			{
				if((*c >= ' ' && *c <= '~') || *c == '\t' || *c == '\n' || *c == '\r')
				{
					ascii_string.push_back(*c);
				}
			}
			
			if(!ascii_string.empty())
			{
				copy_data = new wxTextDataObject(ascii_string);
			}
		}
		else{
			std::string hex_string;
			hex_string.reserve(selection_data.size() * 2);
			
			for(auto c = selection_data.begin(); c != selection_data.end(); ++c)
			{
				const char *nibble_to_hex = "0123456789ABCDEF";
				
				unsigned char high_nibble = (*c & 0xF0) >> 4;
				unsigned char low_nibble  = (*c & 0x0F);
				
				hex_string.push_back(nibble_to_hex[high_nibble]);
				hex_string.push_back(nibble_to_hex[low_nibble]);
			}
			
			copy_data = new wxTextDataObject(hex_string);
		}
	}
	catch(const std::bad_alloc &)
	{
		wxMessageBox(
			"Memory allocation failed while preparing clipboard buffer.",
			"Error", (wxOK | wxICON_ERROR), dialog_parent);
		return;
	}
	catch(const std::exception &e)
	{
		wxMessageBox(e.what(), "Error", (wxOK | wxICON_ERROR), dialog_parent);
		return;
	}
	
	if(copy_data != NULL)
	{
		ClipboardGuard cg;
		if(cg)
		{
			wxTheClipboard->SetData(copy_data);
			
			if(cut)
			{
				doc->erase_data(selection_off, selection_length, -1, Document::CSTATE_CURRENT, "cut selection");
			}
		}
		else{
			delete copy_data;
		}
	}
}
