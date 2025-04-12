/* Reverse Engineer's Hex Editor
 * Copyright (C) 2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_MACFILEHISTORY_HPP
#define REHEX_MACFILEHISTORY_HPP

#ifdef __APPLE__

#include <wx/arrstr.h>
#include <wx/filehistory.h>
#include <wx/string.h>

#include "MacFileName.hpp"

namespace REHex
{
	/**
	 * @brief Specialisation of wxFileHistory which stores NSURL bookmarks along with filenames.
	 *
	 * This specialisation saves an NSURL "bookmark" along with each filename, including a security
	 * context which allows re-opening an allowed file from outside the sandbox after the application
	 * has been restarted and the previous sandbox exemption lost.
	*/
	class MacFileHistory: public wxFileHistory
	{
	private:
		wxArrayString m_fileBookmarks;
		
	public:
		MacFileHistory(size_t maxFiles = 9, wxWindowID idBase = wxID_FILE1);
		
		void AddFileToHistory (const MacFileName &filename);
		
		/**
		 * @brief Get a file from the history, with security context from bookmark (if available).
		 *
		 * This method should be used over GetHistoryFile() on macOS to obtain a MacFileName object
		 * which will allow opening files from outside the sandbox from a previous session.
		 *
		 * The stored bookmark will automatically be refreshed if it is stale.
		*/
		MacFileName GetHistoryMacFile(size_t index);
		
		virtual void AddFileToHistory(const wxString &filename) override;
		virtual void RemoveFileFromHistory(size_t i) override;
		virtual void Save(wxConfigBase &config) override;
		virtual void Load(const wxConfigBase &config) override;
	};
}

#endif /* __APPLE__ */

#endif /* !REHEX_MACFILEHISTORY_HPP */
