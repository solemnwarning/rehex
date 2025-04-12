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

#include "App.hpp"
#include "MacFileName.hpp"
#include "MacFileHistory.hpp"

REHex::MacFileHistory::MacFileHistory(size_t maxFiles, wxWindowID idBase):
	wxFileHistory(maxFiles, idBase) {}

void REHex::MacFileHistory::AddFileToHistory(const MacFileName &filename)
{
	wxString bookmark;
	try {
		bookmark = filename.CreateBookmark();
	}
	catch(const std::exception &e)
	{
		wxGetApp().printf_error("Unable to create bookmark for %s (%s), not adding to recent files\n", filename.GetFileName().GetFullPath().ToStdString().c_str(), e.what());
		return;
	}
	
	wxFileHistory::AddFileToHistory(filename.GetFileName().GetFullPath());
	m_fileBookmarks.insert(m_fileBookmarks.begin(), bookmark);
}

void REHex::MacFileHistory::AddFileToHistory(const wxString &filename)
{
	AddFileToHistory(MacFileName(wxFileName(filename)));
}

void REHex::MacFileHistory::RemoveFileFromHistory(size_t i)
{
	wxFileHistory::RemoveFileFromHistory(i);
	m_fileBookmarks.RemoveAt(i);
}

REHex::MacFileName REHex::MacFileHistory::GetHistoryMacFile(size_t index)
{
	if(m_fileBookmarks[index] != wxEmptyString)
	{
		/* There is a saved bookmark (presumably with security token), try to restore it. */
		
		try {
			MacFileName macfn = MacFileName(m_fileBookmarks[index]);
			
			if(macfn.BookmarkWasStale())
			{
				try {
					m_fileBookmarks[index] = macfn.CreateBookmark();
				}
				catch(const std::exception &e)
				{
					wxGetApp().printf_error("Unable to create new bookmark for %s (%s), keeping stale one\n", m_fileHistory[index].ToStdString().c_str(), e.what());
				}
			}
			
			return macfn;
		}
		catch(const std::exception &e)
		{
			wxGetApp().printf_error("Unable to restore bookmark from recent files for %s (%s), falling back to filename\n", m_fileHistory[index].ToStdString().c_str(), e.what());
		}
	}
	
	return MacFileName(wxFileName(m_fileHistory[index]));
}

void REHex::MacFileHistory::Save(wxConfigBase &config)
{
	wxFileHistory::Save(config);
	
	for (size_t i = 0; i < m_fileMaxFiles; i++)
	{
		wxString buf;
		buf.Printf(wxT("bookmark%d"), (int)(i + 1));
		
		if (i < m_fileBookmarks.GetCount())
		{
			config.Write(buf, wxString(m_fileBookmarks[i]));
		}
		else {
			config.Write(buf, wxEmptyString);
		}
	}
}

void REHex::MacFileHistory::Load(const wxConfigBase &config)
{
	m_fileBookmarks.Clear();
	
	wxFileHistory::Load(config);
	
	/* We use the same iteration over the "fileN" config keys as wxFileHistory to ensure the fileN
	 * and bookmarkN elements are kept together.
	*/
	
	wxString buf;
	buf.Printf(wxT("file%d"), 1);
	
	wxString historyFile;
	while ((m_fileBookmarks.GetCount() < m_fileMaxFiles) &&
		config.Read(buf, &historyFile) && !historyFile.empty())
	{
		buf.Printf(wxT("bookmark%d"), (int)(m_fileBookmarks.GetCount() + 1));
		
		if(config.Read(buf, &historyFile))
		{
			m_fileBookmarks.Add(historyFile);
		}
		else{
			m_fileBookmarks.Add(wxEmptyString);
		}
		
		buf.Printf(wxT("file%d"), (int)(m_fileBookmarks.GetCount() + 1));
		historyFile.clear();
	}
	
}
