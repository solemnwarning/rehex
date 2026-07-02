/* Reverse Engineer's Hex Editor
 * Copyright (C) 2025-2026 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_MACFILENAME_HPP
#define REHEX_MACFILENAME_HPP

#ifdef __APPLE__
#include <AvailabilityMacros.h>
#endif

#include <memory>
#include <wx/filename.h>

#if defined(MAC_OS_X_VERSION_10_7) && MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_X_VERSION_10_7
#define REHEX_MACFILENAME_ENABLE_SS_BOOKMARKS
#endif

namespace REHex
{
#ifdef __APPLE__
	/**
	 * @brief wxFileName look-alike with macOS security-scoped bookmark handling.
	 *
	 * This class holds a filename in an NSURL object and presents a wxFileName-like API for
	 * accessing it, and allows for creating/restoring "security scoped bookmarks" which are
	 * required for persisting filesystem access grants under the macOS application sandbox.
	 *
	 * Cross-platform code should use the FileName typedef, which will be MacFileName on macOS
	 * and wxFileName on other platforms.
	*/
	class MacFileName
	{
	private:
		/**
		 * @brief MacFileName implementation object.
		 *
		 * This class provides the actual implementation of MacFileName, the main class holds an
		 * instance of this in a shared_ptr to allow copying without having to create additional
		 * NSURL objects and use of C# symbols from the implementation file.
		*/
		class MacFileNameImpl;

		std::shared_ptr<MacFileNameImpl> m_impl; /**< Pointer to implementation object. */
		
	public:
		/**
		 * @brief Construct a MacFileName with no backing NSURL object.
		*/
		MacFileName() = default;
		
		/**
		 * @brief Construct an NSURL from an accessible filesystem path.
		*/
		MacFileName(const wxFileName &filename);
		
		#ifdef REHEX_MACFILENAME_ENABLE_SS_BOOKMARKS
		/**
		 * @brief Construct an instance from a security-scoped bookmark.
		 *
		 * This method creates an instance from a Base64-encoded security-scoped bookmark
		 * previously created by the CreateBookmark() method and makes the file available using
		 * normal filesystem APIs.
		 *
		 * The MacFileName object must not be destroyed until access to the file is no longer
		 * required.
		*/
		static MacFileName CreateFromBookmark(const wxString &bookmark);
		#else
		static MacFileName CreateFromBookmark(const wxString &bookmark) = delete; /* Not available before macOS 10.7 */
		#endif

		wxString GetFullName() const;

		wxString GetFullPath() const;
		
		#ifdef REHEX_MACFILENAME_ENABLE_SS_BOOKMARKS
		/**
		 * @brief Create a security-scoped bookmark.
		 *
		 * A security-scoped bookmark allows for accessing (temporarily) allowed files outside of
		 * the sandbox in the future by encoding a security token into the bookmark.
		*/
		wxString CreateBookmark() const;
		
		/**
		 * @brief Check if the MacFileName was created from a "stale" bookmark.
		 *
		 * Any stale bookmarks should be updated to a new one created using CreateBookmark() for
		 * future use.
		*/
		bool BookmarkWasStale() const;
		#else
		wxString CreateBookmark() const = delete; /* Not available before macOS 10.7 */
		bool BookmarkWasStale() const = delete; /* Not available before macOS 10.7 */
		#endif
	};
#endif /* __APPLE__ */
}

#endif /* !REHEX_MACFILENAME_HPP */
