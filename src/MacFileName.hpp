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

#include <wx/filename.h>

namespace REHex
{
#ifdef __APPLE__
	/**
	 * @brief Wrapper for NSURL and security-scoped bookmarks.
	*/
	class MacFileName
	{
	private:
		void *m_url;   /**< Pointer to NSURL object. */
		bool m_ssr;    /**< Was this created from a security-scoped bookmark? */
		bool m_stale;  /**< Was this created from a stale bookmark? */
		
	public:
		/**
		 * @brief Construct a MacFileName with no backing NSURL object.
		*/
		MacFileName();
		
		/**
		 * @brief Construct an NSURL from an accessible filesystem path.
		*/
		MacFileName(const wxFileName &filename);
		
		#if defined(MAC_OS_X_VERSION_10_7) && MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_X_VERSION_10_7
		/**
		 * @brief Construct an NSURL from a security-scoped bookmark.
		 *
		 * This method creates an NSURL from a Base64-encoded security-scoped bookmark previously
		 * created by the CreateBookmark() method and makes the file available.
		 *
		 * The MacFileName object must not be destroyed until access to the file is no longer
		 * required.
		*/
		MacFileName(const wxString &bookmark);
		#else
		MacFileName(const wxString &bookmark) = delete; /* Not available before macOS 10.7 */
		#endif
		
		~MacFileName();
		
		MacFileName(const MacFileName&) = delete;
		MacFileName &operator=(const MacFileName&) = delete;
		
		MacFileName(MacFileName&&);
		MacFileName &operator=(MacFileName&&);
		
		/**
		 * @brief Get the resolved filesystem path for accessing the file.
		*/
		wxFileName GetFileName() const;
		
		#if defined(MAC_OS_X_VERSION_10_7) && MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_X_VERSION_10_7
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
