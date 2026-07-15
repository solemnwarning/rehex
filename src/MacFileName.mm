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

#include <AvailabilityMacros.h>
#import <Foundation/Foundation.h>

#include "MacFileName.hpp"

class REHex::MacFileName::MacFileNameImpl
{
	private:
		NSURL* m_url;  /**< Pointer to NSURL object. */

		/* TODO: Store a wxFileName too and use it for filename operations.
		 *
		 * NSURL helpfully chops off leading ../ portions in some contexts which leads to this
		 * class behaving differently from wxFileName when relative paths are in use.
		*/

#ifdef REHEX_MACFILENAME_ENABLE_SS_BOOKMARKS
		bool m_ssr;    /**< Was this created from a security-scoped bookmark? */
		bool m_stale;  /**< Was this created from a stale bookmark? */
#endif

	public:
		MacFileNameImpl(const wxFileName &filename);

#ifdef REHEX_MACFILENAME_ENABLE_SS_BOOKMARKS
		class BookmarkTag {};
		MacFileNameImpl(const wxString &bookmark, const BookmarkTag&);
#endif

		MacFileNameImpl(const MacFileNameImpl&) = delete;
		MacFileNameImpl &operator=(const MacFileNameImpl&) = delete;

		MacFileNameImpl(MacFileNameImpl&&) = delete;
		MacFileNameImpl &operator=(MacFileNameImpl&&) = delete;

		~MacFileNameImpl();

		wxFileName GetFileName() const;
		
#ifdef REHEX_MACFILENAME_ENABLE_SS_BOOKMARKS
		wxString CreateBookmark() const;
		bool BookmarkWasStale() const;
#endif
};

REHex::MacFileName::MacFileName(const wxFileName &filename):
	m_impl(std::make_shared<MacFileNameImpl>(filename)) {}

REHex::MacFileName::MacFileNameImpl::MacFileNameImpl(const wxFileName &filename)
{
	m_url = [NSURL fileURLWithPath:[NSString stringWithCString:filename.GetFullPath().ToStdString().c_str() encoding:[NSString defaultCStringEncoding]]];
	[m_url retain];

#ifdef REHEX_MACFILENAME_ENABLE_SS_BOOKMARKS
	m_ssr = false;
	m_stale = false;
#endif
}

#ifdef REHEX_MACFILENAME_ENABLE_SS_BOOKMARKS
REHex::MacFileName REHex::MacFileName::CreateFromBookmark(const wxString &bookmark)
{
	MacFileName self;
	self.m_impl = std::make_shared<MacFileNameImpl>(bookmark, MacFileNameImpl::BookmarkTag());

	return self;
}

REHex::MacFileName::MacFileNameImpl::MacFileNameImpl(const wxString &bookmark, const BookmarkTag&):
	m_ssr(true)
{
	/* We need to construct an NSData object to call the initWithBase64EncodedString() method to
	 * construct the actual NSData which has the decoded data from bookmark. Nice API, Apple.
	*/
	NSData *data = [NSData alloc];
	NSData *actual_data = [data initWithBase64EncodedString:[NSString stringWithCString:bookmark.ToStdString().c_str() encoding:[NSString defaultCStringEncoding]] options:0];
	if(actual_data == nil)
	{
		[data release];
		throw std::runtime_error("Invalid Base64-encoded bookmark string");
	}
	
	BOOL is_stale;
	NSError *error;
	m_url = [NSURL URLByResolvingBookmarkData: actual_data
		options: NSURLBookmarkResolutionWithSecurityScope
		relativeToURL: nil
		bookmarkDataIsStale: &is_stale
		error: &error];
	
	[data release];
	
	if(m_url == nil)
	{
		throw std::runtime_error("Unable to restore saved bookmark");
	}
	
	m_stale = !!is_stale;
	
	if(![m_url startAccessingSecurityScopedResource])
	{
		throw std::runtime_error("Unable to access file");
	}
	
	[m_url retain];
}
#endif

bool REHex::MacFileName::IsOk() const
{
	if(m_impl)
	{
		return m_impl->GetFileName().IsOk();
	}
	else{
		return false;
	}
}

bool REHex::MacFileName::IsRelative() const
{
	if(m_impl)
	{
		return m_impl->GetFileName().IsRelative();
	}
	else{
		return false;
	}
}

wxString REHex::MacFileName::GetFullName() const
{
	if(m_impl)
	{
		return m_impl->GetFileName().GetFullName();
	}
	else{
		return wxFileName().GetFullName();
	}
}

wxString REHex::MacFileName::GetFullPath() const
{
	if(m_impl)
	{
		return m_impl->GetFileName().GetFullPath();
	}
	else{
		return wxFileName().GetFullPath();
	}
}

wxString REHex::MacFileName::GetPathWithSep() const
{
	if(m_impl)
	{
		return m_impl->GetFileName().GetPathWithSep();
	}
	else{
		return wxFileName().GetPathWithSep();
	}
}

wxFileName REHex::MacFileName::MacFileNameImpl::GetFileName() const
{
	return wxFileName(wxString([[m_url path] cStringUsingEncoding:[NSString defaultCStringEncoding]]));
}

#if defined(MAC_OS_X_VERSION_10_7) && MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_X_VERSION_10_7
wxString REHex::MacFileName::CreateBookmark() const
{
	if(m_impl)
	{
		return m_impl->CreateBookmark();
	}
	else{
		throw std::logic_error("REHex::MacFileName::CreateBookmark() called on default-constructed object");
	}
}

wxString REHex::MacFileName::MacFileNameImpl::CreateBookmark() const
{
	NSError *error;
	NSData *bookmark = [m_url bookmarkDataWithOptions:NSURLBookmarkCreationWithSecurityScope
		includingResourceValuesForKeys:nil
		relativeToURL:nil
		error:&error];
	
	if(bookmark != nil)
	{
		NSString *base64 = [bookmark base64EncodedStringWithOptions:0];
		return [base64 cStringUsingEncoding:[NSString defaultCStringEncoding]];
	}
	else{
		return wxEmptyString;
	}
}

bool REHex::MacFileName::BookmarkWasStale() const
{
	if(m_impl)
	{
		return m_impl->BookmarkWasStale();
	}
	else{
		throw std::logic_error("REHex::MacFileName::BookmarkWasStale() called on default-constructed object");
	}
}

bool REHex::MacFileName::MacFileNameImpl::BookmarkWasStale() const
{
	return m_stale;
}
#endif

REHex::MacFileName::MacFileNameImpl::~MacFileNameImpl()
{
#ifdef REHEX_MACFILENAME_ENABLE_SS_BOOKMARKS
	if(m_ssr)
	{
		[m_url stopAccessingSecurityScopedResource];
		m_ssr = false;
	}
#endif
	
	[m_url release];
}
