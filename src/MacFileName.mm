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

#import <Foundation/Foundation.h>

#include "MacFileName.hpp"

REHex::MacFileName::MacFileName():
	m_url(nil) {}

REHex::MacFileName::MacFileName(const wxFileName &filename):
	m_ssr(false),
	m_stale(false)
{
	NSURL *url = [NSURL fileURLWithPath:[NSString stringWithCString:filename.GetFullPath().ToStdString().c_str() encoding:[NSString defaultCStringEncoding]]];
	[url retain];
	
	m_url = url;
}

REHex::MacFileName::MacFileName(const wxString &bookmark):
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
	NSURL *url = [NSURL URLByResolvingBookmarkData: actual_data
		options: NSURLBookmarkResolutionWithSecurityScope
		relativeToURL: nil
		bookmarkDataIsStale: &is_stale
		error: &error];
	
	[data release];
	
	if(url == nil)
	{
		throw std::runtime_error("Unable to restore saved bookmark");
	}
	
	m_stale = !!is_stale;
	
	if(![url startAccessingSecurityScopedResource])
	{
		throw std::runtime_error("Unable to access file");
	}
	
	[url retain];
	m_url  = url;
}

REHex::MacFileName::~MacFileName()
{
	NSURL *url = (NSURL*)(m_url);
	
	if(url != nil)
	{
		if(m_ssr)
		{
			[url stopAccessingSecurityScopedResource];
			m_ssr = false;
		}
		
		[url release];
	}
}

REHex::MacFileName::MacFileName(MacFileName &&mfn)
{
	m_url = mfn.m_url;
	m_ssr = mfn.m_ssr;
	m_stale = mfn.m_stale;
	
	mfn.m_url = NULL;
}

REHex::MacFileName &REHex::MacFileName::operator=(MacFileName &&mfn)
{
	m_url = mfn.m_url;
	m_ssr = mfn.m_ssr;
	m_stale = mfn.m_stale;
	
	mfn.m_url = NULL;
	
	return *this;
}

wxFileName REHex::MacFileName::GetFileName() const
{
	NSURL *url = (NSURL*)(m_url);
	return wxFileName(wxString([[url path] cStringUsingEncoding:[NSString defaultCStringEncoding]]));
}

wxString REHex::MacFileName::CreateBookmark() const
{
	NSURL *url = (NSURL*)(m_url);
	
	NSError *error;
	NSData *bookmark = [url bookmarkDataWithOptions:NSURLBookmarkCreationWithSecurityScope
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
	return m_stale;
}
