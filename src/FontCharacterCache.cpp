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

#include "platform.hpp"

#include <algorithm>
#include <unistr.h>
#include <wx/dcmemory.h>
#include <wx/settings.h>

#include "FontCharacterCache.hpp"
#include "profile.hpp"

static unsigned int pack_colour(const wxColour &colour)
{
	return (unsigned int)(colour.Red()) | ((unsigned int)(colour.Blue()) << 8) | ((unsigned int)(colour.Green()) << 16);
}

static wxString wxString_FromUnicodeChar(ucs4_t c)
{
	char c_utf8[6];
	int c_utf8_len = u8_uctomb((uint8_t*)(c_utf8), c, sizeof(c_utf8));
	assert(c_utf8_len > 0);
	
	return wxString::FromUTF8Unchecked(c_utf8, c_utf8_len);
}

REHex::FontCharacterCache::FontCharacterCache():
	m_font(wxSystemSettings::GetFont(wxSYS_OEM_FIXED_FONT)),
	m_char_size_cache(CHAR_SIZE_CACHE_SIZE)
	
	#ifdef REHEX_CACHE_CHARACTER_BITMAPS
	, m_char_bitmap_cache(CHAR_BITMAP_CACHE_SIZE)
	#endif
	
	#ifdef REHEX_CACHE_STRING_BITMAPS
	, m_string_bitmap_cache(STRING_BITMAP_CACHE_SIZE)
	#endif
{
	reset();
}

REHex::FontCharacterCache::FontCharacterCache(const wxFont &font):
	m_font(font),
	m_char_size_cache(CHAR_SIZE_CACHE_SIZE)
	
	#ifdef REHEX_CACHE_CHARACTER_BITMAPS
	, m_char_bitmap_cache(CHAR_BITMAP_CACHE_SIZE)
	#endif
	
	#ifdef REHEX_CACHE_STRING_BITMAPS
	, m_string_bitmap_cache(STRING_BITMAP_CACHE_SIZE)
	#endif
{
	reset();
}

void REHex::FontCharacterCache::set_font(const wxFont &font)
{
	m_font = font;
	reset();
}

wxFont REHex::FontCharacterCache::get_font() const
{
	return m_font;
}

void REHex::FontCharacterCache::reset()
{
	wxBitmap tmp_bitmap(16, 16, wxBITMAP_SCREEN_DEPTH);
	wxMemoryDC dc(tmp_bitmap);
	
	dc.SetFont(m_font);
	
	m_char_height = dc.GetTextExtent("X").GetHeight();
	
	for(int i = 0; i < PRECOMP_STRING_WIDTH_TO; ++i)
	{
		m_string_width_precomp[i] = dc.GetTextExtent(std::string((i + 1), 'X')).GetWidth();
	}
	
	m_char_size_cache.clear();
	
	#ifdef REHEX_CACHE_CHARACTER_BITMAPS
	m_char_bitmap_cache.clear();
	#endif
	
	#ifdef REHEX_CACHE_STRING_BITMAPS
	m_string_bitmap_cache.clear();
	#endif
}

wxSize REHex::FontCharacterCache::fixed_char_size() const
{
	return wxSize(m_string_width_precomp[0], m_char_height);
}

int REHex::FontCharacterCache::fixed_char_width() const
{
	return m_string_width_precomp[0];
}

int REHex::FontCharacterCache::fixed_char_height() const
{
	return m_char_height;
}

int REHex::FontCharacterCache::fixed_string_width(int length) const
{
	if(length == 0)
	{
		return 0;
	}
	
	int string_width = 0;
	
	if(length > PRECOMP_STRING_WIDTH_TO)
	{
		/* If the requested length is longer than PRECOMP_STRING_WIDTH_TO, we scale it
		 * proportional to the available sizes, this will introduce worse rounding errors
		 * for every multiple of PRECOMP_STRING_WIDTH_TO in length, so this case should
		 * ideally not be hit in real-world use, and if it is, PRECOMP_STRING_WIDTH_TO
		 * should probably be increased.
		*/
		
		int div = (length - 1) / PRECOMP_STRING_WIDTH_TO;
		
		string_width += div * m_string_width_precomp[PRECOMP_STRING_WIDTH_TO - 1];
		length -= div * PRECOMP_STRING_WIDTH_TO;
	}
	
	string_width += m_string_width_precomp[length - 1];
	
	return string_width;
}

int REHex::FontCharacterCache::fixed_char_at_x(int x) const
{
	if(m_string_width_precomp[PRECOMP_STRING_WIDTH_TO - 1] > (unsigned int)(x))
	{
		auto it = std::upper_bound(
			m_string_width_precomp,
			m_string_width_precomp + PRECOMP_STRING_WIDTH_TO,
			(unsigned int)(x));
		
		return std::distance(m_string_width_precomp, it);
	}
	else{
		for(int i = PRECOMP_STRING_WIDTH_TO;; ++i)
		{
			int w = fixed_string_width(i + 1);
			if(w > x)
			{
				return i;
			}
		}
	}
}

wxSize REHex::FontCharacterCache::char_size(ucs4_t c) const
{
	const wxSize* s = m_char_size_cache.get(c);
	if (s != NULL)
	{
		return *s;
	}
	else {
		wxBitmap tmp_bitmap(16, 16, wxBITMAP_SCREEN_DEPTH);
		wxMemoryDC dc(tmp_bitmap);
		
		dc.SetFont(m_font);
		
		wxSize size = dc.GetTextExtent(wxString_FromUnicodeChar(c));
		m_char_size_cache.set(c, size);
		
		return size;
	}
}

int REHex::FontCharacterCache::char_width(ucs4_t c) const
{
	return char_size(c).GetWidth();
}

int REHex::FontCharacterCache::char_height(ucs4_t c) const
{
	return char_size(c).GetHeight();
}

#ifdef REHEX_CACHE_CHARACTER_BITMAPS
wxBitmap REHex::FontCharacterCache::char_bitmap(ucs4_t unicode_char, const wxColour &fg_colour, const wxColour &bg_colour) const
{
	return char_bitmap(unicode_char, char_size(unicode_char), fg_colour, bg_colour);
}

wxBitmap REHex::FontCharacterCache::char_bitmap(ucs4_t unicode_char, const wxSize &char_size, const wxColour &fg_colour, const wxColour &bg_colour) const
{
	PROFILE_BLOCK("REHex::FontCharacterCache::get_char_bitmap()");
	
	auto cache_key = std::make_tuple(unicode_char, pack_colour(fg_colour), pack_colour(bg_colour));
	
	const wxBitmap *cached_bitmap;
	{
		PROFILE_INNER_BLOCK("cache lookup");
		cached_bitmap = m_char_bitmap_cache.get(cache_key);
	}
	
	if(cached_bitmap == NULL)
	{
		PROFILE_INNER_BLOCK("generate char bitmap");
		
		/* I (briefly) tried getting this working with 1bpp bitmaps, but couldn't get the
		 * background behaving correctly then found this tidbit on the web:
		 *
		 * > Support for monochrome bitmaps is very limited in wxWidgets. And
		 * > wxNativePixelData is designed for 24bit RGB data, so i doubt it will give the
		 * > expected results for monochrome bitmaps.
		 * >
		 * > Even if it's a waste of memory, i would suggest to work with 24bit RGB bitmaps
		 * > and only at the very end convert it to a 1bit bitmap.
		 * - https://forums.wxwidgets.org/viewtopic.php?p=185332#p185332
		*/
		
		wxBitmap char_bitmap(char_size, wxBITMAP_SCREEN_DEPTH);
		wxMemoryDC mdc(char_bitmap);
		
		mdc.SetFont(m_font);
		
		mdc.SetBackground(wxBrush(bg_colour));
		mdc.Clear();
		
		mdc.SetTextForeground(fg_colour);
		mdc.SetBackgroundMode(wxTRANSPARENT);
		mdc.DrawText(wxString_FromUnicodeChar(unicode_char), 0, 0);
		
		mdc.SelectObject(wxNullBitmap);
		
		cached_bitmap = m_char_bitmap_cache.set(cache_key, char_bitmap);
	}
	
	/* wxBitmap internally does refcounting and CoW, returning a thin wxBitmap copy rather than a
	 * pointer into the cache stops the caller from having to worry about the returned wxColour
	 * being invalidated in the future.
	*/
	return *cached_bitmap;
}
#endif

#ifdef REHEX_CACHE_STRING_BITMAPS
wxBitmap REHex::FontCharacterCache::string_bitmap(int base_column, const std::vector<ucs4_t> &characters, const wxColour &fg_colour, const wxColour &bg_colour) const
{
	PROFILE_BLOCK("REHex::FontCharacterCache::get_string_bitmap()");
	
	assert(!(characters.empty()));
	
	#ifdef REHEX_ASSUME_INTEGER_CHARACTER_WIDTHS
	base_column = 0;
	#endif
	
	StringBitmapCacheKey cache_key(base_column, characters, pack_colour(fg_colour), pack_colour(bg_colour));
	
	const wxBitmap *cached_string;
	{
		PROFILE_INNER_BLOCK("cache lookup");
		cached_string = m_string_bitmap_cache.get(cache_key);
	}
	
	if(cached_string == NULL)
	{
		PROFILE_INNER_BLOCK("generate string bitmap");
		
		std::vector<wxBitmap> char_bitmaps;
		char_bitmaps.reserve(characters.size());
		
		int base_x = fixed_string_width(base_column);
		
		int string_w = 0;
		int string_h = 0;
		
		for(auto c = characters.begin(); c != characters.end(); ++c)
		{
			PROFILE_INNER_BLOCK("get char bitmap");
			
			if(*c == '\0')
			{
				char_bitmaps.emplace_back(wxNullBitmap);
			}
			else{
				char_bitmaps.emplace_back(char_bitmap(*c, fg_colour, bg_colour));
				
				string_w = fixed_string_width(base_column + c - characters.begin()) + char_bitmaps.back().GetWidth();
				
				if(char_bitmaps.back().GetHeight() > string_h)
				{
					string_h = char_bitmaps.back().GetHeight();
				}
			}
		}
		
		string_w -= base_x;
		
		wxBitmap string_bitmap(string_w, string_h, wxBITMAP_SCREEN_DEPTH);
		wxMemoryDC mdc(string_bitmap);
		
		mdc.SetBackground(wxBrush(bg_colour));
		mdc.Clear();
		
		for(size_t i = 0; i < char_bitmaps.size(); ++i)
		{
			PROFILE_INNER_BLOCK("draw char bitmap");
			
			if(char_bitmaps[i].IsOk())
			{
				mdc.DrawBitmap(char_bitmaps[i], (fixed_string_width(base_column + i) - base_x), 0, true);
			}
		}
		
		mdc.SelectObject(wxNullBitmap);
		
		/* In addition to not working on macOS, creating a mask is expensive. */
		#ifndef REHEX_BROKEN_BITMAP_TRANSPARENCY
		string_bitmap.SetMask(new wxMask(string_bitmap, bg_colour));
		#endif
		
		cached_string = m_string_bitmap_cache.set(cache_key, string_bitmap);
	}
	
	return *cached_string;
}

REHex::FontCharacterCache::StringBitmapCacheKey::StringBitmapCacheKey(
	int base_column, const std::vector<ucs4_t> &characters, unsigned int packed_fg_colour, unsigned int packed_bg_colour):
	#ifndef REHEX_ASSUME_INTEGER_CHARACTER_WIDTHS
	base_column(base_column),
	#endif
	characters(characters),
	packed_fg_colour(packed_fg_colour),
	packed_bg_colour(packed_bg_colour) {}

bool REHex::FontCharacterCache::StringBitmapCacheKey::operator<(const StringBitmapCacheKey &rhs) const
{
	#ifndef REHEX_ASSUME_INTEGER_CHARACTER_WIDTHS
	if(base_column != rhs.base_column)
	{
		return base_column < rhs.base_column;
	}
	else
	#endif
	
	if(characters != rhs.characters)
	{
		return characters < rhs.characters;
	}
	else if(packed_fg_colour != rhs.packed_fg_colour)
	{
		return packed_fg_colour < rhs.packed_fg_colour;
	}
	else{
		return packed_bg_colour < rhs.packed_bg_colour;
	}
}
#endif
