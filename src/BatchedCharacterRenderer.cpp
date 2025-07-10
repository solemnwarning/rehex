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

#include <unistr.h>
#include <wx/dcmemory.h>
#include <wx/settings.h>

#include "BatchedCharacterRenderer.hpp"
#include "profile.hpp"

REHex::BatchedCharacterRenderer::BatchedCharacterRenderer(wxDC &dc, const FontCharacterCache &cache, int base_x, int base_y):
	m_dc(dc),
	m_cache(cache),
	m_base_x(base_x),
	m_base_y(base_y)
	
	#if !(defined(REHEX_FORCE_SLOW_PATH)) || (defined(REHEX_CACHE_CHARACTER_BITMAPS) && defined(REHEX_CACHE_STRING_BITMAPS) && !(defined(REHEX_BROKEN_BITMAP_TRANSPARENCY)))
	, m_bgfill(dc)
	#endif
{}

wxRect REHex::BatchedCharacterRenderer::draw_char_fast(int column, ucs4_t codepoint, const wxSize &char_size, const wxColour &fg_colour, const wxColour &bg_colour)
{
	PROFILE_BLOCK("REHex::BatchedCharacterRenderer::draw_char_fast()");
	
	#ifdef REHEX_FORCE_SLOW_TEXT_PATH
	
	return draw_char_slow(column, codepoint, char_size, fg_colour, bg_colour);
	
	#else
	
	#ifdef __APPLE__
	m_deferred_drawtext_slow_last_key = NULL;
	#endif
	
	DeferredDrawTextFastValue &v = m_deferred_drawtext_fast[fg_colour];
	
	if(v.string.length()  < (size_t)(column + 1))
	{
		/* Add padding to skip to requested column. */
		v.string.append(((column + 1) - v.string.length()), ' ');
	}
	
	v.string[column] = codepoint;
	
	wxRect bbox(
		wxPoint((m_base_x + m_cache.fixed_string_width(column)), m_base_y),
		m_cache.fixed_char_size());
	
	/* Because we need to minimise wxDC::DrawText() calls, we draw any background colours
	 * ourselves and set the background mode to transparent when drawing text, which enables
	 * us to skip over characters that shouldn't be touched by that particular wxDC::DrawText()
	 * call by inserting spaces.
	*/
	
	m_bgfill.fill_rectangle(bbox, bg_colour);
	
	return bbox;
	
	#endif
}

wxRect REHex::BatchedCharacterRenderer::draw_char_slow(int column, ucs4_t codepoint, const wxSize &char_size, const wxColour &fg_colour, const wxColour &bg_colour)
{
	PROFILE_BLOCK("REHex::BatchedCharacterRenderer::draw_char_slow()");
	
	#if defined(REHEX_CACHE_CHARACTER_BITMAPS) && defined(REHEX_CACHE_STRING_BITMAPS) && defined(REHEX_BROKEN_BITMAP_TRANSPARENCY)
	/* Okay... wxBitmap masks/transparency don't work on macOS, so if we draw multiple
	 * contiguous lines interleaved, relying on spaces in the string not being drawn
	 * what we instead get is the background colour of the most recently drawn line
	 * overwriting any behind it.
	 *
	 * So, on macOS we instead break up deferred_drawtext_slow into chunks of
	 * contiguous characters, starting a new chunk after changing bg/fg colour or
	 * drawing characters using the fast path.
	 *
	 * Wheeee.
	*/
	
	DeferredDrawTextSlowKey k(0, fg_colour, bg_colour);
	
	if(m_deferred_drawtext_slow_last_key != NULL
		&& m_deferred_drawtext_slow_last_key->fg_colour == fg_colour
		&& m_deferred_drawtext_slow_last_key->bg_colour == bg_colour)
	{
		k.base_column = m_deferred_drawtext_slow_last_key->base_column;
	}
	else{
		k.base_column = column;
	}
	
	bool inserted;
	UnsortedMapVector<DeferredDrawTextSlowKey, DeferredDrawTextSlowValue>::iterator ki;
	std::tie(ki, inserted) = m_deferred_drawtext_slow.insert(std::make_pair(k, DeferredDrawTextSlowValue()));
	
	m_deferred_drawtext_slow_last_key = &(ki->first);
	DeferredDrawTextSlowValue &v = ki->second;
	
	size_t chars_idx = column - k.base_column;
	#else
	DeferredDrawTextSlowValue &v = m_deferred_drawtext_slow[ DeferredDrawTextSlowKey(fg_colour, bg_colour) ];
	size_t chars_idx = column;
	#endif
	
	if(v.chars.size() < (chars_idx + 1))
	{
		#if defined(REHEX_CACHE_CHARACTER_BITMAPS) && defined(REHEX_CACHE_STRING_BITMAPS)
		v.chars.resize((chars_idx + 1), '\0');
		
		#elif defined(REHEX_CACHE_CHARACTER_BITMAPS)
		v.chars.resize((chars_idx + 1), std::make_pair('\0', wxDefaultSize));
		
		#else
		v.chars.resize((chars_idx + 1), wxEmptyString);
		
		#endif
	}
	
	#if defined(REHEX_CACHE_CHARACTER_BITMAPS) && defined(REHEX_CACHE_STRING_BITMAPS)
	v.chars[chars_idx] = codepoint;
	
	#elif defined(REHEX_CACHE_CHARACTER_BITMAPS)
	v.chars[chars_idx].first = codepoint;
	v.chars[chars_idx].second = char_size;
	
	#else
	v.chars[chars_idx] = wx_char;
	
	#endif

	wxRect bbox(
		wxPoint((m_base_x + m_cache.fixed_string_width(column)), m_base_y),
		char_size);
	
	#if defined(REHEX_CACHE_CHARACTER_BITMAPS) && defined(REHEX_CACHE_STRING_BITMAPS) && !(defined(REHEX_BROKEN_BITMAP_TRANSPARENCY))
	/* On platforms with working wxBitmap masking/transparency, our generated string bitmaps have a
	 * transparent background to allow for layering them over each other with spaces, so we must
	 * fill the background ourselves.
	*/
	m_bgfill.fill_rectangle(bbox, bg_colour);
	#endif

	return bbox;
}

wxRect REHex::BatchedCharacterRenderer::draw_char(int column, ucs4_t codepoint, const wxColour &fg_colour, const wxColour &bg_colour)
{
	/* Assume any printable ASCII characters are fixed-width in a fixed-width font and that
	 * any others aren't, we can't trust the font not to lie about the size of some characters
	 * and I haven't come up with a better heuristic for this.
	*/
	if(codepoint >= 0x20 && codepoint <= 0x7E)
	{
		return draw_char(column, codepoint, m_cache.fixed_char_size(), fg_colour, bg_colour);
	}
	else{
		return draw_char(column, codepoint, m_cache.char_size(codepoint), fg_colour, bg_colour);
	}
}

wxRect REHex::BatchedCharacterRenderer::draw_char(int column, ucs4_t codepoint, const wxSize &char_size, const wxColour &fg_colour, const wxColour &bg_colour)
{
	/* Assume any printable ASCII characters are fixed-width in a fixed-width font and that
	 * any others aren't, we can't trust the font not to lie about the size of some characters
	 * and I haven't come up with a better heuristic for this.
	*/
	if(codepoint >= 0x20 && codepoint <= 0x7E)
	{
		return draw_char_fast(column, codepoint, char_size, fg_colour, bg_colour);
	}
	else{
		return draw_char_slow(column, codepoint, char_size, fg_colour, bg_colour);
	}
}

void REHex::BatchedCharacterRenderer::flush()
{
	PROFILE_BLOCK("REHex::BatchedCharacterRenderer::flush()");
	
	#if !(defined(REHEX_FORCE_SLOW_PATH)) || (defined(REHEX_CACHE_CHARACTER_BITMAPS) && defined(REHEX_CACHE_STRING_BITMAPS) && !(defined(REHEX_BROKEN_BITMAP_TRANSPARENCY)))
	/* Paint background colours for any characters on the fast path (or cached strings with working transparency). */
	m_bgfill.flush();
	#endif

	#ifndef REHEX_FORCE_SLOW_TEXT_PATH
	
	/* Fast text rendering path - render fixed-width characters using a single wxDC.DrawText()
	 * call per foreground colour, leaving gaps for characters drawn in other passes using
	 * space characters.
	*/
	
	m_dc.SetFont(m_cache.get_font());
	
	for(auto dd = m_deferred_drawtext_fast.begin(); dd != m_deferred_drawtext_fast.end(); ++dd)
	{
		PROFILE_INNER_BLOCK("drawing text (fast path)");
		
		const wxColour &fg_colour = dd->first;
		
		m_dc.SetTextForeground(fg_colour);
		m_dc.SetBackgroundMode(wxTRANSPARENT);
		
		size_t first_char = dd->second.string.find_first_not_of(' ');
		if(first_char != std::string::npos)
		{
			#ifdef REHEX_ASSUME_INTEGER_CHARACTER_WIDTHS
			m_dc.DrawText(dd->second.string.substr(first_char), (m_base_x + m_cache.fixed_string_width(first_char)), m_base_y);
			#else
			m_dc.DrawText(dd->second.string, m_base_x, m_base_y);
			#endif
		}
	}
	
	#endif
	
	/* Slow text rendering path - render variable-width characters using a single
	 * wxDC.DrawText() call for each character so we can align them to the grid of normal
	 * characters in the font.
	 *
	 * There are two (optional) optimisations here:
	 *
	 * REHEX_CACHE_CHARACTER_BITMAPS
	 *
	 *   Renders the characters into a secondary wxBitmap and caches it so future draws of the
	 *   same character are just a bitmap blit rather than rendering text every time.
	 *
	 *   This offers a significant performance boost on Windows, macOS and Linux and is enabled
	 *   on all platforms.
	 *
	 * REHEX_CACHE_STRING_BITMAPS
	 *
	 *   In addition to REHEX_CACHE_CHARACTER_BITMAPS, the individual character bitmaps in each
	 *   deferred_drawtext_slow are copied into another secondary bitmap, which is again cached
	 *   and blitted to the DC as a whole line in the future.
	 *
	 *   This adds another significant speed boost on Windows and macOS, where it is enabled.
	 *   There is no significant improvement on Linux, so it isn't enabled there.
	*/
	
	for(auto dd = m_deferred_drawtext_slow.begin(); dd != m_deferred_drawtext_slow.end(); ++dd)
	{
		PROFILE_INNER_BLOCK("drawing text (slow path)");
		
		wxColour fg_colour = dd->first.fg_colour;
		wxColour bg_colour = dd->first.bg_colour;
		
		#if defined(REHEX_CACHE_CHARACTER_BITMAPS) && defined(REHEX_CACHE_STRING_BITMAPS)
		
		#ifdef REHEX_ASSUME_INTEGER_CHARACTER_WIDTHS
		wxBitmap string_bitmap = m_cache.string_bitmap(0, dd->second.chars, fg_colour, bg_colour);
		#else
		wxBitmap string_bitmap = m_cache.string_bitmap(dd->first.base_column, dd->second.chars, fg_colour, bg_colour);
		#endif
		
		#if defined(REHEX_CACHE_CHARACTER_BITMAPS) && defined(REHEX_CACHE_STRING_BITMAPS) && defined(REHEX_BROKEN_BITMAP_TRANSPARENCY)
		int string_x = m_base_x + m_cache.fixed_string_width(dd->first.base_column);
		#else
		int string_x = m_base_x;
		#endif
		
		m_dc.DrawBitmap(string_bitmap, string_x, m_base_y, true);
		
		#elif defined(REHEX_CACHE_CHARACTER_BITMAPS)
		for(auto c = dd->second.chars.begin(); c != dd->second.chars.end(); ++c)
		{
			if(c->first != '\0')
			{
				wxBitmap char_bitmap = m_cache.char_bitmap(c->first, c->second, fg_colour, bg_colour);
				int char_x = m_base_x + m_cache.fixed_string_width(c - dd->second.chars.begin());
				
				m_dc.DrawBitmap(char_bitmap, char_x, m_base_y);
			}
		}
		
		#else
		m_dc.SetTextForeground(fg_colour);
		m_dc.SetBackgroundMode(wxTRANSPARENT);

		for(auto c = dd->second.chars.begin(); c != dd->second.chars.end(); ++c)
		{
			if(*c != wxEmptyString)
			{
				int char_x = m_base_x + m_cache.fixed_string_width(c - dd->second.chars.begin());
				m_dc.DrawText(*c, char_x, m_base_y);
			}
		}
		
		#endif
	}
}
