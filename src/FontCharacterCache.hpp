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

#ifndef REHEX_FONTCHARACTERCACHE_HPP
#define REHEX_FONTCHARACTERCACHE_HPP

#include <unitypes.h>
#include <vector>
#include <wx/bitmap.h>
#include <wx/colour.h>
#include <wx/font.h>
#include <wx/gdicmn.h>
#include <wx/string.h>

#include "LRUCache.hpp"

namespace REHex
{
	/**
	 * @brief Cache for character graphics data.
	*/
	class FontCharacterCache
	{
		public:
			/**
			 * @brief Set up a FontCharacterCache with the system default font.
			*/
			FontCharacterCache();
			
			/**
			 * @brief Set up a FontCharacterCache with a specific font.
			*/
			FontCharacterCache(const wxFont &font);
			
			FontCharacterCache(const FontCharacterCache&) = delete;
			FontCharacterCache &operator=(const FontCharacterCache&) = delete;
			
			/**
			 * @brief Change the font and reset the cache.
			*/
			void set_font(const wxFont &font);
			
			/**
			 * @brief Get the assigned font.
			*/
			wxFont get_font() const;
			
			/**
			 * @brief Get the size of a fixed-width character in the selected font.
			 *
			 * NOTE: Even in fixed-pitch fonts, there are special characters and other
			 * outliers which may be of different sizes, so the results of this method
			 * may not be correct beyond basic ASCII characters.
			*/
			wxSize fixed_char_size() const;
			
			/**
			 * @brief Get the width of a fixed-width character in the selected font.
			 *
			 * NOTE: Even in fixed-pitch fonts, there are special characters and other
			 * outliers which may be of different sizes, so the results of this method
			 * may not be correct beyond basic ASCII characters.
			*/
			int fixed_char_width() const;
			
			/**
			 * @brief Get the height of a fixed-width character in the selected font.
			 *
			 * NOTE: Even in fixed-pitch fonts, there are special characters and other
			 * outliers which may be of different sizes, so the results of this method
			 * may not be correct beyond basic ASCII characters.
			*/
			int fixed_char_height() const;
			
			/**
			 * @brief Get the width of a string of fixed-width characters.
			 *
			 * @param length  Number of fixed-width characters in the string.
			 *
			 * NOTE: Even in fixed-pitch fonts, there are special characters and other
			 * outliers which may be of different sizes, so the results of this method
			 * may not be correct beyond basic ASCII characters.
			*/
			int fixed_string_width(int length) const;
			
			/**
			 * @brief Calculate fixed-width character at X pixel offset.
			 *
			 * @param x  X position in string, in pixels.
			 *
			 * NOTE: Even in fixed-pitch fonts, there are special characters and other
			 * outliers which may be of different sizes, so the results of this method
			 * may not be correct beyond basic ASCII characters.
			*/
			int fixed_char_at_x(int x) const;
			
			/**
			 * @brief Get the size of a character in the selected font.
			 *
			 * @param c Unicode code point of character.
			*/
			wxSize char_size(ucs4_t c) const;
			
			/**
			 * @brief Get the width of a character in the selected font.
			 *
			 * @param c Unicode code point of character.
			*/
			int char_width(ucs4_t c) const;
			
			/**
			 * @brief Get the height of a character in the selected font.
			 *
			 * @param c Unicode code point of character.
			*/
			int char_height(ucs4_t c) const;
			
			#ifdef REHEX_CACHE_CHARACTER_BITMAPS
			/**
			 * @brief Render a character to a bitmap (cached).
			 *
			 * @param unicode_char  Unicode code point of the character.
			 * @param fg_colour     Foreground colour.
			 * @param bg_colour     Background colour.
			*/
			wxBitmap char_bitmap(ucs4_t unicode_char, const wxColour &fg_colour, const wxColour &bg_colour) const;
			
			/**
			 * @brief Render a character to a bitmap (cached).
			 *
			 * @param unicode_char  Unicode code point of the character.
			 * @param char_size     Character size obtained from dc.GetTextExtent() method.
			 * @param fg_colour     Foreground colour.
			 * @param bg_colour     Background colour.
			*/
			wxBitmap char_bitmap(ucs4_t unicode_char, const wxSize &char_size, const wxColour &fg_colour, const wxColour &bg_colour) const;
			#endif
			
			#ifdef REHEX_CACHE_STRING_BITMAPS
			/**
			 * @brief Render a string of aligned characters to a bitmap (cached).
			 *
			 * @param base_column Column where generated bitmap will be drawn.
			 * @param characters  List of characters to render in the string.
			 * @param fg_colour   Foreground colour.
			 * @param bg_colour   Background colour.
			 *
			 * This method renders a sequence of characters into a bitmap, aligned to
			 * fixed-point character widths.
			 *
			 * The base_column parameter is intended for keeping characters correctly
			 * aligned when the returned bitmap will be blitted into the middle of a
			 * fixed-width character string. The characters will still be drawn into
			 * the bitmap from position zero, however their relative offsets will be
			 * calculated as if they were further along, allowing for platforms whose
			 * fonts aren't pixel-aligned.
			*/
			wxBitmap string_bitmap(int base_column, const std::vector<ucs4_t> &characters, const wxColour &fg_colour, const wxColour &bg_colour) const;
			#endif
			
		private:
			wxFont m_font;
			
			int m_char_height;
			
			static const int PRECOMP_STRING_WIDTH_TO = 512;
			unsigned int m_string_width_precomp[PRECOMP_STRING_WIDTH_TO];
			
			/**
			 * @brief Clear and recompute any cached data.
			*/
			void reset();
			
			static const size_t CHAR_SIZE_CACHE_SIZE = 4096;
			mutable LRUCache<ucs4_t, wxSize> m_char_size_cache;
			
			#ifdef REHEX_CACHE_CHARACTER_BITMAPS
			static const size_t CHAR_BITMAP_CACHE_SIZE = 8192;
			mutable LRUCache<std::tuple<ucs4_t, unsigned int, unsigned int>, wxBitmap> m_char_bitmap_cache;
			#endif
			
			#ifdef REHEX_CACHE_STRING_BITMAPS
			struct StringBitmapCacheKey
			{
				#ifndef REHEX_ASSUME_INTEGER_CHARACTER_WIDTHS
				int base_column;
				#endif
				
				std::vector<ucs4_t> characters;
				unsigned int packed_fg_colour;
				unsigned int packed_bg_colour;
				
				StringBitmapCacheKey(int base_column, const std::vector<ucs4_t> &characters, unsigned int packed_fg_colour, unsigned int packed_bg_colour);
				
				bool operator<(const StringBitmapCacheKey &rhs) const;
			};
			
			static const size_t STRING_BITMAP_CACHE_SIZE = 256;
			mutable LRUCache<StringBitmapCacheKey, wxBitmap> m_string_bitmap_cache;
			#endif
	};
}

#endif /* !REHEX_FONTCHARACTERCACHE_HPP */
