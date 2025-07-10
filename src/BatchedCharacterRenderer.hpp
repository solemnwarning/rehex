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

#ifndef REHEX_BATCHEDCHARACTERRENDERER_HPP
#define REHEX_BATCHEDCHARACTERRENDERER_HPP

#include <unitypes.h>
#include <vector>
#include <wx/bitmap.h>
#include <wx/colour.h>
#include <wx/dc.h>
#include <wx/font.h>
#include <wx/gdicmn.h>
#include <wx/string.h>

#include "FastRectangleFiller.hpp"
#include "FontCharacterCache.hpp"
#include "LRUCache.hpp"
#include "UnsortedMapVector.hpp"

namespace REHex
{
	/**
	 * @brief Helper class for efficient drawing of monospace character strings.
	 *
	 * This class implements drawing of strings character-by-character in a monospace font
	 * using whatever method is most efficient on the current platform.
	*/
	class BatchedCharacterRenderer
	{
		public:
			BatchedCharacterRenderer(wxDC &dc, const FontCharacterCache &cache, int base_x, int base_y);
			
			/**
			 * @brief Queue a character for drawing.
			 *
			 * @param column     Column to draw character at, in fixed-width characters.
			 * @param codepoint  Unicode code point of character.
			 * @param fg_colour  Foreground colour.
			 * @param bg_colour  Background colour.
			*/
			wxRect draw_char(int column, ucs4_t codepoint, const wxColour &fg_colour, const wxColour &bg_colour);
			
			/**
			 * @brief Queue a character for drawing.
			 *
			 * @param column     Column to draw character at, in fixed-width characters.
			 * @param codepoint  Unicode code point of character.
			 * @param char_size  Character size obtained from dc.GetTextExtent() method.
			 * @param fg_colour  Foreground colour.
			 * @param bg_colour  Background colour.
			*/
			wxRect draw_char(int column, ucs4_t codepoint, const wxSize &char_size, const wxColour &fg_colour, const wxColour &bg_colour);
			
			/**
			 * @brief Queue a character for drawing using the "fast" path.
			 *
			 * @param column     Column to draw character at, in fixed-width characters.
			 * @param codepoint  Unicode code point of character.
			 * @param char_size  Character size obtained from dc.GetTextExtent() method.
			 * @param fg_colour  Foreground colour.
			 * @param bg_colour  Background colour.
			 *
			 * This method queues a character for drawing on the "fast" path, which can
			 * only handle basic ASCII and any other characters which occupy the same
			 * amount of on-screen space as a "normal" character.
			 *
			 * Drawing any weird characters with this method will lead to character
			 * mis-alignment and other rendering glitches.
			*/
			wxRect draw_char_fast(int column, ucs4_t codepoint, const wxSize &char_size, const wxColour &fg_colour, const wxColour &bg_colour);
			
			/**
			 * @brief Queue a character for drawing using the "slow" path.
			 *
			 * @param column     Column to draw character at, in fixed-width characters.
			 * @param codepoint  Unicode code point of character.
			 * @param char_size  Character size obtained from dc.GetTextExtent() method.
			 * @param fg_colour  Foreground colour.
			 * @param bg_colour  Background colour.
			 *
			 * This method queues a character for drawing on the "slow" path, which can
			 * handle wide characters and other oddities which don't necessarily occupy
			 * one character of space in a fixed-pitch font.
			*/
			wxRect draw_char_slow(int column, ucs4_t codepoint, const wxSize &char_size, const wxColour &fg_colour, const wxColour &bg_colour);
			
			/**
			 * @brief Flush pending draw operations to the DC.
			*/
			void flush();
			
		private:
			wxDC &m_dc;
			const FontCharacterCache &m_cache;
			
			int m_base_x;
			int m_base_y;
			
			struct DeferredDrawTextFastValue
			{
				wxString string;
			};
			
			struct DeferredDrawTextSlowKey
			{
				#if defined(REHEX_CACHE_CHARACTER_BITMAPS) && defined(REHEX_CACHE_STRING_BITMAPS) && (defined(REHEX_BROKEN_BITMAP_TRANSPARENCY) || !(defined(REHEX_ASSUME_INTEGER_CHARACTER_WIDTHS)))
				int base_column;
				#endif
				
				wxColour fg_colour;
				wxColour bg_colour;
				
				#if defined(REHEX_CACHE_CHARACTER_BITMAPS) && defined(REHEX_CACHE_STRING_BITMAPS) && (defined(REHEX_BROKEN_BITMAP_TRANSPARENCY) || !(defined(REHEX_ASSUME_INTEGER_CHARACTER_WIDTHS)))
				DeferredDrawTextSlowKey(int base_column, const wxColour &fg_colour, const wxColour &bg_colour):
					base_column(base_column),
				#else
				DeferredDrawTextSlowKey(const wxColour &fg_colour, const wxColour &bg_colour):
				#endif
					fg_colour(fg_colour),
					bg_colour(bg_colour) {}
				
				bool operator==(const DeferredDrawTextSlowKey &rhs) const
				{
					return
						#if defined(REHEX_CACHE_CHARACTER_BITMAPS) && defined(REHEX_CACHE_STRING_BITMAPS) && (defined(REHEX_BROKEN_BITMAP_TRANSPARENCY) || !(defined(REHEX_ASSUME_INTEGER_CHARACTER_WIDTHS)))
						base_column == rhs.base_column
						#else
						true
						#endif
						&& fg_colour == rhs.fg_colour
						&& bg_colour == rhs.bg_colour;
				}
			};
			
			struct DeferredDrawTextSlowValue
			{
				#if defined(REHEX_CACHE_CHARACTER_BITMAPS) && defined(REHEX_CACHE_STRING_BITMAPS)
				std::vector<ucs4_t> chars;
				
				#elif defined(REHEX_CACHE_CHARACTER_BITMAPS)
				std::vector< std::pair<ucs4_t, wxSize> > chars;
				
				#else
				std::vector<wxString> chars;
				
				#endif
			};
			
			#ifndef REHEX_FORCE_SLOW_TEXT_PATH
			UnsortedMapVector<wxColour, DeferredDrawTextFastValue> m_deferred_drawtext_fast;
			#endif

			#if !(defined(REHEX_FORCE_SLOW_PATH)) || (defined(REHEX_CACHE_CHARACTER_BITMAPS) && defined(REHEX_CACHE_STRING_BITMAPS) && !(defined(REHEX_BROKEN_BITMAP_TRANSPARENCY)))
			FastRectangleFiller m_bgfill;
			#endif
			
			UnsortedMapVector<DeferredDrawTextSlowKey, DeferredDrawTextSlowValue> m_deferred_drawtext_slow;
			
			#ifdef REHEX_BROKEN_BITMAP_TRANSPARENCY
			const DeferredDrawTextSlowKey *m_deferred_drawtext_slow_last_key = NULL;
			#endif
	};
}

#endif /* !REHEX_BATCHEDCHARACTERRENDERER_HPP */
