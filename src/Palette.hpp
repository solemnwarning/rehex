/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_PALETTE_HPP
#define REHEX_PALETTE_HPP

#include <string>
#include <wx/colour.h>

namespace REHex {
	/**
	 * @brief Colour palette to use when drawing custom controls.
	*/
	class Palette
	{
		public:
			enum ColourIndex
			{
				PAL_NORMAL_TEXT_BG,
				PAL_NORMAL_TEXT_FG,
				PAL_ALTERNATE_TEXT_FG,
				PAL_INVERT_TEXT_BG,
				PAL_INVERT_TEXT_FG,
				PAL_SELECTED_TEXT_BG,
				PAL_SELECTED_TEXT_FG,
				PAL_SECONDARY_SELECTED_TEXT_BG,
				PAL_SECONDARY_SELECTED_TEXT_FG,
				PAL_DIRTY_TEXT_BG,
				PAL_DIRTY_TEXT_FG,
				PAL_COMMENT_BG,
				PAL_COMMENT_FG,
				
				PAL_CONTRAST_TEXT_1_FG,
				PAL_CONTRAST_TEXT_2_FG,
				PAL_CONTRAST_TEXT_3_FG,
				PAL_CONTRAST_TEXT_4_FG,
				PAL_CONTRAST_TEXT_5_FG,
				
				PAL_MAX = PAL_CONTRAST_TEXT_5_FG,
				
				PAL_INVALID = 9999,
			};
			
			Palette(const std::string &name, const std::string &label, const wxColour colours[], int default_highlight_lightness);
			
			/**
			 * @brief Get the internal name of the palette.
			*/
			const std::string &get_name() const;
			
			/**
			 * @brief Get the display name of the palette.
			*/
			const std::string &get_label() const;
			
			/**
			 * @brief Get the colour at the given palette index.
			 *
			 * @param index Palette index slot (0 .. PAL_MAX).
			*/
			const wxColour &operator[](int index) const;
			
			/**
			 * @brief Blend two palette colours together.
			 *
			 * @param colour_a_idx Palette index of colour A (0 .. PAL_MAX).
			 * @param colour_b_idx Palette index of colour B (0 .. PAL_MAX).
			*/
			wxColour get_average_colour(int colour_a_idx, int colour_b_idx) const;
			
			/**
			 * @brief Blend two colours together.
			*/
			static wxColour get_average_colour(const wxColour &colour_a, const wxColour &colour_b);
			
			int get_default_highlight_lightness() const;
			
			static Palette *create_system_palette();
			static Palette *create_light_palette();
			static Palette *create_dark_palette();
			
		private:
			std::string name;
			std::string label;
			
			wxColour palette[PAL_MAX + 1];
			int default_highlight_lightness;
	};
	
	/**
	 * @brief The active colour palette.
	*/
	extern Palette *active_palette;
}

#endif /* !REHEX_PALETTE_HPP */
