/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018-2020 Daniel Collins <solemnwarning@solemnwarning.net>
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
	class Palette
	{
		public:
			static const int NUM_HIGHLIGHT_COLOURS = 6;
			
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
				
				PAL_HIGHLIGHT_TEXT_MIN_BG,
				PAL_HIGHLIGHT_TEXT_MIN_FG,
				PAL_HIGHLIGHT_TEXT_MAX_BG = (PAL_HIGHLIGHT_TEXT_MIN_BG + (NUM_HIGHLIGHT_COLOURS - 1) * 2),
				PAL_HIGHLIGHT_TEXT_MAX_FG = (PAL_HIGHLIGHT_TEXT_MIN_FG + (NUM_HIGHLIGHT_COLOURS - 1) * 2),
				
				PAL_COMMENT_BG,
				PAL_COMMENT_FG,
				
				PAL_MAX = PAL_COMMENT_FG,
			};
			
			Palette(const std::string &name, const std::string &label, const wxColour colours[]);
			
			const std::string &get_name() const;
			const std::string &get_label() const;
			
			const wxColour &operator[](int index) const;
			
			const wxColour &get_highlight_bg(int highlight_idx) const;
			const wxColour &get_highlight_fg(int highlight_idx) const;
			
			static Palette *create_system_palette();
			static Palette *create_light_palette();
			static Palette *create_dark_palette();
			
		private:
			std::string name;
			std::string label;
			
			wxColour palette[PAL_MAX + 1];
	};
	
	extern Palette *active_palette;
}

#endif /* !REHEX_PALETTE_HPP */
