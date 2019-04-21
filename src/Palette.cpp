/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <assert.h>
#include <wx/colour.h>

#include "Palette.hpp"

#define DARK_THEME

REHex::Palette::Palette()
{
	/* TODO: Default colours should be based on system colours, with gaps (e.g. highlights)
	 * filled with ones which complement them.
	*/
	
	const wxColour DEFAULT_PALETTE[] = {
		#ifdef DARK_THEME
		
		/* +------------+
		 * | DARK THEME |
		 * +------------+
		*/
		
		wxColour(0x00, 0x00, 0x00),  /* PAL_NORMAL_TEXT_BG */
		wxColour(0xFF, 0xFF, 0xFF),  /* PAL_NORMAL_TEXT_FG */
		wxColour(0xC3, 0xC3, 0xC3),  /* PAL_ALTERNATE_TEXT_FG */
		wxColour(0xFF, 0xFF, 0xFF),  /* PAL_INVERT_TEXT_BG */
		wxColour(0x00, 0x00, 0x00),  /* PAL_INVERT_TEXT_FG */
		wxColour(0x00, 0x00, 0xFF),  /* PAL_SELECTED_TEXT_BG */
		wxColour(0xFF, 0xFF, 0xFF),  /* PAL_SELECTED_TEXT_FG */
		
		/* TODO: Pick less eye-searing highlight colours. */
		
		/* White on Red */
		wxColour(0xFF, 0x00, 0x00),  /* PAL_HIGHLIGHT_TEXT_MIN_BG */
		wxColour(0xFF, 0xFF, 0xFF),  /* PAL_HIGHLIGHT_TEXT_MIN_FG */
		
		/* Black on Orange */
		wxColour(0xFE, 0x63, 0x00),
		wxColour(0xFF, 0xFF, 0xFF),
		
		/* Black on Yellow */
		wxColour(0xFC, 0xFF, 0x00),
		wxColour(0x00, 0x00, 0x00),
		
		/* Black on Green */
		wxColour(0x02, 0xFE, 0x07),
		wxColour(0x00, 0x00, 0x00),
		
		/* White on Violet */
		wxColour(0xFD, 0x00, 0xFF),
		wxColour(0xFF, 0xFF, 0xFF),
		
		/* White on Grey */
		wxColour(0x6A, 0x63, 0x6F),  /* PAL_HIGHLIGHT_TEXT_MAX_BG */
		wxColour(0xFF, 0xFF, 0xFF),  /* PAL_HIGHLIGHT_TEXT_MAX_FG */
		
		wxColour(0x58, 0x58, 0x58),  /* PAL_COMMENT_BG */
		wxColour(0xFF, 0xFF, 0xFF),  /* PAL_COMMENT_FG */
		
		#else
		
		/* +-------------+
		 * | LIGHT THEME |
		 * +-------------+
		*/
		
		wxColour(0xFF, 0xFF, 0xFF),  /* PAL_NORMAL_TEXT_BG */
		wxColour(0x00, 0x00, 0x00),  /* PAL_NORMAL_TEXT_FG */
		wxColour(0x69, 0x69, 0x69),  /* PAL_ALTERNATE_TEXT_FG */
		wxColour(0x00, 0x00, 0x00),  /* PAL_INVERT_TEXT_BG */
		wxColour(0xFF, 0xFF, 0xFF),  /* PAL_INVERT_TEXT_FG */
		wxColour(0x00, 0x00, 0xFF),  /* PAL_SELECTED_TEXT_BG */
		wxColour(0xFF, 0xFF, 0xFF),  /* PAL_SELECTED_TEXT_FG */
		
		/* TODO: Pick less eye-searing highlight colours. */
		
		/* White on Red */
		wxColour(0xFF, 0x00, 0x00),  /* PAL_HIGHLIGHT_TEXT_MIN_BG */
		wxColour(0xFF, 0xFF, 0xFF),  /* PAL_HIGHLIGHT_TEXT_MIN_FG */
		
		/* Black on Orange */
		wxColour(0xFE, 0x63, 0x00),
		wxColour(0xFF, 0xFF, 0xFF),
		
		/* Black on Yellow */
		wxColour(0xFC, 0xFF, 0x00),
		wxColour(0x00, 0x00, 0x00),
		
		/* Black on Green */
		wxColour(0x02, 0xFE, 0x07),
		wxColour(0x00, 0x00, 0x00),
		
		/* White on Violet */
		wxColour(0xFD, 0x00, 0xFF),
		wxColour(0xFF, 0xFF, 0xFF),
		
		/* White on Grey */
		wxColour(0x6A, 0x63, 0x6F),  /* PAL_HIGHLIGHT_TEXT_MAX_BG */
		wxColour(0xFF, 0xFF, 0xFF),  /* PAL_HIGHLIGHT_TEXT_MAX_FG */
		
		wxColour(0xD3, 0xD3, 0xD3),  /* PAL_COMMENT_BG */
		wxColour(0x00, 0x00, 0x00),  /* PAL_COMMENT_FG */
		
		#endif
	};
	
	static_assert(sizeof(DEFAULT_PALETTE) == sizeof(palette));
	
	for(int i = 0; i <= PAL_MAX; ++i)
	{
		palette[i] = DEFAULT_PALETTE[i];
	}
}

const wxColour &REHex::Palette::operator[](int index) const
{
	assert(index >= 0);
	assert(index <= PAL_MAX);
	
	return palette[index];
}

const wxColour &REHex::Palette::get_highlight_bg(int index) const
{
	assert(index >= 0);
	assert(index < NUM_HIGHLIGHT_COLOURS);
	
	return palette[PAL_HIGHLIGHT_TEXT_MIN_BG + (index * 2)];
}

const wxColour &REHex::Palette::get_highlight_fg(int index) const
{
	assert(index >= 0);
	assert(index < NUM_HIGHLIGHT_COLOURS);
	
	return palette[PAL_HIGHLIGHT_TEXT_MIN_FG + (index * 2)];
}
