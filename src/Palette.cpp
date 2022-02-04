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

#include "platform.hpp"
#include <assert.h>
#include <wx/colour.h>
#include <wx/settings.h>

#include "Palette.hpp"

static bool is_light(const wxColour &c) { return ((int)(c.Red()) + (int)(c.Green()) + (int)(c.Blue())) / 3 >= 128; }

REHex::Palette *REHex::active_palette = NULL;

REHex::Palette::Palette(const std::string &name, const std::string &label, const wxColour colours[]):
	name(name), label(label)
{
	for(int i = 0; i <= PAL_MAX; ++i)
	{
		palette[i] = colours[i];
	}
}

const std::string &REHex::Palette::get_name() const
{
	return name;
}

const std::string &REHex::Palette::get_label() const
{
	return label;
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

REHex::Palette::ColourIndex REHex::Palette::get_highlight_bg_idx(int index)
{
	assert(index >= 0);
	assert(index < NUM_HIGHLIGHT_COLOURS);
	
	return (ColourIndex)(PAL_HIGHLIGHT_TEXT_MIN_BG + (index * 2));
}

REHex::Palette::ColourIndex REHex::Palette::get_highlight_fg_idx(int index)
{
	assert(index >= 0);
	assert(index < NUM_HIGHLIGHT_COLOURS);
	
	return (ColourIndex)(PAL_HIGHLIGHT_TEXT_MIN_FG + (index * 2));
}

wxColour REHex::Palette::get_average_colour(int colour_a_idx, int colour_b_idx) const
{
	const wxColour &colour_a = (*this)[colour_a_idx];
	const wxColour &colour_b = (*this)[colour_b_idx];
	
	return wxColour(
		(((int)(colour_a.Red())   + (int)(colour_b.Red()))   / 2),
		(((int)(colour_a.Green()) + (int)(colour_b.Green())) / 2),
		(((int)(colour_a.Blue())  + (int)(colour_b.Blue()))  / 2));
}

REHex::Palette *REHex::Palette::create_system_palette()
{
	const wxColour WINDOW        = wxSystemSettings::GetColour(wxSYS_COLOUR_WINDOW);
	const wxColour WINDOWTEXT    = wxSystemSettings::GetColour(wxSYS_COLOUR_WINDOWTEXT);
	const wxColour HIGHLIGHT     = wxSystemSettings::GetColour(wxSYS_COLOUR_HIGHLIGHT);
	const wxColour HIGHLIGHTTEXT = wxSystemSettings::GetColour(wxSYS_COLOUR_HIGHLIGHTTEXT);
	
	const wxColour colours[] = {
		WINDOW,      /* PAL_NORMAL_TEXT_BG */
		WINDOWTEXT,  /* PAL_NORMAL_TEXT_FG */
		
		(is_light(WINDOWTEXT)
			? WINDOWTEXT.ChangeLightness(70)
			: WINDOWTEXT.ChangeLightness(130)),  /* PAL_ALTERNATE_TEXT_FG */
		
		WINDOWTEXT,  /* PAL_INVERT_TEXT_BG */
		WINDOW,      /* PAL_INVERT_TEXT_FG */
		
		HIGHLIGHT,      /* PAL_SELECTED_TEXT_BG */
		HIGHLIGHTTEXT,  /* PAL_SELECTED_TEXT_FG */
		
		(is_light(HIGHLIGHT)
			? HIGHLIGHT.ChangeLightness(70)
			: HIGHLIGHT.ChangeLightness(130)),  /* PAL_SECONDARY_SELECTED_TEXT_BG */
		
		(is_light(HIGHLIGHTTEXT)
			? HIGHLIGHTTEXT.ChangeLightness(70)
			: HIGHLIGHTTEXT.ChangeLightness(130)),  /* PAL_SECONDARY_SELECTED_TEXT_FG */
		
		WINDOW,                      /* PAL_DIRTY_TEXT_BG */
		wxColour(0xFF, 0x00, 0x00),  /* PAL_DIRTY_TEXT_FG */
		
		/* TODO: Algorithmically choose highlight colours that complement system colour scheme. */
		
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
		
		(is_light(WINDOW)
			? WINDOW.ChangeLightness(80)
			: WINDOW.ChangeLightness(130)),  /* PAL_COMMENT_BG */
		
		WINDOWTEXT,  /* PAL_COMMENT_FG */
	};
	
	static_assert(sizeof(colours) == sizeof(palette), "Correct number of colours for Palette");
	
	return new Palette("system", "System colours", colours);
}

REHex::Palette *REHex::Palette::create_light_palette()
{
	const wxColour colours[] = {
		wxColour(0xFF, 0xFF, 0xFF),  /* PAL_NORMAL_TEXT_BG */
		wxColour(0x00, 0x00, 0x00),  /* PAL_NORMAL_TEXT_FG */
		wxColour(0x69, 0x69, 0x69),  /* PAL_ALTERNATE_TEXT_FG */
		wxColour(0x00, 0x00, 0x00),  /* PAL_INVERT_TEXT_BG */
		wxColour(0xFF, 0xFF, 0xFF),  /* PAL_INVERT_TEXT_FG */
		wxColour(0x00, 0x00, 0xFF),  /* PAL_SELECTED_TEXT_BG */
		wxColour(0xFF, 0xFF, 0xFF),  /* PAL_SELECTED_TEXT_FG */
		wxColour(0x00, 0x00, 0x7F),  /* PAL_SECONDARY_SELECTED_TEXT_BG */
		wxColour(0xFF, 0xFF, 0xFF),  /* PAL_SECONDARY_SELECTED_TEXT_FG */
		wxColour(0xFF, 0xFF, 0xFF),  /* PAL_DIRTY_TEXT_BG */
		wxColour(0xFF, 0x00, 0x00),  /* PAL_DIRTY_TEXT_FG */
		
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
	};
	
	static_assert(sizeof(colours) == sizeof(palette), "Correct number of colours for Palette");
	
	return new Palette("light", "Light", colours);
}

REHex::Palette *REHex::Palette::create_dark_palette()
{
	const wxColour colours[] = {
		wxColour(0x00, 0x00, 0x00),  /* PAL_NORMAL_TEXT_BG */
		wxColour(0xFF, 0xFF, 0xFF),  /* PAL_NORMAL_TEXT_FG */
		wxColour(0xC3, 0xC3, 0xC3),  /* PAL_ALTERNATE_TEXT_FG */
		wxColour(0xFF, 0xFF, 0xFF),  /* PAL_INVERT_TEXT_BG */
		wxColour(0x00, 0x00, 0x00),  /* PAL_INVERT_TEXT_FG */
		wxColour(0x00, 0x00, 0xFF),  /* PAL_SELECTED_TEXT_BG */
		wxColour(0xFF, 0xFF, 0xFF),  /* PAL_SELECTED_TEXT_FG */
		wxColour(0x00, 0x00, 0x7F),  /* PAL_SECONDARY_SELECTED_TEXT_BG */
		wxColour(0xFF, 0xFF, 0xFF),  /* PAL_SECONDARY_SELECTED_TEXT_FG */
		wxColour(0x00, 0x00, 0x00),  /* PAL_DIRTY_TEXT_BG */
		wxColour(0xFF, 0x00, 0x00),  /* PAL_DIRTY_TEXT_FG */
		
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
	};
	
	static_assert(sizeof(colours) == sizeof(palette), "Correct number of colours for Palette");
	
	return new Palette("dark", "Dark", colours);
}
