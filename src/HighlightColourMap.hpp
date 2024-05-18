/* Reverse Engineer's Hex Editor
 * Copyright (C) 2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_HIGHLIGHTCOLOURS_HPP
#define REHEX_HIGHLIGHTCOLOURS_HPP

#include <jansson.h>
#include <map>
#include <wx/colour.h>
#include <wx/config.h>

namespace REHex
{
#if 0
	struct GradientColour
	{
		Palette::ColourIndex colour1;
		Palette::ColourIndex colour2;
		
		int colour_delta_steps;
		int colour_delta_pos;
		
		GradientColour():
			colour1(Palette::PAL_INVALID),
			colour2(Palette::PAL_INVALID),
			colour_delta_steps(0),
			colour_delta_pos(0) {}
		
		GradientColour(Palette::ColourIndex colour):
			colour1(colour),
			colour2(colour),
			colour_delta_steps(0),
			colour_delta_pos(0) {}
		
		GradientColour(Palette::ColourIndex colour1, Palette::ColourIndex colour2, int colour_delta_stepsm colour_delta_pos):
			colour1(colour1),
			colour2(colour2),
			colour_delta_steps(colour_delta_steps),
			colour_delta_pos(colour_delta_pos) {}
		
		wxColour blend() const;
		
		bool is_single() const;
		bool is_start() const;
		bool is_end() const;
	};
#endif
	
	class HighlightColourMap
	{
		public:
			struct HighlightColour
			{
				wxColour primary_colour;
				bool primary_colour_is_default;
				
				wxColour secondary_colour;
				bool secondary_colour_is_default;
				
				wxString label;
				bool label_is_default;
				
				void set_primary_colour(const wxColour &colour);
				void set_secondary_colour(const wxColour &colour);
				void set_label(const wxString &label);
				
				bool operator==(const HighlightColour &rhs) const
				{
					return primary_colour == rhs.primary_colour
						&& primary_colour_is_default == rhs.primary_colour_is_default
						&& secondary_colour == rhs.secondary_colour
						&& secondary_colour_is_default == rhs.secondary_colour_is_default
						&& label == rhs.label
						&& label_is_default == rhs.label_is_default;
				}
			};
			
			static constexpr size_t DEFAULT_NUM = 6;
			static constexpr size_t MAX_NUM = 64;
			
			typedef std::map<size_t, HighlightColour>::iterator iterator;
			typedef std::map<size_t, HighlightColour>::const_iterator const_iterator;
			
		private:
			std::map<size_t, HighlightColour> colours;
			int default_colour_lightness;
			
			static HighlightColour make_default_highlight(size_t highlight_idx, int lightness);
			
		public:
			HighlightColourMap();
			
			static HighlightColourMap defaults(int default_colour_lightness = 100);
			
			static HighlightColourMap from_config(const wxConfigBase *config, int default_colour_lightness = 100);
			void to_config(wxConfigBase *config) const;
			
			static HighlightColourMap from_json(const json_t *json, int default_colour_lightness = 100);
			json_t *to_json() const;
			
			iterator add();
			
			void erase(size_t highlight_idx);
			void erase(const const_iterator &iter);
			
			size_t size() const;
			bool empty() const;
			
			iterator find(size_t highlight_idx);
			const_iterator find(size_t highlight_idx) const;
			
			iterator begin();
			iterator end();
			
			const_iterator begin() const;
			const_iterator end() const;
			
			HighlightColour &operator[](size_t highlight_idx);
			
			void set_default_lightness(int lightness);
			
			bool operator==(const HighlightColourMap &rhs) const
			{
				return colours == rhs.colours;
			}
			
			bool operator!=(const HighlightColourMap &rhs) const
			{
				return !(*this == rhs);
			}
	};
}

#endif /* !REHEX_HIGHLIGHTCOLOURS_HPP */
