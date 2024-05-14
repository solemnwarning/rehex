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

#ifndef REHEX_BYTECOLOURMAP_HPP
#define REHEX_BYTECOLOURMAP_HPP

#include <wx/colour.h>
#include <wx/config.h>
#include <wx/gdicmn.h>

#include "Palette.hpp"
#include "HighlightColourMap.hpp"

namespace REHex
{
	/**
	 * @brief Colour mapping for auto-colourising data by byte values.
	*/
	class ByteColourMap
	{
		public:
			/**
			 * @brief A colour from the active palette or a custom colour.
			*/
			class Colour
			{
				private:
					Palette::ColourIndex palette_colour;
					wxColour custom_colour;
					
				public:
					Colour():
						palette_colour(Palette::PAL_INVALID),
						custom_colour(wxNullColour) {}
					
					Colour(Palette::ColourIndex palette_colour):
						palette_colour(palette_colour),
						custom_colour(wxNullColour) {}
					
					Colour(const wxColour &custom_colour):
						palette_colour(Palette::PAL_INVALID),
						custom_colour(custom_colour) {}
					
					/**
					 * @brief Check if this Colour is a Palette colour.
					*/
					bool is_palette_colour() const
					{
						return palette_colour != Palette::PAL_INVALID;
					}
					
					/**
					 * @brief Get the Palette colour index from this Colour.
					*/
					Palette::ColourIndex get_palette_colour() const
					{
						return palette_colour;
					}
					
					bool is_custom_colour() const
					{
						return custom_colour != wxNullColour;
					}
					
					const wxColour &get_custom_colour() const
					{
						return custom_colour;
					}
					
					bool operator==(const Colour &rhs) const
					{
						return palette_colour == rhs.palette_colour && custom_colour == rhs.custom_colour;
					}
			};
			
			/**
			 * @brief Colour for a byte value.
			 *
			 * This type represents either a single colour, or an interpolated point
			 * on a gradient between two colours.
			*/
			struct Value
			{
				Colour colour1;
				Colour colour2;
				
				int colour_delta_steps;
				int colour_delta_pos;
				
				Value():
					colour1(Palette::PAL_NORMAL_TEXT_FG),
					colour2(Palette::PAL_NORMAL_TEXT_FG),
					colour_delta_steps(0),
					colour_delta_pos(0) {}
				
				bool operator==(const Value &rhs) const
				{
					return colour1 == rhs.colour1
						&& colour2 == rhs.colour2
						&& colour_delta_steps == rhs.colour_delta_steps
						&& colour_delta_pos == rhs.colour_delta_pos;
				}
				
				/**
				 * @brief Check if this is a single colour (not a gradient).
				*/
				bool is_single() const;
				
				/**
				 * @brief Check if this is the start of a gradient.
				*/
				bool is_start() const;
				
				/**
				 * @brief Check if this is the end of a gradient.
				*/
				bool is_end() const;
				
				/**
				 * @brief Get the computed colour.
				*/
				wxColour get_colour() const;
			};
			
		private:
			wxString label;
			Value bytes[256];
			
			static std::string serialise_colour_index(Colour index);
			static Colour deserialise_colour_index(const std::string &string);
			
		public:
			/**
			 * @brief Get the display label for this ByteColourMap.
			*/
			const wxString &get_label() const;
			
			/**
			 * @brief Set the display label for this ByteColourMap.
			*/
			void set_label(const wxString &label);
			
			/**
			 * @brief Set the colour for a single byte.
			*/
			void set_colour(unsigned char byte, Colour colour);
			
			/**
			 * @brief Set the colour for a range of bytes.
			*/
			void set_colour_range(unsigned char first_byte, unsigned char last_byte, Colour colour);
			
			/**
			 * @brief Set a range of bytes to use a colour gradient.
			*/
			void set_colour_gradient(unsigned char first_byte, unsigned char last_byte, Colour first_byte_colour, Colour last_byte_colour);
			
			/**
			 * @brief Get the computed colour for a byte value.
			*/
			wxColour get_colour(unsigned char byte) const;
			
			const Value &operator[](unsigned char byte) const;
			
			/**
			 * @brief Load a saved ByteColourMap from a wxConfig.
			*/
			static ByteColourMap load(const wxConfigBase *config);
			
			/**
			 * @brief Save a ByteColourMap to a wxConfig object.
			*/
			void save(wxConfigBase *config);
	};
}

#endif /* !REHEX_BYTECOLOURMAP_HPP */
