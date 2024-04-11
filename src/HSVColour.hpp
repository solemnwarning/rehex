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

#ifndef REHEX_HSVCOLOUR_HPP
#define REHEX_HSVCOLOUR_HPP

#include <utility>
#include <vector>
#include <wx/colour.h>

namespace REHex
{
	/**
	 * @brief A Hue/Saturation/Value colour.
	*/
	struct HSVColour
	{
		float h; /**< Hue (degrees) */
		float s; /**< Saturation (0.0-1.0) */
		float v; /**< Value (0.0-1.0) */
		
		/**
		 * @brief Construct from Hue/Saturation/Value values.
		 *
		 * @param h  Hue (will be wrapped to >= 0.0 && < 360.0).
		 * @param s  Saturation (will be clamped to 0.0-1.0).
		 * @param v  Value (will be clamped to 0.0-1.0).
		*/
		HSVColour(float h, float s, float v);
		
		/**
		 * @brief Construct from an RGB colour.
		*/
		HSVColour(const wxColour &rgb);
		
		/**
		 * @brief Convert to an RGB colour.
		*/
		wxColour to_rgb() const;
		
		/**
		 * @brief Wrap a hue value.
		*/
		static float wrap_h(float h);
		
		/**
		 * @brief Clamp a saturation/value value.
		*/
		static float clamp_sv(float sv);
		
		/**
		 * @brief Pick a hue that contrasts with other hues.
		 *
		 * This function picks a hue which is (numerically) spaced as
		 * far from any of the provided hues as possible.
		 *
		 * Returns the selected hue and the difference between it and
		 * the nearest one in existing_hues.
		*/
		static std::pair<float, float> pick_contrasting_hue(const std::vector<float> &existing_hues);
	};
}

#endif /* !REHEX_HSVCOLOUR_HPP */
