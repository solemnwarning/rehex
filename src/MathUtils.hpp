/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018-2026 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_MATHUTILS_HPP
#define REHEX_MATHUTILS_HPP

#include <assert.h>
#include <cmath>
#include <limits>

#include "BitOffset.hpp"

namespace REHex {
	template<typename T> T _add_clamp_overflow(T a, T b, bool *overflow, T T_min, T T_max, T T_zero)
	{
		if((a < T_zero) != (b < T_zero))
		{
			/* a and b have differing signs - can't overflow */
			if(overflow != NULL)
			{
				*overflow = false;
			}
			
			return a + b;
		}
		else if(a < T_zero)
		{
			/* a and b are negative */
			
			if((T_min - b) <= a)
			{
				/* a + b >= T_min */
				if(overflow != NULL)
				{
					*overflow = false;
				}
				
				return a + b;
			}
			else{
				/* a + b < T_min (underflow) */
				if(overflow != NULL)
				{
					*overflow = true;
				}
				
				return T_min;
			}
		}
		else{
			/* a and b are positive */
			
			if((T_max - b) >= a)
			{
				/* a + b <= T_max */
				if(overflow != NULL)
				{
					*overflow = false;
				}
				
				return a + b;
			}
			else{
				/* a + b > T_max (overflow) */
				if(overflow != NULL)
				{
					*overflow = true;
				}
				
				return T_max;
			}
		}
	}
	
	/**
	 * @brief Adds two integers together, clamping to the range of the type.
	 *
	 * This function adds two integer-type values together, if the result would overflow or
	 * underflow, the result is clamped to the maximum or minimum value representable by the
	 * type T.
	 *
	 * If the "overflow" parameter is non-NULL, whether or not an overflow (or underflow) was
	 * detected is stored there.
	*/
	template<typename T> T add_clamp_overflow(T a, T b, bool *overflow = NULL)
	{
		return _add_clamp_overflow<T>(a, b, overflow, std::numeric_limits<T>::min(), std::numeric_limits<T>::max(), 0);
	}
	
	/**
	 * @brief Specialisation of add_clamp_overflow<T>() for BitOffset.
	*/
	template<> BitOffset add_clamp_overflow(BitOffset a, BitOffset b, bool *overflow);
	
	/**
	 * @brief Multiply two integers together, clamping to the range of the type.
	 *
	 * This function multiplies two integer-type values together, if the result would overflow
	 * or underflow, the result is clamped to the maximum or minimum value representable by the
	 * type T.
	 *
	 * If the "overflow" parameter is non-NULL, whether or not an overflow (or underflow) was
	 * detected is stored there.
	*/
	template<typename T> T multiply_clamp_overflow(T a, T b, bool *overflow = NULL)
	{
		constexpr T MAX = std::numeric_limits<T>::max();
		constexpr T MIN = std::numeric_limits<T>::min();
		
		if(a == 0 || b == 0)
		{
			return 0;
		}
		
		if(a < 0 && b < 0)
		{
			a *= -1;
			b *= -1;
		}
		
		bool did_overflow;
		T result;
		
		if(a > 0 && b > 0)
		{
			if((MAX / a) < b)
			{
				result = MAX;
				did_overflow = true;
			}
			else{
				result = a * b;
				did_overflow = false;
			}
		}
		else if(a > 0)
		{
			if((MIN / a) > b)
			{
				result = MIN;
				did_overflow = true;
			}
			else{
				result = a * b;
				did_overflow = false;
			}
		}
		else{
			if((MIN / b) > a)
			{
				result = MIN;
				did_overflow = true;
			}
			else{
				result = a * b;
				did_overflow = false;
			}
		}
		
		if(overflow != NULL)
		{
			*overflow = did_overflow;
		}
		
		return result;
	}

	/**
	 * @brief Round a floating point number to a number of decimal places.
	 *
	 * @param num     Number to round.
	 * @param places  Number of decimal places to round to.
	 */
	template<typename T> T decimal_round(T num, int places)
	{
		assert(places >= 0);

		T div = pow(10.0f, places);
		return std::round(num * div) / div;
	}
}

#endif /* !REHEX_MATHUTILS_HPP */
