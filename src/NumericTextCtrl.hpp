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

#ifndef REHEX_NUMERICTEXTCTRL_HPP
#define REHEX_NUMERICTEXTCTRL_HPP

#include <stdexcept>
#include <stdlib.h>
#include <wx/textctrl.h>

#include "BitOffset.hpp"

namespace REHex {
	/**
	 * @brief Text control for entering numeric types.
	 *
	 * This control is based on wxTextCtrl, look there for most documentation.
	*/
	class NumericTextCtrl: public wxTextCtrl
	{
		using wxTextCtrl::wxTextCtrl; /* Inherit wxTextCtrl c'tors */
		
		public:
			/**
			 * @brief Base class of input exceptions thrown by NumericTextCtrl.
			*/
			class InputError: public std::runtime_error
			{
				protected:
					InputError(const char *what): runtime_error(what) {}
			};
			
			/**
			 * @brief Exception thrown by NumericTextCtrl when the input value is out of range.
			*/
			class RangeError: public InputError
			{
				public:
					RangeError(): InputError("Number is out of range") {}
			};
			
			/**
			 * @brief Exception thrown by NumericTextCtrl when the input value is not in a known format.
			*/
			class FormatError: public InputError
			{
				public:
					FormatError(): InputError("Number is not of a known format") {}
			};
			
			/**
			 * @brief Exception thrown by NumericTextCtrl when the input value is empty.
			*/
			class EmptyError: public InputError
			{
				public:
					EmptyError(): InputError("No number provided") {}
			};
			
			/**
			 * @brief Parse a numeric string value.
			 *
			 * @param sval      String to parse.
			 * @param min       Minium permissable value.
			 * @param max       Maximum permissable value.
			 * @param rel_base  Value to be added to sval, before min/max check
			 * @param base      Base to parse sval as (0 = any, 8 = oct, 10 = dec, 16 = hex)
			 *
			 * Parses a numeric string value and returns the result.
			 *
			 * On error throws an exception of type NumericTextCtrl::InputError.
			*/
			template<typename T>
				typename std::enable_if<std::numeric_limits<T>::is_integer && std::numeric_limits<T>::is_signed, T>::type
				static ParseValue(std::string sval, T min = std::numeric_limits<T>::min(), T max = std::numeric_limits<T>::max(), T rel_base = 0, int base = 0)
			{
				static_assert(std::numeric_limits<T>::is_integer, "GetValue() instantiated with non-integer type");
				
				if(sval.length() == 0)
				{
					/* String is empty */
					throw EmptyError();
				}
				
				if(sval.find_first_not_of("\t ") == std::string::npos)
				{
					/* String contains only whitespace */
					throw EmptyError();
				}
				
				errno = 0;
				char *endptr;
				
				long long int ival = strtoll(sval.c_str(), &endptr, base);
				if(*endptr != '\0')
				{
					/* Invalid characters */
					throw FormatError();
				}
				if((ival == LLONG_MIN || ival == LLONG_MAX) && errno == ERANGE)
				{
					/* Out of range of long long */
					throw RangeError();
				}
				
				if(sval.find_first_of("+-") != std::string::npos)
				{
					if(ival > 0 && rel_base > 0)
					{
						if((LLONG_MAX - rel_base) < ival)
						{
							/* rel_base + ival > LLONG_MAX */
							throw RangeError();
						}
					}
					else if(ival < 0 && rel_base < 0)
					{
						if((LLONG_MIN - rel_base) > ival)
						{
							/* rel_base + ival < LLONG_MIN */
							throw RangeError();
						}
					}
					
					ival += rel_base;
				}
				
				if(ival < min || ival > max)
				{
					/* Out of range of T or constraint */
					throw RangeError();
				}
				
				return ival;
			}
			
			template<typename T>
				typename std::enable_if<std::numeric_limits<T>::is_integer && !std::numeric_limits<T>::is_signed, T>::type
				static ParseValue(std::string sval, T min = std::numeric_limits<T>::min(), T max = std::numeric_limits<T>::max(), T rel_base = 0, int base = 0)
			{
				static_assert(std::numeric_limits<T>::is_integer, "GetValue() instantiated with non-integer type");
				
				if(sval.length() == 0)
				{
					/* String is empty */
					throw EmptyError();
				}
				
				/* Remove leading whitespace */
				sval.erase(0, strspn(sval.c_str(), "\t "));
				
				if(sval.empty())
				{
					/* String is empty */
					throw EmptyError();
				}
				
				bool rel_neg = (sval.at(0) == '-');
				bool rel_pos = (sval.at(0) == '+');
				
				if(rel_neg || rel_pos)
				{
					sval.erase(0, 1);
					
					if(sval.empty())
					{
						/* That was the only non-whitespace character. */
						throw FormatError();
					}
				}
				
				if(sval.find_first_of("+-\t ") != std::string::npos)
				{
					throw FormatError();
				}
				
				errno = 0;
				char *endptr;
				
				unsigned long long int ival = strtoull(sval.c_str(), &endptr, base);
				if(*endptr != '\0')
				{
					/* Invalid characters */
					throw FormatError();
				}
				if(ival == ULLONG_MAX && errno == ERANGE)
				{
					/* Out of range of long long */
					throw RangeError();
				}
				
				if(rel_neg)
				{
					if(ival > rel_base)
					{
						/* rel_base - ival < 0 */
						throw RangeError();
					}
					else{
						ival = rel_base - ival;
					}
				}
				else if(rel_pos)
				{
					if((ULLONG_MAX - rel_base) < ival)
					{
						/* rel_base + ival > ULLONG_MAX */
						throw RangeError();
					}
					else{
						ival += rel_base;
					}
				}
				
				if(ival < min || ival > max)
				{
					/* Out of range of T or constraint */
					throw RangeError();
				}
				
				return ival;
			}
			
			template<typename T>
				typename std::enable_if<std::is_same<T, BitOffset>::value, T>::type
				static ParseValue(std::string sval, T min = BitOffset::MIN, T max = BitOffset::MAX, T rel_base = BitOffset::ZERO, int base = 0, bool *bit_explicit = NULL)
			{
				if(sval.length() == 0)
				{
					/* String is empty */
					throw EmptyError();
				}
				
				if(sval.find_first_not_of("\t ") == std::string::npos)
				{
					/* String contains only whitespace */
					throw EmptyError();
				}
				
				errno = 0;
				char *endptr;
				
				int bit = 0;
				
				long long int ival = strtoll(sval.c_str(), &endptr, base);
				
				if(endptr[0] == '+' && endptr[1] >= '0' && endptr[1] <= '7')
				{
					bit = endptr[1] - '0';
					endptr += 2;
					
					if(*endptr == 'b')
					{
						++endptr;
					}
					
					if(bit_explicit != NULL)
					{
						*bit_explicit = true;
					}
				}
				else{
					if(bit_explicit != NULL)
					{
						*bit_explicit = false;
					}
				}
				
				if(*endptr != '\0')
				{
					/* Invalid characters */
					throw FormatError();
				}
				else if((ival == LLONG_MIN || ival == LLONG_MAX) && errno == ERANGE)
				{
					/* Out of range of long long */
					throw RangeError();
				}
				else if(ival < BitOffset::MIN.byte() || ival > BitOffset::MAX.byte())
				{
					/* Out of range of BitOffset */
					throw RangeError();
				}
				
				if(ival < 0)
				{
					bit = -bit;
				}
				
				BitOffset boval(ival, bit);
				
				size_t first_non_space = sval.find_first_not_of(" \t");
				assert(first_non_space != std::string::npos);
				
				if(sval[first_non_space] == '+' || sval[first_non_space] == '-')
				{
					if(boval > BitOffset::ZERO && rel_base > BitOffset::ZERO)
					{
						if((BitOffset::MAX - rel_base) < boval)
						{
							/* rel_base + ival > LLONG_MAX */
							throw RangeError();
						}
					}
					else if(boval < BitOffset::ZERO && rel_base < BitOffset::ZERO)
					{
						if((BitOffset::MIN - rel_base) > boval)
						{
							/* rel_base + ival < LLONG_MIN */
							throw RangeError();
						}
					}
					
					boval += rel_base;
				}
				
				return boval;
			}
			
			/**
			 * @brief Parse the control value and return as a number.
			 *
			 * @param min       Minium permissable value.
			 * @param max       Maximum permissable value.
			 * @param rel_base  Value to be added to sval, before min/max check
			 * @param base      Base to parse input as (0 = any, 8 = oct, 10 = dec, 16 = hex)
			 *
			 * On error throws an exception of type NumericTextCtrl::InputError.
			*/
			
			template<typename T>
				typename std::enable_if<std::numeric_limits<T>::is_integer, T>::type
				GetValue(T min = std::numeric_limits<T>::min(), T max = std::numeric_limits<T>::max(), T rel_base = 0, int base = 0)
			{
				std::string sval = wxTextCtrl::GetValue().ToStdString();
				return ParseValue<T>(sval, min, max, rel_base, base);
			}
			
			template<typename T>
				typename std::enable_if<std::is_same<T, BitOffset>::value, T>::type
				GetValue(T min = BitOffset::MIN, T max = BitOffset::MAX, T rel_base = BitOffset::ZERO, int base = 0, bool *bit_explicit = NULL)
			{
				std::string sval = wxTextCtrl::GetValue().ToStdString();
				return ParseValue<T>(sval, min, max, rel_base, base, bit_explicit);
			}
			
			wxString GetStringValue() const
			{
				return wxTextCtrl::GetValue();
			}
	};
}

#endif /* !REHEX_NUMERICTEXTCTRL_HPP */
