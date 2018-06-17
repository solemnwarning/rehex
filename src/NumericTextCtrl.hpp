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

#ifndef REHEX_NUMERICTEXTCTRL_HPP
#define REHEX_NUMERICTEXTCTRL_HPP

#include <stdexcept>
#include <stdlib.h>
#include <wx/textctrl.h>

namespace REHex {
	class NumericTextCtrl: public wxTextCtrl
	{
		using wxTextCtrl::wxTextCtrl; /* Inherit wxTextCtrl c'tors */
		
		public:
			class RangeError: public std::runtime_error
			{
				public:
					RangeError(): runtime_error("Number is out of range") {}
			};
			
			class FormatError: public std::runtime_error
			{
				public:
					FormatError(): runtime_error("Number is not of a known format") {}
			};
			
			class EmptyError: public std::runtime_error
			{
				public:
					EmptyError(): runtime_error("No number provided") {}
			};
			
			template<typename T> T GetValueSigned()
			{
				static_assert(std::numeric_limits<T>::is_integer, "GetValueSigned() instantiated with non-integer type");
				static_assert(std::numeric_limits<T>::is_signed,  "GetValueSigned() instantiated with unsigned type");
				
				std::string sval = GetValue().ToStdString();
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
				
				long long int ival = strtoll(sval.c_str(), &endptr, 0);
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
				
				if(ival < std::numeric_limits<T>::min() || ival > std::numeric_limits<T>::max())
				{
					/* Out of range of T */
					throw RangeError();
				}
				
				return ival;
			}
			
			template<typename T> T GetValueUnsigned()
			{
				static_assert(std::numeric_limits<T>::is_integer, "GetValueUnsigned() instantiated with non-integer type");
				static_assert(!std::numeric_limits<T>::is_signed, "GetValueUnsigned() instantiated with signed type");
				
				std::string sval = GetValue().ToStdString();
				if(sval.length() == 0)
				{
					/* String is empty */
					throw EmptyError();
				}
				
				size_t first_non_space = sval.find_first_not_of("\t ");
				
				if(first_non_space == std::string::npos)
				{
					/* String contains only whitespace */
					throw EmptyError();
				}
				
				if(sval.at(first_non_space) == '-')
				{
					/* Negative numbers not welcome here, NEXT! */
					throw RangeError();
				}
				
				errno = 0;
				char *endptr;
				
				unsigned long long int ival = strtoull(sval.c_str(), &endptr, 0);
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
				
				if(ival < std::numeric_limits<T>::min() || ival > std::numeric_limits<T>::max())
				{
					/* Out of range of T */
					throw RangeError();
				}
				
				return ival;
			}
	};
}

#endif /* !REHEX_NUMERICTEXTCTRL_HPP */
