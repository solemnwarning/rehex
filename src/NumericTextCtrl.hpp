/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018-2019 Daniel Collins <solemnwarning@solemnwarning.net>
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
			class InputError: public std::runtime_error
			{
				protected:
					InputError(const char *what): runtime_error(what) {}
			};
			
			class RangeError: public InputError
			{
				public:
					RangeError(): InputError("Number is out of range") {}
			};
			
			class FormatError: public InputError
			{
				public:
					FormatError(): InputError("Number is not of a known format") {}
			};
			
			class EmptyError: public InputError
			{
				public:
					EmptyError(): InputError("No number provided") {}
			};
			
			template<typename T>
				typename std::enable_if<std::numeric_limits<T>::is_signed, T>::type
				GetValue(T min = std::numeric_limits<T>::min(), T max = std::numeric_limits<T>::max())
			{
				static_assert(std::numeric_limits<T>::is_integer, "GetValue() instantiated with non-integer type");
				
				std::string sval = wxTextCtrl::GetValue().ToStdString();
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
				
				if(ival < min || ival > max)
				{
					/* Out of range of T or constraint */
					throw RangeError();
				}
				
				return ival;
			}
			
			template<typename T>
				typename std::enable_if<!std::numeric_limits<T>::is_signed, T>::type
				GetValue(T min = std::numeric_limits<T>::min(), T max = std::numeric_limits<T>::max())
			{
				static_assert(std::numeric_limits<T>::is_integer, "GetValue() instantiated with non-integer type");
				
				std::string sval = wxTextCtrl::GetValue().ToStdString();
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
				
				if(ival < min || ival > max)
				{
					/* Out of range of T or constraint */
					throw RangeError();
				}
				
				return ival;
			}
	};
}

#endif /* !REHEX_NUMERICTEXTCTRL_HPP */
