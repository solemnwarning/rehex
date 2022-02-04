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

#include "../src/platform.hpp"
#include <gtest/gtest.h>
#include <stdint.h>
#include <stdio.h>
#include <typeinfo>
#include <wx/init.h>
#include <wx/wx.h>

#include "../src/NumericTextCtrl.hpp"

#define GV_RESULT(value_type, string_value, type_value) \
{ \
	const char *test_name = "GetValue<" #value_type "> on a value of " #string_value " returns " #type_value; \
	\
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests")); \
	REHex::NumericTextCtrl *tc = new REHex::NumericTextCtrl(&frame, wxID_ANY); \
	\
	tc->SetValue(string_value); \
	\
	EXPECT_NO_THROW({ \
		value_type v = tc->GetValue<value_type>(); \
		EXPECT_EQ(v, type_value) << test_name; \
	}) << test_name; \
}

#define GV_THROWS(value_type, string_value, exception_class) \
{ \
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests")); \
	REHex::NumericTextCtrl *tc = new REHex::NumericTextCtrl(&frame, wxID_ANY); \
	\
	tc->SetValue(string_value); \
	\
	EXPECT_THROW({ tc->GetValue<value_type>(); }, exception_class) << \
		"GetValue<" #value_type "> on a value of \"" string_value "\" throws " #exception_class; \
}

#define GV_RESULT2(value_type, min, max, rel, string_value, type_value) \
{ \
	const char *test_name = "GetValue<" #value_type "> on a value of " #string_value " returns " #type_value; \
	\
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests")); \
	REHex::NumericTextCtrl *tc = new REHex::NumericTextCtrl(&frame, wxID_ANY); \
	\
	tc->SetValue(string_value); \
	\
	EXPECT_NO_THROW({ \
		value_type v = tc->GetValue<value_type>(min, max, rel); \
		EXPECT_EQ(v, type_value) << test_name; \
	}) << test_name; \
}

#define GV_THROWS2(value_type, min, max, rel, string_value, exception_class) \
{ \
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests")); \
	REHex::NumericTextCtrl *tc = new REHex::NumericTextCtrl(&frame, wxID_ANY); \
	\
	tc->SetValue(string_value); \
	\
	EXPECT_THROW({ tc->GetValue<value_type>(min, max, rel); }, exception_class) << \
		"GetValue<" #value_type "> on a value of \"" string_value "\" throws " #exception_class; \
}

TEST(NumericTextCtrl, GetValue)
{
	GV_RESULT(int8_t,    "0", 0);
	GV_RESULT(int8_t, "-128", -128);
	GV_THROWS(int8_t, "-129", REHex::NumericTextCtrl::RangeError);
	GV_RESULT(int8_t,  "127", 127);
	GV_THROWS(int8_t,  "128", REHex::NumericTextCtrl::RangeError);
	
	GV_RESULT(int8_t,   "0x0", 0);
	GV_RESULT(int8_t, "-0x80", -128);
	GV_THROWS(int8_t, "-0x81", REHex::NumericTextCtrl::RangeError);
	GV_RESULT(int8_t,  "0x7F", 127);
	GV_THROWS(int8_t,  "0x80", REHex::NumericTextCtrl::RangeError);
	GV_THROWS(int8_t,    "7F", REHex::NumericTextCtrl::FormatError);
	
	GV_RESULT(int8_t,    "00", 0);
	GV_RESULT(int8_t, "-0200", -128);
	GV_THROWS(int8_t, "-0201", REHex::NumericTextCtrl::RangeError);
	GV_RESULT(int8_t,  "0177", 127);
	GV_THROWS(int8_t,  "0200", REHex::NumericTextCtrl::RangeError);
	GV_THROWS(int8_t,  "08",   REHex::NumericTextCtrl::FormatError);
	
	GV_RESULT(int16_t,      "0", 0);
	GV_RESULT(int16_t, "-32768", -32768);
	GV_THROWS(int16_t, "-32769", REHex::NumericTextCtrl::RangeError);
	GV_RESULT(int16_t,  "32767", 32767);
	GV_THROWS(int16_t,  "32768", REHex::NumericTextCtrl::RangeError);
	
	GV_RESULT(int16_t,     "0x0", 0);
	GV_RESULT(int16_t, "-0x8000", -32768);
	GV_THROWS(int16_t, "-0x8001", REHex::NumericTextCtrl::RangeError);
	GV_RESULT(int16_t,  "0x7FFF", 32767);
	GV_THROWS(int16_t,  "0x8000", REHex::NumericTextCtrl::RangeError);
	
	GV_RESULT(int16_t,       "00", 0);
	GV_RESULT(int16_t, "-0100000", -32768);
	GV_THROWS(int16_t, "-0100001", REHex::NumericTextCtrl::RangeError);
	GV_RESULT(int16_t,   "077777", 32767);
	GV_THROWS(int16_t,  "0100000", REHex::NumericTextCtrl::RangeError);
	
	GV_RESULT(int32_t,           "0", 0);
	GV_RESULT(int32_t, "-2147483648", -2147483648);
	GV_THROWS(int32_t, "-2147483649", REHex::NumericTextCtrl::RangeError);
	GV_RESULT(int32_t,  "2147483647", 2147483647);
	GV_THROWS(int32_t,  "2147483648", REHex::NumericTextCtrl::RangeError);
	
	GV_RESULT(int32_t,         "0x0", 0);
	GV_RESULT(int32_t, "-0x80000000", -2147483648);
	GV_THROWS(int32_t, "-0x80000001", REHex::NumericTextCtrl::RangeError);
	GV_RESULT(int32_t,  "0x7FFFFFFF", 2147483647);
	GV_THROWS(int32_t,  "0x80000000", REHex::NumericTextCtrl::RangeError);
	
	GV_RESULT(int32_t,            "00", 0);
	GV_RESULT(int32_t, "-020000000000", -2147483648);
	GV_THROWS(int32_t, "-020000000001", REHex::NumericTextCtrl::RangeError);
	GV_RESULT(int32_t,  "017777777777", 2147483647);
	GV_THROWS(int32_t,  "020000000000", REHex::NumericTextCtrl::RangeError);
	
	/* See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=55540 for why the
	 * minimum value of an int64_t is written in such a strange way.
	*/
	
	GV_RESULT(int64_t,                    "0", 0);
	GV_RESULT(int64_t, "-9223372036854775808", -9223372036854775807LL - 1LL);
	GV_THROWS(int64_t, "-9223372036854775809", REHex::NumericTextCtrl::RangeError);
	GV_RESULT(int64_t,  "9223372036854775807", 9223372036854775807LL);
	GV_THROWS(int64_t,  "9223372036854775808", REHex::NumericTextCtrl::RangeError);
	
	GV_RESULT(int64_t,                 "0x0", 0);
	GV_RESULT(int64_t, "-0x8000000000000000", -9223372036854775807LL - 1LL);
	GV_THROWS(int64_t, "-0x8000000000000001", REHex::NumericTextCtrl::RangeError);
	GV_RESULT(int64_t,  "0x7FFFFFFFFFFFFFFF", 9223372036854775807LL);
	GV_THROWS(int64_t,  "0x8000000000000000", REHex::NumericTextCtrl::RangeError);
	
	GV_RESULT(int64_t,                       "00", 0);
	GV_RESULT(int64_t, "-01000000000000000000000", -9223372036854775807LL - 1LL);
	GV_THROWS(int64_t, "-01000000000000000000001", REHex::NumericTextCtrl::RangeError);
	GV_RESULT(int64_t,   "0777777777777777777777", 9223372036854775807LL);
	GV_THROWS(int64_t,  "01000000000000000000000", REHex::NumericTextCtrl::RangeError);
	
	GV_THROWS(int, "",    REHex::NumericTextCtrl::EmptyError);
	GV_THROWS(int, " ",   REHex::NumericTextCtrl::EmptyError);
	GV_THROWS(int, "\t",  REHex::NumericTextCtrl::EmptyError);
	GV_THROWS(int, "0.",  REHex::NumericTextCtrl::FormatError);
	GV_THROWS(int, "0.0", REHex::NumericTextCtrl::FormatError);
	
	GV_RESULT(uint8_t,   "0", 0);
	GV_THROWS(uint8_t,  "-1", REHex::NumericTextCtrl::RangeError);
	GV_RESULT(uint8_t, "255", 0xFF);
	GV_THROWS(uint8_t, "256", REHex::NumericTextCtrl::RangeError);
	
	GV_RESULT(uint8_t,    "0x0", 0);
	GV_THROWS(uint8_t,   "-0x1", REHex::NumericTextCtrl::RangeError);
	GV_RESULT(uint8_t,   "0xFF", 0xFF);
	GV_THROWS(uint8_t,  "0x100", REHex::NumericTextCtrl::RangeError);
	GV_THROWS(uint8_t,     "7F", REHex::NumericTextCtrl::FormatError);
	
	GV_RESULT(uint8_t,   "00", 0);
	GV_THROWS(uint8_t,  "-01", REHex::NumericTextCtrl::RangeError);
	GV_RESULT(uint8_t, "0377", 0xFF);
	GV_THROWS(uint8_t, "0400", REHex::NumericTextCtrl::RangeError);
	GV_THROWS(uint8_t,   "08", REHex::NumericTextCtrl::FormatError);
	
	GV_RESULT(uint16_t,      "0", 0);
	GV_THROWS(uint16_t,     "-1", REHex::NumericTextCtrl::RangeError);
	GV_RESULT(uint16_t,  "65535", 0xFFFF);
	GV_THROWS(uint16_t,  "65536", REHex::NumericTextCtrl::RangeError);
	
	GV_RESULT(uint16_t,      "0x0", 0);
	GV_THROWS(uint16_t,     "-0x1", REHex::NumericTextCtrl::RangeError);
	GV_RESULT(uint16_t,   "0xFFFF", 0xFFFF);
	GV_THROWS(uint16_t,  "0x10000", REHex::NumericTextCtrl::RangeError);
	
	GV_RESULT(uint16_t,       "00", 0);
	GV_THROWS(uint16_t,      "-01", REHex::NumericTextCtrl::RangeError);
	GV_RESULT(uint16_t,  "0177777", 0xFFFF);
	GV_THROWS(uint16_t,  "0200000", REHex::NumericTextCtrl::RangeError);
	
	GV_RESULT(uint32_t,           "0", 0U);
	GV_THROWS(uint32_t,          "-1", REHex::NumericTextCtrl::RangeError);
	GV_RESULT(uint32_t,  "4294967295", 0xFFFFFFFF);
	GV_THROWS(uint32_t,  "4294967296", REHex::NumericTextCtrl::RangeError);
	
	GV_RESULT(uint32_t,         "0x0", 0U);
	GV_THROWS(uint32_t,        "-0x1", REHex::NumericTextCtrl::RangeError);
	GV_RESULT(uint32_t,  "0xFFFFFFFF", 0xFFFFFFFF);
	GV_THROWS(uint32_t, "0x100000000", REHex::NumericTextCtrl::RangeError);
	
	GV_RESULT(uint32_t,            "00", 0U);
	GV_THROWS(uint32_t,           "-01", REHex::NumericTextCtrl::RangeError);
	GV_RESULT(uint32_t,  "037777777777", 0xFFFFFFFF);
	GV_THROWS(uint32_t,  "040000000000", REHex::NumericTextCtrl::RangeError);
	
	GV_RESULT(uint64_t,                     "0", 0ULL);
	GV_THROWS(uint64_t,                    "-1", REHex::NumericTextCtrl::RangeError);
	GV_RESULT(uint64_t,  "18446744073709551615", 0xFFFFFFFFFFFFFFFFULL);
	GV_THROWS(uint64_t,  "18446744073709551616", REHex::NumericTextCtrl::RangeError);
	
	GV_RESULT(uint64_t,                 "0x0", 0ULL);
	GV_THROWS(uint64_t,                "-0x1", REHex::NumericTextCtrl::RangeError);
	GV_RESULT(uint64_t,  "0xFFFFFFFFFFFFFFFF", 0xFFFFFFFFFFFFFFFFULL);
	GV_THROWS(uint64_t, "0x10000000000000000", REHex::NumericTextCtrl::RangeError);
	
	GV_RESULT(uint64_t,                      "00", 0ULL);
	GV_THROWS(uint64_t,                     "-01", REHex::NumericTextCtrl::RangeError);
	GV_RESULT(uint64_t, "01777777777777777777777", 0xFFFFFFFFFFFFFFFFULL);
	GV_THROWS(uint64_t, "02000000000000000000000", REHex::NumericTextCtrl::RangeError);
	
	GV_THROWS(unsigned, "",    REHex::NumericTextCtrl::EmptyError);
	GV_THROWS(unsigned, " ",   REHex::NumericTextCtrl::EmptyError);
	GV_THROWS(unsigned, "\t",  REHex::NumericTextCtrl::EmptyError);
	GV_THROWS(unsigned, "0.",  REHex::NumericTextCtrl::FormatError);
	GV_THROWS(unsigned, "0.0", REHex::NumericTextCtrl::FormatError);
	
	/* Relative values */
	
	GV_RESULT2(unsigned long long, 0, ULLONG_MAX,  0,   "0",                  0U);
	GV_RESULT2(unsigned long long, 0, ULLONG_MAX,  0,  "-0",                  0U);
	GV_THROWS2(unsigned long long, 0, ULLONG_MAX,  0,  "-1",                  REHex::NumericTextCtrl::RangeError);
	GV_RESULT2(unsigned long long, 0, ULLONG_MAX,  0,  "+0",                  0U);
	GV_RESULT2(unsigned long long, 0, ULLONG_MAX,  0,  "+0xFFFFFFFFFFFFFFFF", 0xFFFFFFFFFFFFFFFFULL);
	
	GV_RESULT2(unsigned long long, 0, ULLONG_MAX, 10,  "0",                   0U);
	GV_RESULT2(unsigned long long, 0, ULLONG_MAX, 10,  "5",                   5U);
	GV_RESULT2(unsigned long long, 0, ULLONG_MAX, 10, "+0",                  10U);
	GV_RESULT2(unsigned long long, 0, ULLONG_MAX, 10, "-0",                  10U);
	GV_RESULT2(unsigned long long, 0, ULLONG_MAX, 10, "+5",                  15U);
	GV_RESULT2(unsigned long long, 0, ULLONG_MAX, 10, "-5",                   5U);
	GV_RESULT2(unsigned long long, 0, ULLONG_MAX, 10, "-10",                  0U);
	GV_THROWS2(unsigned long long, 0, ULLONG_MAX, 10, "-11",                 REHex::NumericTextCtrl::RangeError);
	GV_RESULT2(unsigned long long, 0, ULLONG_MAX, 10, "+0xFFFFFFFFFFFFFFF5", 0xFFFFFFFFFFFFFFFFULL);
	GV_THROWS2(unsigned long long, 0, ULLONG_MAX, 10, "+0xFFFFFFFFFFFFFFF6", REHex::NumericTextCtrl::RangeError);
	
	GV_RESULT2(long long, LLONG_MIN, LLONG_MAX,  0,  "0",                                     0);
	GV_RESULT2(long long, LLONG_MIN, LLONG_MAX, 10,  "0",                                     0);
	GV_RESULT2(long long, LLONG_MIN, LLONG_MAX, 10,  "5",                                     5);
	GV_RESULT2(long long, LLONG_MIN, LLONG_MAX, 10, "+0",                                    10);
	GV_RESULT2(long long, LLONG_MIN, LLONG_MAX, 10, "-0",                                    10);
	GV_RESULT2(long long, LLONG_MIN, LLONG_MAX, 10, "+5",                                    15);
	GV_RESULT2(long long, LLONG_MIN, LLONG_MAX, 10, "-5",                                     5);
	GV_RESULT2(long long, LLONG_MIN, LLONG_MAX, 10, "-11",                                   -1);
	GV_RESULT2(long long, LLONG_MIN, LLONG_MAX, 10, "+9223372036854775797", 9223372036854775807LL);
	GV_THROWS2(long long, LLONG_MIN, LLONG_MAX, 10, "+9223372036854775798", REHex::NumericTextCtrl::RangeError);
	GV_RESULT2(long long, LLONG_MIN, LLONG_MAX, 10, "-9223372036854775808", -9223372036854775798LL);
	
	GV_RESULT2(long long, LLONG_MIN, LLONG_MAX,   0,  "0",                                      0);
	GV_RESULT2(long long, LLONG_MIN, LLONG_MAX, -10,  "0",                                      0);
	GV_RESULT2(long long, LLONG_MIN, LLONG_MAX, -10,  "5",                                      5);
	GV_RESULT2(long long, LLONG_MIN, LLONG_MAX, -10, "+0",                                    -10);
	GV_RESULT2(long long, LLONG_MIN, LLONG_MAX, -10, "-0",                                    -10);
	GV_RESULT2(long long, LLONG_MIN, LLONG_MAX, -10, "+5",                                     -5);
	GV_RESULT2(long long, LLONG_MIN, LLONG_MAX, -10, "-5",                                    -15);
	GV_RESULT2(long long, LLONG_MIN, LLONG_MAX, -10, "-9223372036854775798", -9223372036854775807LL - 1LL);
	GV_THROWS2(long long, LLONG_MIN, LLONG_MAX, -10, "-9223372036854775799", REHex::NumericTextCtrl::RangeError);
}
