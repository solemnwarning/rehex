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

#include "../src/util.hpp"

#define PARSE_ASCII_NIBBLE_OK(c, expect) \
{ \
	EXPECT_NO_THROW({ \
		unsigned char r = REHex::parse_ascii_nibble(c); \
		EXPECT_EQ(r, expect) << "REHex::parse_ascii_nibble("  << c << ") returns correct value"; \
	}) << "REHex::parse_ascii_nibble(" << c << ") doesn't throw"; \
}

#define PARSE_ASCII_NIBBLE_BAD(c) \
	EXPECT_THROW(REHex::parse_ascii_nibble((char)c), REHex::ParseError) << "REHex::parse_ascii_nibble(" << c << ") throws ParseError";

#define PARSE_HEX_STRING_OK(hex, ...) \
{ \
	std::vector<unsigned char> expect_data( { __VA_ARGS__ } ); \
	\
	EXPECT_NO_THROW({ \
		std::vector<unsigned char> got_data = REHex::parse_hex_string(hex); \
		EXPECT_EQ(got_data, expect_data) << "REHex::parse_hex_string(" #hex ") returns correct data"; \
	}) << "REHex::parse_hex_string(" << #hex << ") doesn't throw"; \
}

#define PARSE_HEX_STRING_BAD(hex) \
	EXPECT_THROW(REHex::parse_hex_string(hex), REHex::ParseError) << "REHex::parse_hex_string(" #hex ") throws ParseError";

using namespace REHex;

TEST(Util, parse_ascii_nibble)
{
	PARSE_ASCII_NIBBLE_BAD('\0');
	
	PARSE_ASCII_NIBBLE_BAD('/');
	PARSE_ASCII_NIBBLE_OK ('0', 0x0);
	PARSE_ASCII_NIBBLE_OK ('1', 0x1);
	PARSE_ASCII_NIBBLE_OK ('2', 0x2);
	PARSE_ASCII_NIBBLE_OK ('3', 0x3);
	PARSE_ASCII_NIBBLE_OK ('4', 0x4);
	PARSE_ASCII_NIBBLE_OK ('5', 0x5);
	PARSE_ASCII_NIBBLE_OK ('6', 0x6);
	PARSE_ASCII_NIBBLE_OK ('7', 0x7);
	PARSE_ASCII_NIBBLE_OK ('8', 0x8);
	PARSE_ASCII_NIBBLE_OK ('9', 0x9);
	PARSE_ASCII_NIBBLE_BAD(':');
	
	PARSE_ASCII_NIBBLE_BAD('@');
	PARSE_ASCII_NIBBLE_OK ('A', 0xA);
	PARSE_ASCII_NIBBLE_OK ('B', 0xB);
	PARSE_ASCII_NIBBLE_OK ('C', 0xC);
	PARSE_ASCII_NIBBLE_OK ('D', 0xD);
	PARSE_ASCII_NIBBLE_OK ('E', 0xE);
	PARSE_ASCII_NIBBLE_OK ('F', 0xF);
	PARSE_ASCII_NIBBLE_BAD('G');
	
	PARSE_ASCII_NIBBLE_BAD('`');
	PARSE_ASCII_NIBBLE_OK ('a', 0xA);
	PARSE_ASCII_NIBBLE_OK ('b', 0xB);
	PARSE_ASCII_NIBBLE_OK ('c', 0xC);
	PARSE_ASCII_NIBBLE_OK ('d', 0xD);
	PARSE_ASCII_NIBBLE_OK ('e', 0xE);
	PARSE_ASCII_NIBBLE_OK ('f', 0xF);
	PARSE_ASCII_NIBBLE_BAD('g');
	
	PARSE_ASCII_NIBBLE_BAD(0xFF);
}

TEST(Util, parse_hex_string)
{
	PARSE_HEX_STRING_OK("");
	PARSE_HEX_STRING_OK(" ");
	PARSE_HEX_STRING_OK("\t");
	PARSE_HEX_STRING_OK("\r");
	PARSE_HEX_STRING_OK("\n");
	
	PARSE_HEX_STRING_OK("00",     0x00);
	PARSE_HEX_STRING_OK("1002",   0x10, 0x02);
	PARSE_HEX_STRING_OK("AAFF",   0xAA, 0xFF);
	PARSE_HEX_STRING_OK(" AAFF",  0xAA, 0xFF);
	PARSE_HEX_STRING_OK("AA FF",  0xAA, 0xFF);
	PARSE_HEX_STRING_OK("AA FF ", 0xAA, 0xFF);
	PARSE_HEX_STRING_OK("AAF F",  0xAA, 0xFF);
	PARSE_HEX_STRING_OK("A AFF",  0xAA, 0xFF);
	
	PARSE_HEX_STRING_OK("0123456789ABCDEFabcdef",
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF);
	
	PARSE_HEX_STRING_BAD("A");
	PARSE_HEX_STRING_BAD("AA B");
	PARSE_HEX_STRING_BAD("A BB");
	PARSE_HEX_STRING_BAD("ABB");
	
	PARSE_HEX_STRING_BAD("/");
	PARSE_HEX_STRING_BAD(":");
	PARSE_HEX_STRING_BAD("@");
	PARSE_HEX_STRING_BAD("G");
	PARSE_HEX_STRING_BAD("`");
	PARSE_HEX_STRING_BAD("g");
}

TEST(Util, format_offset)
{
	EXPECT_EQ(format_offset(0, OFFSET_BASE_HEX, 0), "0000:0000");
	EXPECT_EQ(format_offset(0, OFFSET_BASE_DEC, 0), "0000000000");
	
	EXPECT_EQ(format_offset( 0xABCDEF10LL, OFFSET_BASE_HEX,         0x0LL),         "ABCD:EF10");
	EXPECT_EQ(format_offset( 0xABCDEF10LL, OFFSET_BASE_HEX,  0xFFFFFFFFLL),         "ABCD:EF10");
	EXPECT_EQ(format_offset( 0xABCDEF10LL, OFFSET_BASE_HEX, 0x100000000LL), "00000000:ABCDEF10");
	EXPECT_EQ(format_offset( 0xFFFFFFFFLL, OFFSET_BASE_HEX,         0x0LL),         "FFFF:FFFF");
	EXPECT_EQ(format_offset(0x100000000LL, OFFSET_BASE_HEX,         0x0LL), "00000001:00000000");
	
	EXPECT_EQ(format_offset(1234567890LL, OFFSET_BASE_DEC,          0LL),          "1234567890");
	EXPECT_EQ(format_offset(1234567890LL, OFFSET_BASE_DEC, 4294967295LL),          "1234567890");
	EXPECT_EQ(format_offset(1234567890LL, OFFSET_BASE_DEC, 4294967296LL), "0000000001234567890");
	EXPECT_EQ(format_offset(4294967295LL, OFFSET_BASE_DEC,          0LL),          "4294967295");
	EXPECT_EQ(format_offset(4294967296LL, OFFSET_BASE_DEC,          0LL), "0000000004294967296");
}

#define TEST_ADD_CLAMP_OVERFLOW(a, b, result, expect_overflow) \
	EXPECT_EQ(add_clamp_overflow<int>(a, b), result); \
	EXPECT_EQ(add_clamp_overflow<int>(a, b, &overflow_detected), result); \
	EXPECT_EQ(overflow_detected, expect_overflow);\
	\
	EXPECT_EQ(add_clamp_overflow<int>(b, a), result); \
	EXPECT_EQ(add_clamp_overflow<int>(b, a, &overflow_detected), result); \
	EXPECT_EQ(overflow_detected, expect_overflow);

TEST(Util, add_clamp_overflow)
{
	bool overflow_detected;
	
	TEST_ADD_CLAMP_OVERFLOW(      1,    1,       2, false);
	TEST_ADD_CLAMP_OVERFLOW(     10,    1,      11, false);
	TEST_ADD_CLAMP_OVERFLOW(1000000,    1, 1000001, false);
	TEST_ADD_CLAMP_OVERFLOW(   -100,  200,     100, false);
	TEST_ADD_CLAMP_OVERFLOW(   -100, -100,    -200, false);
	TEST_ADD_CLAMP_OVERFLOW(   -100,    0,    -100, false);
	TEST_ADD_CLAMP_OVERFLOW(      0,    0,       0, false);
	
	TEST_ADD_CLAMP_OVERFLOW(INT_MAX,            0,  INT_MAX,      false);
	TEST_ADD_CLAMP_OVERFLOW(INT_MAX,            1,  INT_MAX,      true);
	TEST_ADD_CLAMP_OVERFLOW(INT_MAX - 1,        0,  INT_MAX - 1,  false);
	TEST_ADD_CLAMP_OVERFLOW(INT_MAX - 1,        1,  INT_MAX,      false);
	TEST_ADD_CLAMP_OVERFLOW(INT_MAX - 1,        2,  INT_MAX,      true);
	TEST_ADD_CLAMP_OVERFLOW(INT_MAX,           -1,  INT_MAX - 1,  false);
	TEST_ADD_CLAMP_OVERFLOW(INT_MAX,      INT_MAX,  INT_MAX,      true);
	
	TEST_ADD_CLAMP_OVERFLOW(INT_MIN,            0,  INT_MIN,      false);
	TEST_ADD_CLAMP_OVERFLOW(INT_MIN,           -1,  INT_MIN,      true);
	TEST_ADD_CLAMP_OVERFLOW(INT_MIN + 1,        0,  INT_MIN + 1,  false);
	TEST_ADD_CLAMP_OVERFLOW(INT_MIN + 1,       -1,  INT_MIN,      false);
	TEST_ADD_CLAMP_OVERFLOW(INT_MIN + 1,       -2,  INT_MIN,      true);
	TEST_ADD_CLAMP_OVERFLOW(INT_MIN,            1,  INT_MIN + 1,  false);
	TEST_ADD_CLAMP_OVERFLOW(INT_MIN,      INT_MIN,  INT_MIN,      true);
	
	TEST_ADD_CLAMP_OVERFLOW(INT_MIN, INT_MAX, -1, false);
}
