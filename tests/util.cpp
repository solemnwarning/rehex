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

#define TEST_ADD_CLAMP_OVERFLOW(T, a, b, result, expect_overflow) \
	EXPECT_EQ(add_clamp_overflow<T>(a, b), result); \
	EXPECT_EQ(add_clamp_overflow<T>(a, b, &overflow_detected), result); \
	EXPECT_EQ(overflow_detected, expect_overflow);\
	\
	EXPECT_EQ(add_clamp_overflow<T>(b, a), result); \
	EXPECT_EQ(add_clamp_overflow<T>(b, a, &overflow_detected), result); \
	EXPECT_EQ(overflow_detected, expect_overflow);

TEST(Util, add_clamp_overflow)
{
	bool overflow_detected;
	
	TEST_ADD_CLAMP_OVERFLOW(int,       1,    1,       2, false);
	TEST_ADD_CLAMP_OVERFLOW(int,      10,    1,      11, false);
	TEST_ADD_CLAMP_OVERFLOW(int, 1000000,    1, 1000001, false);
	TEST_ADD_CLAMP_OVERFLOW(int,    -100,  200,     100, false);
	TEST_ADD_CLAMP_OVERFLOW(int,    -100, -100,    -200, false);
	TEST_ADD_CLAMP_OVERFLOW(int,    -100,    0,    -100, false);
	TEST_ADD_CLAMP_OVERFLOW(int,       0,    0,       0, false);
	
	TEST_ADD_CLAMP_OVERFLOW(int, INT_MAX,            0,  INT_MAX,      false);
	TEST_ADD_CLAMP_OVERFLOW(int, INT_MAX,            1,  INT_MAX,      true);
	TEST_ADD_CLAMP_OVERFLOW(int, INT_MAX - 1,        0,  INT_MAX - 1,  false);
	TEST_ADD_CLAMP_OVERFLOW(int, INT_MAX - 1,        1,  INT_MAX,      false);
	TEST_ADD_CLAMP_OVERFLOW(int, INT_MAX - 1,        2,  INT_MAX,      true);
	TEST_ADD_CLAMP_OVERFLOW(int, INT_MAX,           -1,  INT_MAX - 1,  false);
	TEST_ADD_CLAMP_OVERFLOW(int, INT_MAX,      INT_MAX,  INT_MAX,      true);
	
	TEST_ADD_CLAMP_OVERFLOW(int, INT_MIN,            0,  INT_MIN,      false);
	TEST_ADD_CLAMP_OVERFLOW(int, INT_MIN,           -1,  INT_MIN,      true);
	TEST_ADD_CLAMP_OVERFLOW(int, INT_MIN + 1,        0,  INT_MIN + 1,  false);
	TEST_ADD_CLAMP_OVERFLOW(int, INT_MIN + 1,       -1,  INT_MIN,      false);
	TEST_ADD_CLAMP_OVERFLOW(int, INT_MIN + 1,       -2,  INT_MIN,      true);
	TEST_ADD_CLAMP_OVERFLOW(int, INT_MIN,            1,  INT_MIN + 1,  false);
	TEST_ADD_CLAMP_OVERFLOW(int, INT_MIN,      INT_MIN,  INT_MIN,      true);
	
	TEST_ADD_CLAMP_OVERFLOW(int, INT_MIN, INT_MAX, -1, false);
}

TEST(Util, add_clamp_overflow_BitOffset)
{
	bool overflow_detected;
	
	TEST_ADD_CLAMP_OVERFLOW(BitOffset,       1,    1,       2, false);
	TEST_ADD_CLAMP_OVERFLOW(BitOffset,      10,    1,      11, false);
	TEST_ADD_CLAMP_OVERFLOW(BitOffset, 1000000,    1, 1000001, false);
	TEST_ADD_CLAMP_OVERFLOW(BitOffset,    -100,  200,     100, false);
	TEST_ADD_CLAMP_OVERFLOW(BitOffset,    -100, -100,    -200, false);
	TEST_ADD_CLAMP_OVERFLOW(BitOffset,    -100,    0,    -100, false);
	TEST_ADD_CLAMP_OVERFLOW(BitOffset,       0,    0,       0, false);
	
	TEST_ADD_CLAMP_OVERFLOW(BitOffset, BitOffset::MAX,                   0,  BitOffset::MAX,      false);
	TEST_ADD_CLAMP_OVERFLOW(BitOffset, BitOffset::MAX,                   1,  BitOffset::MAX,      true);
	TEST_ADD_CLAMP_OVERFLOW(BitOffset, BitOffset::MAX - 1,               0,  BitOffset::MAX - 1,  false);
	TEST_ADD_CLAMP_OVERFLOW(BitOffset, BitOffset::MAX - 1,               1,  BitOffset::MAX,      false);
	TEST_ADD_CLAMP_OVERFLOW(BitOffset, BitOffset::MAX - 1,               2,  BitOffset::MAX,      true);
	TEST_ADD_CLAMP_OVERFLOW(BitOffset, BitOffset::MAX,                  -1,  BitOffset::MAX - 1,  false);
	TEST_ADD_CLAMP_OVERFLOW(BitOffset, BitOffset::MAX,      BitOffset::MAX,  BitOffset::MAX,      true);
	
	TEST_ADD_CLAMP_OVERFLOW(BitOffset, BitOffset::MIN,                   0,  BitOffset::MIN,      false);
	TEST_ADD_CLAMP_OVERFLOW(BitOffset, BitOffset::MIN,                  -1,  BitOffset::MIN,      true);
	TEST_ADD_CLAMP_OVERFLOW(BitOffset, BitOffset::MIN + 1,               0,  BitOffset::MIN + 1,  false);
	TEST_ADD_CLAMP_OVERFLOW(BitOffset, BitOffset::MIN + 1,              -1,  BitOffset::MIN,      false);
	TEST_ADD_CLAMP_OVERFLOW(BitOffset, BitOffset::MIN + 1,              -2,  BitOffset::MIN,      true);
	TEST_ADD_CLAMP_OVERFLOW(BitOffset, BitOffset::MIN,                   1,  BitOffset::MIN + 1,  false);
	TEST_ADD_CLAMP_OVERFLOW(BitOffset, BitOffset::MIN,      BitOffset::MIN,  BitOffset::MIN,      true);
	
	TEST_ADD_CLAMP_OVERFLOW(BitOffset, BitOffset::MIN, BitOffset::MAX, BitOffset::ZERO, false);
}

TEST(Util, memcpy_left)
{
	std::vector<unsigned char> src = { 0x7A, 2, 5, 128, 0xFF, 0xFF };
	
	std::vector<unsigned char> expect_shift1 = { 0xF4, 4,  11,  1,    0xFF, 0xFE };
	std::vector<unsigned char> expect_shift4 = { 0xA0, 32, 88,  0x0F, 0xFF, 0xF0 };
	std::vector<unsigned char> expect_shift7 = { 1,    2,  192, 127,  0xFF, 128 };
	
	std::vector<unsigned char> dst(src.size());
	CarryBits ret;
	
	ret = memcpy_left(dst.data(), src.data(), src.size(), 0);
	EXPECT_EQ(dst, src);
	EXPECT_EQ(ret.value, 0);
	EXPECT_EQ(ret.mask, 0);
	
	ret = memcpy_left(dst.data(), src.data(), src.size(), 1);
	EXPECT_EQ(dst, expect_shift1);
	EXPECT_EQ(ret.value, 0);
	EXPECT_EQ(ret.mask, 1);
	
	ret = memcpy_left(dst.data(), src.data(), src.size(), 4);
	EXPECT_EQ(dst, expect_shift4);
	EXPECT_EQ(ret.value, 7);
	EXPECT_EQ(ret.mask, 15);
	
	ret = memcpy_left(dst.data(), src.data(), src.size(), 7);
	EXPECT_EQ(dst, expect_shift7);
	EXPECT_EQ(ret.value, 61);
	EXPECT_EQ(ret.mask, 127);
}

TEST(Util, memcpy_right)
{
	std::vector<unsigned char> src = { 0xFF, 2, 5, 128, 0xFF, 252 };
	
	std::vector<unsigned char> dst(src.size());
	CarryBits ret;
	
	memset(dst.data(), 0, dst.size());
	ret = memcpy_right(dst.data(), src.data(), src.size(), 0);
	EXPECT_EQ(dst, src);
	EXPECT_EQ(ret.mask, 0);
	EXPECT_EQ(ret.value, 0);
	
	memset(dst.data(), 0, dst.size());
	ret = memcpy_right(dst.data(), src.data(), src.size(), 1);
	EXPECT_EQ(dst, std::vector<unsigned char>({ 127, 129,  2,  192, 127, 254 }));
	EXPECT_EQ(ret.mask, 128);
	EXPECT_EQ(ret.value, 0);
	
	memset(dst.data(), 0, dst.size());
	ret = memcpy_right(dst.data(), src.data(), src.size(), 4);
	EXPECT_EQ(dst, std::vector<unsigned char>({ 0x0F, 0xF0, 32,  88, 0x0F, 0xFF }));
	EXPECT_EQ(ret.mask, 240);
	EXPECT_EQ(ret.value, 192);
	
	memset(dst.data(), 0, dst.size());
	ret = memcpy_right(dst.data(), src.data(), src.size(), 7);
	EXPECT_EQ(dst, std::vector<unsigned char>({ 1, 254,  4, 11, 1, 0xFF }));
	EXPECT_EQ(ret.mask, 254);
	EXPECT_EQ(ret.value, 248);
	
	memset(dst.data(), 0xFF, dst.size());
	ret = memcpy_right(dst.data(), src.data(), src.size(), 7);
	EXPECT_EQ(dst, std::vector<unsigned char>({ 0xFF, 254,  4, 11, 1, 0xFF }));
	EXPECT_EQ(ret.mask, 254);
	EXPECT_EQ(ret.value, 248);
}
