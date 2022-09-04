/* Reverse Engineer's Hex Editor
 * Copyright (C) 2022 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "../src/endian_conv.hpp"

using namespace REHex;

TEST(beXXXtoh, i32)
{
	unsigned char d[] = { 0x12, 0x34, 0xFF, 0x00 };
	
	int32_t i;
	memcpy(&i, d, sizeof(i));
	
	i = beXXXtoh(i);
	
	EXPECT_EQ(i, 0x1234FF00);
}

TEST(beXXXtoh, u16)
{
	unsigned char d[] = { 0x12, 0xFF };
	
	uint16_t i;
	memcpy(&i, d, sizeof(i));
	
	i = beXXXtoh(i);
	
	EXPECT_EQ(i, 0x12FFU);
}

TEST(beXXXtoh, f32)
{
	unsigned char d[] = { 0x3F, 0x80, 0x00, 0x00 };
	
	float f;
	memcpy(&f, d, sizeof(f));
	
	f = beXXXtoh(f);
	
	EXPECT_EQ(f, 1.0f);
}

TEST(beXXXtoh, f64)
{
	unsigned char d[] = { 0xC0, 0x09, 0x21, 0xF9, 0xF0, 0x1B, 0x86, 0x6E };
	
	double f;
	memcpy(&f, d, sizeof(f));
	
	f = beXXXtoh(f);
	
	EXPECT_EQ(f, -3.14159);
}

TEST(beXXXtohp, i64)
{
	unsigned char d[] = { 0x00, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE };
	
	int64_t i = beXXXtoh_p<int64_t>(d);
	
	EXPECT_EQ(i, 0x00123456789ABCDELL);
}

TEST(beXXXtohp, f32)
{
	unsigned char d[] = { 0x3F, 0x80, 0x00, 0x00 };
	
	float f = beXXXtoh_p<float>(d);
	
	EXPECT_EQ(f, 1.0f);
}

TEST(leXXXtoh, i32)
{
	unsigned char d[] = { 0x00, 0xFF, 0x34, 0x12 };
	
	int32_t i;
	memcpy(&i, d, sizeof(i));
	
	i = leXXXtoh(i);
	
	EXPECT_EQ(i, 0x1234FF00);
}

TEST(leXXXtoh, u16)
{
	unsigned char d[] = { 0xFF, 0x12 };
	
	uint16_t i;
	memcpy(&i, d, sizeof(i));
	
	i = leXXXtoh(i);
	
	EXPECT_EQ(i, 0x12FFU);
}

TEST(leXXXtoh, f32)
{
	unsigned char d[] = { 0x00, 0x00, 0x80, 0x3F };
	
	float f;
	memcpy(&f, d, sizeof(f));
	
	f = leXXXtoh(f);
	
	EXPECT_EQ(f, 1.0f);
}

TEST(leXXXtoh, f64)
{
	unsigned char d[] = { 0x6E, 0x86, 0x1B, 0xF0, 0xF9, 0x21, 0x09, 0xC0 };
	
	double f;
	memcpy(&f, d, sizeof(f));
	
	f = leXXXtoh(f);
	
	EXPECT_EQ(f, -3.14159);
}

TEST(leXXXtohp, i64)
{
	unsigned char d[] = { 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12, 0x00 };
	
	int64_t i = leXXXtoh_p<int64_t>(d);
	
	EXPECT_EQ(i, 0x00123456789ABCDELL);
}

TEST(leXXXtohp, f32)
{
	unsigned char d[] = { 0x00, 0x00, 0x80, 0x3F };
	
	float f = leXXXtoh_p<float>(d);
	
	EXPECT_EQ(f, 1.0f);
}
