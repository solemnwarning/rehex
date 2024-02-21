/* Reverse Engineer's Hex Editor
 * Copyright (C) 2023-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "../src/BitOffset.hpp"

using namespace REHex;

TEST(BitOffset, BasicTests)
{
	EXPECT_EQ(BitOffset(0, 0).bit(), 0);
	EXPECT_EQ(BitOffset(0, 0).byte(), 0);
	
	EXPECT_EQ(BitOffset(0, 1).bit(), 1);
	EXPECT_EQ(BitOffset(0, 1).byte(), 0);
	
	EXPECT_EQ(BitOffset(0, 7).bit(), 7);
	EXPECT_EQ(BitOffset(0, 7).byte(), 0);
	
	EXPECT_EQ(BitOffset(10, 0).bit(), 0);
	EXPECT_EQ(BitOffset(10, 0).byte(), 10);
	
	EXPECT_EQ(BitOffset(10, 7).bit(), 7);
	EXPECT_EQ(BitOffset(10, 7).byte(), 10);
	
	EXPECT_EQ(BitOffset(-1, 0).bit(), 0);
	EXPECT_EQ(BitOffset(-1, 0).byte(), -1);
	
	EXPECT_EQ(BitOffset(-1, -7).bit(), -7);
	EXPECT_EQ(BitOffset(-1, -7).byte(), -1);
	
	EXPECT_EQ(BitOffset(0xFFFFFFFFFFFFFFFLL, 0).bit(), 0);
	EXPECT_EQ(BitOffset(0xFFFFFFFFFFFFFFFLL, 0).byte(), 0xFFFFFFFFFFFFFFFLL);
	
	EXPECT_EQ(BitOffset(-0x1000000000000000LL, 0).bit(), 0);
	EXPECT_EQ(BitOffset(-0x1000000000000000LL, 0).byte(), -0x1000000000000000LL);
	
	EXPECT_EQ(BitOffset(0xFFFFFFFFFFFFFFFLL, 7).bit(), 7);
	EXPECT_EQ(BitOffset(0xFFFFFFFFFFFFFFFLL, 7).byte(), 0xFFFFFFFFFFFFFFFLL);
	
	EXPECT_EQ(BitOffset(-0x1000000000000000LL, -7).bit(), -7);
	EXPECT_EQ(BitOffset(-0x1000000000000000LL, -7).byte(), -0x1000000000000000LL);
	
	EXPECT_FALSE(BitOffset(0, 0) < BitOffset(0, 0));
	EXPECT_FALSE(BitOffset(1, 0) < BitOffset(1, 0));
	EXPECT_FALSE(BitOffset(-1, 0) < BitOffset(-1, 0));
	
	EXPECT_TRUE(BitOffset(0, 0) < BitOffset(1, 0));
	EXPECT_FALSE(BitOffset(1, 0) < BitOffset(0, 0));
	
	EXPECT_TRUE(BitOffset(0, 0) < BitOffset(0, 1));
	EXPECT_FALSE(BitOffset(0, 1) < BitOffset(0, 0));
	
	EXPECT_TRUE(BitOffset(1, 7) < BitOffset(2, 0));
	EXPECT_FALSE(BitOffset(2, 0) < BitOffset(1, 7));
	
	EXPECT_TRUE(BitOffset(-1, 0) < BitOffset(0, 0));
	EXPECT_FALSE(BitOffset(0, 0) < BitOffset(-1, 0));
	
	EXPECT_TRUE(BitOffset(-2, 0) < BitOffset(-1, 0));
	EXPECT_FALSE(BitOffset(-1, 0) < BitOffset(-2, 0));
	
	EXPECT_TRUE(BitOffset(-1, -4) < BitOffset(-1, -3));
	EXPECT_FALSE(BitOffset(-1, -3) < BitOffset(-1, -4));
}

TEST(BitOffset, Addition)
{
	EXPECT_EQ( BitOffset(  0, 0) + BitOffset(  1, 0),  BitOffset(  1, 0));
	EXPECT_EQ( BitOffset( 40, 0) + BitOffset( 10, 0),  BitOffset( 50, 0));
	EXPECT_EQ( BitOffset( 40, 0) + BitOffset(-10, 0),  BitOffset( 30, 0));
	EXPECT_EQ( BitOffset(-10, 0) + BitOffset(-10, 0),  BitOffset(-20, 0));
	EXPECT_EQ( BitOffset(-10, 0) + BitOffset( 40, 0),  BitOffset( 30, 0));
	
	EXPECT_EQ( BitOffset(0, 0) + BitOffset(0, 1),  BitOffset(0, 1));
	EXPECT_EQ( BitOffset(0, 3) + BitOffset(0, 4),  BitOffset(0, 7));
	EXPECT_EQ( BitOffset(0, 3) + BitOffset(0, 5),  BitOffset(1, 0));
	EXPECT_EQ( BitOffset(0, 3) + BitOffset(0, 6),  BitOffset(1, 1));
	EXPECT_EQ( BitOffset(0, 3) + BitOffset(1, 6),  BitOffset(2, 1));
	
	EXPECT_EQ( BitOffset(0,  3) + BitOffset(0, -4),  BitOffset( 0, -1));
	EXPECT_EQ( BitOffset(0, -4) + BitOffset(0, -4),  BitOffset(-1,  0));
	
	EXPECT_EQ( BitOffset (10,  2) + BitOffset(0, -4),  BitOffset(  9,  6));
	EXPECT_EQ( BitOffset(-10, -2) + BitOffset(0, -4),  BitOffset(-10, -6));
	
	BitOffset bo(10, 0);
	
	bo += BitOffset(10, 0);
	EXPECT_EQ(bo, BitOffset(20, 0));
	
	bo += BitOffset(-40, -2);
	EXPECT_EQ(bo, BitOffset(-20, -2));
}

TEST(BitOffset, Subtraction)
{
	EXPECT_EQ( BitOffset(  0, 0) - BitOffset(  1, 0),  BitOffset( -1, 0));
	EXPECT_EQ( BitOffset( 40, 0) - BitOffset( 10, 0),  BitOffset( 30, 0));
	EXPECT_EQ( BitOffset( 40, 0) - BitOffset(-10, 0),  BitOffset( 50, 0));
	EXPECT_EQ( BitOffset(-10, 0) - BitOffset(-10, 0),  BitOffset(  0, 0));
	EXPECT_EQ( BitOffset(-10, 0) - BitOffset( 40, 0),  BitOffset(-50, 0));
	
	EXPECT_EQ( BitOffset(0, 0) - BitOffset(0, 1),  BitOffset(0, -1));
	EXPECT_EQ( BitOffset(0, 3) - BitOffset(1, 2),  BitOffset(0, -7));
	EXPECT_EQ( BitOffset(0, 3) - BitOffset(1, 3),  BitOffset(-1, 0));
	
	EXPECT_EQ( BitOffset(0, 3) - BitOffset(1, 5),  BitOffset(-1, -2));
	EXPECT_EQ( BitOffset(0, 3) - BitOffset(0, 6),  BitOffset(0, -3));
	
	EXPECT_EQ( BitOffset(0,  3) - BitOffset(0, -4),  BitOffset(0, 7));
	EXPECT_EQ( BitOffset(0, -4) - BitOffset(0, -4),  BitOffset(0, 0));
	
	EXPECT_EQ( BitOffset (10,  2) - BitOffset(0, -4),  BitOffset( 10,  6));
	EXPECT_EQ( BitOffset(-10, -2) - BitOffset(0, -4),  BitOffset( -9, -6));
	
	BitOffset bo(10, 0);
	
	bo -= BitOffset(4, 2);
	EXPECT_EQ(bo, BitOffset(5, 6));
	
	bo -= BitOffset(-10, 0);
	EXPECT_EQ(bo, BitOffset(15, 6));
}
