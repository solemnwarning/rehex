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

static const long long INT61_MIN = -0x1000000000000000LL;
static const long long INT61_MAX = 0xFFFFFFFFFFFFFFFLL;

static void BitOffset_BasicTests_Range(int64_t byte_min, int64_t byte_max)
{
	for(int64_t i = byte_min; i <= byte_max; ++i)
	{
		int jinc = i < 0 ? -1 : 1;
		
		for(int j = 0; j >= -7 && j <= 7; j += jinc)
		{
			EXPECT_EQ(BitOffset(i, j).byte(), i) << "BitOffset(" << i << ", " << j << ").byte() yields original byte";
			EXPECT_EQ(BitOffset(i, j).bit(), j) << "BitOffset(" << i << ", " << j << ").byte() yields original bit";
		}
		
		for(int j = 0; j >= -6 && j <= 6; j += jinc)
		{
			if(i >= 0)
			{
				EXPECT_TRUE( BitOffset(i, j)      < BitOffset(i, j + 1))  << "BitOffset(" << i << ", " << j       << ") is less than BitOffset("     << i << ", " << (j + 1) << ")";
				EXPECT_FALSE( BitOffset(i, j + 1) < BitOffset(i, j))      << "BitOffset(" << i << ", " << (j + 1) << ") is not less than BitOffset(" << i << ", " << j << ")";
				EXPECT_FALSE( BitOffset(i, j)     < BitOffset(i, j))      << "BitOffset(" << i << ", " << j       << ") is not less than BitOffset(" << i << ", " << j << ")";
			}
			else{
				EXPECT_FALSE( BitOffset(i, j)     < BitOffset(i, j - 1))  << "BitOffset(" << i << ", " << j       << ") is not less than BitOffset("     << i << ", " << (j - 1) << ")";
				EXPECT_TRUE(  BitOffset(i, j - 1) < BitOffset(i, j))      << "BitOffset(" << i << ", " << (j - 1) << ") is less than BitOffset(" << i << ", " << j << ")";
				EXPECT_FALSE( BitOffset(i, j)     < BitOffset(i, j))      << "BitOffset(" << i << ", " << j       << ") is not less than BitOffset(" << i << ", " << j << ")";
			}
			
			if(i > byte_min)
			{
				EXPECT_FALSE( BitOffset(i, j) < BitOffset(i - 1, 0)) << "BitOffset(" << i << ", " << j       << ") is not less than BitOffset(" << (i - 1) << ", " << 0 << ")";
				EXPECT_TRUE(  BitOffset(i - 1, 0) < BitOffset(i, j)) << "BitOffset(" << (i - 1) << ", " << 0 << ") is less than BitOffset(" << i << ", " << j << ")";
				
				if(i > 0)
				{
					EXPECT_FALSE( BitOffset(i, j) < BitOffset(i - 1, 7)) << "BitOffset(" << i << ", " << j       << ") is not less than BitOffset(" << (i - 1) << ", " << 7 << ")";
					EXPECT_TRUE(  BitOffset(i - 1, 7) < BitOffset(i, j)) << "BitOffset(" << (i - 1) << ", " << 7 << ") is less than BitOffset(" << i << ", " << j << ")";
				}
				else{
					EXPECT_FALSE( BitOffset(i, j) < BitOffset(i - 1, -7)) << "BitOffset(" << i << ", " << j       << ") is not less than BitOffset(" << (i - 1) << ", " << -7 << ")";
					EXPECT_TRUE(  BitOffset(i - 1, -7) < BitOffset(i, j)) << "BitOffset(" << (i - 1) << ", " << -7 << ") is less than BitOffset(" << i << ", " << j << ")";
				}
			}
		}
	}
}

TEST(BitOffset, BasicTests)
{
	/* Arguably excessively paranoid tests here which verify BitOffset can
	 * correctly store/return/compare ranges of values through the entire
	 * 61/3-bit space.
	*/
	
	BitOffset_BasicTests_Range(-10000, 10000);
	
	BitOffset_BasicTests_Range((int64_t)(INT16_MIN) - 10000, (int64_t)(INT16_MIN) + 10000);
	BitOffset_BasicTests_Range((int64_t)(INT16_MAX) - 10000, (int64_t)(INT16_MAX) + 10000);
	BitOffset_BasicTests_Range((int64_t)(INT32_MIN) - 10000, (int64_t)(INT32_MIN) + 10000);
	BitOffset_BasicTests_Range((int64_t)(INT32_MAX) - 10000, (int64_t)(INT32_MAX) + 10000);
	BitOffset_BasicTests_Range((int64_t)(INT61_MIN) + 1,     (int64_t)(INT61_MIN) + 10000);
	BitOffset_BasicTests_Range((int64_t)(INT61_MAX) - 10000, (int64_t)(INT61_MAX));
	
	EXPECT_TRUE ( BitOffset(0, 0) == BitOffset(0, 0) );
	EXPECT_FALSE( BitOffset(0, 0) != BitOffset(0, 0) );
	EXPECT_FALSE( BitOffset(0, 1) == BitOffset(0, 0) );
	EXPECT_TRUE ( BitOffset(0, 1) != BitOffset(0, 0) );
	EXPECT_FALSE( BitOffset(0, 0) == BitOffset(0, 1) );
	EXPECT_TRUE ( BitOffset(0, 0) != BitOffset(0, 1) );
	EXPECT_FALSE( BitOffset(1, 0) == BitOffset(0, 0) );
	EXPECT_TRUE ( BitOffset(1, 0) != BitOffset(0, 0) );
	EXPECT_FALSE( BitOffset(0, 0) == BitOffset(1, 0) );
	EXPECT_TRUE ( BitOffset(0, 0) != BitOffset(1, 0) );
	EXPECT_FALSE( BitOffset(1, 0) == BitOffset(-1, 0) );
	EXPECT_TRUE ( BitOffset(1, 0) != BitOffset(-1, 0) );
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

TEST(BitOffset, Modulo)
{
	EXPECT_EQ(BitOffset(0, 0) % BitOffset(1, 0), BitOffset(0, 0));
	EXPECT_EQ(BitOffset(1, 0) % BitOffset(1, 0), BitOffset(0, 0));
	EXPECT_EQ(BitOffset(0, 5) % BitOffset(1, 0), BitOffset(0, 5));
	EXPECT_EQ(BitOffset(1, 2) % BitOffset(1, 0), BitOffset(0, 2));
	EXPECT_EQ(BitOffset(1, 2) % BitOffset(0, 1), BitOffset(0, 0));
	EXPECT_EQ(BitOffset(1, 2) % BitOffset(0, 4), BitOffset(0, 2));
	EXPECT_EQ(BitOffset(1, 0) % BitOffset(0, 4), BitOffset(0, 0));
	EXPECT_EQ(BitOffset(2, 0) % BitOffset(0, 4), BitOffset(0, 0));
	EXPECT_EQ(BitOffset(1, 4) % BitOffset(0, 4), BitOffset(0, 0));
	EXPECT_EQ(BitOffset(1, 0) % BitOffset(0, 7), BitOffset(0, 1));
	EXPECT_EQ(BitOffset(2, 0) % BitOffset(0, 7), BitOffset(0, 2));
}
