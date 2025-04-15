/* Reverse Engineer's Hex Editor
 * Copyright (C) 2024-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "../src/Range.hpp"

using namespace REHex;

TEST(ByteRange, End)
{
	ByteRange range(10, 5);
	
	/* Sanity check the c'tor */
	EXPECT_EQ(range.offset, 10);
	EXPECT_EQ(range.length, 5);
	
	EXPECT_EQ(range.end(), 15);
}

TEST(ByteRange, LessThan)
{
	EXPECT_FALSE(ByteRange(10, 5) < ByteRange(10, 5));
	
	EXPECT_FALSE(ByteRange(11, 5) < ByteRange(10, 5));
	EXPECT_TRUE(ByteRange(10, 5) < ByteRange(11, 5));
	
	EXPECT_FALSE(ByteRange(10, 6) < ByteRange(10, 5));
	EXPECT_TRUE(ByteRange(10, 5) < ByteRange(10, 6));
}

TEST(ByteRange, TestOverlaps)
{
	/* Contained ranges. */
	
	EXPECT_TRUE(ByteRange(10, 5).overlaps(ByteRange(10, 5)));
	
	EXPECT_TRUE(ByteRange(10, 5).overlaps(ByteRange(11, 0)));
	EXPECT_TRUE(ByteRange(11, 0).overlaps(ByteRange(10, 5)));
	
	EXPECT_TRUE(ByteRange(10, 5).overlaps(ByteRange(10, 1)));
	EXPECT_TRUE(ByteRange(10, 1).overlaps(ByteRange(10, 5)));
	
	EXPECT_TRUE(ByteRange(10, 5).overlaps(ByteRange(12, 1)));
	EXPECT_TRUE(ByteRange(12, 1).overlaps(ByteRange(10, 5)));
	
	EXPECT_TRUE(ByteRange(14, 1).overlaps(ByteRange(10, 5)));
	EXPECT_TRUE(ByteRange(10, 5).overlaps(ByteRange(14, 1)));
	
	/* Overlapping from beyond edges. */
	
	EXPECT_TRUE(ByteRange(8, 3).overlaps(ByteRange(10, 5)));
	EXPECT_TRUE(ByteRange(10, 5).overlaps(ByteRange(8, 3)));
	
	EXPECT_TRUE(ByteRange(10, 5).overlaps(ByteRange(12, 5)));
	EXPECT_TRUE(ByteRange(12, 5).overlaps(ByteRange(10, 5)));
	
	/* Abutting the ends, not overlapping. */
	
	EXPECT_FALSE(ByteRange(10, 5).overlaps(ByteRange(10, 0)));
	EXPECT_FALSE(ByteRange(10, 0).overlaps(ByteRange(10, 5)));
	
	EXPECT_FALSE(ByteRange(8, 2).overlaps(ByteRange(10, 5)));
	EXPECT_FALSE(ByteRange(10, 5).overlaps(ByteRange(8, 2)));
	
	EXPECT_FALSE(ByteRange(10, 5).overlaps(ByteRange(15, 5)));
	EXPECT_FALSE(ByteRange(15, 5).overlaps(ByteRange(10, 5)));
}

TEST(ByteRange, TestContains)
{
	/* Contained ranges. */
	
	EXPECT_TRUE(ByteRange(10, 5).contains(ByteRange(10, 5)));
	
	EXPECT_TRUE(ByteRange(10, 5).contains(ByteRange(10, 0)));
	EXPECT_FALSE(ByteRange(10, 0).contains(ByteRange(10, 5)));
	
	EXPECT_TRUE(ByteRange(10, 5).contains(ByteRange(11, 0)));
	EXPECT_FALSE(ByteRange(11, 0).contains(ByteRange(10, 5)));
	
	EXPECT_TRUE(ByteRange(10, 5).contains(ByteRange(10, 1)));
	EXPECT_FALSE(ByteRange(10, 1).contains(ByteRange(10, 5)));
	
	EXPECT_TRUE(ByteRange(10, 5).contains(ByteRange(12, 1)));
	EXPECT_FALSE(ByteRange(12, 1).contains(ByteRange(10, 5)));
	
	EXPECT_TRUE(ByteRange(10, 5).contains(ByteRange(14, 1)));
	EXPECT_FALSE(ByteRange(14, 1).contains(ByteRange(10, 5)));
	
	/* Overlapping from beyond edges. */
	
	EXPECT_FALSE(ByteRange(8, 3).contains(ByteRange(10, 5)));
	EXPECT_FALSE(ByteRange(10, 5).contains(ByteRange(8, 3)));
	
	EXPECT_FALSE(ByteRange(10, 5).contains(ByteRange(12, 5)));
	EXPECT_FALSE(ByteRange(12, 5).contains(ByteRange(10, 5)));
	
	/* Abutting the ends, not overlapping. */
	
	EXPECT_FALSE(ByteRange(8, 2).contains(ByteRange(10, 5)));
	EXPECT_FALSE(ByteRange(10, 5).contains(ByteRange(8, 2)));
	
	EXPECT_FALSE(ByteRange(10, 5).contains(ByteRange(15, 5)));
	EXPECT_FALSE(ByteRange(15, 5).contains(ByteRange(10, 5)));
}

TEST(ByteRange, TestIntersection)
{
	/* Overlapping adjacent ranges. */
	EXPECT_EQ(ByteRange::intersection(ByteRange(10, 50), ByteRange(20, 80)), ByteRange(20, 40));
	EXPECT_EQ(ByteRange::intersection(ByteRange(20, 80), ByteRange(10, 50)), ByteRange(20, 40));
	
	/* Nested ranges. */
	EXPECT_EQ(ByteRange::intersection(ByteRange(10, 50), ByteRange(20, 10)), ByteRange(20, 10));
	EXPECT_EQ(ByteRange::intersection(ByteRange(20, 10), ByteRange(10, 50)), ByteRange(20, 10));
	
	/* No overlap. */
	EXPECT_EQ(ByteRange::intersection(ByteRange(10, 10), ByteRange(20, 10)), ByteRange(20, 0));
	EXPECT_EQ(ByteRange::intersection(ByteRange(20, 10), ByteRange(10, 10)), ByteRange(20, 0));
	EXPECT_EQ(ByteRange::intersection(ByteRange(10, 10), ByteRange(70, 10)), ByteRange(70, 0));
	EXPECT_EQ(ByteRange::intersection(ByteRange(70, 10), ByteRange(10, 10)), ByteRange(70, 0));
}
