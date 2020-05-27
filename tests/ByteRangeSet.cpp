/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <gtest/gtest.h>
#include <stdio.h>

#include "../src/ByteRangeSet.hpp"

using namespace REHex;

#define EXPECT_RANGES(...) \
{ \
	ByteRangeSet::Range ranges_a[] = { __VA_ARGS__ }; \
	std::set<ByteRangeSet::Range> ranges(ranges_a, ranges_a + (sizeof(ranges_a) / sizeof(*ranges_a))); \
	EXPECT_EQ(brs.get_ranges(), ranges); \
}

/* Used by Google Test to print out Range values. */
std::ostream& operator<<(std::ostream& os, const ByteRangeSet::Range& range)
{
	char buf[128];
	snprintf(buf, sizeof(buf), "{ offset = %zd, length = %zd }", range.offset, range.length);
	
	return os << buf;
}

TEST(ByteRangeSet, EmptySet)
{
	ByteRangeSet brs;
	
	EXPECT_RANGES();
}

TEST(ByteRangeSet, AddOneRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 20);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 20),
	);
}

TEST(ByteRangeSet, AddExclusiveRanges)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 20);
	brs.set_range(40, 30);
	brs.set_range(80, 40);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 20),
		ByteRangeSet::Range(40, 30),
		ByteRangeSet::Range(80, 40),
	);
}

TEST(ByteRangeSet, AddSameRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 20);
	brs.set_range(10, 20);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 20),
	);
}

TEST(ByteRangeSet, SetRangeAtStartOfRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 20);
	brs.set_range(10, 1);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 20),
	);
}

TEST(ByteRangeSet, SetRangeAtEndOfRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 20);
	brs.set_range(29, 1);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 20),
	);
}

TEST(ByteRangeSet, SetRangeBeforeRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 20);
	brs.set_range(5, 5);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(5, 25),
	);
}

TEST(ByteRangeSet, SetRangeAfterRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 20);
	brs.set_range(30, 50);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 70),
	);
}

TEST(ByteRangeSet, SetRangeBetweenRanges)
{
	ByteRangeSet brs;
	
	brs.set_range(5,   1);
	brs.set_range(10, 20);
	brs.set_range(40, 20);
	brs.set_range(99,  1);
	
	brs.set_range(30, 10);
	
	EXPECT_RANGES(
		ByteRangeSet::Range( 5,  1),
		ByteRangeSet::Range(10, 50),
		ByteRangeSet::Range(99,  1),
	);
}

TEST(ByteRangeSet, SetRangeOverlappingStartOfRange)
{
	ByteRangeSet brs;
	
	brs.set_range(1,  1);
	brs.set_range(10, 20);
	
	brs.set_range(5,  10);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(1,  1),
		ByteRangeSet::Range(5, 25),
	);
}

TEST(ByteRangeSet, SetRangeOverlappingEndOfRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 20);
	brs.set_range(50, 20);
	
	brs.set_range(25, 10);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 25),
		ByteRangeSet::Range(50, 20),
	);
}

TEST(ByteRangeSet, SetRangeOverlappingSeveralRanges)
{
	ByteRangeSet brs;
	
	brs.set_range( 5,  1);
	brs.set_range(10, 20);
	brs.set_range(40, 10);
	brs.set_range(60,  5);
	brs.set_range(70, 10);
	
	brs.set_range(15, 47);
	
	EXPECT_RANGES(
		ByteRangeSet::Range( 5,  1),
		ByteRangeSet::Range(10, 55),
		ByteRangeSet::Range(70, 10),
	);
}

TEST(ByteRangeSet, AddZeroLengthRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 0);
	
	EXPECT_RANGES();
}

TEST(ByteRangeSet, ClearRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 10);
	
	brs.clear_range(10, 10);
	
	EXPECT_RANGES();
}

TEST(ByteRangeSet, ClearAtStartOfRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 10);
	
	brs.clear_range(10, 3);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(13, 7),
	);
}

TEST(ByteRangeSet, ClearMiddleOfRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 10);
	
	brs.clear_range(16, 2);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 6),
		ByteRangeSet::Range(18, 2),
	);
}

TEST(ByteRangeSet, ClearAtEndOfRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 10);
	
	brs.clear_range(17, 3);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 7),
	);
}

TEST(ByteRangeSet, ClearOverlappingStartOfRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 10);
	
	brs.clear_range(5, 10);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(15, 5),
	);
}

TEST(ByteRangeSet, ClearOverlappingEndOfRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 10);
	
	brs.clear_range(15, 10);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 5),
	);
}

TEST(ByteRangeSet, ClearOverlappingSeveralRanges)
{
	ByteRangeSet brs;
	
	brs.set_range( 5,  1);
	brs.set_range(10, 20);
	brs.set_range(40, 10);
	brs.set_range(60,  5);
	brs.set_range(70, 10);
	
	brs.clear_range(15, 47);
	
	EXPECT_RANGES(
		ByteRangeSet::Range( 5,  1),
		ByteRangeSet::Range(10,  5),
		ByteRangeSet::Range(62,  3),
		ByteRangeSet::Range(70, 10),
	);
}

TEST(ByteRangeSet, ClearBetweenRanges)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 20);
	brs.set_range(40, 20);
	
	brs.clear_range(30, 10);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 20),
		ByteRangeSet::Range(40, 20),
	);
}

TEST(ByteRangeSet, IsSetAtStartOfRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 10);
	brs.set_range(30, 10);
	
	EXPECT_TRUE(brs.isset(10));
	EXPECT_TRUE(brs.isset(30));
}

TEST(ByteRangeSet, IsSetAtEndOfRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 10);
	brs.set_range(30, 10);
	
	EXPECT_TRUE(brs.isset(19));
	EXPECT_TRUE(brs.isset(39));
}

TEST(ByteRangeSet, IsSetMiddleOfRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 10);
	brs.set_range(30, 10);
	
	EXPECT_TRUE(brs.isset(15));
	EXPECT_TRUE(brs.isset(35));
}

TEST(ByteRangeSet, IsSetBeforeRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 10);
	brs.set_range(30, 10);
	
	EXPECT_FALSE(brs.isset(9));
}

TEST(ByteRangeSet, IsSetAfterRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 10);
	brs.set_range(30, 10);
	
	EXPECT_FALSE(brs.isset(40));
}

TEST(ByteRangeSet, IsSetBetweenRanges)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 10);
	brs.set_range(30, 10);
	
	EXPECT_FALSE(brs.isset(20));
	EXPECT_FALSE(brs.isset(25));
	EXPECT_FALSE(brs.isset(29));
}

TEST(ByteRangeSet, IsSetNoRanges)
{
	ByteRangeSet brs;
	
	EXPECT_FALSE(brs.isset(10));
}
