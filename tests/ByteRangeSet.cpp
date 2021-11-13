/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2021 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "../src/ByteRangeSet.hpp"

using namespace REHex;

#define EXPECT_RANGES(...) \
{ \
	std::vector<ByteRangeSet::Range> ranges = { __VA_ARGS__ }; \
	EXPECT_EQ(brs.get_ranges(), ranges); \
}

/* Used by Google Test to print out Range values. */
std::ostream& operator<<(std::ostream& os, const ByteRangeSet::Range& range)
{
	char buf[128];
	snprintf(buf, sizeof(buf), "{ offset = %jd, length = %jd }", (intmax_t)(range.offset), (intmax_t)(range.length));
	
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

TEST(ByteRangeSet, AddMultiRanges)
{
	ByteRangeSet brs;
	
	ByteRangeSet::Range ranges[] = {
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(30, 5),
		ByteRangeSet::Range(40, 20),
	};
	
	brs.set_ranges(ranges, ranges + (sizeof(ranges) / sizeof(*ranges)));
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(30, 5),
		ByteRangeSet::Range(40, 20),
	);
}

/* Add ranges to the set which involves erasing and replacing a single element. */
TEST(ByteRangeSet, AddMultiRangesSingleErase)
{
	ByteRangeSet brs;
	
	ByteRangeSet::Range ranges1[] = {
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(30, 5),
		ByteRangeSet::Range(40, 20),
	};
	
	brs.set_ranges(ranges1, ranges1 + (sizeof(ranges1) / sizeof(*ranges1)));
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(30, 5),
		ByteRangeSet::Range(40, 20),
	);
	
	ByteRangeSet::Range ranges2[] = {
		ByteRangeSet::Range(5, 20),
		ByteRangeSet::Range(70, 4),
	};
	
	brs.set_ranges(ranges2, ranges2 + (sizeof(ranges2) / sizeof(*ranges2)));
	
	EXPECT_RANGES(
		ByteRangeSet::Range(5, 20),
		ByteRangeSet::Range(30, 5),
		ByteRangeSet::Range(40, 20),
		ByteRangeSet::Range(70, 4),
	);
}

/* Add ranges to the set which involves erasing and replacing contiguous elements. */
TEST(ByteRangeSet, AddMultiRangesContiguousErase)
{
	ByteRangeSet brs;
	
	ByteRangeSet::Range ranges1[] = {
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(30, 5),
		ByteRangeSet::Range(40, 20),
	};
	
	brs.set_ranges(ranges1, ranges1 + (sizeof(ranges1) / sizeof(*ranges1)));
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(30, 5),
		ByteRangeSet::Range(40, 20),
	);
	
	ByteRangeSet::Range ranges2[] = {
		ByteRangeSet::Range(28, 3),
		ByteRangeSet::Range(45, 30),
		ByteRangeSet::Range(80, 9),
	};
	
	brs.set_ranges(ranges2, ranges2 + (sizeof(ranges2) / sizeof(*ranges2)));
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(28, 7),
		ByteRangeSet::Range(40, 35),
		ByteRangeSet::Range(80, 9),
	);
}

/* Add ranges to the set which involves erasing and replacing discontiguous elements. */
TEST(ByteRangeSet, AddMultiRangesDiscontiguousErase)
{
	ByteRangeSet brs;
	
	ByteRangeSet::Range ranges1[] = {
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(30, 5),
		ByteRangeSet::Range(40, 20),
		ByteRangeSet::Range(100, 15),
		ByteRangeSet::Range(130, 10),
		ByteRangeSet::Range(180, 3),
		ByteRangeSet::Range(190, 6),
		ByteRangeSet::Range(200, 10),
		ByteRangeSet::Range(220, 10),
	};
	
	brs.set_ranges(ranges1, ranges1 + (sizeof(ranges1) / sizeof(*ranges1)));
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(30, 5),
		ByteRangeSet::Range(40, 20),
		ByteRangeSet::Range(100, 15),
		ByteRangeSet::Range(130, 10),
		ByteRangeSet::Range(180, 3),
		ByteRangeSet::Range(190, 6),
		ByteRangeSet::Range(200, 10),
		ByteRangeSet::Range(220, 10),
	);
	
	ByteRangeSet::Range ranges2[] = {
		ByteRangeSet::Range(5, 2),
		ByteRangeSet::Range(28, 3),
		ByteRangeSet::Range(80, 10),
		ByteRangeSet::Range(110, 20),
		ByteRangeSet::Range(150, 1),
		ByteRangeSet::Range(183, 17),
		ByteRangeSet::Range(250, 5),
	};
	
	brs.set_ranges(ranges2, ranges2 + (sizeof(ranges2) / sizeof(*ranges2)));
	
	EXPECT_RANGES(
		ByteRangeSet::Range(5, 2),
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(28, 7),
		ByteRangeSet::Range(40, 20),
		ByteRangeSet::Range(80, 10),
		ByteRangeSet::Range(100, 40),
		ByteRangeSet::Range(150, 1),
		ByteRangeSet::Range(180, 30),
		ByteRangeSet::Range(220, 10),
		ByteRangeSet::Range(250, 5),
	);
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

/* Clear ranges from the set which involves erasing a single element. */
TEST(ByteRangeSet, ClearMultiRangesSingleErase)
{
	const std::vector<ByteRangeSet::Range> INITIAL_RANGES = {
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(30, 5),
		ByteRangeSet::Range(40, 20),
	};
	
	ByteRangeSet brs(INITIAL_RANGES.begin(), INITIAL_RANGES.end());
	
	const std::vector<ByteRangeSet::Range> CLEAR_RANGES = {
		ByteRangeSet::Range(40, 20),
	};
	
	brs.clear_ranges(CLEAR_RANGES.begin(), CLEAR_RANGES.end());
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(30, 5),
	);
}

/* Clear ranges from the set which involves erasing and replacing a single element. */
TEST(ByteRangeSet, ClearMultiRangesSingleReplace)
{
	const std::vector<ByteRangeSet::Range> INITIAL_RANGES = {
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(30, 5),
		ByteRangeSet::Range(40, 20),
	};
	
	ByteRangeSet brs(INITIAL_RANGES.begin(), INITIAL_RANGES.end());
	
	const std::vector<ByteRangeSet::Range> CLEAR_RANGES = {
		ByteRangeSet::Range(35, 10),
	};
	
	brs.clear_ranges(CLEAR_RANGES.begin(), CLEAR_RANGES.end());
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(30, 5),
		ByteRangeSet::Range(45, 15),
	);
}

/* Clear ranges from the set which involves erasing multiple contiguous elements. */
TEST(ByteRangeSet, ClearMultiRangesContiguousErase)
{
	const std::vector<ByteRangeSet::Range> INITIAL_RANGES = {
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(30, 5),
		ByteRangeSet::Range(40, 20),
		ByteRangeSet::Range(65, 5),
		ByteRangeSet::Range(80, 10),
	};
	
	ByteRangeSet brs(INITIAL_RANGES.begin(), INITIAL_RANGES.end());
	
	const std::vector<ByteRangeSet::Range> CLEAR_RANGES = {
		ByteRangeSet::Range(40, 20),
		ByteRangeSet::Range(62, 8),
	};
	
	brs.clear_ranges(CLEAR_RANGES.begin(), CLEAR_RANGES.end());
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(30, 5),
		ByteRangeSet::Range(80, 10),
	);
}

/* Clear ranges from the set which involves erasing and replacing multiple contiguous elements. */
TEST(ByteRangeSet, ClearMultiRangesContiguousReplace)
{
	const std::vector<ByteRangeSet::Range> INITIAL_RANGES = {
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(30, 5),
		ByteRangeSet::Range(40, 20),
		ByteRangeSet::Range(65, 5),
		ByteRangeSet::Range(80, 10),
	};
	
	ByteRangeSet brs(INITIAL_RANGES.begin(), INITIAL_RANGES.end());
	
	const std::vector<ByteRangeSet::Range> CLEAR_RANGES = {
		ByteRangeSet::Range(45, 22),
	};
	
	brs.clear_ranges(CLEAR_RANGES.begin(), CLEAR_RANGES.end());
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(30, 5),
		ByteRangeSet::Range(40, 5),
		ByteRangeSet::Range(67, 3),
		ByteRangeSet::Range(80, 10),
	);
}

/* Clear ranges from the set which involves erasing multiple discontiguous elements. */
TEST(ByteRangeSet, ClearMultiRangesDiscontiguousErase)
{
	const std::vector<ByteRangeSet::Range> INITIAL_RANGES = {
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(30, 5),
		ByteRangeSet::Range(40, 20),
		ByteRangeSet::Range(65, 5),
		ByteRangeSet::Range(80, 10),
	};
	
	ByteRangeSet brs(INITIAL_RANGES.begin(), INITIAL_RANGES.end());
	
	const std::vector<ByteRangeSet::Range> CLEAR_RANGES = {
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(60, 40),
	};
	
	brs.clear_ranges(CLEAR_RANGES.begin(), CLEAR_RANGES.end());
	
	EXPECT_RANGES(
		ByteRangeSet::Range(30, 5),
		ByteRangeSet::Range(40, 20),
	);
}

/* Clear ranges from the set which involves erasing and replacing multiple discontiguous elements. */
TEST(ByteRangeSet, ClearMultiRangesDiscontiguousReplace)
{
	const std::vector<ByteRangeSet::Range> INITIAL_RANGES = {
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(30, 5),
		ByteRangeSet::Range(40, 20),
		ByteRangeSet::Range(65, 5),
		ByteRangeSet::Range(80, 10),
	};
	
	ByteRangeSet brs(INITIAL_RANGES.begin(), INITIAL_RANGES.end());
	
	const std::vector<ByteRangeSet::Range> CLEAR_RANGES = {
		ByteRangeSet::Range(8,  10),
		ByteRangeSet::Range(50, 18),
	};
	
	brs.clear_ranges(CLEAR_RANGES.begin(), CLEAR_RANGES.end());
	
	EXPECT_RANGES(
		ByteRangeSet::Range(18, 2),
		ByteRangeSet::Range(30, 5),
		ByteRangeSet::Range(40, 10),
		ByteRangeSet::Range(68, 2),
		ByteRangeSet::Range(80, 10),
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

TEST(ByteRangeSet, IsSetOverlappingStartOfRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 10);
	brs.set_range(30, 10);
	
	EXPECT_FALSE(brs.isset(9, 2));
	EXPECT_FALSE(brs.isset(29, 2));
}

TEST(ByteRangeSet, IsSetRangeAtStartOfRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 10);
	brs.set_range(30, 10);
	
	EXPECT_TRUE(brs.isset(10, 2));
	EXPECT_TRUE(brs.isset(30, 2));
}

TEST(ByteRangeSet, IsSetRangeInRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 10);
	brs.set_range(30, 10);
	
	EXPECT_TRUE(brs.isset(12, 5));
	EXPECT_TRUE(brs.isset(34, 4));
}

TEST(ByteRangeSet, IsSetRangeAtEndOfRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 10);
	brs.set_range(30, 10);
	
	EXPECT_TRUE(brs.isset(18, 2));
	EXPECT_TRUE(brs.isset(38, 2));
}

TEST(ByteRangeSet, IsSetOverlappingEndOfRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 10);
	brs.set_range(30, 10);
	
	EXPECT_FALSE(brs.isset(19, 2));
	EXPECT_FALSE(brs.isset(39, 2));
}

TEST(ByteRangeSet, IsSetRangeEncompassingRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 10);
	brs.set_range(30, 10);
	
	EXPECT_FALSE(brs.isset(5, 20));
	EXPECT_FALSE(brs.isset(25, 20));
}

TEST(ByteRangeSet, IsSetNoRanges)
{
	ByteRangeSet brs;
	
	EXPECT_FALSE(brs.isset(10));
}

TEST(ByteRangeSet, DataInsertedBeforeRanges)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 20);
	brs.set_range(40, 10);
	brs.set_range(60, 10);
	
	brs.data_inserted(9, 5);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(15, 20),
		ByteRangeSet::Range(45, 10),
		ByteRangeSet::Range(65, 10),
	);
}

TEST(ByteRangeSet, DataInsertedAfterRanges)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 20);
	brs.set_range(40, 10);
	brs.set_range(60, 10);
	
	brs.data_inserted(70, 5);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 20),
		ByteRangeSet::Range(40, 10),
		ByteRangeSet::Range(60, 10),
	);
}

TEST(ByteRangeSet, DataInsertedBetweenRanges)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 20);
	brs.set_range(40, 10);
	brs.set_range(60, 10);
	
	brs.data_inserted(35, 5);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 20),
		ByteRangeSet::Range(45, 10),
		ByteRangeSet::Range(65, 10),
	);
}

TEST(ByteRangeSet, DataInsertedAtStartOfRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 20);
	brs.set_range(40, 10);
	brs.set_range(60, 10);
	
	brs.data_inserted(10, 5);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(15, 20),
		ByteRangeSet::Range(45, 10),
		ByteRangeSet::Range(65, 10),
	);
}

TEST(ByteRangeSet, DataInsertedAtEndOfRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 20);
	brs.set_range(40, 10);
	brs.set_range(60, 10);
	
	brs.data_inserted(29, 5);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 19),
		ByteRangeSet::Range(34,  1),
		ByteRangeSet::Range(45, 10),
		ByteRangeSet::Range(65, 10),
	);
}

TEST(ByteRangeSet, DataInsertedIntoRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 20);
	brs.set_range(40, 10);
	brs.set_range(60, 10);
	
	brs.data_inserted(44, 5);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 20),
		ByteRangeSet::Range(40,  4),
		ByteRangeSet::Range(49,  6),
		ByteRangeSet::Range(65, 10),
	);
}

/* Tests ByteRangeSet::data_inserted() on a large enough set to use threading. */
TEST(ByteRangeSet, DataInsertedParallel)
{
	ByteRangeSet brs;
	
	/* Populate a reference vector with double the ranges necessary to trigger necessary to
	 * trigger threading, then some change to check the remainder is handled properly.
	*/
	
	const size_t N_RANGES = ByteRangeSet::DATA_INSERTED_THREAD_MIN * 2 + 5;
	size_t next_range = 0;
	
	std::vector<ByteRangeSet::Range> ranges;
	ranges.reserve(N_RANGES);
	
	for(size_t i = 0; i < N_RANGES; ++i)
	{
		ranges.push_back(ByteRangeSet::Range(next_range, 5));
		next_range += 10;
	}
	
	/* Populate ByteRangeSet with reference data. */
	
	brs.set_ranges(ranges.begin(), ranges.end());
	EXPECT_TRUE(brs.get_ranges() == ranges) << "ByteRangeSet initial data populated correctly";
	
	/* Insert some data within the 10th range. */
	
	brs.data_inserted(102, 5);
	EXPECT_TRUE(brs.get_ranges() != ranges) << "ByteRangeSet::data_inserted() modified ranges";
	
	/* Munge our data to reflect what should be the new reality... */
	
	ranges[10].length = 2;
	ranges.insert(std::next(ranges.begin(), 11), ByteRangeSet::Range(107, 3));
	
	for(size_t i = 12; i < ranges.size(); ++i)
	{
		ranges[i].offset += 5;
	}
	
	/* ...and check it matches. */
	EXPECT_TRUE(brs.get_ranges() == ranges) << "ByteRangeSet::data_inserted() correctly modified ranges";
}

TEST(ByteRangeSet, DataErasedBeforeRanges)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 20);
	brs.set_range(40, 10);
	brs.set_range(60, 10);
	
	brs.data_erased(5, 5);
	
	EXPECT_RANGES(
		ByteRangeSet::Range( 5, 20),
		ByteRangeSet::Range(35, 10),
		ByteRangeSet::Range(55, 10),
	);
}

TEST(ByteRangeSet, DataErasedAfterRanges)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 20);
	brs.set_range(40, 10);
	brs.set_range(60, 10);
	
	brs.data_erased(70, 5);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 20),
		ByteRangeSet::Range(40, 10),
		ByteRangeSet::Range(60, 10),
	);
}

TEST(ByteRangeSet, DataErasedMatchingRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 20);
	brs.set_range(40, 10);
	brs.set_range(60, 10);
	
	brs.data_erased(40, 10);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 20),
		ByteRangeSet::Range(50, 10),
	);
}

TEST(ByteRangeSet, DataErasedOverlappingStartOfRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 20);
	brs.set_range(40, 10);
	brs.set_range(60, 10);
	
	brs.data_erased(35, 10);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 20),
		ByteRangeSet::Range(35,  5),
		ByteRangeSet::Range(50, 10),
	);
}

TEST(ByteRangeSet, DataErasedOverlappingEndOfRange)
{
	ByteRangeSet brs;
	
	brs.set_range(10, 20);
	brs.set_range(40, 10);
	brs.set_range(60, 10);
	
	brs.data_erased(45, 10);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 20),
		ByteRangeSet::Range(40,  5),
		ByteRangeSet::Range(50, 10),
	);
}

TEST(ByteRangeSet, DataErasedOverlappingMultipleRanges)
{
	ByteRangeSet brs;
	
	brs.set_range( 5,  2);
	brs.set_range(10, 20);
	brs.set_range(40, 10);
	brs.set_range(60, 10);
	brs.set_range(80,  5);
	
	brs.data_erased(15, 50);
	
	EXPECT_RANGES(
		ByteRangeSet::Range( 5,  2),
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(30,  5),
	);
}

TEST(ByteRangeSet, IntersectionNoOverlap)
{
	const std::vector<ByteRangeSet::Range> RANGES_A = {
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(30, 20),
		ByteRangeSet::Range(70, 10),
	};
	
	const ByteRangeSet SET_A(RANGES_A.begin(), RANGES_A.end());
	
	const std::vector<ByteRangeSet::Range> RANGES_B = {
		ByteRangeSet::Range(20, 10),
		ByteRangeSet::Range(50, 20),
		ByteRangeSet::Range(80, 10),
	};
	
	const ByteRangeSet SET_B(RANGES_B.begin(), RANGES_B.end());
	
	const std::vector<ByteRangeSet::Range> INTERSECTION = {};
	
	EXPECT_EQ(ByteRangeSet::intersection(SET_A, SET_B).get_ranges(), INTERSECTION);
	EXPECT_EQ(ByteRangeSet::intersection(SET_B, SET_A).get_ranges(), INTERSECTION);
}

TEST(ByteRangeSet, IntersectionPartialOverlap)
{
	const std::vector<ByteRangeSet::Range> RANGES_A = {
		ByteRangeSet::Range(50, 20),
		ByteRangeSet::Range(90, 10),
	};
	
	const ByteRangeSet SET_A(RANGES_A.begin(), RANGES_A.end());
	
	const std::vector<ByteRangeSet::Range> RANGES_B = {
		ByteRangeSet::Range(20, 10),
		ByteRangeSet::Range(60, 20),
	};
	
	const ByteRangeSet SET_B(RANGES_B.begin(), RANGES_B.end());
	
	const std::vector<ByteRangeSet::Range> INTERSECTION = {
		ByteRangeSet::Range(60, 10),
	};
	
	EXPECT_EQ(ByteRangeSet::intersection(SET_A, SET_B).get_ranges(), INTERSECTION);
	EXPECT_EQ(ByteRangeSet::intersection(SET_B, SET_A).get_ranges(), INTERSECTION);
}

TEST(ByteRangeSet, IntersectionSubset)
{
	const std::vector<ByteRangeSet::Range> RANGES_A = {
		ByteRangeSet::Range(50, 30),
	};
	
	const ByteRangeSet SET_A(RANGES_A.begin(), RANGES_A.end());
	
	const std::vector<ByteRangeSet::Range> RANGES_B = {
		ByteRangeSet::Range(60, 5),
	};
	
	const ByteRangeSet SET_B(RANGES_B.begin(), RANGES_B.end());
	
	const std::vector<ByteRangeSet::Range> INTERSECTION = {
		ByteRangeSet::Range(60, 5),
	};
	
	EXPECT_EQ(ByteRangeSet::intersection(SET_A, SET_B).get_ranges(), INTERSECTION);
	EXPECT_EQ(ByteRangeSet::intersection(SET_B, SET_A).get_ranges(), INTERSECTION);
}

TEST(ByteRangeSet, IntersectionExactMatch)
{
	const std::vector<ByteRangeSet::Range> RANGES_A = {
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(50, 20),
		ByteRangeSet::Range(70, 10),
	};
	
	const ByteRangeSet SET_A(RANGES_A.begin(), RANGES_A.end());
	
	const std::vector<ByteRangeSet::Range> RANGES_B = {
		ByteRangeSet::Range(20, 10),
		ByteRangeSet::Range(50, 20),
		ByteRangeSet::Range(80, 10),
	};
	
	const ByteRangeSet SET_B(RANGES_B.begin(), RANGES_B.end());
	
	const std::vector<ByteRangeSet::Range> INTERSECTION = {
		ByteRangeSet::Range(50, 20),
	};
	
	EXPECT_EQ(ByteRangeSet::intersection(SET_A, SET_B).get_ranges(), INTERSECTION);
	EXPECT_EQ(ByteRangeSet::intersection(SET_B, SET_A).get_ranges(), INTERSECTION);
}

TEST(ByteRangeSet, IntersectionMultipleSubsetsOfSingleRange)
{
	const std::vector<ByteRangeSet::Range> RANGES_A = {
		ByteRangeSet::Range(0, 100),
		ByteRangeSet::Range(110, 50),
	};
	
	const ByteRangeSet SET_A(RANGES_A.begin(), RANGES_A.end());
	
	const std::vector<ByteRangeSet::Range> RANGES_B = {
		ByteRangeSet::Range(20, 10),
		ByteRangeSet::Range(50, 20),
		ByteRangeSet::Range(80, 40),
	};
	
	const ByteRangeSet SET_B(RANGES_B.begin(), RANGES_B.end());
	
	const std::vector<ByteRangeSet::Range> INTERSECTION = {
		ByteRangeSet::Range(20, 10),
		ByteRangeSet::Range(50, 20),
		ByteRangeSet::Range(80, 20),
		ByteRangeSet::Range(110, 10),
	};
	
	EXPECT_EQ(ByteRangeSet::intersection(SET_A, SET_B).get_ranges(), INTERSECTION);
	EXPECT_EQ(ByteRangeSet::intersection(SET_B, SET_A).get_ranges(), INTERSECTION);
}

TEST(ByteRangeSet, IntersectionCombined)
{
	const std::vector<ByteRangeSet::Range> RANGES_A = {
		/* No overlap */
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(30, 20),
		ByteRangeSet::Range(70, 10),
		
		/* Partial overlap */
		ByteRangeSet::Range(150, 20),
		ByteRangeSet::Range(190, 10),
		
		/* Subset */
		ByteRangeSet::Range(250, 30),
		
		/* Exact match */
		ByteRangeSet::Range(350, 20),
		
		/* Multiple subsets */
		ByteRangeSet::Range(400, 100),
		ByteRangeSet::Range(510, 50),
		
		ByteRangeSet::Range(0, 100),
	};
	
	const ByteRangeSet SET_A(RANGES_A.begin(), RANGES_A.end());
	
	const std::vector<ByteRangeSet::Range> RANGES_B = {
		/* No overlap */
		ByteRangeSet::Range(20, 10),
		ByteRangeSet::Range(50, 20),
		ByteRangeSet::Range(80, 10),
		
		/* Partial overlap */
		ByteRangeSet::Range(120, 10),
		ByteRangeSet::Range(160, 20),
		
		/* Subset */
		ByteRangeSet::Range(260, 5),
		
		/* Exact match */
		ByteRangeSet::Range(350, 20),
		
		/* Multiple subsets */
		ByteRangeSet::Range(420, 10),
		ByteRangeSet::Range(450, 20),
		ByteRangeSet::Range(480, 40),
	};
	
	const ByteRangeSet SET_B(RANGES_B.begin(), RANGES_B.end());
	
	const std::vector<ByteRangeSet::Range> INTERSECTION = {
		/* Partial overlap */
		ByteRangeSet::Range(160, 10),
		
		/* Subset */
		ByteRangeSet::Range(260, 5),
		
		/* Exact match */
		ByteRangeSet::Range(350, 20),
		
		/* Multiple subsets */
		ByteRangeSet::Range(420, 10),
		ByteRangeSet::Range(450, 20),
		ByteRangeSet::Range(480, 20),
		ByteRangeSet::Range(510, 10),
	};
	
	EXPECT_EQ(ByteRangeSet::intersection(SET_A, SET_B).get_ranges(), INTERSECTION);
	EXPECT_EQ(ByteRangeSet::intersection(SET_B, SET_A).get_ranges(), INTERSECTION);
}

TEST(ByteRangeSet, IntersectionEmptySet)
{
	const std::vector<ByteRangeSet::Range> NON_EMPTY_RANGE = {
		ByteRangeSet::Range(10, 10),
	};
	
	const ByteRangeSet NON_EMPTY_SET(NON_EMPTY_RANGE.begin(), NON_EMPTY_RANGE.end());
	
	const std::vector<ByteRangeSet::Range> EMPTY_RANGE = {};
	const ByteRangeSet EMPTY_SET;
	
	EXPECT_EQ(ByteRangeSet::intersection( NON_EMPTY_SET, EMPTY_SET     ).get_ranges(), EMPTY_RANGE);
	EXPECT_EQ(ByteRangeSet::intersection( EMPTY_SET,     NON_EMPTY_SET ).get_ranges(), EMPTY_RANGE);
	EXPECT_EQ(ByteRangeSet::intersection( EMPTY_SET,     EMPTY_SET     ).get_ranges(), EMPTY_RANGE);
}

TEST(ByteRangeSet, FindFirstIn)
{
	const std::vector<ByteRangeSet::Range> RANGES = {
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(50, 30),
	};
	
	const ByteRangeSet SET(RANGES.begin(), RANGES.end());
	
	EXPECT_EQ(SET.find_first_in( 0,   0), SET.end());
	EXPECT_EQ(SET.find_first_in( 0,  10), SET.end());
	EXPECT_EQ(SET.find_first_in( 0,  11), std::next(SET.begin(), 0));
	EXPECT_EQ(SET.find_first_in( 0,  20), std::next(SET.begin(), 0));
	EXPECT_EQ(SET.find_first_in( 0,  30), std::next(SET.begin(), 0));
	EXPECT_EQ(SET.find_first_in( 0, 100), std::next(SET.begin(), 0));
	EXPECT_EQ(SET.find_first_in(10,   0), SET.end());
	EXPECT_EQ(SET.find_first_in(10,  10), std::next(SET.begin(), 0));
	EXPECT_EQ(SET.find_first_in(10,  20), std::next(SET.begin(), 0));
	EXPECT_EQ(SET.find_first_in(19,   1), std::next(SET.begin(), 0));
	EXPECT_EQ(SET.find_first_in(20,  30), SET.end());
	EXPECT_EQ(SET.find_first_in(20,  31), std::next(SET.begin(), 1));
	EXPECT_EQ(SET.find_first_in(20, 100), std::next(SET.begin(), 1));
	EXPECT_EQ(SET.find_first_in(79, 100), std::next(SET.begin(), 1));
	EXPECT_EQ(SET.find_first_in(80, 100), SET.end());
}

TEST(ByteRangeSet, FindLastIn)
{
	const std::vector<ByteRangeSet::Range> RANGES = {
		ByteRangeSet::Range(10, 10),
		ByteRangeSet::Range(50, 30),
	};
	
	const ByteRangeSet SET(RANGES.begin(), RANGES.end());
	
	EXPECT_EQ(SET.find_last_in( 0,   0), SET.end());
	EXPECT_EQ(SET.find_last_in( 0,  10), SET.end());
	EXPECT_EQ(SET.find_last_in( 0,  11), std::next(SET.begin(), 0));
	EXPECT_EQ(SET.find_last_in( 0,  20), std::next(SET.begin(), 0));
	EXPECT_EQ(SET.find_last_in( 0,  30), std::next(SET.begin(), 0));
	EXPECT_EQ(SET.find_last_in( 0, 100), std::next(SET.begin(), 1));
	EXPECT_EQ(SET.find_last_in(10,   0), SET.end());
	EXPECT_EQ(SET.find_last_in(10,  10), std::next(SET.begin(), 0));
	EXPECT_EQ(SET.find_last_in(10,  20), std::next(SET.begin(), 0));
	EXPECT_EQ(SET.find_last_in(19,   1), std::next(SET.begin(), 0));
	EXPECT_EQ(SET.find_last_in(19,  31), std::next(SET.begin(), 0));
	EXPECT_EQ(SET.find_last_in(19,  32), std::next(SET.begin(), 1));
	EXPECT_EQ(SET.find_last_in(20,  30), SET.end());
	EXPECT_EQ(SET.find_last_in(20,  31), std::next(SET.begin(), 1));
	EXPECT_EQ(SET.find_last_in(20, 100), std::next(SET.begin(), 1));
	EXPECT_EQ(SET.find_last_in(79, 100), std::next(SET.begin(), 1));
	EXPECT_EQ(SET.find_last_in(80, 100), SET.end());
}

TEST(OrderedByteRangeSet, EmptySet)
{
	OrderedByteRangeSet brs;
	
	EXPECT_RANGES();
}

TEST(OrderedByteRangeSet, AddOneRange)
{
	OrderedByteRangeSet brs;
	
	brs.set_range(10, 20);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 20),
	);
}

TEST(OrderedByteRangeSet, AddExclusiveRanges)
{
	OrderedByteRangeSet brs;
	
	brs.set_range(10, 20);
	brs.set_range(80, 40);
	brs.set_range(40, 30);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 20),
		ByteRangeSet::Range(80, 40),
		ByteRangeSet::Range(40, 30),
	);
}

TEST(OrderedByteRangeSet, AddSameRange)
{
	OrderedByteRangeSet brs;
	
	brs.set_range(10, 20);
	brs.set_range(10, 20);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 20),
	);
}

TEST(OrderedByteRangeSet, AddOverlappingRanges)
{
	OrderedByteRangeSet brs;
	
	brs.set_range(10, 20);
	brs.set_range(15, 40);
	brs.set_range(20, 10);
	
	brs.set_range(80, 10);
	brs.set_range(70, 15);
	brs.set_range(85, 10);
	
	EXPECT_RANGES(
		ByteRangeSet::Range(10, 20),
		ByteRangeSet::Range(30, 25),
		ByteRangeSet::Range(80, 10),
		ByteRangeSet::Range(70, 10),
		ByteRangeSet::Range(90,  5),
	);
	
	EXPECT_FALSE(brs.isset(9));
	EXPECT_TRUE(brs.isset(10, 45));
	EXPECT_FALSE(brs.isset(55));
	
	EXPECT_FALSE(brs.isset(69));
	EXPECT_TRUE(brs.isset(70, 25));
	EXPECT_FALSE(brs.isset(95));
}
