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

#include "../src/ByteAccumulator.hpp"

using namespace REHex;

TEST(ByteAccumulator, BasicTests)
{
	ByteAccumulator accumulator;
	
	EXPECT_EQ(accumulator.get_total_bytes(),  0U) << "ByteAccumulator counters are initialised to zero";
	EXPECT_EQ(accumulator.get_byte_count(10), 0U) << "ByteAccumulator counters are initialised to zero";
	EXPECT_EQ(accumulator.get_byte_count(15), 0U) << "ByteAccumulator counters are initialised to zero";
	EXPECT_EQ(accumulator.get_byte_count(20), 0U) << "ByteAccumulator counters are initialised to zero";
	EXPECT_EQ(accumulator.get_byte_count(25), 0U) << "ByteAccumulator counters are initialised to zero";
	EXPECT_EQ(accumulator.get_byte_sum(),     0U) << "ByteAccumulator counters are initialised to zero";
	
	accumulator.add_byte(10);
	accumulator.add_byte(10);
	accumulator.add_byte(20);
	accumulator.add_byte(15);
	
	EXPECT_EQ(accumulator.get_total_bytes(),   4U) << "ByteAccumulator::get_total_bytes() returns number of bytes recorded since initialisation";
	EXPECT_EQ(accumulator.get_byte_count(10),  2U) << "ByteAccumulator::get_byte_count() returns number of times byte was recorded since initialisation";
	EXPECT_EQ(accumulator.get_byte_count(15),  1U) << "ByteAccumulator::get_byte_count() returns number of times byte was recorded since initialisation";
	EXPECT_EQ(accumulator.get_byte_count(20),  1U) << "ByteAccumulator::get_byte_count() returns number of times byte was recorded since initialisation";
	EXPECT_EQ(accumulator.get_byte_count(25),  0U) << "ByteAccumulator::get_byte_count() returns number of times byte was recorded since initialisation";
	EXPECT_EQ(accumulator.get_byte_sum(),     55U) << "ByteAccumulator::get_byte_sum() returns sum of bytes recorded since initialisation";
	
	EXPECT_EQ(accumulator.get_min_byte(), 10U) << "ByteAccumulator::get_min_byte() returns smallest byte recorded since initialisation";
	EXPECT_EQ(accumulator.get_max_byte(), 20U) << "ByteAccumulator::get_min_byte() returns largest byte recorded since initialisation";
	
	accumulator.reset();
	
	EXPECT_EQ(accumulator.get_total_bytes(),  0U) << "ByteAccumulator::reset() method resets all counters";
	EXPECT_EQ(accumulator.get_byte_count(10), 0U) << "ByteAccumulator::reset() method resets all counters";
	EXPECT_EQ(accumulator.get_byte_count(15), 0U) << "ByteAccumulator::reset() method resets all counters";
	EXPECT_EQ(accumulator.get_byte_count(20), 0U) << "ByteAccumulator::reset() method resets all counters";
	EXPECT_EQ(accumulator.get_byte_count(25), 0U) << "ByteAccumulator::reset() method resets all counters";
	EXPECT_EQ(accumulator.get_byte_sum(),     0U) << "ByteAccumulator::reset() method resets all counters";
	
	accumulator.add_byte(15);
	accumulator.add_byte(25);
	
	EXPECT_EQ(accumulator.get_total_bytes(),   2U) << "ByteAccumulator::get_total_bytes() returns number of bytes recorded since reset";
	EXPECT_EQ(accumulator.get_byte_count(10),  0U) << "ByteAccumulator::get_byte_count() returns number of times byte was recorded since reset";
	EXPECT_EQ(accumulator.get_byte_count(15),  1U) << "ByteAccumulator::get_byte_count() returns number of times byte was recorded since reset";
	EXPECT_EQ(accumulator.get_byte_count(20),  0U) << "ByteAccumulator::get_byte_count() returns number of times byte was recorded since reset";
	EXPECT_EQ(accumulator.get_byte_count(25),  1U) << "ByteAccumulator::get_byte_count() returns number of times byte was recorded since reset";
	EXPECT_EQ(accumulator.get_byte_sum(),     40U) << "ByteAccumulator::get_byte_sum() returns sum of bytes recorded since reset";
	
	EXPECT_EQ(accumulator.get_min_byte(), 15U) << "ByteAccumulator::get_min_byte() returns smallest byte recorded since reset";
	EXPECT_EQ(accumulator.get_max_byte(), 25U) << "ByteAccumulator::get_max_byte() returns largest byte recorded since reset";
}

TEST(ByteAccumulator, AddAccumulator)
{
	ByteAccumulator a1;
	a1.add_byte(10);
	a1.add_byte(10);
	a1.add_byte(20);
	
	{
		ByteAccumulator a2;
		a2.add_byte(20);
		a2.add_byte(30);
		
		a1 += a2;
	}
	
	EXPECT_EQ(a1.get_total_bytes(),   5U) << "ByteAccumulator counts combined bytes after adding a ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_count(10),  2U) << "ByteAccumulator counts combined byte counts after adding a ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_count(20),  2U) << "ByteAccumulator counts combined byte counts after adding a ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_count(30),  1U) << "ByteAccumulator counts combined byte counts after adding a ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_sum(),     90U) << "ByteAccumulator counts combined byte sum after adding a ByteAccumulator object";
	
	EXPECT_EQ(a1.get_min_byte(), 10U) << "ByteAccumulator has correct min byte after adding a ByteAccumulator object";
	EXPECT_EQ(a1.get_max_byte(), 30U) << "ByteAccumulator has correct min byte after adding a ByteAccumulator object";
	
	{
		ByteAccumulator a2;
		a2.add_byte(5);
		
		a1 += a2;
	}
	
	EXPECT_EQ(a1.get_total_bytes(),   6U) << "ByteAccumulator counts combined bytes after adding a ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_count( 5),  1U) << "ByteAccumulator counts combined byte counts after adding a ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_count(10),  2U) << "ByteAccumulator counts combined byte counts after adding a ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_count(20),  2U) << "ByteAccumulator counts combined byte counts after adding a ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_count(30),  1U) << "ByteAccumulator counts combined byte counts after adding a ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_sum(),     95U) << "ByteAccumulator counts combined byte sum after adding a ByteAccumulator object";
	
	EXPECT_EQ(a1.get_min_byte(),  5U) << "ByteAccumulator has correct min byte after adding a ByteAccumulator object";
	EXPECT_EQ(a1.get_max_byte(), 30U) << "ByteAccumulator has correct min byte after adding a ByteAccumulator object";
	
	{
		ByteAccumulator a2;
		a2.add_byte(40);
		
		a1 += a2;
	}
	
	EXPECT_EQ(a1.get_total_bytes(),   7U) << "ByteAccumulator counts combined bytes after adding a ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_count( 5),  1U) << "ByteAccumulator counts combined byte counts after adding a ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_count(10),  2U) << "ByteAccumulator counts combined byte counts after adding a ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_count(20),  2U) << "ByteAccumulator counts combined byte counts after adding a ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_count(30),  1U) << "ByteAccumulator counts combined byte counts after adding a ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_count(40),  1U) << "ByteAccumulator counts combined byte counts after adding a ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_sum(),    135U) << "ByteAccumulator counts combined byte sum after adding a ByteAccumulator object";
	
	EXPECT_EQ(a1.get_min_byte(),  5U) << "ByteAccumulator has correct min byte after adding a ByteAccumulator object";
	EXPECT_EQ(a1.get_max_byte(), 40U) << "ByteAccumulator has correct min byte after adding a ByteAccumulator object";
	
	a1 += ByteAccumulator();
	
	EXPECT_EQ(a1.get_total_bytes(),   7U) << "ByteAccumulator counts combined bytes after adding a empty ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_count( 5),  1U) << "ByteAccumulator counts combined byte counts after adding a empty ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_count(10),  2U) << "ByteAccumulator counts combined byte counts after adding a empty ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_count(20),  2U) << "ByteAccumulator counts combined byte counts after adding a empty ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_count(30),  1U) << "ByteAccumulator counts combined byte counts after adding a empty ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_count(40),  1U) << "ByteAccumulator counts combined byte counts after adding a empty ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_sum(),    135U) << "ByteAccumulator counts combined byte sum after adding a empty ByteAccumulator object";
	
	EXPECT_EQ(a1.get_min_byte(),  5U) << "ByteAccumulator has correct min byte after adding a empty ByteAccumulator object";
	EXPECT_EQ(a1.get_max_byte(), 40U) << "ByteAccumulator has correct min byte after adding a empty ByteAccumulator object";
}

TEST(ByteAccumulator, SubtractAccumulator)
{
	ByteAccumulator a1;
	a1.add_byte(10);
	a1.add_byte(20);
	a1.add_byte(30);
	a1.add_byte(30);
	a1.add_byte(30);
	
	{
		ByteAccumulator a2;
		a2.add_byte(10);
		a2.add_byte(30);
		
		a1 -= a2;
	}
	
	EXPECT_EQ(a1.get_total_bytes(),   3U) << "ByteAccumulator counts combined bytes after subtracting a ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_count(10),  0U) << "ByteAccumulator counts combined byte counts after subtracting a ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_count(20),  1U) << "ByteAccumulator counts combined byte counts after subtracting a ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_count(30),  2U) << "ByteAccumulator counts combined byte counts after subtracting a ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_sum(),     80U) << "ByteAccumulator counts combined byte sum after subtracting a ByteAccumulator object";
	
	EXPECT_EQ(a1.get_min_byte(), 20U) << "ByteAccumulator has correct min byte after subtracting a ByteAccumulator object";
	EXPECT_EQ(a1.get_max_byte(), 30U) << "ByteAccumulator has correct min byte after subtracting a ByteAccumulator object";
	
	{
		ByteAccumulator a2;
		a2.add_byte(30);
		a2.add_byte(30);
		
		a1 -= a2;
	}
	
	EXPECT_EQ(a1.get_total_bytes(),   1U) << "ByteAccumulator counts combined bytes after subtracting a ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_count(10),  0U) << "ByteAccumulator counts combined byte counts after subtracting a ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_count(20),  1U) << "ByteAccumulator counts combined byte counts after subtracting a ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_count(30),  0U) << "ByteAccumulator counts combined byte counts after subtracting a ByteAccumulator object";
	EXPECT_EQ(a1.get_byte_sum(),     20U) << "ByteAccumulator counts combined byte sum after subtracting a ByteAccumulator object";
	
	EXPECT_EQ(a1.get_min_byte(), 20U) << "ByteAccumulator has correct min byte after subtracting a ByteAccumulator object";
	EXPECT_EQ(a1.get_max_byte(), 20U) << "ByteAccumulator has correct min byte after subtracting a ByteAccumulator object";
}
