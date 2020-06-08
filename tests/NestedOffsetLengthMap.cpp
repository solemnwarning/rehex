/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018-2020 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <iterator>

#include "../src/NestedOffsetLengthMap.hpp"

#define OK_SET(offset, length, value) \
{ \
	EXPECT_TRUE(NestedOffsetLengthMap_set(map, offset, length, value)) \
		<< "Setting " << offset << "," << length << " = " << value << " succeeded"; \
	\
	NestedOffsetLengthMapKey k(offset, length); \
	EXPECT_TRUE((map.find(k) != map.end()) && map.find(k)->second == value) \
		<< "Setting " << offset << "," << length << " = " << value << " really succeeded"; \
}

#define BAD_SET(offset, length, why) \
{ \
	EXPECT_FALSE(NestedOffsetLengthMap_set(map, offset, length, 0)) << why; \
}

#define OK_GET(offset, value) \
{ \
	auto i = NestedOffsetLengthMap_get(map, offset); \
	EXPECT_TRUE(i != map.end()) << "NestedOffsetLengthMap_get(map, " << offset << ") returns an element"; \
	if(i != map.end()) \
	{ \
		EXPECT_EQ(i->second, value) << "NestedOffsetLengthMap_get(map, " << offset << ") finds " << value; \
	} \
}

#define BAD_GET(offset) \
{ \
	auto i = NestedOffsetLengthMap_get(map, offset); \
	EXPECT_TRUE(i == map.end()) << "NestedOffsetLengthMap_get(map, " << offset << ") returns no element"; \
}

#define GET_ALL_CHECK(map, offset, ...) \
{ \
	auto got_iterators = NestedOffsetLengthMap_get_all(map, offset); \
	const std::vector<int> expect_indexes = { __VA_ARGS__ }; \
	std::list<NestedOffsetLengthMap<int>::const_iterator> expect_iterators; \
	for(const int i : expect_indexes) \
	{ \
		expect_iterators.push_back(std::next(map.begin(), i)); \
	} \
	EXPECT_EQ(got_iterators, expect_iterators); \
}

#define GET_RECURSIVE_CHECK(map, offset, length, ...) \
{ \
	auto got_iterators = NestedOffsetLengthMap_get_recursive(map, NestedOffsetLengthMapKey(offset, length)); \
	const std::vector<int> expect_indexes = { __VA_ARGS__ }; \
	std::list<NestedOffsetLengthMap<int>::const_iterator> expect_iterators; \
	for(const int i : expect_indexes) \
	{ \
		expect_iterators.push_back(std::next(map.begin(), i)); \
	} \
	EXPECT_EQ(got_iterators, expect_iterators); \
}

using namespace REHex;

TEST(NestedOffsetLengthMap, Basic)
{
	{
		NestedOffsetLengthMap<int> map;
		
		OK_SET(0,  0,  1 );
		OK_SET(0,  10, 2 );
		OK_SET(20, 10, 3 );
		OK_SET(20, 0,  4 );
		OK_SET(20, 5,  5 );
		OK_SET(25, 5,  6 );
		OK_SET(30, 10, 7 );
		OK_SET(30, 10, 8 ); /* Overwrite */
		OK_SET(15, 15, 9 );
		OK_SET(40, 0,  10);
		OK_SET(50, 1,  11);
		
		OK_GET(0, 2);
		OK_GET(20, 5);
		OK_GET(21, 5);
		OK_GET(24, 5);
		OK_GET(25, 6);
		OK_GET(30, 8);
		OK_GET(50, 11);
		
		BAD_GET(10);
		BAD_GET(14);
		BAD_GET(40);
	}
	
	{
		NestedOffsetLengthMap<int> map;
		
		OK_SET(10, 10, 1);
		OK_SET(30, 10, 2);
		OK_SET(50, 10, 3);
		
		BAD_SET(9, 2, "Overlapping start of existing range at start of map");
		BAD_SET(29, 2, "Overlapping start of existing range in middle of map");
		BAD_SET(49, 2, "Overlapping start of existing range at end of map");
		
		BAD_SET(29, 2, "Overlapping end of existing range at start of map");
		BAD_SET(39, 2, "Overlapping end of existing range in middle of map");
		BAD_SET(59, 2, "Overlapping end of existing range at end of map");
	}
}

TEST(NestedOffsetLengthMap, GetAll)
{
	NestedOffsetLengthMap<int> map;
	NestedOffsetLengthMap_set(map, 5,  4,  0);  /* 0 */
	NestedOffsetLengthMap_set(map, 5,  5,  0);  /* 1 */
	NestedOffsetLengthMap_set(map, 5,  20, 0);  /* 2 */
	NestedOffsetLengthMap_set(map, 10, 0,  0);  /* 3 */
	NestedOffsetLengthMap_set(map, 10, 5,  0);  /* 4 */
	NestedOffsetLengthMap_set(map, 10, 10, 0);  /* 5 */
	
	GET_ALL_CHECK(
		map, 4,
		/* No matches */);
	
	GET_ALL_CHECK(
		map, 5,
		0, 1, 2);
	
	GET_ALL_CHECK(
		map, 8,
		0, 1, 2);
	
	GET_ALL_CHECK(
		map, 9,
		1, 2);
	
	GET_ALL_CHECK(
		map, 10,
		3, 4, 5, 2);
	
	GET_ALL_CHECK(
		map, 11,
		4, 5, 2);
	
	GET_ALL_CHECK(
		map, 19,
		5, 2);
	
	GET_ALL_CHECK(
		map, 20,
		2);
}

TEST(NestedOffsetLengthMap, GetRecursive)
{
	NestedOffsetLengthMap<int> map;
	NestedOffsetLengthMap_set(map, 5,  4,  0);  /* 0 */
	NestedOffsetLengthMap_set(map, 5,  5,  0);  /* 1 */
	NestedOffsetLengthMap_set(map, 5,  20, 0);  /* 2 */
	NestedOffsetLengthMap_set(map, 10, 0,  0);  /* 3 */
	NestedOffsetLengthMap_set(map, 10, 5,  0);  /* 4 */
	NestedOffsetLengthMap_set(map, 10, 10, 0);  /* 5 */
	NestedOffsetLengthMap_set(map, 40, 0,  0);  /* 6 */
	NestedOffsetLengthMap_set(map, 40, 5,  0);  /* 7 */
	NestedOffsetLengthMap_set(map, 40, 10, 0);  /* 8 */
	
	GET_RECURSIVE_CHECK(
		map, 5, 0,
		/* No matches */);
	
	GET_RECURSIVE_CHECK(
		map, 5, 4,
		0);
	
	GET_RECURSIVE_CHECK(
		map, 5, 5,
		0, 1);
	
	GET_RECURSIVE_CHECK(
		map, 5, 20,
		0, 1, 2, 3, 4, 5);
	
	GET_RECURSIVE_CHECK(
		map, 10, 0,
		3);
	
	GET_RECURSIVE_CHECK(
		map, 10, 5,
		3, 4);
	
	GET_RECURSIVE_CHECK(
		map, 10, 10,
		3, 4, 5);
	
	GET_RECURSIVE_CHECK(
		map, 40, 0,
		6);
	
	GET_RECURSIVE_CHECK(
		map, 40, 5,
		6, 7);
	
	GET_RECURSIVE_CHECK(
		map, 40, 10,
		6, 7, 8);
}

TEST(NestedOffsetLengthMap, DataInserted)
{
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 0, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_inserted(map, 0, 4);
		
		EXPECT_EQ(map.begin()->first.offset, 14) << "Inserting data before zero-length key shifts offset";
		EXPECT_EQ(map.begin()->first.length, 0)  << "Inserting data before zero-length key doesn't touch length";
		EXPECT_EQ(keys_modified,             1U) << "Inserting data before zero-length key returns 1 key modified";
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 0, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_inserted(map, 6, 4);
		
		EXPECT_EQ(map.begin()->first.offset, 14) << "Inserting data immediately before zero-length key shifts offset";
		EXPECT_EQ(map.begin()->first.length, 0)  << "Inserting data immediately before zero-length key doesn't touch length";
		EXPECT_EQ(keys_modified,             1U) << "Inserting data immediately before zero-length key returns 1 key modified";
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 0, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_inserted(map, 10, 1);
		
		EXPECT_EQ(map.begin()->first.offset, 11) << "Inserting data at zero-length key shifts offset";
		EXPECT_EQ(map.begin()->first.length, 0)  << "Inserting data at zero-length key doesn't touch length";
		EXPECT_EQ(keys_modified,             1U) << "Inserting data at zero-length key returns 1 key modified";
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 0, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_inserted(map, 11, 1);
		
		EXPECT_EQ(map.begin()->first.offset, 10) << "Inserting data after zero-length key doesn't touch offset";
		EXPECT_EQ(map.begin()->first.length, 0)  << "Inserting data after zero-length key doesn't touch length";
		EXPECT_EQ(keys_modified,             0U) << "Inserting data after zero-length key returns 0 keys modified";
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_inserted(map, 0, 4);
		
		EXPECT_EQ(map.begin()->first.offset, 14) << "Inserting data before nonzero-length key shifts offset";
		EXPECT_EQ(map.begin()->first.length, 8)  << "Inserting data before nonzero-length key doesn't touch length";
		EXPECT_EQ(keys_modified,             1U) << "Inserting data before nonzero-length key returns 1 key modified";
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_inserted(map, 6, 4);
		
		EXPECT_EQ(map.begin()->first.offset, 14) << "Inserting data immediately before nonzero-length key shifts offset";
		EXPECT_EQ(map.begin()->first.length, 8)  << "Inserting data immediately before nonzero-length key doesn't touch length";
		EXPECT_EQ(keys_modified,             1U) << "Inserting data immediately before nonzero-length key returns 1 key modified";
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_inserted(map, 10, 1);
		
		EXPECT_EQ(map.begin()->first.offset, 11) << "Inserting data at nonzero-length key shifts offset";
		EXPECT_EQ(map.begin()->first.length, 8)  << "Inserting data at nonzero-length key doesn't touch length";
		EXPECT_EQ(keys_modified,             1U) << "Inserting data at nonzero-length key returns 1 key modified";
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_inserted(map, 11, 4);
		
		EXPECT_EQ(map.begin()->first.offset, 10) << "Inserting data after start of nonzero-length key doesn't shift offset";
		EXPECT_EQ(map.begin()->first.length, 12) << "Inserting data after start of nonzero-length key increases length";
		EXPECT_EQ(keys_modified,             1U) << "Inserting data after start of nonzero-length key returns 1 key modified";
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_inserted(map, 17, 4);
		
		EXPECT_EQ(map.begin()->first.offset, 10) << "Inserting data before end of nonzero-length key doesn't shift offset";
		EXPECT_EQ(map.begin()->first.length, 12) << "Inserting data before end of nonzero-length key increases length";
		EXPECT_EQ(keys_modified,             1U) << "Inserting data before end of nonzero-length key returns 1 key modified";
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_inserted(map, 18, 1);
		
		EXPECT_EQ(map.begin()->first.offset, 10) << "Inserting data after nonzero-length key doesn't touch offset";
		EXPECT_EQ(map.begin()->first.length, 8)  << "Inserting data after nonzero-length key doesn't touch length";
		EXPECT_EQ(keys_modified,             0U) << "Inserting data after nonzero-length key returns 0 keys modified";
	}
}
	
TEST(NestedOffsetLengthMap, DataErased)
{
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 0, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 0, 4);
		
		EXPECT_EQ(map.begin()->first.offset, 6)  << "Erasing data before zero-length key shifts offset";
		EXPECT_EQ(map.begin()->first.length, 0)  << "Erasing data before zero-length key doesn't touch length";
		EXPECT_EQ(keys_modified,             1U) << "Erasing data before zero-length key returns 1 key modified";
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 0, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 6, 4);
		
		EXPECT_EQ(map.begin()->first.offset, 6)  << "Erasing data immediately before zero-length key shifts offset";
		EXPECT_EQ(map.begin()->first.length, 0)  << "Erasing data immediately before zero-length key doesn't touch length";
		EXPECT_EQ(keys_modified,             1U) << "Erasing data immediately before zero-length key returns 1 key modified";
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 0, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 10, 1);
		
		EXPECT_TRUE(map.empty())     << "Erasing data at zero-length key deletes key";
		EXPECT_EQ(keys_modified, 1U) << "Erasing data at zero-length key returns 1 key modified";
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 0, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 4, 20);
		
		EXPECT_TRUE(map.empty())     << "Erasing data encompassing zero-length key deletes key";
		EXPECT_EQ(keys_modified, 1U) << "Erasing data encompassing zero-length key returns 1 key modified";
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 0, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 11, 4);
		
		EXPECT_EQ(map.begin()->first.offset, 10) << "Erasing data immediately after zero-length key doesn't touch offset";
		EXPECT_EQ(map.begin()->first.length, 0)  << "Erasing data immediately after zero-length key doesn't touch length";
		EXPECT_EQ(keys_modified,             0U) << "Erasing data immediately after zero-length key returns 0 keys modified";
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 0, 4);
		
		EXPECT_EQ(map.begin()->first.offset, 6)  << "Erasing data before nonzero-length key shifts offset";
		EXPECT_EQ(map.begin()->first.length, 8)  << "Erasing data before nonzero-length key doesn't touch length";
		EXPECT_EQ(keys_modified,             1U) << "Erasing data before nonzero-length key returns 1 key modified";
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 6, 4);
		
		EXPECT_EQ(map.begin()->first.offset, 6)  << "Erasing data immediately before nonzero-length key shifts offset";
		EXPECT_EQ(map.begin()->first.length, 8)  << "Erasing data immediately before nonzero-length key doesn't touch length";
		EXPECT_EQ(keys_modified,             1U) << "Erasing data immediately before nonzero-length key returns 1 key modified";
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 10, 2);
		
		EXPECT_EQ(map.begin()->first.offset, 10) << "Erasing data at start of nonzero-length key doesn't touch offset";
		EXPECT_EQ(map.begin()->first.length, 6)  << "Erasing data at start of nonzero-length key reduces length";
		EXPECT_EQ(keys_modified,             1U) << "Erasing data at start of nonzero-length key returns 1 key modified";
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 16, 2);
		
		EXPECT_EQ(map.begin()->first.offset, 10) << "Erasing data at end of nonzero-length key doesn't touch offset";
		EXPECT_EQ(map.begin()->first.length, 6)  << "Erasing data at end of nonzero-length key reduces length";
		EXPECT_EQ(keys_modified,             1U) << "Erasing data at end of nonzero-length key returns 1 key modified";
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 13, 2);
		
		EXPECT_EQ(map.begin()->first.offset, 10) << "Erasing data in nonzero-length key doesn't touch offset";
		EXPECT_EQ(map.begin()->first.length, 6)  << "Erasing data in nonzero-length key reduces length";
		EXPECT_EQ(keys_modified,             1U) << "Erasing data in nonzero-length key returns 1 key modified";
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 10, 8);
		
		EXPECT_TRUE(map.empty())     << "Erasing data matching nonzero-length key deletes key";
		EXPECT_EQ(keys_modified, 1U) << "Erasing data matching nonzero-length key returns 1 key modified";
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 8, 6);
		
		EXPECT_EQ(map.begin()->first.offset, 8)  << "Erasing data spanning start of nonzero-length key shifts offset";
		EXPECT_EQ(map.begin()->first.length, 4)  << "Erasing data spanning start of nonzero-length key reduces length";
		EXPECT_EQ(keys_modified,             1U) << "Erasing data spanning start of nonzero-length key returns 1 key modified";
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 16, 6);
		
		EXPECT_EQ(map.begin()->first.offset, 10)  << "Erasing data spanning end of nonzero-length key doesn't touch offset";
		EXPECT_EQ(map.begin()->first.length, 6)   << "Erasing data spanning end of nonzero-length key reduces length";
		EXPECT_EQ(keys_modified,             1U)  << "Erasing data spanning end of nonzero-length key returns 1 key modified";
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 4, 20);
		
		EXPECT_TRUE(map.empty())     << "Erasing data encompassing nonzero-length key deletes key";
		EXPECT_EQ(keys_modified, 1U) << "Erasing data encompassing nonzero-length key returns 1 key modified";
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 18, 4);
		
		EXPECT_EQ(map.begin()->first.offset, 10) << "Erasing data immediately after nonzero-length key doesn't touch offset";
		EXPECT_EQ(map.begin()->first.length, 8)  << "Erasing data immediately after nonzero-length key doesn't touch length";
		EXPECT_EQ(keys_modified,             0U) << "Erasing data immediately after nonzero-length key returns 0 keys modified";
	}
}
