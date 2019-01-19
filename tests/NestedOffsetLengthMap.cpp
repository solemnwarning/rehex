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

#include "tests/tap/basic.h"

#include "../src/NestedOffsetLengthMap.hpp"

#define OK_SET(offset, length, value) \
{ \
	ok(NestedOffsetLengthMap_set(map, offset, length, value), \
		"Setting %d,%d = %d succeeded (%s:%d)", offset, length, value, __FILE__, __LINE__); \
	\
	NestedOffsetLengthMapKey k(offset, length); \
	ok((map.find(k) != map.end()) && map.find(k)->second == value, \
		"Setting %d,%d = %d really succeeded (%s:%d)", offset, length, value, __FILE__, __LINE__); \
}

#define BAD_SET(offset, length, fmt, ...) \
{ \
	ok(!NestedOffsetLengthMap_set(map, offset, length, 0), fmt " (%s:%d)", __FILE__, __LINE__, ## __VA_ARGS__); \
}

#define OK_GET(offset, value) \
{ \
	auto i = NestedOffsetLengthMap_get(map, offset); \
	ok((i != map.end() && i->second == value), \
		"NestedOffsetLengthMap_get(map, %d) finds %d (%s:%d)", offset, value, __FILE__, __LINE__); \
}

#define BAD_GET(offset) \
{ \
	auto i = NestedOffsetLengthMap_get(map, offset); \
	ok((i == map.end()), \
		"NestedOffsetLengthMap_get(map, %d) finds no match (%s:%d)", offset, __FILE__, __LINE__) \
		|| diag("Found value: %d", i->second); \
}

using namespace REHex;

int main(int argc, char **argv)
{
	plan_lazy();
	
	/* Testing:
	 *
	 * NestedOffsetLengthMap_set()
	 * NestedOffsetLengthMap_get()
	*/
	
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
	
	/* Testing:
	 *
	 * NestedOffsetLengthMap_data_inserted()
	*/
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 0, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_inserted(map, 0, 4);
		
		is_int(14, map.begin()->first.offset, "Inserting data before zero-length key shifts offset");
		is_int(0,  map.begin()->first.length, "Inserting data before zero-length key doesn't touch length");
		is_int(keys_modified, 1,              "Inserting data before zero-length key returns 1 key modified");
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 0, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_inserted(map, 6, 4);
		
		is_int(14, map.begin()->first.offset, "Inserting data immediately before zero-length key shifts offset");
		is_int(0,  map.begin()->first.length, "Inserting data immediately before zero-length key doesn't touch length");
		is_int(keys_modified, 1,              "Inserting data immediately before zero-length key returns 1 key modified");
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 0, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_inserted(map, 10, 1);
		
		is_int(11, map.begin()->first.offset, "Inserting data at zero-length key shifts offset");
		is_int(0,  map.begin()->first.length, "Inserting data at zero-length key doesn't touch length");
		is_int(keys_modified, 1,              "Inserting data at zero-length key returns 1 key modified");
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 0, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_inserted(map, 11, 1);
		
		is_int(10, map.begin()->first.offset, "Inserting data after zero-length key doesn't touch offset");
		is_int(0,  map.begin()->first.length, "Inserting data after zero-length key doesn't touch length");
		is_int(keys_modified, 0,              "Inserting data after zero-length key returns 0 keys modified");
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_inserted(map, 0, 4);
		
		is_int(14, map.begin()->first.offset, "Inserting data before nonzero-length key shifts offset");
		is_int(8,  map.begin()->first.length, "Inserting data before nonzero-length key doesn't touch length");
		is_int(keys_modified, 1,              "Inserting data before nonzero-length key returns 1 key modified");
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_inserted(map, 6, 4);
		
		is_int(14, map.begin()->first.offset, "Inserting data immediately before nonzero-length key shifts offset");
		is_int(8,  map.begin()->first.length, "Inserting data immediately before nonzero-length key doesn't touch length");
		is_int(keys_modified, 1,              "Inserting data immediately before nonzero-length key returns 1 key modified");
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_inserted(map, 10, 1);
		
		is_int(11, map.begin()->first.offset, "Inserting data at nonzero-length key shifts offset");
		is_int(8,  map.begin()->first.length, "Inserting data at nonzero-length key doesn't touch length");
		is_int(keys_modified, 1,              "Inserting data at nonzero-length key returns 1 key modified");
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_inserted(map, 11, 4);
		
		is_int(10, map.begin()->first.offset, "Inserting data after start of nonzero-length key doesn't shift offset");
		is_int(12, map.begin()->first.length, "Inserting data after start of nonzero-length key increases length");
		is_int(keys_modified, 1,              "Inserting data after start of nonzero-length key returns 1 key modified");
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_inserted(map, 17, 4);
		
		is_int(10, map.begin()->first.offset, "Inserting data before end of nonzero-length key doesn't shift offset");
		is_int(12, map.begin()->first.length, "Inserting data before end of nonzero-length key increases length");
		is_int(keys_modified, 1,              "Inserting data before end of nonzero-length key returns 1 key modified");
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_inserted(map, 18, 1);
		
		is_int(10, map.begin()->first.offset, "Inserting data after nonzero-length key doesn't touch offset");
		is_int(8,  map.begin()->first.length, "Inserting data after nonzero-length key doesn't touch length");
		is_int(keys_modified, 0,              "Inserting data after nonzero-length key returns 0 keys modified");
	}
	
	/* Testing:
	 *
	 * NestedOffsetLengthMap_data_erased()
	*/
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 0, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 0, 4);
		
		is_int(6, map.begin()->first.offset, "Erasing data before zero-length key shifts offset");
		is_int(0, map.begin()->first.length, "Erasing data before zero-length key doesn't touch length");
		is_int(keys_modified, 1,             "Erasing data before zero-length key returns 1 key modified");
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 0, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 6, 4);
		
		is_int(6, map.begin()->first.offset, "Erasing data immediately before zero-length key shifts offset");
		is_int(0, map.begin()->first.length, "Erasing data immediately before zero-length key doesn't touch length");
		is_int(keys_modified, 1,             "Erasing data immediately before zero-length key returns 1 key modified");
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 0, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 10, 1);
		
		ok(map.empty(),          "Erasing data at zero-length key deletes key");
		is_int(keys_modified, 1, "Erasing data at zero-length key returns 1 key modified");
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 0, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 4, 20);
		
		ok(map.empty(),          "Erasing data encompassing zero-length key deletes key");
		is_int(keys_modified, 1, "Erasing data encompassing zero-length key returns 1 key modified");
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 0, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 11, 4);
		
		is_int(10, map.begin()->first.offset, "Erasing data immediately after zero-length key doesn't touch offset");
		is_int(0,  map.begin()->first.length, "Erasing data immediately after zero-length key doesn't touch length");
		is_int(keys_modified, 0,              "Erasing data immediately after zero-length key returns 0 keys modified");
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 0, 4);
		
		is_int(6, map.begin()->first.offset, "Erasing data before nonzero-length key shifts offset");
		is_int(8, map.begin()->first.length, "Erasing data before nonzero-length key doesn't touch length");
		is_int(keys_modified, 1,             "Erasing data before nonzero-length key returns 1 key modified");
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 6, 4);
		
		is_int(6, map.begin()->first.offset, "Erasing data immediately before nonzero-length key shifts offset");
		is_int(8, map.begin()->first.length, "Erasing data immediately before nonzero-length key doesn't touch length");
		is_int(keys_modified, 1,             "Erasing data immediately before nonzero-length key returns 1 key modified");
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 10, 2);
		
		is_int(10, map.begin()->first.offset, "Erasing data at start of nonzero-length key doesn't touch offset");
		is_int(6,  map.begin()->first.length, "Erasing data at start of nonzero-length key reduces length");
		is_int(keys_modified, 1,              "Erasing data at start of nonzero-length key returns 1 key modified");
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 16, 2);
		
		is_int(10, map.begin()->first.offset, "Erasing data at end of nonzero-length key doesn't touch offset");
		is_int(6,  map.begin()->first.length, "Erasing data at end of nonzero-length key reduces length");
		is_int(keys_modified, 1,              "Erasing data at end of nonzero-length key returns 1 key modified");
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 13, 2);
		
		is_int(10, map.begin()->first.offset, "Erasing data in nonzero-length key doesn't touch offset");
		is_int(6,  map.begin()->first.length, "Erasing data in nonzero-length key reduces length");
		is_int(keys_modified, 1,              "Erasing data in nonzero-length key returns 1 key modified");
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 10, 8);
		
		ok(map.empty(),          "Erasing data matching nonzero-length key deletes key");
		is_int(keys_modified, 1, "Erasing data matching nonzero-length key returns 1 key modified");
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 8, 6);
		
		is_int(8, map.begin()->first.offset, "Erasing data spanning start of nonzero-length key shifts offset");
		is_int(4, map.begin()->first.length, "Erasing data spanning start of nonzero-length key reduces length");
		is_int(keys_modified, 1,             "Erasing data spanning start of nonzero-length key returns 1 key modified");
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 16, 6);
		
		is_int(10, map.begin()->first.offset, "Erasing data spanning end of nonzero-length key doesn't touch offset");
		is_int(6,  map.begin()->first.length, "Erasing data spanning end of nonzero-length key reduces length");
		is_int(keys_modified, 1,              "Erasing data spanning end of nonzero-length key returns 1 key modified");
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 4, 20);
		
		ok(map.empty(),          "Erasing data encompassing nonzero-length key deletes key");
		is_int(keys_modified, 1, "Erasing data encompassing nonzero-length key returns 1 key modified");
	}
	
	{
		NestedOffsetLengthMap<int> map;
		NestedOffsetLengthMap_set(map, 10, 8, 0);
		size_t keys_modified = NestedOffsetLengthMap_data_erased(map, 18, 4);
		
		is_int(10, map.begin()->first.offset, "Erasing data immediately after nonzero-length key doesn't touch offset");
		is_int(8,  map.begin()->first.length, "Erasing data immediately after nonzero-length key doesn't touch length");
		is_int(keys_modified, 0,              "Erasing data immediately after nonzero-length key returns 0 keys modified");
	}
	
	return 0;
}
