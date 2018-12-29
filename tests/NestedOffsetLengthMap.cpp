/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018 Daniel Collins <solemnwarning@solemnwarning.net>
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
	
	BAD_SET(15, 14, "Overlapping start of existing range");
	BAD_SET(25, 6,  "Overlapping end of existing range");
	
	OK_GET(0, 2);
	OK_GET(20, 5);
	OK_GET(21, 5);
	OK_GET(24, 5);
	OK_GET(25, 6);
	OK_GET(30, 8);
	
	BAD_GET(10);
	BAD_GET(14);
	BAD_GET(40);
	
	return 0;
}
