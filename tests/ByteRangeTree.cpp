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
#include <iterator>

/* Enable extra sanity checks (expensive) in ByteRangeTree. */
#define REHEX_BYTERANGETREE_CHECKS

#include "../src/ByteRangeTree.hpp"

using namespace REHex;

TEST(ByteRangeTree, DepthFirstForwards)
{
	ByteRangeTree<int> tree;
	
	ASSERT_TRUE(tree.set(0, 100, 0));
		ASSERT_TRUE(tree.set(0, 20, 1));
			ASSERT_TRUE(tree.set(0,  5, 2));
			ASSERT_TRUE(tree.set(5,  5, 3));
			ASSERT_TRUE(tree.set(10, 5, 4));
		ASSERT_TRUE(tree.set(30, 20, 5));
			ASSERT_TRUE(tree.set(35, 5, 6));
			ASSERT_TRUE(tree.set(40, 5, 7));
	ASSERT_TRUE(tree.set(100, 100, 8));
		ASSERT_TRUE(tree.set(120, 20, 9));
			ASSERT_TRUE(tree.set(120, 5, 10));
			ASSERT_TRUE(tree.set(125, 5, 11));
			ASSERT_TRUE(tree.set(130, 5, 12));
		ASSERT_TRUE(tree.set(150, 20, 13));
			ASSERT_TRUE(tree.set(155, 5, 14));
			ASSERT_TRUE(tree.set(160, 5, 15));
	ASSERT_TRUE(tree.set(200, 100, 16));
		ASSERT_TRUE(tree.set(220, 20, 17));
			ASSERT_TRUE(tree.set(220, 5, 18));
			ASSERT_TRUE(tree.set(225, 5, 19));
			ASSERT_TRUE(tree.set(230, 5, 20));
		ASSERT_TRUE(tree.set(250, 20, 21));
			ASSERT_TRUE(tree.set(255, 5, 22));
			ASSERT_TRUE(tree.set(260, 5, 23));
	
	ByteRangeTree<int>::Node *node = tree.first_depth_first_node();
	
	for(int i = 0; i <= 23; ++i)
	{
		ASSERT_NE(node, nullptr);
		ASSERT_EQ(node->value, i);
		
		node = ByteRangeTree<int>::next_depth_first_node(node);
	}
	
	ASSERT_EQ(node, nullptr);
}

TEST(ByteRangeTree, DepthFirstBackwards)
{
	ByteRangeTree<int> tree;
	
	ASSERT_TRUE(tree.set(0, 100, 0));
		ASSERT_TRUE(tree.set(0, 20, 1));
			ASSERT_TRUE(tree.set(0,  5, 2));
			ASSERT_TRUE(tree.set(5,  5, 3));
			ASSERT_TRUE(tree.set(10, 5, 4));
		ASSERT_TRUE(tree.set(30, 20, 5));
			ASSERT_TRUE(tree.set(35, 5, 6));
			ASSERT_TRUE(tree.set(40, 5, 7));
	ASSERT_TRUE(tree.set(100, 100, 8));
		ASSERT_TRUE(tree.set(120, 20, 9));
			ASSERT_TRUE(tree.set(120, 5, 10));
			ASSERT_TRUE(tree.set(125, 5, 11));
			ASSERT_TRUE(tree.set(130, 5, 12));
		ASSERT_TRUE(tree.set(150, 20, 13));
			ASSERT_TRUE(tree.set(155, 5, 14));
			ASSERT_TRUE(tree.set(160, 5, 15));
	ASSERT_TRUE(tree.set(200, 100, 16));
		ASSERT_TRUE(tree.set(220, 20, 17));
			ASSERT_TRUE(tree.set(220, 5, 18));
			ASSERT_TRUE(tree.set(225, 5, 19));
			ASSERT_TRUE(tree.set(230, 5, 20));
		ASSERT_TRUE(tree.set(250, 20, 21));
			ASSERT_TRUE(tree.set(255, 5, 22));
			ASSERT_TRUE(tree.set(260, 5, 23));
	
	ByteRangeTree<int>::Node *node = tree.last_depth_first_node();
	
	for(int i = 23; i >= 0; --i)
	{
		ASSERT_NE(node, nullptr);
		ASSERT_EQ(node->value, i);
		
		node = ByteRangeTree<int>::prev_depth_first_node(node);
	}
	
	ASSERT_EQ(node, nullptr);
}

TEST(ByteRangeTree, Iterator)
{
	ByteRangeTree<int> tree;
	
	ASSERT_TRUE(tree.set(0, 100, 0));
		ASSERT_TRUE(tree.set(0, 20, 1));
			ASSERT_TRUE(tree.set(0,  5, 2));
			ASSERT_TRUE(tree.set(5,  5, 3));
			ASSERT_TRUE(tree.set(10, 5, 4));
		ASSERT_TRUE(tree.set(30, 20, 5));
			ASSERT_TRUE(tree.set(35, 5, 6));
			ASSERT_TRUE(tree.set(40, 5, 7));
	ASSERT_TRUE(tree.set(100, 100, 8));
		ASSERT_TRUE(tree.set(120, 20, 9));
			ASSERT_TRUE(tree.set(120, 5, 10));
			ASSERT_TRUE(tree.set(125, 5, 11));
			ASSERT_TRUE(tree.set(130, 5, 12));
		ASSERT_TRUE(tree.set(150, 20, 13));
			ASSERT_TRUE(tree.set(155, 5, 14));
			ASSERT_TRUE(tree.set(160, 5, 15));
	ASSERT_TRUE(tree.set(200, 100, 16));
		ASSERT_TRUE(tree.set(220, 20, 17));
			ASSERT_TRUE(tree.set(220, 5, 18));
			ASSERT_TRUE(tree.set(225, 5, 19));
			ASSERT_TRUE(tree.set(230, 5, 20));
		ASSERT_TRUE(tree.set(250, 20, 21));
			ASSERT_TRUE(tree.set(255, 5, 22));
			ASSERT_TRUE(tree.set(260, 5, 23));
	
	ByteRangeTree<int>::iterator it = tree.begin();
	
	for(int i = 0; i <= 23; ++i)
	{
		ASSERT_NE(it, tree.end());
		ASSERT_EQ(it->value, i);
		
		++it;
	}
	
	ASSERT_EQ(it, tree.end());
	
	for(int i = 23; i >= 0; --i)
	{
		--it;
		
		ASSERT_EQ(it->value, i);
	}
	
	ASSERT_EQ(it, tree.begin());
}

TEST(ByteRangeTree, ConstIterator)
{
	ByteRangeTree<int> tree;
	
	ASSERT_TRUE(tree.set(0, 100, 0));
		ASSERT_TRUE(tree.set(0, 20, 1));
			ASSERT_TRUE(tree.set(0,  5, 2));
			ASSERT_TRUE(tree.set(5,  5, 3));
			ASSERT_TRUE(tree.set(10, 5, 4));
		ASSERT_TRUE(tree.set(30, 20, 5));
			ASSERT_TRUE(tree.set(35, 5, 6));
			ASSERT_TRUE(tree.set(40, 5, 7));
	ASSERT_TRUE(tree.set(100, 100, 8));
		ASSERT_TRUE(tree.set(120, 20, 9));
			ASSERT_TRUE(tree.set(120, 5, 10));
			ASSERT_TRUE(tree.set(125, 5, 11));
			ASSERT_TRUE(tree.set(130, 5, 12));
		ASSERT_TRUE(tree.set(150, 20, 13));
			ASSERT_TRUE(tree.set(155, 5, 14));
			ASSERT_TRUE(tree.set(160, 5, 15));
	ASSERT_TRUE(tree.set(200, 100, 16));
		ASSERT_TRUE(tree.set(220, 20, 17));
			ASSERT_TRUE(tree.set(220, 5, 18));
			ASSERT_TRUE(tree.set(225, 5, 19));
			ASSERT_TRUE(tree.set(230, 5, 20));
		ASSERT_TRUE(tree.set(250, 20, 21));
			ASSERT_TRUE(tree.set(255, 5, 22));
			ASSERT_TRUE(tree.set(260, 5, 23));
	
	ByteRangeTree<int>::const_iterator it = tree.begin();
	
	for(int i = 0; i <= 23; ++i)
	{
		ASSERT_NE(it, tree.end());
		ASSERT_EQ(it->value, i);
		
		++it;
	}
	
	ASSERT_EQ(it, tree.end());
	
	for(int i = 23; i >= 0; --i)
	{
		--it;
		
		ASSERT_EQ(it->value, i);
	}
	
	ASSERT_EQ(it, tree.begin());
}

static std::string BitRangeTree_to_string(const BitRangeTree<int> &tree)
{
	std::string s = "";
	
	std::function<void(const BitRangeTree<int>::Node*, int)> walk_node;
	walk_node = [&](const BitRangeTree<int>::Node *node, int indent)
	{
		while(node != NULL)
		{
			s += std::string(indent, ' ')
				+ std::to_string(node->key.offset.byte()) + "+" + std::to_string(node->key.offset.bit()) + "b, "
				+ std::to_string(node->key.length.byte()) + "+" + std::to_string(node->key.length.bit()) + "b = "
				+ std::to_string(node->value) + "\n";
			walk_node(node->get_first_child(), indent + 2);
			
			node = node->get_next();
		}
	};
	
	walk_node(tree.first_root_node(), 0);
	
	return s;
}

TEST(BitRangeTree, PopulateTree)
{
	BitRangeTree<int> tree;
	
	ASSERT_TRUE(tree.set(BitOffset(10, 0), BitOffset(10, 0), 1));
	ASSERT_TRUE(tree.set(BitOffset(20, 2), BitOffset(1, 0),  2));
	ASSERT_TRUE(tree.set(BitOffset(21, 2), BitOffset(1, 0),  3));
	
	ASSERT_TRUE(tree.set(BitOffset(50, 2), BitOffset(0, 2),  4));
	ASSERT_TRUE(tree.set(BitOffset(50, 4), BitOffset(0, 2),  5));
	
	ASSERT_EQ(BitRangeTree_to_string(tree),
		"10+0b, 10+0b = 1\n"
		"20+2b, 1+0b = 2\n"
		"21+2b, 1+0b = 3\n"
		"50+2b, 0+2b = 4\n"
		"50+4b, 0+2b = 5\n"
	);
	
	ASSERT_TRUE(tree.set(BitOffset(50, 2), BitOffset(0, 2),  6)) << "Overwriting an existing node is allowed";
	
	ASSERT_EQ(BitRangeTree_to_string(tree),
		"10+0b, 10+0b = 1\n"
		"20+2b, 1+0b = 2\n"
		"21+2b, 1+0b = 3\n"
		"50+2b, 0+2b = 6\n"
		"50+4b, 0+2b = 5\n"
	);
	
	ASSERT_FALSE(tree.can_set(BitOffset(50, 1), BitOffset(0, 2)))    << "Insertion overlapping the start of an existing node is not allowed";
	ASSERT_FALSE(tree.set    (BitOffset(50, 1), BitOffset(0, 2), 6)) << "Insertion overlapping the start of an existing node is not allowed";
	
	ASSERT_FALSE(tree.can_set(BitOffset(50, 3), BitOffset(0, 2)))    << "Insertion overlapping the end of an existing node is not allowed";
	ASSERT_FALSE(tree.set    (BitOffset(50, 3), BitOffset(0, 2), 6)) << "Insertion overlapping the end of an existing node is not allowed";
	
	ASSERT_TRUE(tree.can_set(BitOffset(50, 2), BitOffset(0, 1)))    << "Insertion inside an existing node is allowed";
	ASSERT_TRUE(tree.set    (BitOffset(50, 2), BitOffset(0, 1), 7)) << "Insertion inside an existing node is allowed";
	
	ASSERT_TRUE(tree.can_set(BitOffset(50, 2), BitOffset(0, 0)))    << "Insertion inside an existing node is allowed";
	ASSERT_TRUE(tree.set    (BitOffset(50, 2), BitOffset(0, 0), 8)) << "Insertion inside an existing node is allowed";
	
	ASSERT_EQ(BitRangeTree_to_string(tree),
		"10+0b, 10+0b = 1\n"
		"20+2b, 1+0b = 2\n"
		"21+2b, 1+0b = 3\n"
		"50+2b, 0+2b = 6\n"
		"  50+2b, 0+1b = 7\n"
		"    50+2b, 0+0b = 8\n"
		"50+4b, 0+2b = 5\n"
	);
	
	ASSERT_TRUE(tree.can_set(BitOffset(48, 0), BitOffset(10, 0)))    << "Insertion encapsulating existing nodes is allowed";
	ASSERT_TRUE(tree.set    (BitOffset(48, 0), BitOffset(10, 0), 9)) << "Insertion encapsulating existing nodes is allowed";
	
	ASSERT_EQ(BitRangeTree_to_string(tree),
		"10+0b, 10+0b = 1\n"
		"20+2b, 1+0b = 2\n"
		"21+2b, 1+0b = 3\n"
		"48+0b, 10+0b = 9\n"
		"  50+2b, 0+2b = 6\n"
		"    50+2b, 0+1b = 7\n"
		"      50+2b, 0+0b = 8\n"
		"  50+4b, 0+2b = 5\n"
	);
}

TEST(BitRangeTree, EraseNode)
{
	BitRangeTree<int> tree;
	
	ASSERT_TRUE(tree.set(BitOffset(10, 0), BitOffset(10, 0), 1));
	ASSERT_TRUE(tree.set(BitOffset(20, 2), BitOffset( 1, 0), 2));
	ASSERT_TRUE(tree.set(BitOffset(21, 2), BitOffset( 1, 0), 3));
	ASSERT_TRUE(tree.set(BitOffset(50, 4), BitOffset( 0, 2), 5));
	ASSERT_TRUE(tree.set(BitOffset(50, 2), BitOffset( 0, 2), 6));
	ASSERT_TRUE(tree.set(BitOffset(50, 2), BitOffset( 0, 1), 7));
	ASSERT_TRUE(tree.set(BitOffset(50, 2), BitOffset( 0, 0), 8));
	ASSERT_TRUE(tree.set(BitOffset(48, 0), BitOffset(10, 0), 9));
	
	ASSERT_EQ(BitRangeTree_to_string(tree),
		"10+0b, 10+0b = 1\n"
		"20+2b, 1+0b = 2\n"
		"21+2b, 1+0b = 3\n"
		"48+0b, 10+0b = 9\n"
		"  50+2b, 0+2b = 6\n"
		"    50+2b, 0+1b = 7\n"
		"      50+2b, 0+0b = 8\n"
		"  50+4b, 0+2b = 5\n"
	);
	
	ASSERT_EQ(tree.erase(BitRangeTreeKey(BitOffset(20, 2), BitOffset(1, 0))), 1U);
	
	ASSERT_EQ(BitRangeTree_to_string(tree),
		"10+0b, 10+0b = 1\n"
		"21+2b, 1+0b = 3\n"
		"48+0b, 10+0b = 9\n"
		"  50+2b, 0+2b = 6\n"
		"    50+2b, 0+1b = 7\n"
		"      50+2b, 0+0b = 8\n"
		"  50+4b, 0+2b = 5\n"
	);
	
	ASSERT_EQ(tree.erase(BitRangeTreeKey(BitOffset(20, 2), BitOffset(1, 0))), 0U);
	
	ASSERT_EQ(tree.erase(BitRangeTreeKey(BitOffset(50, 2), BitOffset(0, 2))), 1U);
	
	ASSERT_EQ(BitRangeTree_to_string(tree),
		"10+0b, 10+0b = 1\n"
		"21+2b, 1+0b = 3\n"
		"48+0b, 10+0b = 9\n"
		"  50+2b, 0+1b = 7\n"
		"    50+2b, 0+0b = 8\n"
		"  50+4b, 0+2b = 5\n"
	);
}

TEST(BitRangeTree, EraseNodeRecursive)
{
	BitRangeTree<int> tree;
	
	ASSERT_TRUE(tree.set(BitOffset(10, 0), BitOffset(10, 0), 1));
	ASSERT_TRUE(tree.set(BitOffset(20, 2), BitOffset( 1, 0), 2));
	ASSERT_TRUE(tree.set(BitOffset(21, 2), BitOffset( 1, 0), 3));
	ASSERT_TRUE(tree.set(BitOffset(50, 4), BitOffset( 0, 2), 5));
	ASSERT_TRUE(tree.set(BitOffset(50, 2), BitOffset( 0, 2), 6));
	ASSERT_TRUE(tree.set(BitOffset(50, 2), BitOffset( 0, 1), 7));
	ASSERT_TRUE(tree.set(BitOffset(50, 2), BitOffset( 0, 0), 8));
	ASSERT_TRUE(tree.set(BitOffset(48, 0), BitOffset(10, 0), 9));
	
	ASSERT_EQ(BitRangeTree_to_string(tree),
		"10+0b, 10+0b = 1\n"
		"20+2b, 1+0b = 2\n"
		"21+2b, 1+0b = 3\n"
		"48+0b, 10+0b = 9\n"
		"  50+2b, 0+2b = 6\n"
		"    50+2b, 0+1b = 7\n"
		"      50+2b, 0+0b = 8\n"
		"  50+4b, 0+2b = 5\n"
	);
	
	ASSERT_EQ(tree.erase_recursive(BitRangeTreeKey(BitOffset(20, 2), BitOffset(1, 0))), 1U);
	
	ASSERT_EQ(BitRangeTree_to_string(tree),
		"10+0b, 10+0b = 1\n"
		"21+2b, 1+0b = 3\n"
		"48+0b, 10+0b = 9\n"
		"  50+2b, 0+2b = 6\n"
		"    50+2b, 0+1b = 7\n"
		"      50+2b, 0+0b = 8\n"
		"  50+4b, 0+2b = 5\n"
	);
	
	ASSERT_EQ(tree.erase_recursive(BitRangeTreeKey(BitOffset(20, 2), BitOffset(1, 0))), 0U);
	
	ASSERT_EQ(tree.erase_recursive(BitRangeTreeKey(BitOffset(50, 2), BitOffset(0, 2))), 3U);
	
	ASSERT_EQ(BitRangeTree_to_string(tree),
		"10+0b, 10+0b = 1\n"
		"21+2b, 1+0b = 3\n"
		"48+0b, 10+0b = 9\n"
		"  50+4b, 0+2b = 5\n"
	);
}

TEST(BitRangeTree, DataErased)
{
	BitRangeTree<int> tree;
	
	ASSERT_TRUE(tree.set(BitOffset(10, 0), BitOffset(10, 0), 1));
	ASSERT_TRUE(tree.set(BitOffset(20, 2), BitOffset( 1, 0), 2));
	ASSERT_TRUE(tree.set(BitOffset(21, 2), BitOffset( 1, 0), 3));
	ASSERT_TRUE(tree.set(BitOffset(50, 4), BitOffset( 0, 2), 5));
	ASSERT_TRUE(tree.set(BitOffset(50, 2), BitOffset( 0, 2), 6));
	ASSERT_TRUE(tree.set(BitOffset(50, 2), BitOffset( 0, 1), 7));
	ASSERT_TRUE(tree.set(BitOffset(50, 2), BitOffset( 0, 0), 8));
	ASSERT_TRUE(tree.set(BitOffset(48, 0), BitOffset(10, 0), 9));
	
	ASSERT_EQ(BitRangeTree_to_string(tree),
		"10+0b, 10+0b = 1\n"
		"20+2b, 1+0b = 2\n"
		"21+2b, 1+0b = 3\n"
		"48+0b, 10+0b = 9\n"
		"  50+2b, 0+2b = 6\n"
		"    50+2b, 0+1b = 7\n"
		"      50+2b, 0+0b = 8\n"
		"  50+4b, 0+2b = 5\n"
	);
	
	EXPECT_EQ(tree.data_erased(18, 4), 8U);
	
	ASSERT_EQ(BitRangeTree_to_string(tree),
		"10+0b, 8+0b = 1\n"
		"18+0b, 0+2b = 3\n"
		"44+0b, 10+0b = 9\n"
		"  46+2b, 0+2b = 6\n"
		"    46+2b, 0+1b = 7\n"
		"      46+2b, 0+0b = 8\n"
		"  46+4b, 0+2b = 5\n"
	);
}

TEST(BitRangeTree, DataInserted)
{
	BitRangeTree<int> tree;
	
	ASSERT_TRUE(tree.set(BitOffset(10, 0), BitOffset(10, 0), 1));
	ASSERT_TRUE(tree.set(BitOffset(20, 2), BitOffset( 1, 0), 2));
	ASSERT_TRUE(tree.set(BitOffset(21, 2), BitOffset( 1, 0), 3));
	ASSERT_TRUE(tree.set(BitOffset(50, 4), BitOffset( 0, 2), 5));
	ASSERT_TRUE(tree.set(BitOffset(50, 2), BitOffset( 0, 2), 6));
	ASSERT_TRUE(tree.set(BitOffset(50, 2), BitOffset( 0, 1), 7));
	ASSERT_TRUE(tree.set(BitOffset(50, 2), BitOffset( 0, 0), 8));
	ASSERT_TRUE(tree.set(BitOffset(48, 0), BitOffset(10, 0), 9));
	
	ASSERT_EQ(BitRangeTree_to_string(tree),
		"10+0b, 10+0b = 1\n"
		"20+2b, 1+0b = 2\n"
		"21+2b, 1+0b = 3\n"
		"48+0b, 10+0b = 9\n"
		"  50+2b, 0+2b = 6\n"
		"    50+2b, 0+1b = 7\n"
		"      50+2b, 0+0b = 8\n"
		"  50+4b, 0+2b = 5\n"
	);
	
	EXPECT_EQ(tree.data_inserted(21, 4), 7U);
	
	ASSERT_EQ(BitRangeTree_to_string(tree),
		"10+0b, 10+0b = 1\n"
		"20+2b, 5+0b = 2\n"
		"25+2b, 1+0b = 3\n"
		"52+0b, 10+0b = 9\n"
		"  54+2b, 0+2b = 6\n"
		"    54+2b, 0+1b = 7\n"
		"      54+2b, 0+0b = 8\n"
		"  54+4b, 0+2b = 5\n"
	);
}
