/* Reverse Engineer's Hex Editor
 * Copyright (C) 2023 Daniel Collins <solemnwarning@solemnwarning.net>
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
