/* Reverse Engineer's Hex Editor
 * Copyright (C) 2026 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <portable_endian.h>

#include "../src/FourCC.hpp"

using namespace REHex;

TEST(FourCC, InitFromString)
{
	FourCC ABCD("ABCD");
	FourCC XYZ("XYZ ");
	
	EXPECT_STREQ(ABCD.string(), "ABCD");
	EXPECT_EQ(ABCD.code(), htobe32(0x41424344));

	EXPECT_STREQ(XYZ.string(), "XYZ ");
	EXPECT_EQ(XYZ.code(), htobe32(0x58595A20));

	EXPECT_TRUE(ABCD == ABCD);
	EXPECT_TRUE(ABCD == "ABCD");
	EXPECT_FALSE(ABCD == XYZ);
	EXPECT_FALSE(ABCD == "XYZ ");

	EXPECT_FALSE(ABCD != ABCD);
	EXPECT_FALSE(ABCD != "ABCD");
	EXPECT_TRUE(ABCD != XYZ);
	EXPECT_TRUE(ABCD != "XYZ ");

	EXPECT_FALSE(ABCD < ABCD);
	EXPECT_FALSE(ABCD < "ABCD");
	EXPECT_TRUE(ABCD < XYZ);
	EXPECT_TRUE(ABCD < "XYZ ");
	EXPECT_FALSE(XYZ < ABCD);
	EXPECT_FALSE(XYZ < "ABCD");
}

TEST(FourCC, InitFromBytes)
{
	FourCC ABCD('A', 'B', 'C', 'D');
	FourCC XYZ('X', 'Y', 'Z', ' ');
	
	EXPECT_STREQ(ABCD.string(), "ABCD");
	EXPECT_EQ(ABCD.code(), htobe32(0x41424344));

	EXPECT_STREQ(XYZ.string(), "XYZ ");
	EXPECT_EQ(XYZ.code(), htobe32(0x58595A20));

	EXPECT_TRUE(ABCD == ABCD);
	EXPECT_TRUE(ABCD == "ABCD");
	EXPECT_FALSE(ABCD == XYZ);
	EXPECT_FALSE(ABCD == "XYZ ");

	EXPECT_FALSE(ABCD != ABCD);
	EXPECT_FALSE(ABCD != "ABCD");
	EXPECT_TRUE(ABCD != XYZ);
	EXPECT_TRUE(ABCD != "XYZ ");

	EXPECT_FALSE(ABCD < ABCD);
	EXPECT_FALSE(ABCD < "ABCD");
	EXPECT_TRUE(ABCD < XYZ);
	EXPECT_TRUE(ABCD < "XYZ ");
	EXPECT_FALSE(XYZ < ABCD);
	EXPECT_FALSE(XYZ < "ABCD");
}
