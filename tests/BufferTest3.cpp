/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "BufferTest.h"

TEST(Buffer, InsertEmptyFile)
{
	const std::vector<unsigned char> BEGIN_DATA = {};
	const std::vector<unsigned char> END_DATA   = { 0xAA, 0xBB, 0xCC, 0xDD };
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(0, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 4);
			});
			
			TEST_LENGTH(4);
		}
	);
}

TEST(Buffer, InsertEmptyFileMulti)
{
	const std::vector<unsigned char> BEGIN_DATA = {};
	const std::vector<unsigned char> END_DATA   = { 0xAA, 0x00, 0x11, 0xBB, 0xCC, 0xEE, 0xFF, 0xDD };
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(0, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			TEST_INSERT_OK(3, (std::vector<unsigned char>{ 0xEE, 0xFF }));
			TEST_INSERT_OK(1, (std::vector<unsigned char>{ 0x00, 0x11 }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 8);
			});
			
			TEST_LENGTH(8);
		}
	);
}

TEST(Buffer, InsertEmptyFileBeyondEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {};
	const std::vector<unsigned char> END_DATA   = {};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_FAIL(1, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0, 0);
			});
			
			TEST_LENGTH(0);
		}
	);
}

TEST(Buffer, InsertTinyFileStart)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0xAA, 0xBB, 0xCC, 0xDD,
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(0, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 10);
			});
			
			TEST_LENGTH(10);
		}
	);
}

TEST(Buffer, InsertTinyFileMiddle)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x68, 0xAB,
		0xAA, 0xBB, 0xCC, 0xDD,
		0x8A, 0xEF, 0x5F, 0xCA,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(2, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 10);
			});
			
			TEST_LENGTH(10);
		}
	);
}

TEST(Buffer, InsertTinyFileEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA,
		0xAA, 0xBB, 0xCC, 0xDD,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(6, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 10);
			});
			
			TEST_LENGTH(10);
		}
	);
}

TEST(Buffer, InsertTinyFileMulti)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA,
	};
	
	const std::vector<unsigned char> END_DATA = {
		/* > */ 0xAA, 0x00, 0x11, 0xBB, 0xCC, 0xDD, /* < */
		0x68, 0xAB, /* > */ 0xEE, 0xFF, /* < */ 0x8A, 0xEF, 0x5F, 0xCA,
		
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(0, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 10);
			});
			
			TEST_INSERT_OK(6, (std::vector<unsigned char>{ 0xEE, 0xFF }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 12);
			});
			
			TEST_INSERT_OK(1, (std::vector<unsigned char>{ 0x00, 0x11 }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 14);
			});
			
			TEST_LENGTH(14);
		}
	);
}

TEST(Buffer, InsertTinyFileBeyondEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_FAIL(7, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0, 6);
			});
			
			TEST_LENGTH(6);
		}
	);
}

TEST(Buffer, InsertSingleBlockFileStart)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0xAA, 0xBB, 0xCC, 0xDD,
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(0, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 12);
			});
			
			TEST_LENGTH(12);
		}
	);
}

TEST(Buffer, InsertSingleBlockFileMiddle)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x68, 0xAB,
		0xAA, 0xBB, 0xCC, 0xDD,
		0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(2, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 12);
			});
			
			TEST_LENGTH(12);
		}
	);
}

TEST(Buffer, InsertSingleBlockFileEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
		0xAA, 0xBB, 0xCC, 0xDD,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(8, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 12);
			});
			
			TEST_LENGTH(12);
		}
	);
}

TEST(Buffer, InsertSingleBlockFileMulti)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0xAA, 0x00, 0x11, 0xBB, 0xCC, 0xDD,
		0x68, 0xAB, 0xEE, 0xFF, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(0, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 12);
			});
			
			TEST_INSERT_OK(6, (std::vector<unsigned char>{ 0xEE, 0xFF }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 14);
			});
			
			TEST_INSERT_OK(1, (std::vector<unsigned char>{ 0x00, 0x11 }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY, 0, 16);
			});
			
			TEST_LENGTH(16);
		}
	);
}

TEST(Buffer, InsertSingleBlockFileBeyondEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x68, 0xAB, 0x8A, 0xEF, 0x5F, 0xCA, 0x1E, 0xDD,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_FAIL(9, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0, 8);
			});
			
			TEST_LENGTH(8);
		}
	);
}

TEST(Buffer, InsertMultiBlockFileFirstBlockStart)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0xAA, 0xBB, 0xCC, 0xDD,
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(0, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY,    0,  12);
				TEST_BLOCK_DEF(UNLOADED, 12, 8);
				TEST_BLOCK_DEF(UNLOADED, 20, 8);
				TEST_BLOCK_DEF(UNLOADED, 28, 5);
			});
			
			TEST_LENGTH(33);
		}
	);
}

TEST(Buffer, InsertMultiBlockFileFirstBlockMiddle)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8,
						0xAA, 0xBB, 0xCC, 0xDD,
						0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(5, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY,    0,  12);
				TEST_BLOCK_DEF(UNLOADED, 12, 8);
				TEST_BLOCK_DEF(UNLOADED, 20, 8);
				TEST_BLOCK_DEF(UNLOADED, 28, 5);
			});
			
			TEST_LENGTH(33);
		}
	);
}

TEST(Buffer, InsertMultiBlockFileThirdBlockStart)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xAA, 0xBB, 0xCC, 0xDD,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(16, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(DIRTY,    16, 12);
				TEST_BLOCK_DEF(UNLOADED, 28, 5);
			});
			
			TEST_LENGTH(33);
		}
	);
}

TEST(Buffer, InsertMultiBlockFileThirdBlockMiddle)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0,
			0xAA, 0xBB, 0xCC, 0xDD,
			0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(17, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(DIRTY,    16, 12);
				TEST_BLOCK_DEF(UNLOADED, 28, 5);
			});
			
			TEST_LENGTH(33);
		}
	);
}

TEST(Buffer, InsertMultiBlockFileLastBlockStart)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0xAA, 0xBB, 0xCC, 0xDD,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(24, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(DIRTY,    24, 9);
			});
			
			TEST_LENGTH(33);
		}
	);
}

TEST(Buffer, InsertMultiBlockFileLastBlockMiddle)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24,
				0xAA, 0xBB, 0xCC, 0xDD,
				0x3C, 0x43, 0xE1,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(26, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(DIRTY,    24, 9);
			});
			
			TEST_LENGTH(33);
		}
	);
}

TEST(Buffer, InsertMultiBlockFileLastBlockEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
						0xAA, 0xBB, 0xCC, 0xDD,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(29, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(DIRTY,    24, 9);
			});
			
			TEST_LENGTH(33);
		}
	);
}

TEST(Buffer, InsertMultiBlockFileMulti)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x3E, 0x0E, 0x87, 0x93, /* > */ 0xAA, 0xBB, 0xCC, 0xDD, /* < */ 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, /* > */ 0x00, 0x11, /* < */ 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, /* > */ 0xEE, 0xFF, /* < */ 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_OK(4,  (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			TEST_INSERT_OK(22, (std::vector<unsigned char>{ 0xEE, 0xFF }));
			TEST_INSERT_OK(16, (std::vector<unsigned char>{ 0x00, 0x11 }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(DIRTY,    0,  12);
				TEST_BLOCK_DEF(DIRTY,    12, 10);
				TEST_BLOCK_DEF(DIRTY,    22, 10);
				TEST_BLOCK_DEF(UNLOADED, 32, 5);
			});
			
			TEST_LENGTH(37);
		}
	);
}

TEST(Buffer, InsertMultiBlockFileBeyondEnd)
{
	const std::vector<unsigned char> BEGIN_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	const std::vector<unsigned char> END_DATA = {
		0x3E, 0x0E, 0x87, 0x93, 0xA8, 0x60, 0x78, 0x6A,
		0x27, 0x17, 0xB0, 0x2E, 0x96, 0xD7, 0xA7, 0xC2,
		0xE0, 0x11, 0x94, 0xE3, 0x60, 0x18, 0x31, 0xC5,
		0x7D, 0x24, 0x3C, 0x43, 0xE1,
	};
	
	TEST_BUFFER_MANIP(
		{
			TEST_INSERT_FAIL(30, (std::vector<unsigned char>{ 0xAA, 0xBB, 0xCC, 0xDD }));
			
			TEST_BLOCKS({
				TEST_BLOCK_DEF(UNLOADED, 0,  8);
				TEST_BLOCK_DEF(UNLOADED, 8,  8);
				TEST_BLOCK_DEF(UNLOADED, 16, 8);
				TEST_BLOCK_DEF(UNLOADED, 24, 5);
			});
			
			TEST_LENGTH(29);
		}
	);
}

/* Verifies we can read/write files containing any bytes without any funky
 * behaviour occuring (see 52de6b2a41d7ad82761764e250f92b359cafd072).
*/
TEST(Buffer, ReadWriteAnyBytes)
{
	std::vector<unsigned char> BEGIN_DATA(512, 0);
	std::vector<unsigned char> END_DATA(512, 0);
	
	for(int i = 0; i < 512; ++i)
	{
		BEGIN_DATA[i] = (i % 255);
		END_DATA[i]   = (i % 255);
	}
	
	TEST_BUFFER_MANIP({});
}

#ifndef _WIN32
TEST(Buffer, DeleteBackingFileAndRestore)
{
	TempFilename f1, f2;
	
	write_file(f1.tmpfile, std::vector<unsigned char>({ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 }));
	
	REHex::Buffer b(f1.tmpfile);
	b.read_data(0, 1024); /* Buffer file. */
	
	run_wx_for(REHex::Buffer::FILE_CHECK_INTERVAL_MS * 2);
	
	ASSERT_FALSE(b.file_deleted());
	ASSERT_FALSE(b.file_modified());
	
	ASSERT_EQ(rename(f1.tmpfile, f2.tmpfile), 0) << "Moving backing file aside succeeds";
	
	run_wx_until([&]() { return b.file_deleted(); });
	
	EXPECT_TRUE(b.file_deleted())   << "REHex::Buffer::file_deleted() returns true when backing file has been removed";
	EXPECT_FALSE(b.file_modified()) << "REHex::Buffer::file_modified() returns false when backing file has been removed";
	
	b.write_inplace();
	
	run_wx_for(REHex::Buffer::FILE_CHECK_INTERVAL_MS * 2);
	
	EXPECT_FALSE(b.file_deleted()) << "REHex::Buffer::file_deleted() returns false after file is re-written by REHex::Buffer::write_inplace()";
	EXPECT_FALSE(b.file_modified()) << "REHex::Buffer::file_modified() returns false after file is re-written by REHex::Buffer::write_inplace()";
	
	std::vector<unsigned char> file_data = read_file(f1.tmpfile);
	EXPECT_EQ(file_data, std::vector<unsigned char>({ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 })) << "File is restored with correct data";
}

TEST(Buffer, ReplaceBackingFileAndRestore)
{
	TempFilename f1, f2, f3;
	
	write_file(f1.tmpfile, std::vector<unsigned char>({ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 }));
	write_file(f2.tmpfile, std::vector<unsigned char>({ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }));
	
	REHex::Buffer b(f1.tmpfile);
	b.read_data(0, 1024); /* Buffer file. */
	
	run_wx_for(REHex::Buffer::FILE_CHECK_INTERVAL_MS * 2);
	
	ASSERT_FALSE(b.file_deleted());
	ASSERT_FALSE(b.file_modified());
	
	ASSERT_EQ(rename(f1.tmpfile, f3.tmpfile), 0) << "Moving backing file aside succeeds";
	ASSERT_EQ(rename(f2.tmpfile, f1.tmpfile), 0) << "Replacing backing file succeeds";
	
	run_wx_until([&]() { return b.file_deleted(); });
	
	EXPECT_TRUE(b.file_deleted())   << "REHex::Buffer::file_deleted() returns true when backing file has been replaced";
	EXPECT_FALSE(b.file_modified()) << "REHex::Buffer::file_modified() returns false when backing file has been replaced";
	
	b.write_inplace();
	
	run_wx_for(REHex::Buffer::FILE_CHECK_INTERVAL_MS * 2);
	
	EXPECT_FALSE(b.file_deleted()) << "REHex::Buffer::file_deleted() returns false after file is re-written by REHex::Buffer::write_inplace()";
	EXPECT_FALSE(b.file_modified()) << "REHex::Buffer::file_modified() returns false after file is re-written by REHex::Buffer::write_inplace()";
	
	std::vector<unsigned char> file_data = read_file(f1.tmpfile);
	EXPECT_EQ(file_data, std::vector<unsigned char>({ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 })) << "File is restored with correct data";
}

TEST(Buffer, ReplaceBackingFileAndReload)
{
	TempFilename f1, f2, f3;
	
	write_file(f1.tmpfile, std::vector<unsigned char>({ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 }));
	write_file(f2.tmpfile, std::vector<unsigned char>({ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }));
	
	REHex::Buffer b(f1.tmpfile);
	b.read_data(0, 1024); /* Buffer file. */
	
	run_wx_for(REHex::Buffer::FILE_CHECK_INTERVAL_MS * 2);
	
	ASSERT_FALSE(b.file_deleted());
	ASSERT_FALSE(b.file_modified());
	
	ASSERT_EQ(rename(f1.tmpfile, f3.tmpfile), 0) << "Moving backing file aside succeeds";
	ASSERT_EQ(rename(f2.tmpfile, f1.tmpfile), 0) << "Replacing backing file succeeds";
	
	run_wx_until([&]() { return b.file_deleted(); });
	
	EXPECT_TRUE(b.file_deleted())   << "REHex::Buffer::file_deleted() returns true when backing file has been replaced";
	EXPECT_FALSE(b.file_modified()) << "REHex::Buffer::file_modified() returns false when backing file has been replaced";
	
	b.reload();
	
	run_wx_for(REHex::Buffer::FILE_CHECK_INTERVAL_MS * 2);
	
	EXPECT_FALSE(b.file_deleted()) << "REHex::Buffer::file_deleted() returns false after REHex::Buffer::reload() is called";
	EXPECT_FALSE(b.file_modified()) << "REHex::Buffer::file_modified() returns false after REHex::Buffer::reload() is called";
	
	std::vector<unsigned char> file_data = b.read_data(0, 1024);
	EXPECT_EQ(file_data, std::vector<unsigned char>({ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF })) << "Buffer contains new content";
}
#endif

TEST(Buffer, ModifyBackingFileAndReload)
{
	TempFilename f1;
	write_file(f1.tmpfile, std::vector<unsigned char>({ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 }));
	
	REHex::Buffer b(f1.tmpfile);
	b.read_data(0, 1024); /* Buffer file. */
	
	run_wx_for(REHex::Buffer::FILE_CHECK_INTERVAL_MS * 2);
	
	ASSERT_FALSE(b.file_deleted());
	ASSERT_FALSE(b.file_modified());
	
	write_file(f1.tmpfile, std::vector<unsigned char>({ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }));
	
	run_wx_until([&]() { return b.file_modified(); });
	
	EXPECT_TRUE(b.file_modified()) << "REHex::Buffer::file_modified() returns true when backing file has been modified";
	EXPECT_FALSE(b.file_deleted()) << "REHex::Buffer::file_deleted() returns false when backing file has been modified";
	
	b.reload();
	
	run_wx_for(REHex::Buffer::FILE_CHECK_INTERVAL_MS * 2);
	
	EXPECT_FALSE(b.file_deleted()) << "REHex::Buffer::file_deleted() returns false after REHex::Buffer::reload() is called";
	EXPECT_FALSE(b.file_modified()) << "REHex::Buffer::file_modified() returns false after REHex::Buffer::reload() is called";
	
	std::vector<unsigned char> file_data = b.read_data(0, 1024);
	EXPECT_EQ(file_data, std::vector<unsigned char>({ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF })) << "Buffer contains new content";
}

TEST(Buffer, ReadBitsWholeFile)
{
	TempFilename f1;
	write_file(f1.tmpfile, std::vector<unsigned char>({ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 }));
	
	REHex::Buffer b(f1.tmpfile);
	
	std::vector<bool> bits = b.read_bits(REHex::BitOffset(0, 0), 100);
	
	std::vector<bool> EXPECT = {
		false, false, false, false, false, false, false, false, /* 0x00 */
		false, false, false, false, false, false, false,  true, /* 0x01 */
		false, false, false, false, false, false,  true, false, /* 0x02 */
		false, false, false, false, false, false,  true,  true, /* 0x03 */
		false, false, false, false, false,  true, false, false, /* 0x04 */
		false, false, false, false, false,  true, false,  true, /* 0x05 */
		false, false, false, false, false,  true,  true, false, /* 0x06 */
		false, false, false, false, false,  true,  true,  true, /* 0x07 */
	};
	
	EXPECT_EQ(bits, EXPECT);
}

TEST(Buffer, ReadBitsFromFile)
{
	TempFilename f1;
	write_file(f1.tmpfile, std::vector<unsigned char>({ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 }));
	
	REHex::Buffer b(f1.tmpfile);
	
	std::vector<bool> bits = b.read_bits(REHex::BitOffset(1, 2), 15);
	
	std::vector<bool> EXPECT = {
		/* false, false, false, false, false, false, false, false, */  /* 0x00 */
		/* false, false, */ false, false, false, false, false,  true,  /* 0x01 */
		false, false, false, false, false, false,  true, false,        /* 0x02 */
		false, /* false, false, false, false, false,  true,  true, */  /* 0x03 */
		/* false, false, false, false, false,  true, false, false, */  /* 0x04 */
		/* false, false, false, false, false,  true, false,  true, */  /* 0x05 */
		/* false, false, false, false, false,  true,  true, false, */  /* 0x06 */
		/* false, false, false, false, false,  true,  true,  true, */  /* 0x07 */
	};
	
	EXPECT_EQ(bits, EXPECT);
}

TEST(Buffer, ReadBitsAtEOF)
{
	TempFilename f1;
	write_file(f1.tmpfile, std::vector<unsigned char>({ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 }));
	
	REHex::Buffer b(f1.tmpfile);
	
	std::vector<bool> bits = b.read_bits(REHex::BitOffset(7, 5), 15);
	
	std::vector<bool> EXPECT = {
		/* false, false, false, false, false, false, false, false, */  /* 0x00 */
		/* false, false, false, false, false, false, false,  true, */  /* 0x01 */
		/* false, false, false, false, false, false,  true, false, */  /* 0x02 */
		/* false, false, false, false, false, false,  true,  true, */  /* 0x03 */
		/* false, false, false, false, false,  true, false, false, */  /* 0x04 */
		/* false, false, false, false, false,  true, false,  true, */  /* 0x05 */
		/* false, false, false, false, false,  true,  true, false, */  /* 0x06 */
		/* false, false, false, false, false, */  true,  true,  true,  /* 0x07 */
	};
	
	EXPECT_EQ(bits, EXPECT);
}
