/* Reverse Engineer's Hex Editor
 * Copyright (C) 2022 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <thread>
#include <vector>

#include "../src/SharedDocumentPointer.hpp"
#include "../src/DataHistogramAccumulator.hpp"

#define EXPECT_BUCKET(dha, idx, mv, Mv, c) \
	EXPECT_EQ(dha.get_buckets()[idx].min_value, mv); \
	EXPECT_EQ(dha.get_buckets()[idx].max_value, Mv); \
	EXPECT_EQ(dha.get_buckets()[idx].count, c);

using namespace REHex;

TEST(DataHistogramAccumulator, X8Bit256Buckets)
{
	SharedDocumentPointer document(SharedDocumentPointer::make());
	
	const unsigned char DATA[] = { 0x00, 0x00, 0x08, 0xFF, 0xFF, 0x00 };
	document->insert_data(0, DATA, sizeof(DATA));
	
	DataHistogramAccumulator<uint8_t> dha(document, 0, sizeof(uint8_t), sizeof(DATA), 256);
	dha.wait_for_completion();
	
	ASSERT_EQ(dha.get_buckets().size(), 256U);
	
	EXPECT_BUCKET(dha,   0,   0U,   0U, 3U);
	EXPECT_BUCKET(dha,   1,   1U,   1U, 0U);
	EXPECT_BUCKET(dha,   2,   2U,   2U, 0U);
	EXPECT_BUCKET(dha,   8,   8U,   8U, 1U);
	EXPECT_BUCKET(dha, 255, 255U, 255U, 2U);
}

TEST(DataHistogramAccumulator, X8Bit128Buckets)
{
	SharedDocumentPointer document(SharedDocumentPointer::make());
	
	const unsigned char DATA[] = { 0x00, 0x00, 0x08, 0xFF, 0xFF, 0x00 };
	document->insert_data(0, DATA, sizeof(DATA));
	
	DataHistogramAccumulator<uint8_t> dha(document, 0, sizeof(uint8_t), sizeof(DATA), 128);
	dha.wait_for_completion();
	
	ASSERT_EQ(dha.get_buckets().size(), 128U);
	
	EXPECT_BUCKET(dha,   0,   0U,   1U, 3U);
	EXPECT_BUCKET(dha,   1,   2U,   3U, 0U);
	EXPECT_BUCKET(dha,   2,   4U,   5U, 0U);
	EXPECT_BUCKET(dha,   4,   8U,   9U, 1U);
	EXPECT_BUCKET(dha, 127, 254U, 255U, 2U);
	
		DataHistogramAccumulator<uint8_t> dha_00(&dha, &(dha.get_buckets()[0]));
		dha_00.wait_for_completion();
		
		ASSERT_EQ(dha_00.get_buckets().size(), 2U);
		
		EXPECT_BUCKET(dha_00, 0, 0U, 0U, 3U);
		EXPECT_BUCKET(dha_00, 1, 1U, 1U, 0U);
		
		DataHistogramAccumulator<uint8_t> dha_01(&dha, &(dha.get_buckets()[1]));
		dha_01.wait_for_completion();
		
		ASSERT_EQ(dha_01.get_buckets().size(), 2U);
		
		EXPECT_BUCKET(dha_01, 0, 2U, 2U, 0U);
		EXPECT_BUCKET(dha_01, 1, 3U, 3U, 0U);
		
		DataHistogramAccumulator<uint8_t> dha_127(&dha, &(dha.get_buckets()[127]));
		dha_127.wait_for_completion();
		
		ASSERT_EQ(dha_127.get_buckets().size(), 2U);
		
		EXPECT_BUCKET(dha_127, 0, 254U, 254U, 0U);
		EXPECT_BUCKET(dha_127, 1, 255U, 255U, 2U);
}

TEST(DataHistogramAccumulator, X8Bit32Buckets)
{
	SharedDocumentPointer document(SharedDocumentPointer::make());
	
	const unsigned char DATA[] = { 0x00, 0x00, 0x08, 0xFF, 0xFF, 0x00 };
	document->insert_data(0, DATA, sizeof(DATA));
	
	DataHistogramAccumulator<uint8_t> dha(document, 0, sizeof(uint8_t), sizeof(DATA), 32);
	dha.wait_for_completion();
	
	ASSERT_EQ(dha.get_buckets().size(), 32U);
	
	EXPECT_BUCKET(dha,  0,   0U,   7U, 3U);
	EXPECT_BUCKET(dha,  1,   8U,  15U, 1U);
	EXPECT_BUCKET(dha,  2,  16U,  23U, 0U);
	EXPECT_BUCKET(dha,  3,  24U,  31U, 0U);
	EXPECT_BUCKET(dha, 31, 248U, 255U, 2U);
	
		DataHistogramAccumulator<uint8_t> dha_00(&dha, &(dha.get_buckets()[0]));
		dha_00.wait_for_completion();
		
		ASSERT_EQ(dha_00.get_buckets().size(), 8U);
		
		EXPECT_BUCKET(dha_00, 0, 0U, 0U, 3U);
		EXPECT_BUCKET(dha_00, 1, 1U, 1U, 0U);
		EXPECT_BUCKET(dha_00, 2, 2U, 2U, 0U);
		EXPECT_BUCKET(dha_00, 7, 7U, 7U, 0U);
		
		DataHistogramAccumulator<uint8_t> dha_01(&dha, &(dha.get_buckets()[1]));
		dha_01.wait_for_completion();
		
		ASSERT_EQ(dha_01.get_buckets().size(), 8U);
		
		EXPECT_BUCKET(dha_01, 0,  8U,  8U, 1U);
		EXPECT_BUCKET(dha_01, 1,  9U,  9U, 0U);
		EXPECT_BUCKET(dha_01, 2, 10U, 10U, 0U);
		EXPECT_BUCKET(dha_01, 7, 15U, 15U, 0U);
		
		DataHistogramAccumulator<uint8_t> dha_31(&dha, &(dha.get_buckets()[31]));
		dha_31.wait_for_completion();
		
		ASSERT_EQ(dha_31.get_buckets().size(), 8U);
		
		EXPECT_BUCKET(dha_31, 0, 248U, 248U, 0U);
		EXPECT_BUCKET(dha_31, 1, 249U, 249U, 0U);
		EXPECT_BUCKET(dha_31, 6, 254U, 254U, 0U);
		EXPECT_BUCKET(dha_31, 7, 255U, 255U, 2U);
}

TEST(DataHistogramAccumulator, X8Bit16Buckets)
{
	SharedDocumentPointer document(SharedDocumentPointer::make());
	
	const unsigned char DATA[] = { 0x00, 0x00, 0x08, 0xFF, 0xFF, 0x00 };
	document->insert_data(0, DATA, sizeof(DATA));
	
	DataHistogramAccumulator<uint8_t> dha(document, 0, sizeof(uint8_t), sizeof(DATA), 16);
	dha.wait_for_completion();
	
	ASSERT_EQ(dha.get_buckets().size(), 16U);
	
	EXPECT_BUCKET(dha,  0,   0U,  15U, 4U);
	EXPECT_BUCKET(dha,  1,  16U,  31U, 0U);
	EXPECT_BUCKET(dha,  2,  32U,  47U, 0U);
	EXPECT_BUCKET(dha,  3,  48U,  63U, 0U);
	EXPECT_BUCKET(dha, 15, 240U, 255U, 2U);
	
		DataHistogramAccumulator<uint8_t> dha_00(&dha, &(dha.get_buckets()[0]));
		dha_00.wait_for_completion();
		
		ASSERT_EQ(dha_00.get_buckets().size(), 16U);
		
		EXPECT_BUCKET(dha_00,  0,  0U, 0U,  3U);
		EXPECT_BUCKET(dha_00,  1,  1U, 1U,  0U);
		EXPECT_BUCKET(dha_00,  2,  2U, 2U,  0U);
		EXPECT_BUCKET(dha_00,  8,  8U, 8U,  1U);
		EXPECT_BUCKET(dha_00, 15, 15U, 15U, 0U);
		
		DataHistogramAccumulator<uint8_t> dha_15(&dha, &(dha.get_buckets()[15]));
		dha_15.wait_for_completion();
		
		ASSERT_EQ(dha_15.get_buckets().size(), 16U);
		
		EXPECT_BUCKET(dha_15,  0, 240U, 240U, 0U);
		EXPECT_BUCKET(dha_15,  1, 241U, 241U, 0U);
		EXPECT_BUCKET(dha_15,  2, 242U, 242U, 0U);
		EXPECT_BUCKET(dha_15,  8, 248U, 248U, 0U);
		EXPECT_BUCKET(dha_15, 15, 255U, 255U, 2U);
}

TEST(DataHistogramAccumulator, X16BitLE256Buckets)
{
	SharedDocumentPointer document(SharedDocumentPointer::make());
	
	const unsigned char DATA[] = {
		0x00, 0x00,
		0x00, 0x00,
		0x08, 0x00,
		0xFF, 0x00,
		0xFF, 0x00,
		0x00, 0x00,
		0xFF, 0xFF,
		0x00, 0x01,
	};
	
	document->insert_data(0, DATA, sizeof(DATA));
	
	DataHistogramAccumulator<uint16_t> dha(document, 0, sizeof(uint16_t), sizeof(DATA), 256);
	dha.wait_for_completion();
	
	ASSERT_EQ(dha.get_buckets().size(), 256U);
	
	EXPECT_BUCKET(dha,   0,     0U,   255U, 6U);
	EXPECT_BUCKET(dha,   1,   256U,   511U, 1U);
	EXPECT_BUCKET(dha,   2,   512U,   767U, 0U);
	EXPECT_BUCKET(dha,   8,  2048U,  2303U, 0U);
	EXPECT_BUCKET(dha, 255, 65280U, 65535U, 1U);
	
		DataHistogramAccumulator<uint16_t> dha_00(&dha, &(dha.get_buckets()[0]));
		dha_00.wait_for_completion();
		
		ASSERT_EQ(dha_00.get_buckets().size(), 256U);
		
		EXPECT_BUCKET(dha_00,   0,   0U,   0U,  3U);
		EXPECT_BUCKET(dha_00,   1,   1U,   1U,  0U);
		EXPECT_BUCKET(dha_00,   2,   2U,   2U,  0U);
		EXPECT_BUCKET(dha_00,   8,   8U,   8U,  1U);
		EXPECT_BUCKET(dha_00, 255, 255U, 255U,  2U);
}

TEST(DataHistogramAccumulator, X16BitLE16Buckets)
{
	SharedDocumentPointer document(SharedDocumentPointer::make());
	
	const unsigned char DATA[] = {
		0x00, 0x00,
		0x00, 0x00,
		0x08, 0x00,
		0xFF, 0x00,
		0xFF, 0x00,
		0x00, 0x00,
		0xFF, 0xFF,
		0x00, 0x01,
	};
	
	document->insert_data(0, DATA, sizeof(DATA));
	
	DataHistogramAccumulator<uint16_t> dha(document, 0, sizeof(uint16_t), sizeof(DATA), 16);
	dha.wait_for_completion();
	
	ASSERT_EQ(dha.get_buckets().size(), 16U);
	
	EXPECT_BUCKET(dha,  0,     0U,  4095U, 7U);
	EXPECT_BUCKET(dha,  1,  4096U,  8191U, 0U);
	EXPECT_BUCKET(dha,  2,  8192U, 12287U, 0U);
	EXPECT_BUCKET(dha,  8, 32768U, 36863U, 0U);
	EXPECT_BUCKET(dha, 15, 61440U, 65535U, 1U);
	
		DataHistogramAccumulator<uint16_t> dha_00(&dha, &(dha.get_buckets()[0]));
		dha_00.wait_for_completion();
		
		ASSERT_EQ(dha_00.get_buckets().size(), 16U);
		
		EXPECT_BUCKET(dha_00,  0,    0U,  255U, 6U);
		EXPECT_BUCKET(dha_00,  1,  256U,  511U, 1U);
		EXPECT_BUCKET(dha_00,  2,  512U,  767U, 0U);
		EXPECT_BUCKET(dha_00,  8, 2048U, 2303U, 0U);
		EXPECT_BUCKET(dha_00, 15, 3840U, 4095U, 0U);
		
			DataHistogramAccumulator<uint16_t> dha_00_00(&dha_00, &(dha_00.get_buckets()[0]));
			dha_00_00.wait_for_completion();
			
			ASSERT_EQ(dha_00_00.get_buckets().size(), 16U);
			
			EXPECT_BUCKET(dha_00_00,  0,   0U,  15U, 4U);
			EXPECT_BUCKET(dha_00_00,  1,  16U,  31U, 0U);
			EXPECT_BUCKET(dha_00_00,  2,  32U,  47U, 0U);
			EXPECT_BUCKET(dha_00_00,  8, 128U, 143U, 0U);
			EXPECT_BUCKET(dha_00_00, 15, 240U, 255U, 2U);
			
				DataHistogramAccumulator<uint16_t> dha_00_00_00(&dha_00_00, &(dha_00_00.get_buckets()[0]));
				dha_00_00_00.wait_for_completion();
				
				ASSERT_EQ(dha_00_00_00.get_buckets().size(), 16U);
				
				EXPECT_BUCKET(dha_00_00_00,  0,  0U,  0U, 3U);
				EXPECT_BUCKET(dha_00_00_00,  1,  1U,  1U, 0U);
				EXPECT_BUCKET(dha_00_00_00,  2,  2U,  2U, 0U);
				EXPECT_BUCKET(dha_00_00_00,  8,  8U,  8U, 1U);
				EXPECT_BUCKET(dha_00_00_00, 15, 15U, 15U, 0U);
				
				DataHistogramAccumulator<uint16_t> dha_00_00_01(&dha_00_00, &(dha_00_00.get_buckets()[1]));
				dha_00_00_01.wait_for_completion();
				
				ASSERT_EQ(dha_00_00_01.get_buckets().size(), 16U);
				
				EXPECT_BUCKET(dha_00_00_01,  0, 16U, 16U, 0U);
				EXPECT_BUCKET(dha_00_00_01,  1, 17U, 17U, 0U);
				EXPECT_BUCKET(dha_00_00_01,  2, 18U, 18U, 0U);
				EXPECT_BUCKET(dha_00_00_01,  8, 24U, 24U, 0U);
				EXPECT_BUCKET(dha_00_00_01, 15, 31U, 31U, 0U);
			
			DataHistogramAccumulator<uint16_t> dha_00_01(&dha_00, &(dha_00.get_buckets()[1]));
			dha_00_01.wait_for_completion();
			
			ASSERT_EQ(dha_00_01.get_buckets().size(), 16U);
			
			EXPECT_BUCKET(dha_00_01,  0, 256U, 271U, 1U);
			EXPECT_BUCKET(dha_00_01,  1, 272U, 287U, 0U);
			EXPECT_BUCKET(dha_00_01,  2, 288U, 303U, 0U);
			EXPECT_BUCKET(dha_00_01,  8, 384U, 399U, 0U);
			EXPECT_BUCKET(dha_00_01, 15, 496U, 511U, 0U);
			
				DataHistogramAccumulator<uint16_t> dha_00_01_00(&dha_00_01, &(dha_00_01.get_buckets()[0]));
				dha_00_01_00.wait_for_completion();
				
				ASSERT_EQ(dha_00_01_00.get_buckets().size(), 16U);
				
				EXPECT_BUCKET(dha_00_01_00,  0, 256U, 256U, 1U);
				EXPECT_BUCKET(dha_00_01_00,  1, 257U, 257U, 0U);
				EXPECT_BUCKET(dha_00_01_00,  2, 258U, 258U, 0U);
				EXPECT_BUCKET(dha_00_01_00,  8, 264U, 264U, 0U);
				EXPECT_BUCKET(dha_00_01_00, 15, 271U, 271U, 0U);
				
				DataHistogramAccumulator<uint16_t> dha_00_01_01(&dha_00_01, &(dha_00_01.get_buckets()[1]));
				dha_00_01_01.wait_for_completion();
				
				ASSERT_EQ(dha_00_01_01.get_buckets().size(), 16U);
				
				EXPECT_BUCKET(dha_00_01_01,  0, 272U, 272U, 0U);
				EXPECT_BUCKET(dha_00_01_01,  1, 273U, 273U, 0U);
				EXPECT_BUCKET(dha_00_01_01,  2, 274U, 274U, 0U);
				EXPECT_BUCKET(dha_00_01_01,  8, 280U, 280U, 0U);
				EXPECT_BUCKET(dha_00_01_01, 15, 287U, 287U, 0U);
		
		DataHistogramAccumulator<uint16_t> dha_15(&dha, &(dha.get_buckets()[15]));
		dha_15.wait_for_completion();
		
		ASSERT_EQ(dha_15.get_buckets().size(), 16U);
		
		EXPECT_BUCKET(dha_15,  0, 61440U, 61695U, 0U);
		EXPECT_BUCKET(dha_15,  1, 61696U, 61951U, 0U);
		EXPECT_BUCKET(dha_15,  2, 61952U, 62207U, 0U);
		EXPECT_BUCKET(dha_15,  8, 63488U, 63743U, 0U);
		EXPECT_BUCKET(dha_15, 15, 65280U, 65535U, 1U);
		
			DataHistogramAccumulator<uint16_t> dha_15_15(&dha_15, &(dha_15.get_buckets()[15]));
			dha_15_15.wait_for_completion();
			
			ASSERT_EQ(dha_15_15.get_buckets().size(), 16U);
			
			EXPECT_BUCKET(dha_15_15,  0, 65280U, 65295U, 0U);
			EXPECT_BUCKET(dha_15_15,  1, 65296U, 65311U, 0U);
			EXPECT_BUCKET(dha_15_15,  2, 65312U, 65327U, 0U);
			EXPECT_BUCKET(dha_15_15,  8, 65408U, 65423U, 0U);
			EXPECT_BUCKET(dha_15_15, 15, 65520U, 65535U, 1U);
			
				DataHistogramAccumulator<uint16_t> dha_15_15_15(&dha_15_15, &(dha_15_15.get_buckets()[15]));
				dha_15_15_15.wait_for_completion();
				
				ASSERT_EQ(dha_15_15_15.get_buckets().size(), 16U);
				
				EXPECT_BUCKET(dha_15_15_15,  0, 65520U, 65520U, 0U);
				EXPECT_BUCKET(dha_15_15_15,  1, 65521U, 65521U, 0U);
				EXPECT_BUCKET(dha_15_15_15,  2, 65522U, 65522U, 0U);
				EXPECT_BUCKET(dha_15_15_15,  8, 65528U, 65528U, 0U);
				EXPECT_BUCKET(dha_15_15_15, 15, 65535U, 65535U, 1U);
}

TEST(DataHistogramAccumulator, X16BitLE64Buckets)
{
	SharedDocumentPointer document(SharedDocumentPointer::make());
	
	const unsigned char DATA[] = {
		0x00, 0x00,
		0x00, 0x00,
		0x08, 0x00,
		0xFF, 0x00,
		0xFF, 0x00,
		0x00, 0x00,
		0xFF, 0xFF,
		0x00, 0x01,
	};
	
	document->insert_data(0, DATA, sizeof(DATA));
	
	DataHistogramAccumulator<uint16_t> dha(document, 0, sizeof(uint16_t), sizeof(DATA), 64);
	dha.wait_for_completion();
	
	ASSERT_EQ(dha.get_buckets().size(), 64U);
	
	EXPECT_BUCKET(dha,  0,     0U,  1023U, 7U);
	EXPECT_BUCKET(dha,  1,  1024U,  2047U, 0U);
	EXPECT_BUCKET(dha,  2,  2048U,  3071U, 0U);
	EXPECT_BUCKET(dha,  8,  8192U,  9215U, 0U);
	EXPECT_BUCKET(dha, 63, 64512U, 65535U, 1U);
	
		DataHistogramAccumulator<uint16_t> dha_00(&dha, &(dha.get_buckets()[0]));
		dha_00.wait_for_completion();
		
		ASSERT_EQ(dha_00.get_buckets().size(), 64U);
		
		EXPECT_BUCKET(dha_00,  0,    0U,   15U, 4U);
		EXPECT_BUCKET(dha_00,  1,   16U,   31U, 0U);
		EXPECT_BUCKET(dha_00, 15,  240U,  255U, 2U);
		EXPECT_BUCKET(dha_00, 16,  256U,  271U, 1U);
		EXPECT_BUCKET(dha_00, 63, 1008U, 1023U, 0U);
		
			DataHistogramAccumulator<uint16_t> dha_00_00(&dha_00, &(dha_00.get_buckets()[0]));
			dha_00_00.wait_for_completion();
			
			ASSERT_EQ(dha_00_00.get_buckets().size(), 16U);
			
			EXPECT_BUCKET(dha_00_00,  0,  0U,  0U, 3U);
			EXPECT_BUCKET(dha_00_00,  1,  1U,  1U, 0U);
			EXPECT_BUCKET(dha_00_00,  2,  2U,  2U, 0U);
			EXPECT_BUCKET(dha_00_00,  8,  8U,  8U, 1U);
			EXPECT_BUCKET(dha_00_00, 15, 15U, 15U, 0U);
			
			DataHistogramAccumulator<uint16_t> dha_00_01(&dha_00, &(dha_00.get_buckets()[1]));
			dha_00_01.wait_for_completion();
			
			ASSERT_EQ(dha_00_01.get_buckets().size(), 16U);
			
			EXPECT_BUCKET(dha_00_01,  0, 16U, 16U, 0U);
			EXPECT_BUCKET(dha_00_01,  1, 17U, 17U, 0U);
			EXPECT_BUCKET(dha_00_01,  2, 18U, 18U, 0U);
			EXPECT_BUCKET(dha_00_01,  8, 24U, 24U, 0U);
			EXPECT_BUCKET(dha_00_01, 15, 31U, 31U, 0U);
	
		DataHistogramAccumulator<uint16_t> dha_01(&dha, &(dha.get_buckets()[1]));
		dha_01.wait_for_completion();
		
		ASSERT_EQ(dha_01.get_buckets().size(), 64U);
		
		EXPECT_BUCKET(dha_01,  0, 1024U, 1039U, 0U);
		EXPECT_BUCKET(dha_01,  1, 1040U, 1055U, 0U);
		EXPECT_BUCKET(dha_01, 15, 1264U, 1279U, 0U);
		EXPECT_BUCKET(dha_01, 16, 1280U, 1295U, 0U);
		EXPECT_BUCKET(dha_01, 63, 2032U, 2047U, 0U);
		
			DataHistogramAccumulator<uint16_t> dha_01_00(&dha_01, &(dha_01.get_buckets()[0]));
			dha_01_00.wait_for_completion();
			
			ASSERT_EQ(dha_01_00.get_buckets().size(), 16U);
			
			EXPECT_BUCKET(dha_01_00,  0, 1024U, 1024U, 0U);
			EXPECT_BUCKET(dha_01_00,  1, 1025U, 1025U, 0U);
			EXPECT_BUCKET(dha_01_00,  2, 1026U, 1026U, 0U);
			EXPECT_BUCKET(dha_01_00,  8, 1032U, 1032U, 0U);
			EXPECT_BUCKET(dha_01_00, 15, 1039U, 1039U, 0U);
			
			DataHistogramAccumulator<uint16_t> dha_01_01(&dha_01, &(dha_01.get_buckets()[1]));
			dha_01_01.wait_for_completion();
			
			ASSERT_EQ(dha_01_01.get_buckets().size(), 16U);
			
			EXPECT_BUCKET(dha_01_01,  0, 1040U, 1040U, 0U);
			EXPECT_BUCKET(dha_01_01,  1, 1041U, 1041U, 0U);
			EXPECT_BUCKET(dha_01_01,  2, 1042U, 1042U, 0U);
			EXPECT_BUCKET(dha_01_01,  8, 1048U, 1048U, 0U);
			EXPECT_BUCKET(dha_01_01, 15, 1055U, 1055U, 0U);
}
