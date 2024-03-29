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
#include <wx/event.h>

#include "../src/CharacterFinder.hpp"
#include "../src/SharedDocumentPointer.hpp"

using namespace REHex;

TEST(CharacterFinder, FindsASCIICharacters)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	unsigned char data[256];
	for(int i = 0; i < 256; ++i)
	{
		data[i] = i;
	}
	
	doc->insert_data(0, data, sizeof(data));
	
	CharacterFinder cf(doc, 0, sizeof(data));
	
	while(!cf.finished()) {} /* SPIN */
	
	for(int i = 0; i < 256; ++i)
	{
		EXPECT_EQ(cf.get_char_start(i), i);
		EXPECT_EQ(cf.get_char_length(i), 1);
	}
}

TEST(CharacterFinder, FindsUTF8Characters)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	unsigned char data[] = {
		/* Control characters */
		'\0', '\n', 0x7F,
		
		/* Printable ASCII */
		'A', 'z', '9', '#',
		
		/* 2 byte codepoints */
		0xC2, 0x80,
		0xDF, 0xBF,
		
		/* Invalid sequence */
		0xFE, 0xFE, 0xFF, 0xFF,
		
		/* 3 byte codepoints */
		0xE0, 0xA0, 0x80,
		0xEF, 0xBF, 0xBF,
		
		/* 4 byte codepoints */
		0xF0, 0x90, 0x80, 0x80,
		0xF0, 0xA0, 0x80, 0x80,
	};
	
	doc->insert_data(0, data, sizeof(data));
	doc->set_data_type(0, sizeof(data), "text:UTF-8");
	
	CharacterFinder cf(doc, 0, sizeof(data));
	
	while(!cf.finished()) {} /* SPIN */
	
	/* Control characters */
	
	EXPECT_EQ(cf.get_char_start(0), 0);
	EXPECT_EQ(cf.get_char_length(0), 1);
	
	EXPECT_EQ(cf.get_char_start(1), 1);
	EXPECT_EQ(cf.get_char_length(1), 1);
	
	EXPECT_EQ(cf.get_char_start(2), 2);
	EXPECT_EQ(cf.get_char_length(2), 1);
	
	/* Printable ASCII */
	
	EXPECT_EQ(cf.get_char_start(3), 3);
	EXPECT_EQ(cf.get_char_length(3), 1);
	
	EXPECT_EQ(cf.get_char_start(4), 4);
	EXPECT_EQ(cf.get_char_length(4), 1);
	
	EXPECT_EQ(cf.get_char_start(5), 5);
	EXPECT_EQ(cf.get_char_length(5), 1);
	
	EXPECT_EQ(cf.get_char_start(6), 6);
	EXPECT_EQ(cf.get_char_length(6), 1);
	
	/* 2 byte code points */
	
	EXPECT_EQ(cf.get_char_start(7), 7);
	EXPECT_EQ(cf.get_char_length(7), 2);
	EXPECT_EQ(cf.get_char_start(8), 7);
	EXPECT_EQ(cf.get_char_length(8), 2);
	
	EXPECT_EQ(cf.get_char_start(9),  9);
	EXPECT_EQ(cf.get_char_length(9),  2);
	EXPECT_EQ(cf.get_char_start(10), 9);
	EXPECT_EQ(cf.get_char_length(10), 2);
	
	/* Invalid sequence */
	
	EXPECT_EQ(cf.get_char_start(11), 11);
	EXPECT_EQ(cf.get_char_length(11), 1);
	EXPECT_EQ(cf.get_char_start(12), 12);
	EXPECT_EQ(cf.get_char_length(12), 1);
	EXPECT_EQ(cf.get_char_start(13), 13);
	EXPECT_EQ(cf.get_char_length(13), 1);
	EXPECT_EQ(cf.get_char_start(14), 14);
	EXPECT_EQ(cf.get_char_length(14), 1);
	
	/* 3 byte codepoints */
	
	EXPECT_EQ(cf.get_char_start(15), 15);
	EXPECT_EQ(cf.get_char_length(15), 3);
	EXPECT_EQ(cf.get_char_start(16), 15);
	EXPECT_EQ(cf.get_char_length(16), 3);
	EXPECT_EQ(cf.get_char_start(17), 15);
	EXPECT_EQ(cf.get_char_length(17), 3);
	
	EXPECT_EQ(cf.get_char_start(18), 18);
	EXPECT_EQ(cf.get_char_length(18), 3);
	EXPECT_EQ(cf.get_char_start(19), 18);
	EXPECT_EQ(cf.get_char_length(19), 3);
	EXPECT_EQ(cf.get_char_start(20), 18);
	EXPECT_EQ(cf.get_char_length(20), 3);
	
	/* 4 byte codepoints */
	
	EXPECT_EQ(cf.get_char_start(21), 21);
	EXPECT_EQ(cf.get_char_length(21), 4);
	EXPECT_EQ(cf.get_char_start(22), 21);
	EXPECT_EQ(cf.get_char_length(22), 4);
	EXPECT_EQ(cf.get_char_start(23), 21);
	EXPECT_EQ(cf.get_char_length(23), 4);
	EXPECT_EQ(cf.get_char_start(24), 21);
	EXPECT_EQ(cf.get_char_length(24), 4);
	
	EXPECT_EQ(cf.get_char_start(25), 25);
	EXPECT_EQ(cf.get_char_length(25), 4);
	EXPECT_EQ(cf.get_char_start(26), 25);
	EXPECT_EQ(cf.get_char_length(26), 4);
	EXPECT_EQ(cf.get_char_start(27), 25);
	EXPECT_EQ(cf.get_char_length(27), 4);
	EXPECT_EQ(cf.get_char_start(28), 25);
	EXPECT_EQ(cf.get_char_length(28), 4);
}

TEST(CharacterFinder, FindsShiftJISCharacters)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	static const unsigned char SJIS_STRING[] = {
		0x8d, 0xdd, 0x82, 0xcf, 0x82, 0xcb, 0x83, 0x58, 0x96, 0x59, 0x8e, 0x73, 0x83, 0x8f, 0x98, 0x61,
		0x95, 0xd4, 0x83, 0x41, 0x96, 0xe9, 0x92, 0xca, 0x82, 0xdb, 0x82, 0xe7, 0x83, 0x58, 0x94, 0x84,
		0x8f, 0xea, 0x95, 0x4b, 0x83, 0x8c, 0x83, 0x6c, 0x83, 0x4e, 0x83, 0x92, 0x95, 0xc0, 0x90, 0xb3,
		0x83, 0x80, 0x83, 0x45, 0x83, 0x86, 0x83, 0x84, 0x95, 0xb7, 0x93, 0xfa, 0x94, 0xed, 0x82, 0xb3,
		0x82, 0xbb, 0x82, 0xbe, 0x91, 0xdf, 0x92, 0x63, 0x94, 0x92, 0x82, 0xc8, 0x82, 0xcc, 0x82, 0xbb,
		0x89, 0xbb, 0x8c, 0xa9, 0x83, 0x67, 0x83, 0x4a, 0x83, 0x84, 0x95, 0x94, 0x8b, 0xb3, 0x97, 0xbf,
		0x83, 0x8a, 0x83, 0x5e, 0x83, 0x71, 0x91, 0x53, 0x96, 0xfb, 0x83, 0x6c, 0x83, 0x49, 0x89, 0x66,
		0x37, 0x89, 0x98, 0x83, 0x6c, 0x83, 0x71, 0x8c, 0xec, 0x8d, 0x90, 0x8d, 0x9e, 0x82, 0xd7, 0x82,
		0xa8, 0x89, 0x93, 0x8a, 0x7c, 0x8f, 0xc4, 0x8d, 0xbc, 0x91, 0xe6, 0x82, 0xbf, 0x81, 0x42, 0x8e,
		0x91, 0x82, 0xbb, 0x83, 0x58, 0x8e, 0x64, 0x8d, 0x90, 0x83, 0x88, 0x83, 0x8f, 0x93, 0x6f, 0x8a,
		0x77, 0x83, 0x77, 0x83, 0x8c, 0x83, 0x86, 0x83, 0x5c, 0x8a, 0xca, 0x95, 0xdb, 0x82, 0xce, 0x82,
		0xd9, 0x82, 0xd3, 0x92, 0x9b, 0x8d, 0x4b, 0x96, 0x6b, 0x82, 0xd1, 0x83, 0x68, 0x82, 0xad, 0x82,
		0xbb, 0x8f, 0x5f, 0x34, 0x38, 0x8f, 0x88, 0x82, 0xab, 0x82, 0xbb, 0x82, 0xc8, 0x82, 0xc5, 0x89,
		0xc6, 0x89, 0xc8, 0x83, 0x62, 0x95, 0xaa, 0x8a, 0xd9, 0x83, 0x58, 0x89, 0xc1, 0x33, 0x92, 0x66,
		0x82, 0xbf, 0x89, 0xb9, 0x8f, 0xf3, 0x82, 0xb1, 0x8c, 0xc9, 0x8e, 0x77, 0x96, 0xcd, 0x82, 0xb8,
		0x81, 0x42, 0x8f, 0xdc, 0x83, 0x8f, 0x95, 0xfa, 0x97, 0xa4, 0x82, 0xc4, 0x82, 0xa4, 0x93, 0x57,
		0x8e, 0xcb, 0x82, 0xd6, 0x83, 0x43, 0x8a, 0xd4, 0x38, 0x31, 0x8e, 0x73, 0x91, 0xce, 0x82, 0xc2,
		0x82, 0xd2, 0x82, 0xd3, 0x8c, 0xa0, 0x93, 0x8a, 0x83, 0x91, 0x83, 0x43, 0x83, 0x74, 0x83, 0x56,
		0x91, 0xf0, 0x8a, 0x4d, 0x83, 0x6d, 0x83, 0x84, 0x83, 0x5a, 0x83, 0x8f, 0x96, 0xe2, 0x8e, 0xe8,
		0x8e, 0x7e, 0x83, 0x56, 0x83, 0x60, 0x83, 0x69, 0x91, 0xba, 0x88, 0xea, 0x82, 0xbe, 0x97, 0xd6,
		0x92, 0xc3, 0x83, 0x84, 0x83, 0x4c, 0x83, 0x4e, 0x95, 0xaa, 0x8c, 0x83, 0x94, 0x4d, 0x8e, 0x77,
		0x82, 0xbe, 0x82, 0xb5, 0x81, 0x42, 0x0a,
	};
	
	doc->insert_data(0, SJIS_STRING, sizeof(SJIS_STRING));
	doc->set_data_type(0, sizeof(SJIS_STRING), "text:MSCP932");
	
	CharacterFinder cf(doc, 0, sizeof(SJIS_STRING));
	
	while(!cf.finished()) {} /* SPIN */
	
	EXPECT_EQ(cf.get_char_start(0x00),  0x00);
	EXPECT_EQ(cf.get_char_length(0x00), 2);
	EXPECT_EQ(cf.get_char_start(0x01),  0x00);
	EXPECT_EQ(cf.get_char_length(0x01), 2);
	
	EXPECT_EQ(cf.get_char_start(0x02),  0x02);
	EXPECT_EQ(cf.get_char_length(0x02), 2);
	EXPECT_EQ(cf.get_char_start(0x03),  0x02);
	EXPECT_EQ(cf.get_char_length(0x03), 2);
	
	EXPECT_EQ(cf.get_char_start(0xA1),  0xA1);
	EXPECT_EQ(cf.get_char_length(0xA1), 2);
	EXPECT_EQ(cf.get_char_start(0xA2),  0xA1);
	EXPECT_EQ(cf.get_char_length(0xA2), 2);
	
	EXPECT_EQ(cf.get_char_start(0xC3),  0xC3);
	EXPECT_EQ(cf.get_char_length(0xC3), 1);
	
	EXPECT_EQ(cf.get_char_start(0xC4),  0xC4);
	EXPECT_EQ(cf.get_char_length(0xC4), 1);
	
	EXPECT_EQ(cf.get_char_start(0xF8),  0xF8);
	EXPECT_EQ(cf.get_char_length(0xF8), 2);
	EXPECT_EQ(cf.get_char_start(0xF9),  0xF8);
	EXPECT_EQ(cf.get_char_length(0xF9), 2);
}

TEST(CharacterFinder, FindsShiftJISCharactersMultipleChunks)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	static const unsigned char SJIS_STRING[] = {
		0x8d, 0xdd, 0x82, 0xcf, 0x82, 0xcb, 0x83, 0x58, 0x96, 0x59, 0x8e, 0x73, 0x83, 0x8f, 0x98, 0x61,
		0x95, 0xd4, 0x83, 0x41, 0x96, 0xe9, 0x92, 0xca, 0x82, 0xdb, 0x82, 0xe7, 0x83, 0x58, 0x94, 0x84,
		0x8f, 0xea, 0x95, 0x4b, 0x83, 0x8c, 0x83, 0x6c, 0x83, 0x4e, 0x83, 0x92, 0x95, 0xc0, 0x90, 0xb3,
		0x83, 0x80, 0x83, 0x45, 0x83, 0x86, 0x83, 0x84, 0x95, 0xb7, 0x93, 0xfa, 0x94, 0xed, 0x82, 0xb3,
		0x82, 0xbb, 0x82, 0xbe, 0x91, 0xdf, 0x92, 0x63, 0x94, 0x92, 0x82, 0xc8, 0x82, 0xcc, 0x82, 0xbb,
		0x89, 0xbb, 0x8c, 0xa9, 0x83, 0x67, 0x83, 0x4a, 0x83, 0x84, 0x95, 0x94, 0x8b, 0xb3, 0x97, 0xbf,
		0x83, 0x8a, 0x83, 0x5e, 0x83, 0x71, 0x91, 0x53, 0x96, 0xfb, 0x83, 0x6c, 0x83, 0x49, 0x89, 0x66,
		0x37, 0x89, 0x98, 0x83, 0x6c, 0x83, 0x71, 0x8c, 0xec, 0x8d, 0x90, 0x8d, 0x9e, 0x82, 0xd7, 0x82,
		0xa8, 0x89, 0x93, 0x8a, 0x7c, 0x8f, 0xc4, 0x8d, 0xbc, 0x91, 0xe6, 0x82, 0xbf, 0x81, 0x42, 0x8e,
		0x91, 0x82, 0xbb, 0x83, 0x58, 0x8e, 0x64, 0x8d, 0x90, 0x83, 0x88, 0x83, 0x8f, 0x93, 0x6f, 0x8a,
		0x77, 0x83, 0x77, 0x83, 0x8c, 0x83, 0x86, 0x83, 0x5c, 0x8a, 0xca, 0x95, 0xdb, 0x82, 0xce, 0x82,
		0xd9, 0x82, 0xd3, 0x92, 0x9b, 0x8d, 0x4b, 0x96, 0x6b, 0x82, 0xd1, 0x83, 0x68, 0x82, 0xad, 0x82,
		0xbb, 0x8f, 0x5f, 0x34, 0x38, 0x8f, 0x88, 0x82, 0xab, 0x82, 0xbb, 0x82, 0xc8, 0x82, 0xc5, 0x89,
		0xc6, 0x89, 0xc8, 0x83, 0x62, 0x95, 0xaa, 0x8a, 0xd9, 0x83, 0x58, 0x89, 0xc1, 0x33, 0x92, 0x66,
		0x82, 0xbf, 0x89, 0xb9, 0x8f, 0xf3, 0x82, 0xb1, 0x8c, 0xc9, 0x8e, 0x77, 0x96, 0xcd, 0x82, 0xb8,
		0x81, 0x42, 0x8f, 0xdc, 0x83, 0x8f, 0x95, 0xfa, 0x97, 0xa4, 0x82, 0xc4, 0x82, 0xa4, 0x93, 0x57,
		0x8e, 0xcb, 0x82, 0xd6, 0x83, 0x43, 0x8a, 0xd4, 0x38, 0x31, 0x8e, 0x73, 0x91, 0xce, 0x82, 0xc2,
		0x82, 0xd2, 0x82, 0xd3, 0x8c, 0xa0, 0x93, 0x8a, 0x83, 0x91, 0x83, 0x43, 0x83, 0x74, 0x83, 0x56,
		0x91, 0xf0, 0x8a, 0x4d, 0x83, 0x6d, 0x83, 0x84, 0x83, 0x5a, 0x83, 0x8f, 0x96, 0xe2, 0x8e, 0xe8,
		0x8e, 0x7e, 0x83, 0x56, 0x83, 0x60, 0x83, 0x69, 0x91, 0xba, 0x88, 0xea, 0x82, 0xbe, 0x97, 0xd6,
		0x92, 0xc3, 0x83, 0x84, 0x83, 0x4c, 0x83, 0x4e, 0x95, 0xaa, 0x8c, 0x83, 0x94, 0x4d, 0x8e, 0x77,
		0x82, 0xbe, 0x82, 0xb5, 0x81, 0x42, 0x0a,
	};
	
	for(int i = 0, off = 0; i < 32; ++i, off += sizeof(SJIS_STRING))
	{
		doc->insert_data(off, SJIS_STRING, sizeof(SJIS_STRING));
		doc->set_data_type(off, sizeof(SJIS_STRING), "text:MSCP932");
	}
	
	CharacterFinder cf(doc, sizeof(SJIS_STRING), sizeof(SJIS_STRING) * 30, sizeof(SJIS_STRING) / 4 /* 85 */);
	
	while(!cf.finished()) {} /* SPIN */
	
	/* before start of range */
	EXPECT_EQ(cf.get_char_start (0x0156), -1);
	EXPECT_EQ(cf.get_char_length(0x0156), -1);
	
	/* at start of range */
	EXPECT_EQ(cf.get_char_start (0x0157), 0x0157);
	EXPECT_EQ(cf.get_char_length(0x0157), 2);
	EXPECT_EQ(cf.get_char_start (0x0158), 0x0157);
	EXPECT_EQ(cf.get_char_length(0x0158), 2);
	
	/* after start of chunk */
	EXPECT_EQ(cf.get_char_start (0x0159), 0x0159);
	EXPECT_EQ(cf.get_char_length(0x0159), 2);
	EXPECT_EQ(cf.get_char_start (0x015A), 0x0159);
	EXPECT_EQ(cf.get_char_length(0x015A), 2);
	
	/* before end of chunk */
	EXPECT_EQ(cf.get_char_start (0x01A9), 0x01A9);
	EXPECT_EQ(cf.get_char_length(0x01A9), 2);
	EXPECT_EQ(cf.get_char_start (0x01AA), 0x01A9);
	EXPECT_EQ(cf.get_char_length(0x01AA), 2);
	
	/* this one straddles a chunk boundary */
	EXPECT_EQ(cf.get_char_start (0x01AB), 0x01AB);
	EXPECT_EQ(cf.get_char_length(0x01AB), 2);
	EXPECT_EQ(cf.get_char_start (0x01AC), 0x01AB);
	EXPECT_EQ(cf.get_char_length(0x01AC), 2);
	
	/* after start of chunk */
	EXPECT_EQ(cf.get_char_start (0x01AD), 0x01AD);
	EXPECT_EQ(cf.get_char_length(0x01AD), 2);
	EXPECT_EQ(cf.get_char_start (0x01AE), 0x01AD);
	EXPECT_EQ(cf.get_char_length(0x01AE), 2);
	
	/* at end of chunk */
	EXPECT_EQ(cf.get_char_start (0x02A9), 0x02A9);
	EXPECT_EQ(cf.get_char_length(0x02AB), 2);
	EXPECT_EQ(cf.get_char_start (0x02AA), 0x02A9);
	EXPECT_EQ(cf.get_char_length(0x02AA), 2);
	
	/* at start of chunk */
	EXPECT_EQ(cf.get_char_start (0x02AB), 0x02AB);
	EXPECT_EQ(cf.get_char_length(0x02AB), 2);
	EXPECT_EQ(cf.get_char_start (0x02AC), 0x02AB);
	EXPECT_EQ(cf.get_char_length(0x02AC), 2);
	
	EXPECT_EQ(cf.get_char_start (0x0D65), 0x0D65);
	EXPECT_EQ(cf.get_char_length(0x0D65), 1);
	
	/* before end of range */
	EXPECT_EQ(cf.get_char_start (0x2986), 0x2986);
	EXPECT_EQ(cf.get_char_length(0x2986), 2);
	EXPECT_EQ(cf.get_char_start (0x2987), 0x2986);
	EXPECT_EQ(cf.get_char_length(0x2987), 2);
	
	/* at end of range */
	EXPECT_EQ(cf.get_char_start (0x2988), 0x2988);
	EXPECT_EQ(cf.get_char_length(0x2988), 1);
	
	/* after end of range */
	EXPECT_EQ(cf.get_char_start (0x2989), -1);
	EXPECT_EQ(cf.get_char_length(0x2989), -1);
}

TEST(CharacterFinder, FindsShiftJISCharactersMultipleChunksAligned)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	static const unsigned char SJIS_STRING[] = {
		0x8d, 0xdd, 0x82, 0xcf, 0x82, 0xcb, 0x83, 0x58, 0x96, 0x59, 0x8e, 0x73, 0x83, 0x8f, 0x98, 0x61,
		0x95, 0xd4, 0x83, 0x41, 0x96, 0xe9, 0x92, 0xca, 0x82, 0xdb, 0x82, 0xe7, 0x83, 0x58, 0x94, 0x84,
		0x8f, 0xea, 0x95, 0x4b, 0x83, 0x8c, 0x83, 0x6c, 0x83, 0x4e, 0x83, 0x92, 0x95, 0xc0, 0x90, 0xb3,
		0x83, 0x80, 0x83, 0x45, 0x83, 0x86, 0x83, 0x84, 0x95, 0xb7, 0x93, 0xfa, 0x94, 0xed, 0x82, 0xb3,
		0x82, 0xbb, 0x82, 0xbe, 0x91, 0xdf, 0x92, 0x63, 0x94, 0x92, 0x82, 0xc8, 0x82, 0xcc, 0x82, 0xbb,
		0x89, 0xbb, 0x8c, 0xa9, 0x83, 0x67, 0x83, 0x4a, 0x83, 0x84, 0x95, 0x94, 0x8b, 0xb3, 0x97, 0xbf,
		0x83, 0x8a, 0x83, 0x5e, 0x83, 0x71, 0x91, 0x53, 0x96, 0xfb, 0x83, 0x6c, 0x83, 0x49, 0x89, 0x66,
		0x37, 0x89, 0x98, 0x83, 0x6c, 0x83, 0x71, 0x8c, 0xec, 0x8d, 0x90, 0x8d, 0x9e, 0x82, 0xd7, 0x82,
		0xa8, 0x89, 0x93, 0x8a, 0x7c, 0x8f, 0xc4, 0x8d, 0xbc, 0x91, 0xe6, 0x82, 0xbf, 0x81, 0x42, 0x8e,
		0x91, 0x82, 0xbb, 0x83, 0x58, 0x8e, 0x64, 0x8d, 0x90, 0x83, 0x88, 0x83, 0x8f, 0x93, 0x6f, 0x8a,
		0x77, 0x83, 0x77, 0x83, 0x8c, 0x83, 0x86, 0x83, 0x5c, 0x8a, 0xca, 0x95, 0xdb, 0x82, 0xce, 0x82,
		0xd9, 0x82, 0xd3, 0x92, 0x9b, 0x8d, 0x4b, 0x96, 0x6b, 0x82, 0xd1, 0x83, 0x68, 0x82, 0xad, 0x82,
		0xbb, 0x8f, 0x5f, 0x34, 0x38, 0x8f, 0x88, 0x82, 0xab, 0x82, 0xbb, 0x82, 0xc8, 0x82, 0xc5, 0x89,
		0xc6, 0x89, 0xc8, 0x83, 0x62, 0x95, 0xaa, 0x8a, 0xd9, 0x83, 0x58, 0x89, 0xc1, 0x33, 0x92, 0x66,
		0x82, 0xbf, 0x89, 0xb9, 0x8f, 0xf3, 0x82, 0xb1, 0x8c, 0xc9, 0x8e, 0x77, 0x96, 0xcd, 0x82, 0xb8,
		0x81, 0x42, 0x8f, 0xdc, 0x83, 0x8f, 0x95, 0xfa, 0x97, 0xa4, 0x82, 0xc4, 0x82, 0xa4, 0x93, 0x57,
		0x8e, 0xcb, 0x82, 0xd6, 0x83, 0x43, 0x8a, 0xd4, 0x38, 0x31, 0x8e, 0x73, 0x91, 0xce, 0x82, 0xc2,
		0x82, 0xd2, 0x82, 0xd3, 0x8c, 0xa0, 0x93, 0x8a, 0x83, 0x91, 0x83, 0x43, 0x83, 0x74, 0x83, 0x56,
		0x91, 0xf0, 0x8a, 0x4d, 0x83, 0x6d, 0x83, 0x84, 0x83, 0x5a, 0x83, 0x8f, 0x96, 0xe2, 0x8e, 0xe8,
		0x8e, 0x7e, 0x83, 0x56, 0x83, 0x60, 0x83, 0x69, 0x91, 0xba, 0x88, 0xea, 0x82, 0xbe, 0x97, 0xd6,
		0x92, 0xc3, 0x83, 0x84, 0x83, 0x4c, 0x83, 0x4e, 0x95, 0xaa, 0x8c, 0x83, 0x94, 0x4d, 0x8e, 0x77,
		0x82, 0xbe, 0x82, 0xb5, 0x81, 0x42, 0x0a,
	};
	
	for(int i = 0, off = 0; i < 32; ++i, off += sizeof(SJIS_STRING))
	{
		doc->insert_data(off, SJIS_STRING, sizeof(SJIS_STRING));
		doc->set_data_type(off, sizeof(SJIS_STRING), "text:MSCP932");
	}
	
	CharacterFinder cf(doc, sizeof(SJIS_STRING), sizeof(SJIS_STRING) * 30, sizeof(SJIS_STRING));
	
	while(!cf.finished()) {} /* SPIN */
	
	/* before start of range */
	EXPECT_EQ(cf.get_char_start (0x0156), -1);
	EXPECT_EQ(cf.get_char_length(0x0156), -1);
	
	/* at start of range */
	EXPECT_EQ(cf.get_char_start (0x0157), 0x0157);
	EXPECT_EQ(cf.get_char_length(0x0157), 2);
	EXPECT_EQ(cf.get_char_start (0x0158), 0x0157);
	EXPECT_EQ(cf.get_char_length(0x0158), 2);
	
	/* after start of chunk */
	EXPECT_EQ(cf.get_char_start (0x0159), 0x0159);
	EXPECT_EQ(cf.get_char_length(0x0159), 2);
	EXPECT_EQ(cf.get_char_start (0x015A), 0x0159);
	EXPECT_EQ(cf.get_char_length(0x015A), 2);
	
	/* before end of chunk */
	EXPECT_EQ(cf.get_char_start (0x01A9), 0x01A9);
	EXPECT_EQ(cf.get_char_length(0x01A9), 2);
	EXPECT_EQ(cf.get_char_start (0x01AA), 0x01A9);
	EXPECT_EQ(cf.get_char_length(0x01AA), 2);
	
	/* this one straddles a chunk boundary */
	EXPECT_EQ(cf.get_char_start (0x01AB), 0x01AB);
	EXPECT_EQ(cf.get_char_length(0x01AB), 2);
	EXPECT_EQ(cf.get_char_start (0x01AC), 0x01AB);
	EXPECT_EQ(cf.get_char_length(0x01AC), 2);
	
	/* after start of chunk */
	EXPECT_EQ(cf.get_char_start (0x01AD), 0x01AD);
	EXPECT_EQ(cf.get_char_length(0x01AD), 2);
	EXPECT_EQ(cf.get_char_start (0x01AE), 0x01AD);
	EXPECT_EQ(cf.get_char_length(0x01AE), 2);
	
	/* at end of chunk */
	EXPECT_EQ(cf.get_char_start (0x02A9), 0x02A9);
	EXPECT_EQ(cf.get_char_length(0x02AB), 2);
	EXPECT_EQ(cf.get_char_start (0x02AA), 0x02A9);
	EXPECT_EQ(cf.get_char_length(0x02AA), 2);
	
	/* at start of chunk */
	EXPECT_EQ(cf.get_char_start (0x02AB), 0x02AB);
	EXPECT_EQ(cf.get_char_length(0x02AB), 2);
	EXPECT_EQ(cf.get_char_start (0x02AC), 0x02AB);
	EXPECT_EQ(cf.get_char_length(0x02AC), 2);
	
	EXPECT_EQ(cf.get_char_start (0x0D65), 0x0D65);
	EXPECT_EQ(cf.get_char_length(0x0D65), 1);
	
	/* before end of range */
	EXPECT_EQ(cf.get_char_start (0x2986), 0x2986);
	EXPECT_EQ(cf.get_char_length(0x2986), 2);
	EXPECT_EQ(cf.get_char_start (0x2987), 0x2986);
	EXPECT_EQ(cf.get_char_length(0x2987), 2);
	
	/* at end of range */
	EXPECT_EQ(cf.get_char_start (0x2988), 0x2988);
	EXPECT_EQ(cf.get_char_length(0x2988), 1);
	
	/* after end of range */
	EXPECT_EQ(cf.get_char_start (0x2989), -1);
	EXPECT_EQ(cf.get_char_length(0x2989), -1);
}
