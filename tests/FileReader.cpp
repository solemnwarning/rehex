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
#include <string>
#include <vector>

#include "../src/FileReader.hpp"
#include "testutil.hpp"

using namespace REHex;

TEST(FileReader, ReadEmptyFile)
{
	TempFilename tfn;
	write_file(tfn.tmpfile, {});
	
	FileReader fr(tfn.tmpfile);
	
	char buf[1024];
	size_t read_count = fr.read(buf, 1024, 0);
	
	EXPECT_EQ(read_count, 0U);
}

TEST(FileReader, ReadTextFile)
{
	static const std::string REFERENCE_TEXT =
		"exultant\n"
		"sock\n"
		"acrid\n"
		"undesirable\n"
		"punch\n"
		"real\n"
		"forgetful\n"
		"wreck\n";
	
	TempFilename tfn;
	write_file(tfn.tmpfile, REFERENCE_TEXT.data(), REFERENCE_TEXT.length());
	
	FileReader fr(tfn.tmpfile);
	
	char buf[1024];
	size_t read_count = fr.read(buf, 1024, 0);
	
	ASSERT_EQ(read_count, REFERENCE_TEXT.length());
	EXPECT_EQ(std::string(buf, read_count), REFERENCE_TEXT);
}

TEST(FileReader, ReadBinaryFile)
{
	std::vector<unsigned char> REFERENCE_DATA;
	REFERENCE_DATA.reserve(512);
	
	for(int i = 0; i < 512; ++i)
	{
		REFERENCE_DATA.push_back(i % 256);
	}
	
	TempFilename tfn;
	write_file(tfn.tmpfile, REFERENCE_DATA);
	
	FileReader fr(tfn.tmpfile);
	
	unsigned char buf[1024];
	size_t read_count = fr.read(buf, 1024, 0);
	
	ASSERT_EQ(read_count, REFERENCE_DATA.size());
	EXPECT_EQ(std::vector<unsigned char>(buf, (buf + read_count)), REFERENCE_DATA);
}

TEST(FileReader, ReadBinaryFilePiecemeal)
{
	std::vector<unsigned char> REFERENCE_DATA;
	REFERENCE_DATA.reserve(512);
	
	for(int i = 0; i < 512; ++i)
	{
		REFERENCE_DATA.push_back(i % 256);
	}
	
	TempFilename tfn;
	write_file(tfn.tmpfile, REFERENCE_DATA);
	
	FileReader fr(tfn.tmpfile);
	
	unsigned char buf[1024];
	size_t read_count = fr.read(buf, 128, 0);
	ASSERT_EQ(read_count, 128U);
	
	read_count += fr.read(buf + 128, 128, 0);
	ASSERT_EQ(read_count, 256U);
	
	read_count += fr.read(buf + 256, 128, 0);
	ASSERT_EQ(read_count, 384U);
	
	read_count += fr.read(buf + 384, 400, 0);
	ASSERT_EQ(read_count, 512U);
	
	EXPECT_EQ(std::vector<unsigned char>(buf, (buf + read_count)), REFERENCE_DATA);
}

TEST(FileReader, ReadBinaryFileEarlyEOF)
{
	std::vector<unsigned char> REFERENCE_DATA;
	REFERENCE_DATA.reserve(128);
	
	for(int i = 0; i < 128; ++i)
	{
		REFERENCE_DATA.push_back(i % 256);
	}
	
	TempFilename tfn;
	write_file(tfn.tmpfile, REFERENCE_DATA);
	
	FileReader fr(tfn.tmpfile);
	
	unsigned char buf[1024];
	EXPECT_THROW({ fr.read(buf, 256, 129); }, FileReader::eof_error);
}

TEST(FileReader, ReadTLV)
{
	char FILE_DATA[] =
		"A123" "\x0F\x00\x00\x00" "jolly breakable"
		"B456" "\x0A\x00\x00\x00" "tricky van";
	
	TempFilename tfn;
	write_file(tfn.tmpfile, FILE_DATA, (sizeof(FILE_DATA) - 1));
	
	FileReader fr(tfn.tmpfile);
	
	char buf[1024];
	size_t read_count;
	
	bool result = fr.read_tlv([&](const FourCC &type, uint32_t length)
	{
		EXPECT_EQ(type, "A123");
		EXPECT_EQ(length, 15U);
		
		read_count = fr.read(buf, 1024, 0);
	});
	
	ASSERT_TRUE(result);
	EXPECT_EQ(read_count, 15U);
	EXPECT_EQ(std::string(buf, read_count), std::string("jolly breakable"));
	
	result = fr.read_tlv([&](const FourCC &type, uint32_t length)
	{
		EXPECT_EQ(type, "B456");
		EXPECT_EQ(length, 10U);
		
		read_count = fr.read(buf, 1024, 0);
	});
	
	ASSERT_TRUE(result);
	EXPECT_EQ(read_count, 10U);
	EXPECT_EQ(std::string(buf, read_count), std::string("tricky van"));
	
	result = fr.read_tlv([&](const FourCC &type, uint32_t length)
	{
		FAIL() << "This function should not be called";
	});
	
	EXPECT_FALSE(result);
}

TEST(FileReader, ReadNestedTLV)
{
	char FILE_DATA[] =
		"ZZZZ" "\x29\x00\x00\x00"
			"A123" "\x0F\x00\x00\x00" "jolly breakable"
			"B456" "\x0A\x00\x00\x00" "tricky van";
	
	TempFilename tfn;
	write_file(tfn.tmpfile, FILE_DATA, (sizeof(FILE_DATA) - 1));
	
	FileReader fr(tfn.tmpfile);
	
	char buf1[1024], buf2[1024];
	size_t read_count1, read_count2;
	bool result0, result1, result2, result3, result4;
	
	result0 = fr.read_tlv([&](const FourCC &type, uint32_t length)
	{
		result1 = fr.read_tlv([&](const FourCC &type, uint32_t length)
		{
			EXPECT_EQ(type, "A123");
			EXPECT_EQ(length, 15U);
			
			read_count1 = fr.read(buf1, 1024, 0);
		});
		
		result2 = fr.read_tlv([&](const FourCC &type, uint32_t length)
		{
			EXPECT_EQ(type, "B456");
			EXPECT_EQ(length, 10U);
			
			read_count2 = fr.read(buf2, 1024, 0);
		});
		
		result3 = fr.read_tlv([&](const FourCC &type, uint32_t length)
		{
			FAIL() << "This function should not be called";
		});
	});
	
	result4 = fr.read_tlv([&](const FourCC &type, uint32_t length)
	{
		FAIL() << "This function should not be called";
	});
	
	ASSERT_TRUE(result0);
	
	ASSERT_TRUE(result1);
	EXPECT_EQ(read_count1, 15U);
	EXPECT_EQ(std::string(buf1, read_count1), std::string("jolly breakable"));
	
	ASSERT_TRUE(result2);
	EXPECT_EQ(read_count2, 10U);
	EXPECT_EQ(std::string(buf2, read_count2), std::string("tricky van"));
	
	EXPECT_FALSE(result3);
	
	EXPECT_FALSE(result4);
}

TEST(FileReader, ReadTruncatedTLVHeader)
{
	char FILE_DATA[] =
		"A123" "\x0F\x00\x00\x00" "jolly breakable"
		"B456" "\x0A\x00\x00";
	
	TempFilename tfn;
	write_file(tfn.tmpfile, FILE_DATA, (sizeof(FILE_DATA) - 1));
	
	FileReader fr(tfn.tmpfile);
	
	char buf[1024];
	size_t read_count;
	
	bool result = fr.read_tlv([&](const FourCC &type, uint32_t length)
	{
		EXPECT_EQ(type, "A123");
		EXPECT_EQ(length, 15U);
		
		read_count = fr.read(buf, 1024, 0);
	});
	
	ASSERT_TRUE(result);
	EXPECT_EQ(read_count, 15U);
	EXPECT_EQ(std::string(buf, read_count), std::string("jolly breakable"));
	
	EXPECT_THROW(fr.read_tlv([&](const FourCC &type, uint32_t length) { FAIL() << "This function should not be called"; }), FileReader::eof_error);
}

TEST(FileReader, ReadTruncatedTLVData)
{
	char FILE_DATA[] =
		"A123" "\x0F\x00\x00\x00" "jolly breakable"
		"B456" "\x0A\x00\x00\x00" "tricky va";
	
	TempFilename tfn;
	write_file(tfn.tmpfile, FILE_DATA, (sizeof(FILE_DATA) - 1));
	
	FileReader fr(tfn.tmpfile);
	
	char buf[1024];
	size_t read_count;
	
	bool result = fr.read_tlv([&](const FourCC &type, uint32_t length)
	{
		EXPECT_EQ(type, "A123");
		EXPECT_EQ(length, 15U);
		
		read_count = fr.read(buf, 1024, 0);
	});
	
	ASSERT_TRUE(result);
	EXPECT_EQ(read_count, 15U);
	EXPECT_EQ(std::string(buf, read_count), std::string("jolly breakable"));
	
	EXPECT_THROW(fr.read_tlv([&](const FourCC &type, uint32_t length) { fr.read(buf, length, length); }), FileReader::eof_error);
}

TEST(FileReader, ReadTruncatedNestedTLVHeader)
{
	char FILE_DATA[] =
		"ZZZZ" "\x1E\x00\x00\x00"
		"A123" "\x0F\x00\x00\x00" "jolly breakable"
		"B456" "\x0A\x00\x00"
		"ZZZZ" "\x00\x00\x00\x00";

	TempFilename tfn;
	write_file(tfn.tmpfile, FILE_DATA, (sizeof(FILE_DATA) - 1));

	FileReader fr(tfn.tmpfile);

	char buf1[1024];
	size_t read_count1;
	bool result0, result1;

	result0 = fr.read_tlv([&](const FourCC &type, uint32_t length)
	{
		result1 = fr.read_tlv([&](const FourCC &type, uint32_t length)
		{
			EXPECT_EQ(type, "A123");
			EXPECT_EQ(length, 15U);

			read_count1 = fr.read(buf1, 1024, 0);
		});

		EXPECT_THROW({ fr.read_tlv([&](const FourCC &type, uint32_t length) { FAIL() << "This function should not be called"; }); }, FileReader::eof_error);
	});

	ASSERT_TRUE(result0);

	ASSERT_TRUE(result1);
	EXPECT_EQ(read_count1, 15U);
	EXPECT_EQ(std::string(buf1, read_count1), std::string("jolly breakable"));
}

TEST(FileReader, ReadJSON)
{
	const char *JSON = "{ \"foo\": \"bar\", \"baz\": [ 1, 2, 3 ] }";
	
	TempFilename tfn;
	write_file(tfn.tmpfile, JSON, strlen(JSON));
	
	FileReader fr(tfn.tmpfile);

	EXPECT_EQ(AutoJSON(JSON), AutoJSON(fr.read_json().release()));
}

TEST(FileReader, ReadJSONMultiple)
{
	const char *JSON1 = "{ \"foo\": \"bar\", \"baz\": [ 1, 2, 3 ] }";
	const char *JSON2 = "{ \"foo\": \"bar\", \"baz\": [ 4, 5, 6 ] }";
	const char *JSON3 = "{ \"foo\": \"bar\", \"baz\": [ 7, 8, 9 ] }";
	
	char ALL_JSON[256];
	snprintf(ALL_JSON, sizeof(ALL_JSON), "%s%s%s", JSON1, JSON2, JSON3);

	TempFilename tfn;
	write_file(tfn.tmpfile, ALL_JSON, strlen(ALL_JSON));
	
	FileReader fr(tfn.tmpfile);

	EXPECT_EQ(AutoJSON(JSON1), AutoJSON(fr.read_json(true).release()));
	EXPECT_EQ(AutoJSON(JSON2), AutoJSON(fr.read_json(true).release()));
	EXPECT_EQ(AutoJSON(JSON3), AutoJSON(fr.read_json(true).release()));
}

TEST(FileReader, ReadBadJSON)
{
	const char *JSON = "{ \"foo\" }";
	
	TempFilename tfn;
	write_file(tfn.tmpfile, JSON, strlen(JSON));
	
	FileReader fr(tfn.tmpfile);

	EXPECT_THROW({ fr.read_json(); }, std::runtime_error);
}
