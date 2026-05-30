/* Reverse Engineer's Hex Editor
 * Copyright (C) 2023-2026 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <wx/filefn.h>

#include "../src/FileWriter.hpp"
#include "testutil.hpp"

using namespace REHex;

static std::string read_file(const char *filename)
{
	FILE *fh = fopen(filename, "rb");
	always_assert(fh);
	
	std::string data;
	
	unsigned char buf[1024];
	size_t len;
	while((len = fread(buf, 1, sizeof(buf), fh)) > 0)
	{
		data += std::string((const char*)(buf), len);
	}
	
	always_assert(!ferror(fh));
	
	fclose(fh);
	
	return data;
}

TEST(FileWriterTest, WriteFile)
{
	TempFilename tfn;
	
	{
		FileWriter fw(tfn.tmpfile);
		fw.write("hello world\n", 12);
		fw.write("foobar\n", 7);
		fw.commit();
	}
	
	EXPECT_EQ(read_file(tfn.tmpfile),
		"hello world\n"
		"foobar\n");
}

TEST(FileWriterTest, WriteFileNoCommit)
{
	TempFilename tfn;
	
	{
		FileWriter fw(tfn.tmpfile);
		fw.write("hello world\n", 12);
		fw.write("foobar\n", 7);
	}
	
	EXPECT_FALSE(wxFileExists(tfn.tmpfile)) << "FileWriter does not write file when destroyed without a call to commit()";
}

TEST(FileWriterTest, WriteTLV)
{
	TempFilename tfn;
	
	{
		FileWriter fw(tfn.tmpfile);
		fw.write("hello world\n", 12);
		
		fw.write_tlv("ABCD", [&]()
		{
			fw.write("foobar\n", 7);
			fw.write("foobaz\n", 7);
		});
		
		fw.write_tlv("XYZ ", [&]()
		{
			fw.write("second thing", 12);
		});
		
		fw.commit();
	}
	
	const char EXPECTED_DATA[] =
		"hello world\n"
		"ABCD" "\x0E\x00\x00\x00" "foobar\nfoobaz\n"
		"XYZ " "\x0C\x00\x00\x00" "second thing";
	
	EXPECT_EQ(read_file(tfn.tmpfile), std::string(EXPECTED_DATA, (sizeof(EXPECTED_DATA) - 1)));
}

TEST(FileWriterTest, WriteNestedTLV)
{
	TempFilename tfn;
	
	{
		FileWriter fw(tfn.tmpfile);
		fw.write("hello world\n", 12);
		
		fw.write_tlv("ABCD", [&]()
		{
			fw.write("foobar\n", 7);
			
			fw.write_tlv("XYZ ", [&]()
			{
				fw.write("second thing", 12);
			});
			
			fw.write("foobaz\n", 7);
		});
		
		fw.commit();
	}
	
	const char EXPECTED_DATA[] =
		"hello world\n"
		"ABCD" "\x22\x00\x00\x00"
			"foobar\n"
			"XYZ " "\x0C\x00\x00\x00" "second thing"
			"foobaz\n";
	
	EXPECT_EQ(read_file(tfn.tmpfile), std::string(EXPECTED_DATA, (sizeof(EXPECTED_DATA) - 1)));
}
