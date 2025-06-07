/* Reverse Engineer's Hex Editor
 * Copyright (C) 2019-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <wx/frame.h>

#include "../src/document.hpp"
#include "../src/search.hpp"
#include "../src/SharedDocumentPointer.hpp"

/* This MUST come after the wxWidgets headers have been included, else we pull in windows.h BEFORE the wxWidgets
 * headers when building on Windows and this causes unicode-flavoured pointer conversion errors.
*/
#include <portable_endian.h>

/* These wrappers are needed to compile on OS X, as passing a signed constant to the native byte
 * swapping stuff compiles to an out-of-range value.
*/
static int16_t htole16s(int16_t h) { return htole16(h); }
static int16_t htobe16s(int16_t h) { return htobe16(h); }
static int32_t htole32s(int32_t h) { return htole32(h); }
static int32_t htobe32s(int32_t h) { return htobe32(h); }
static int64_t htole64s(int64_t h) { return htole64(h); }
static int64_t htobe64s(int64_t h) { return htobe64(h); }

TEST(SearchValue, SearchForU8)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("100", REHex::Search::Value::FMT_I8);
	
	{
		uint8_t check = 100;
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches correct value";
	}
	
	{
		uint8_t check = 101;
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match wrong value";
	}
	
	{
		struct { uint8_t u8; char pad[10]; } check = { 100 };
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches value with trailing data";
	}
	
	{
		struct { char pad[10]; uint8_t u8; } check = { {}, 100 };
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match value with leading data";
	}
}

TEST(SearchValue, SearchForS8)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("-100", REHex::Search::Value::FMT_I8);
	
	{
		int8_t check = -100;
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches correct value";
	}
	
	{
		int8_t check = -101;
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match wrong value";
	}
	
	{
		struct { int8_t u8; char pad[10]; } check = { -100 };
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches value with trailing data";
	}
	
	{
		struct { char pad[10]; int8_t u8; } check = { {}, -100 };
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match value with leading data";
	}
}

TEST(SearchValue, SearchForU16LE)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("50000", REHex::Search::Value::FMT_I16 | REHex::Search::Value::FMT_LE);
	
	{
		uint16_t check = htole16(50000);
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches correct value";
	}
	
	{
		struct { uint16_t u16; char pad[10]; } check = { htole16(50000) };
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches value with trailing data";
	}
	
	{
		struct { char pad[10]; uint16_t u16; } check = { {}, htole16(50000) };
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match value with leading data";
	}
	
	{
		uint16_t check = htole16(50001);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match wrong value";
	}
	
	{
		uint16_t check = htobe16(50001);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match big endian value";
	}
	
	s.configure("100", REHex::Search::Value::FMT_I16 | REHex::Search::Value::FMT_LE);
	
	{
		uint8_t check = 100;
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 8-bit value";
	}
}

TEST(SearchValue, SearchForS16LE)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("-2000", REHex::Search::Value::FMT_I16 | REHex::Search::Value::FMT_LE);
	
	{
		int16_t check = htole16s(-2000);
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches correct value";
	}
	
	{
		struct { int16_t u16; char pad[10]; } check = { htole16s(-2000) };
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches value with trailing data";
	}
	
	{
		struct { char pad[10]; int16_t u16; } check = { {}, htole16s(-2000) };
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match value with leading data";
	}
	
	{
		int16_t check = htole16s(-2001);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match wrong value";
	}
	
	{
		int16_t check = htobe16s(-2000);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match big endian value";
	}
	
	s.configure("-100", REHex::Search::Value::FMT_I16 | REHex::Search::Value::FMT_LE);
	
	{
		int8_t check = -100;
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 8-bit value";
	}
}

TEST(SearchValue, SearchForU16BE)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("50000", REHex::Search::Value::FMT_I16 | REHex::Search::Value::FMT_BE);
	
	{
		uint16_t check = htobe16(50000);
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches correct value";
	}
	
	{
		struct { uint16_t u16; char pad[10]; } check = { htobe16(50000) };
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches value with trailing data";
	}
	
	{
		struct { char pad[10]; uint16_t u16; } check = { {}, htobe16(50000) };
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match value with leading data";
	}
	
	{
		uint16_t check = htobe16(50001);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match wrong value";
	}
	
	{
		uint16_t check = htole16(50001);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match little endian value";
	}
	
	{
		uint32_t check = htobe32(50000);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 32-bit value";
	}
	
	{
		uint64_t check = htobe64(50000);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 64-bit value";
	}
	
	s.configure("100", REHex::Search::Value::FMT_I16 | REHex::Search::Value::FMT_BE);
	
	{
		uint8_t check = 100;
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 8-bit value";
	}
}

TEST(SearchValue, SearchForS16BE)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("-2000", REHex::Search::Value::FMT_I16 | REHex::Search::Value::FMT_BE);
	
	{
		int16_t check = htobe16s(-2000);
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches correct value";
	}
	
	{
		struct { int16_t u16; char pad[10]; } check = { htobe16s(-2000) };
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches value with trailing data";
	}
	
	{
		struct { char pad[10]; int16_t u16; } check = { {}, htobe16s(-2000) };
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match value with leading data";
	}
	
	{
		int16_t check = htobe16s(-2001);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match wrong value";
	}
	
	{
		int16_t check = htole16s(-2000);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match little endian value";
	}
	
	{
		int32_t check = htobe32s(-2000);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 32-bit value";
	}
	
	{
		int64_t check = htobe64s(-2000);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 64-bit value";
	}
	
	s.configure("-100", REHex::Search::Value::FMT_I16 | REHex::Search::Value::FMT_BE);
	
	{
		int8_t check = -100;
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 8-bit value";
	}
}

TEST(SearchValue, SearchForU16EE)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("1234", REHex::Search::Value::FMT_I16 | REHex::Search::Value::FMT_LE | REHex::Search::Value::FMT_BE);
	
	{
		uint16_t check = htole16(1234);
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches little endian value";
	}
	
	{
		uint16_t check = htobe16(1234);
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches big endian value";
	}
}

TEST(SearchValue, SearchForU32LE)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("4000000000", REHex::Search::Value::FMT_I32 | REHex::Search::Value::FMT_LE);
	
	{
		uint32_t check = htole32(4000000000);
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches correct value";
	}
	
	{
		struct { uint32_t u32; char pad[10]; } check = { htole32(4000000000) };
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches value with trailing data";
	}
	
	{
		struct { char pad[10]; uint32_t u32; } check = { {}, htole32(4000000000) };
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match value with leading data";
	}
	
	{
		uint32_t check = htole32(4000000001);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match wrong value";
	}
	
	{
		uint32_t check = htobe32(4000000001);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match big endian value";
	}
	
	s.configure("100", REHex::Search::Value::FMT_I32 | REHex::Search::Value::FMT_LE);
	
	{
		uint8_t check = 100;
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 8-bit value";
	}
	
	{
		uint16_t check = htole16(100);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 16-bit value";
	}
}

TEST(SearchValue, SearchForS32LE)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("-1000000000", REHex::Search::Value::FMT_I32 | REHex::Search::Value::FMT_LE);
	
	{
		int32_t check = htole32s(-1000000000);
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches correct value";
	}
	
	{
		struct { int32_t u32; char pad[10]; } check = { htole32s(-1000000000) };
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches value with trailing data";
	}
	
	{
		struct { char pad[10]; int32_t u32; } check = { {}, htole32s(-1000000000) };
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match value with leading data";
	}
	
	{
		int32_t check = htole32s(-1000000001);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match wrong value";
	}
	
	{
		int32_t check = htobe32s(-1000000000);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match big endian value";
	}
	
	s.configure("-100", REHex::Search::Value::FMT_I32 | REHex::Search::Value::FMT_LE);
	
	{
		int8_t check = -100;
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 8-bit value";
	}
	
	{
		int16_t check = htole16s(-100);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 16-bit value";
	}
}

TEST(SearchValue, SearchForU32BE)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("4000000000", REHex::Search::Value::FMT_I32 | REHex::Search::Value::FMT_BE);
	
	{
		uint32_t check = htobe32(4000000000);
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches correct value";
	}
	
	{
		struct { uint32_t u32; char pad[10]; } check = { htobe32(4000000000) };
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches value with trailing data";
	}
	
	{
		struct { char pad[10]; uint32_t u32; } check = { {}, htobe32(4000000000) };
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match value with leading data";
	}
	
	{
		uint32_t check = htobe32(4000000001);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match wrong value";
	}
	
	{
		uint32_t check = htole32(4000000001);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match little endian value";
	}
	
	{
		uint64_t check = htobe64(4000000000);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 64-bit value";
	}
	
	s.configure("100", REHex::Search::Value::FMT_I32 | REHex::Search::Value::FMT_BE);
	
	{
		uint8_t check = 100;
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 8-bit value";
	}
	
	{
		uint16_t check = htobe16(100);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 16-bit value";
	}
}

TEST(SearchValue, SearchForS32BE)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("-1000000000", REHex::Search::Value::FMT_I32 | REHex::Search::Value::FMT_BE);
	
	{
		int32_t check = htobe32s(-1000000000);
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches correct value";
	}
	
	{
		struct { int32_t u32; char pad[10]; } check = { htobe32s(-1000000000) };
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches value with trailing data";
	}
	
	{
		struct { char pad[10]; int32_t u32; } check = { {}, htobe32s(-1000000000) };
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match value with leading data";
	}
	
	{
		int32_t check = htobe32s(-1000000001);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match wrong value";
	}
	
	{
		int32_t check = htole32s(-1000000000);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match little endian value";
	}
	
	{
		int64_t check = htobe64s(-1000000000);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 64-bit value";
	}
	
	s.configure("-100", REHex::Search::Value::FMT_I32 | REHex::Search::Value::FMT_BE);
	
	{
		int8_t check = -100;
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 8-bit value";
	}
	
	{
		int16_t check = htobe16s(-100);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 16-bit value";
	}
}

TEST(SearchValue, SearchForU32EE)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("1234", REHex::Search::Value::FMT_I32 | REHex::Search::Value::FMT_LE | REHex::Search::Value::FMT_BE);
	
	{
		uint32_t check = htole32(1234);
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches little endian value";
	}
	
	{
		uint32_t check = htobe32(1234);
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches big endian value";
	}
}

TEST(SearchValue, SearchForU64LE)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("8000000000", REHex::Search::Value::FMT_I64 | REHex::Search::Value::FMT_LE);
	
	{
		uint64_t check = htole64(8000000000);
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches correct value";
	}
	
	{
		struct { uint64_t u64; char pad[10]; } check = { htole64(8000000000) };
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches value with trailing data";
	}
	
	{
		struct { char pad[10]; uint64_t u64; } check = { {}, htole64(8000000000) };
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match value with leading data";
	}
	
	{
		uint64_t check = htole64(8000000001);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match wrong value";
	}
	
	{
		uint64_t check = htobe64(8000000001);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match big endian value";
	}
	
	s.configure("100", REHex::Search::Value::FMT_I64 | REHex::Search::Value::FMT_LE);
	
	{
		uint8_t check = 100;
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 8-bit value";
	}
	
	{
		uint16_t check = htole16(100);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 16-bit value";
	}
	
	{
		uint32_t check = htole32(100);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 32-bit value";
	}
}

TEST(SearchValue, SearchForS64LE)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("-8000000000", REHex::Search::Value::FMT_I64 | REHex::Search::Value::FMT_LE);
	
	{
		int64_t check = htole64s(-8000000000);
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches correct value";
	}
	
	{
		struct { int64_t u64; char pad[10]; } check = { htole64s(-8000000000) };
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches value with trailing data";
	}
	
	{
		struct { char pad[10]; int64_t u64; } check = { {}, htole64s(-8000000000) };
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match value with leading data";
	}
	
	{
		int64_t check = htole64s(-8000000001);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match wrong value";
	}
	
	{
		int64_t check = htobe64s(-8000000000);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match big endian value";
	}
	
	s.configure("-100", REHex::Search::Value::FMT_I64 | REHex::Search::Value::FMT_LE);
	
	{
		int8_t check = -100;
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 8-bit value";
	}
	
	{
		int16_t check = htole16s(-100);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 16-bit value";
	}
	
	{
		int32_t check = htole32s(-100);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 32-bit value";
	}
}

TEST(SearchValue, SearchForU64BE)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("8000000000", REHex::Search::Value::FMT_I64 | REHex::Search::Value::FMT_BE);
	
	{
		uint64_t check = htobe64(8000000000);
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches correct value";
	}
	
	{
		struct { uint64_t u64; char pad[10]; } check = { htobe64(8000000000) };
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches value with trailing data";
	}
	
	{
		struct { char pad[10]; uint64_t u64; } check = { {}, htobe64(8000000000) };
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match value with leading data";
	}
	
	{
		uint64_t check = htobe64(8000000001);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match wrong value";
	}
	
	{
		uint64_t check = htole64(8000000001);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match little endian value";
	}
	
	s.configure("100", REHex::Search::Value::FMT_I64 | REHex::Search::Value::FMT_BE);
	
	{
		uint8_t check = 100;
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 8-bit value";
	}
	
	{
		uint16_t check = htobe16(100);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 16-bit value";
	}
	
	{
		uint32_t check = htobe32(100);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 32-bit value";
	}
}

TEST(SearchValue, SearchForS64BE)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("-8000000000", REHex::Search::Value::FMT_I64 | REHex::Search::Value::FMT_BE);
	
	{
		int64_t check = htobe64s(-8000000000);
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches correct value";
	}
	
	{
		struct { int64_t u64; char pad[10]; } check = { htobe64s(-8000000000) };
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches value with trailing data";
	}
	
	{
		struct { char pad[10]; int64_t u64; } check = { {}, htobe64s(-8000000000) };
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match value with leading data";
	}
	
	{
		int64_t check = htobe64s(-8000000001);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match wrong value";
	}
	
	{
		int64_t check = htole64s(-8000000000);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match little endian value";
	}
	
	s.configure("-100", REHex::Search::Value::FMT_I64 | REHex::Search::Value::FMT_BE);
	
	{
		int8_t check = -100;
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 8-bit value";
	}
	
	{
		int16_t check = htobe16s(-100);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 16-bit value";
	}
	
	{
		int32_t check = htobe32s(-100);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 32-bit value";
	}
}

TEST(SearchValue, SearchForU64EE)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("1234", REHex::Search::Value::FMT_I64 | REHex::Search::Value::FMT_LE | REHex::Search::Value::FMT_BE);
	
	{
		uint64_t check = htole64(1234);
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches little endian value";
	}
	
	{
		uint64_t check = htobe64(1234);
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches big endian value";
	}
}

TEST(SearchValue, SearchFor1664EE)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("123",
		REHex::Search::Value::FMT_I16 | REHex::Search::Value::FMT_I64 |
		REHex::Search::Value::FMT_LE | REHex::Search::Value::FMT_BE);
	
	{
		uint8_t check = 123;
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 8-bit value";
	}
	
	{
		uint16_t check = htole16(123);
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches 16-bit little endian value";
	}
	
	{
		uint32_t check = htobe32(123);
		EXPECT_FALSE(s.test(&check, sizeof(check))) << "Doesn't match 32-bit big endian value";
	}
	
	{
		uint64_t check = htobe64(123);
		EXPECT_TRUE(s.test(&check, sizeof(check))) << "Matches 64-bit big endian value";
	}
}

#define F32_1_POINT_4_LE 0x33, 0x33, 0xb3, 0x3f
#define F32_1_POINT_4_BE 0x3f, 0xb3, 0x33, 0x33
#define F32_1_POINT_5_LE 0x00, 0x00, 0xc0, 0x3f
#define F32_1_POINT_5_BE 0x3f, 0xc0, 0x00, 0x00
#define F32_2_POINT_0_LE 0x00, 0x00, 0x00, 0x40
#define F32_POS_INF_LE 0x00, 0x00, 0x80, 0x7f
#define F32_NEG_INF_LE 0x00, 0x00, 0x80, 0xff
#define F32_NAN1_LE 0x00, 0x00, 0xc0, 0xff
#define F32_NAN2_LE 0x00, 0x10, 0xc0, 0xff

TEST(SearchValue, SearchForF32LE)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("1.5", REHex::Search::Value::FMT_F32 | REHex::Search::Value::FMT_LE);
	
	{
		unsigned char check[] = { F32_1_POINT_5_LE };
		EXPECT_TRUE(s.test(check, sizeof(check))) << "Matches correct value";
	}
	
	{
		unsigned char check[] = { F32_1_POINT_5_LE, 0x00, 0x00, 0x00, 0x00 };
		EXPECT_TRUE(s.test(check, sizeof(check))) << "Matches value with trailing data";
	}
	
	{
		unsigned char check[] = { 0x00, 0x00, 0x00, 0x00, F32_1_POINT_5_LE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match value with leading data";
	}
	
	{
		unsigned char check[] = { F32_1_POINT_4_LE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match wrong value";
	}
	
	{
		unsigned char check[] = { F32_1_POINT_5_BE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match big endian value";
	}
	
	s.configure("1.5", REHex::Search::Value::FMT_F32 | REHex::Search::Value::FMT_LE, "0.25");
	
	{
		unsigned char check[] = { F32_1_POINT_4_LE };
		EXPECT_TRUE(s.test(check, sizeof(check))) << "Matches close value using epsilon";
	}
	
	{
		unsigned char check[] = { F32_2_POINT_0_LE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match an out-of-range value using epsilon";
	}
	
	{
		unsigned char check[] = { F32_NEG_INF_LE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match infinity";
	}
	
	{
		unsigned char check[] = { F32_NAN1_LE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match NaN";
	}
}

TEST(SearchValue, SearchForF32Infinity)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("inf", REHex::Search::Value::FMT_F32 | REHex::Search::Value::FMT_LE);
	
	{
		unsigned char check[] = { F32_POS_INF_LE };
		EXPECT_TRUE(s.test(check, sizeof(check))) << "Matches positive infinity";
	}
	
	{
		unsigned char check[] = { F32_NEG_INF_LE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match inf with -inf";
	}
	
	{
		unsigned char check[] = { F32_1_POINT_5_LE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match a number";
	}
	
	{
		unsigned char check[] = { F32_NAN1_LE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match NaN";
	}
	
	s.configure("-inf", REHex::Search::Value::FMT_F32 | REHex::Search::Value::FMT_LE);
	
	{
		unsigned char check[] = { F32_NEG_INF_LE };
		EXPECT_TRUE(s.test(check, sizeof(check))) << "Matches negative infinity";
	}
}

TEST(SearchValue, SearchForF32NaN)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("NaN", REHex::Search::Value::FMT_F32 | REHex::Search::Value::FMT_LE);
	
	{
		unsigned char check[] = { F32_NAN1_LE };
		EXPECT_TRUE(s.test(check, sizeof(check))) << "Matches NaN value";
	}
	
	{
		unsigned char check[] = { F32_NAN2_LE };
		EXPECT_TRUE(s.test(check, sizeof(check))) << "Matches NaN value";
	}
	
	{
		unsigned char check[] = { F32_POS_INF_LE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match infinity";
	}
	
	{
		unsigned char check[] = { F32_1_POINT_4_LE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match a number";
	}
}

TEST(SearchValue, SearchForF32BE)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("1.5", REHex::Search::Value::FMT_F32 | REHex::Search::Value::FMT_BE);
	
	{
		unsigned char check[] = { F32_1_POINT_5_BE };
		EXPECT_TRUE(s.test(check, sizeof(check))) << "Matches correct value";
	}
	
	{
		unsigned char check[] = { F32_1_POINT_5_BE, 0x00, 0x00, 0x00, 0x00 };
		EXPECT_TRUE(s.test(check, sizeof(check))) << "Matches value with trailing data";
	}
	
	{
		unsigned char check[] = { 0x00, 0x00, 0x00, 0x00, F32_1_POINT_5_BE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match value with leading data";
	}
	
	{
		unsigned char check[] = { F32_1_POINT_4_BE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match wrong value";
	}
	
	{
		unsigned char check[] = { F32_1_POINT_5_LE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match little endian value";
	}
}

TEST(SearchValue, SearchForF32EE)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("1.5", REHex::Search::Value::FMT_F32 | REHex::Search::Value::FMT_LE | REHex::Search::Value::FMT_BE);
	
	{
		unsigned char check[] = { F32_1_POINT_5_BE };
		EXPECT_TRUE(s.test(check, sizeof(check))) << "Matches big endian value";
	}
	
	{
		unsigned char check[] = { F32_1_POINT_5_LE };
		EXPECT_TRUE(s.test(check, sizeof(check))) << "Matches little endian value";
	}
	
	{
		unsigned char check[] = { F32_1_POINT_5_BE, 0x00, 0x00, 0x00, 0x00 };
		EXPECT_TRUE(s.test(check, sizeof(check))) << "Matches value with trailing data";
	}
	
	{
		unsigned char check[] = { 0x00, 0x00, 0x00, 0x00, F32_1_POINT_5_BE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match value with leading data";
	}
	
	{
		unsigned char check[] = { F32_1_POINT_4_BE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match wrong value";
	}
}

#define F64_1_POINT_4_LE 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0xf6, 0x3f
#define F64_1_POINT_4_BE 0x3f, 0xf6, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
#define F64_1_POINT_5_LE 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x3f
#define F64_1_POINT_5_BE 0x3f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define F64_2_POINT_0_LE 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40
#define F64_POS_INF_LE 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x7f
#define F64_NEG_INF_LE 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff
#define F64_NAN1_LE 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff
#define F64_NAN2_LE 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0xf8, 0xff

TEST(SearchValue, SearchForF64LE)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("1.5", REHex::Search::Value::FMT_F64 | REHex::Search::Value::FMT_LE);
	
	{
		unsigned char check[] = { F64_1_POINT_5_LE };
		EXPECT_TRUE(s.test(check, sizeof(check))) << "Matches correct value";
	}
	
	{
		unsigned char check[] = { F64_1_POINT_5_LE, 0x00, 0x00, 0x00, 0x00 };
		EXPECT_TRUE(s.test(check, sizeof(check))) << "Matches value with trailing data";
	}
	
	{
		unsigned char check[] = { 0x00, 0x00, 0x00, 0x00, F64_1_POINT_5_LE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match value with leading data";
	}
	
	{
		unsigned char check[] = { F64_1_POINT_4_LE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match wrong value";
	}
	
	{
		unsigned char check[] = { F64_1_POINT_5_BE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match big endian value";
	}
	
	s.configure("1.5", REHex::Search::Value::FMT_F64 | REHex::Search::Value::FMT_LE, "0.25");
	
	{
		unsigned char check[] = { F64_1_POINT_4_LE };
		EXPECT_TRUE(s.test(check, sizeof(check))) << "Matches close value using epsilon";
	}
	
	{
		unsigned char check[] = { F64_2_POINT_0_LE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match an out-of-range value using epsilon";
	}
	
	{
		unsigned char check[] = { F64_NEG_INF_LE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match infinity";
	}
	
	{
		unsigned char check[] = { F64_NAN1_LE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match NaN";
	}
}

TEST(SearchValue, SearchForF64Infinity)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("inf", REHex::Search::Value::FMT_F64 | REHex::Search::Value::FMT_LE);
	
	{
		unsigned char check[] = { F64_POS_INF_LE };
		EXPECT_TRUE(s.test(check, sizeof(check))) << "Matches positive infinity";
	}
	
	{
		unsigned char check[] = { F64_NEG_INF_LE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match inf with -inf";
	}
	
	{
		unsigned char check[] = { F64_1_POINT_5_LE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match a number";
	}
	
	{
		unsigned char check[] = { F64_NAN1_LE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match NaN";
	}
	
	s.configure("-inf", REHex::Search::Value::FMT_F64 | REHex::Search::Value::FMT_LE);
	
	{
		unsigned char check[] = { F64_NEG_INF_LE };
		EXPECT_TRUE(s.test(check, sizeof(check))) << "Matches negative infinity";
	}
}

TEST(SearchValue, SearchForF64NaN)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("NaN", REHex::Search::Value::FMT_F64 | REHex::Search::Value::FMT_LE);
	
	{
		unsigned char check[] = { F64_NAN1_LE };
		EXPECT_TRUE(s.test(check, sizeof(check))) << "Matches NaN value";
	}
	
	{
		unsigned char check[] = { F64_NAN2_LE };
		EXPECT_TRUE(s.test(check, sizeof(check))) << "Matches NaN value";
	}
	
	{
		unsigned char check[] = { F64_POS_INF_LE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match infinity";
	}
	
	{
		unsigned char check[] = { F64_1_POINT_4_LE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match a number";
	}
}

TEST(SearchValue, SearchForF64BE)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("1.5", REHex::Search::Value::FMT_F64 | REHex::Search::Value::FMT_BE);
	
	{
		unsigned char check[] = { F64_1_POINT_5_BE };
		EXPECT_TRUE(s.test(check, sizeof(check))) << "Matches correct value";
	}
	
	{
		unsigned char check[] = { F64_1_POINT_5_BE, 0x00, 0x00, 0x00, 0x00 };
		EXPECT_TRUE(s.test(check, sizeof(check))) << "Matches value with trailing data";
	}
	
	{
		unsigned char check[] = { 0x00, 0x00, 0x00, 0x00, F64_1_POINT_5_BE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match value with leading data";
	}
	
	{
		unsigned char check[] = { F64_1_POINT_4_BE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match wrong value";
	}
	
	{
		unsigned char check[] = { F64_1_POINT_5_LE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match little endian value";
	}
}

TEST(SearchValue, SearchForF64EE)
{
	wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
	REHex::SharedDocumentPointer doc(REHex::SharedDocumentPointer::make());
	
	REHex::Search::Value s(&frame, doc);
	s.configure("1.5", REHex::Search::Value::FMT_F64 | REHex::Search::Value::FMT_LE | REHex::Search::Value::FMT_BE);
	
	{
		unsigned char check[] = { F64_1_POINT_5_BE };
		EXPECT_TRUE(s.test(check, sizeof(check))) << "Matches big endian value";
	}
	
	{
		unsigned char check[] = { F64_1_POINT_5_LE };
		EXPECT_TRUE(s.test(check, sizeof(check))) << "Matches little endian value";
	}
	
	{
		unsigned char check[] = { F64_1_POINT_5_BE, 0x00, 0x00, 0x00, 0x00 };
		EXPECT_TRUE(s.test(check, sizeof(check))) << "Matches value with trailing data";
	}
	
	{
		unsigned char check[] = { 0x00, 0x00, 0x00, 0x00, F64_1_POINT_5_BE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match value with leading data";
	}
	
	{
		unsigned char check[] = { F64_1_POINT_4_BE };
		EXPECT_FALSE(s.test(check, sizeof(check))) << "Doesn't match wrong value";
	}
}
