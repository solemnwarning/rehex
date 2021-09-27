/* Reverse Engineer's Hex Editor
 * Copyright (C) 2021 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "../src/CharacterEncoder.hpp"

using namespace REHex;

#define X(...) { __VA_ARGS__ }

#define TEST_VALID_DECODE(input_data, expect_encoded_char, expect_utf8_char, desc)\
{ \
	unsigned char data[] = input_data; \
	\
	unsigned char expect_encoded_char_d[] = expect_encoded_char; \
	unsigned char expect_utf8_char_d[] = expect_utf8_char; \
	\
	EXPECT_NO_THROW({ \
		EncodedCharacter ec = encoder.decode(data, sizeof(data)); \
		\
		EXPECT_EQ(ec.encoded_char, std::string((const char*)(expect_encoded_char_d), sizeof(expect_encoded_char_d))) << desc; \
		EXPECT_EQ(ec.utf8_char, std::string((const char*)(expect_utf8_char_d), sizeof(expect_utf8_char_d))) << desc; \
	}) << desc; \
}

#define TEST_INVALID_DECODE(input_data, desc) \
{ \
	unsigned char data[] = input_data; \
	\
	EXPECT_THROW({ \
		EncodedCharacter ec = encoder.decode(data, sizeof(data)); \
		\
		EXPECT_EQ(ec.encoded_char, std::string()) << desc; \
		EXPECT_EQ(ec.utf8_char, std::string()) << desc; \
	}, CharacterEncoder::InvalidCharacter) << desc; \
}

TEST(CharacterEncoderASCII, Decode)
{
	CharacterEncoderASCII encoder;
	
	TEST_VALID_DECODE( X( '\0' ), X( '\0' ), X( '\0' ), "Control characters are decoded" );
	TEST_VALID_DECODE( X( '\n' ), X( '\n' ), X( '\n' ), "Control characters are decoded" );
	TEST_VALID_DECODE( X( 0x7F ), X( 0x7F ), X( 0x7F ), "Control characters are decoded" ); /* DEL */
	
	TEST_VALID_DECODE( X( 'A' ), X( 'A' ), X( 'A' ), "7-bit characters are decoded" );
	TEST_VALID_DECODE( X( '9' ), X( '9' ), X( '9' ), "7-bit characters are decoded" );
	TEST_VALID_DECODE( X( '#' ), X( '#' ), X( '#' ), "7-bit characters are decoded" );
	
	TEST_INVALID_DECODE( X( 0x80 ), "8-bit characters are rejected" );
	TEST_INVALID_DECODE( X( 0xFE ), "8-bit characters are rejected" );
	TEST_INVALID_DECODE( X( 0xFF ), "8-bit characters are rejected" );
	
	TEST_VALID_DECODE( X( '\r', '\n' ), X( '\r' ), X( '\r' ), "Trailing characters are ignored" );
	TEST_VALID_DECODE( X( 'Z', 'X'   ), X( 'Z'  ), X( 'Z'  ), "Trailing characters are ignored" );
}

TEST(CharacterEncoder88591, Decode)
{
	CharacterEncoderIconv encoder("ISO-8859-1", 1);
	
	TEST_VALID_DECODE( X( '\0' ), X( '\0' ), X( '\0' ), "Control characters are decoded" );
	TEST_VALID_DECODE( X( '\n' ), X( '\n' ), X( '\n' ), "Control characters are decoded" );
	TEST_VALID_DECODE( X( 0x7F ), X( 0x7F ), X( 0x7F ), "Control characters are decoded" ); /* DEL */
	
	TEST_VALID_DECODE( X( 'A' ), X( 'A' ), X( 'A' ), "7-bit characters are decoded" );
	TEST_VALID_DECODE( X( '9' ), X( '9' ), X( '9' ), "7-bit characters are decoded" );
	TEST_VALID_DECODE( X( '#' ), X( '#' ), X( '#' ), "7-bit characters are decoded" );
	
	TEST_VALID_DECODE( X( 0xA0 ), X( 0xA0 ), X( 0xC2, 0xA0 ), "8-bit characters are decoded" ); /* NO-BREAK SPACE */
	TEST_VALID_DECODE( X( 0xA3 ), X( 0xA3 ), X( 0xC2, 0xA3 ), "8-bit characters are decoded" ); /* POUND SIGN */
	TEST_VALID_DECODE( X( 0xFF ), X( 0xFF ), X( 0xC3, 0xBF ), "8-bit characters are decoded" ); /* LATIN SMALL LETTER Y WITH DIAERESIS */
	
	TEST_VALID_DECODE( X( '\r', '\n' ), X( '\r' ), X( '\r'       ), "Trailing characters are ignored" );
	TEST_VALID_DECODE( X( 'Z', 'X'   ), X( 'Z'  ), X( 'Z'        ), "Trailing characters are ignored" );
	TEST_VALID_DECODE( X( 0xA1, '!'  ), X( 0xA1 ), X( 0xC2, 0xA1 ), "Trailing characters are ignored" );
}

TEST(CharacterEncoderUTF8, Decode)
{
	CharacterEncoderIconv encoder("UTF-8", 1);
	
	TEST_VALID_DECODE( X( '\0' ), X( '\0' ), X( '\0' ), "Control characters are decoded" );
	TEST_VALID_DECODE( X( '\n' ), X( '\n' ), X( '\n' ), "Control characters are decoded" );
	TEST_VALID_DECODE( X( 0x7F ), X( 0x7F ), X( 0x7F ), "Control characters are decoded" ); /* DEL */
	
	TEST_VALID_DECODE( X( 'A' ), X( 'A' ), X( 'A' ), "7-bit characters are decoded" );
	TEST_VALID_DECODE( X( '9' ), X( '9' ), X( '9' ), "7-bit characters are decoded" );
	TEST_VALID_DECODE( X( '#' ), X( '#' ), X( '#' ), "7-bit characters are decoded" );
	
	TEST_VALID_DECODE( X( 0xC2, 0x80             ), X( 0xC2, 0x80             ), X( 0xC2, 0x80             ), "2 byte codepoints are decoded" );
	TEST_VALID_DECODE( X( 0xDF, 0xBF             ), X( 0xDF, 0xBF             ), X( 0xDF, 0xBF             ), "2 byte codepoints are decoded" );
	TEST_VALID_DECODE( X( 0xE0, 0xA0, 0x80       ), X( 0xE0, 0xA0, 0x80       ), X( 0xE0, 0xA0, 0x80       ), "3 byte codepoints are decoded" );
	TEST_VALID_DECODE( X( 0xEF, 0xBF, 0xBF       ), X( 0xEF, 0xBF, 0xBF       ), X( 0xEF, 0xBF, 0xBF       ), "3 byte codepoints are decoded" );
	TEST_VALID_DECODE( X( 0xF0, 0x90, 0x80, 0x80 ), X( 0xF0, 0x90, 0x80, 0x80 ), X( 0xF0, 0x90, 0x80, 0x80 ), "4 byte codepoints are decoded" );
	TEST_VALID_DECODE( X( 0xF0, 0xA0, 0x80, 0x80 ), X( 0xF0, 0xA0, 0x80, 0x80 ), X( 0xF0, 0xA0, 0x80, 0x80 ), "4 byte codepoints are decoded" );
	
	TEST_INVALID_DECODE( X( 0x80, 0xC2             ), "misaligned 2 byte codepoints are rejected" );
	TEST_INVALID_DECODE( X( 0xBF, 0xDF             ), "misaligned 2 byte codepoints are rejected" );
	TEST_INVALID_DECODE( X( 0xA0, 0x80, 0xE0       ), "misaligned 3 byte codepoints are rejected" );
	TEST_INVALID_DECODE( X( 0xBF, 0xEF, 0xBF       ), "misaligned 3 byte codepoints are rejected" );
	TEST_INVALID_DECODE( X( 0x80, 0x80, 0xF0, 0x90 ), "misaligned 4 byte codepoints are rejected" );
	TEST_INVALID_DECODE( X( 0x80, 0xF0, 0xA0, 0x80 ), "misaligned 4 byte codepoints are rejected" );
	
	TEST_VALID_DECODE( X( '\r', '\n'                  ), X( '\r'                   ), X( '\r'                   ), "Trailing characters are ignored" );
	TEST_VALID_DECODE( X( 'Z', 'X'                    ), X( 'Z'                    ), X( 'Z'                    ), "Trailing characters are ignored" );
	TEST_VALID_DECODE( X( 0xC2, 0x80, 'Q'             ), X( 0xC2, 0x80             ), X( 0xC2, 0x80             ), "Trailing characters are ignored" );
	TEST_VALID_DECODE( X( 0xEF, 0xBF, 0xBF, '0'       ), X( 0xEF, 0xBF, 0xBF       ), X( 0xEF, 0xBF, 0xBF       ), "Trailing characters are ignored" );
	TEST_VALID_DECODE( X( 0xF0, 0xA0, 0x80, 0x80, 'A' ), X( 0xF0, 0xA0, 0x80, 0x80 ), X( 0xF0, 0xA0, 0x80, 0x80 ), "Trailing characters are ignored" );
	
	TEST_INVALID_DECODE( X( 0xC0, 0xAF                         ), "Overlong sequences are rejected" );
	TEST_INVALID_DECODE( X( 0xE0, 0x80, 0xAF                   ), "Overlong sequences are rejected" );
	TEST_INVALID_DECODE( X( 0xF0, 0x80, 0x80, 0xAF             ), "Overlong sequences are rejected" );
	TEST_INVALID_DECODE( X( 0xF8, 0x80, 0x80, 0xAF             ), "Overlong sequences are rejected" );
	TEST_INVALID_DECODE( X( 0xFC, 0x80, 0x80, 0x80, 0x80, 0xAF ), "Overlong sequences are rejected" );
}
