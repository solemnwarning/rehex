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
#include <stdexcept>
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
		EXPECT_EQ(ec.encoded_char(), std::string((const char*)(expect_encoded_char_d), sizeof(expect_encoded_char_d))) << desc; \
		EXPECT_EQ(ec.utf8_char(), std::string((const char*)(expect_utf8_char_d), sizeof(expect_utf8_char_d))) << desc; \
	}) << desc; \
}

#define TEST_INVALID_DECODE(input_data, desc) \
{ \
	unsigned char data[] = input_data; \
	EncodedCharacter ec = encoder.decode(data, sizeof(data)); \
	\
	EXPECT_FALSE(ec.valid) << desc; \
	\
	[&](){ EXPECT_THROW(ec.encoded_char(), std::logic_error) << desc; }(); \
	[&](){ EXPECT_THROW(ec.utf8_char(),    std::logic_error) << desc; }(); \
}

#define TEST_VALID_ENCODE(input_data, expect_encoded_char, expect_utf8_char, desc)\
{ \
	unsigned char data[] = input_data; \
	\
	unsigned char expect_encoded_char_d[] = expect_encoded_char; \
	unsigned char expect_utf8_char_d[] = expect_utf8_char; \
	\
	EXPECT_NO_THROW({ \
		EncodedCharacter ec = encoder.encode(std::string((const char*)(data), sizeof(data))); \
		\
		EXPECT_EQ(ec.encoded_char(), std::string((const char*)(expect_encoded_char_d), sizeof(expect_encoded_char_d))) << desc; \
		EXPECT_EQ(ec.utf8_char(), std::string((const char*)(expect_utf8_char_d), sizeof(expect_utf8_char_d))) << desc; \
	}) << desc; \
}

#define TEST_INVALID_ENCODE(input_data, desc) \
{ \
	unsigned char data[] = input_data; \
	EncodedCharacter ec = encoder.encode(std::string((const char*)(data), sizeof(data))); \
	\
	EXPECT_FALSE(ec.valid); \
	\
	[&](){ EXPECT_THROW(ec.encoded_char(), std::logic_error) << desc; }(); \
	[&](){ EXPECT_THROW(ec.utf8_char(),    std::logic_error) << desc; }(); \
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

TEST(CharacterEncoderASCII, Encode)
{
	CharacterEncoderASCII encoder;
	
	TEST_VALID_ENCODE( X( '\0' ), X( '\0' ), X( '\0' ), "Control characters are encoded" );
	TEST_VALID_ENCODE( X( '\n' ), X( '\n' ), X( '\n' ), "Control characters are encoded" );
	TEST_VALID_ENCODE( X( 0x7F ), X( 0x7F ), X( 0x7F ), "Control characters are encoded" ); /* DEL */
	
	TEST_VALID_ENCODE( X( 'A' ), X( 'A' ), X( 'A' ), "7-bit characters are encoded" );
	TEST_VALID_ENCODE( X( '9' ), X( '9' ), X( '9' ), "7-bit characters are encoded" );
	TEST_VALID_ENCODE( X( '#' ), X( '#' ), X( '#' ), "7-bit characters are encoded" );
	
	TEST_INVALID_ENCODE( X( 0x80 ), "8-bit characters are rejected" );
	TEST_INVALID_ENCODE( X( 0xFE ), "8-bit characters are rejected" );
	TEST_INVALID_ENCODE( X( 0xFF ), "8-bit characters are rejected" );
	
	TEST_VALID_ENCODE( X( '\r', '\n' ), X( '\r' ), X( '\r' ), "Trailing characters are ignored" );
	TEST_VALID_ENCODE( X( 'Z', 'X'   ), X( 'Z'  ), X( 'Z'  ), "Trailing characters are ignored" );
}

TEST(CharacterEncoder88591, Decode)
{
	CharacterEncoderIconv encoder("ISO-8859-1", 1, true);
	
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

TEST(CharacterEncoder88591, Encode)
{
	CharacterEncoderIconv encoder("ISO-8859-1", 1, true);
	
	TEST_VALID_ENCODE( X( '\0' ), X( '\0' ), X( '\0' ), "Control characters are encoded" );
	TEST_VALID_ENCODE( X( '\n' ), X( '\n' ), X( '\n' ), "Control characters are encoded" );
	TEST_VALID_ENCODE( X( 0x7F ), X( 0x7F ), X( 0x7F ), "Control characters are encoded" ); /* DEL */
	
	TEST_VALID_ENCODE( X( 'A' ), X( 'A' ), X( 'A' ), "7-bit characters are encoded" );
	TEST_VALID_ENCODE( X( '9' ), X( '9' ), X( '9' ), "7-bit characters are encoded" );
	TEST_VALID_ENCODE( X( '#' ), X( '#' ), X( '#' ), "7-bit characters are encoded" );
	
	TEST_VALID_ENCODE( X( 0xC2, 0xA0 ), X( 0xA0 ), X( 0xC2, 0xA0 ), "8-bit characters are encoded" ); /* NO-BREAK SPACE */
	TEST_VALID_ENCODE( X( 0xC2, 0xA3 ), X( 0xA3 ), X( 0xC2, 0xA3 ), "8-bit characters are encoded" ); /* POUND SIGN */
	TEST_VALID_ENCODE( X( 0xC3, 0xBF ), X( 0xFF ), X( 0xC3, 0xBF ), "8-bit characters are encoded" ); /* LATIN SMALL LETTER Y WITH DIAERESIS */
	
	TEST_VALID_ENCODE( X( '\r', '\n'      ), X( '\r' ), X( '\r'       ), "Trailing characters are ignored" );
	TEST_VALID_ENCODE( X( 'Z', 'X'        ), X( 'Z'  ), X( 'Z'        ), "Trailing characters are ignored" );
	TEST_VALID_ENCODE( X( 0xC2, 0xA1, '!' ), X( 0xA1 ), X( 0xC2, 0xA1 ), "Trailing characters are ignored" );
}

TEST(CharacterEncoderUTF8, Decode)
{
	CharacterEncoderIconv encoder("UTF-8", 1, true);
	
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

TEST(CharacterEncoderUTF8, Encode)
{
	CharacterEncoderIconv encoder("UTF-8", 1, true);
	
	TEST_VALID_ENCODE( X( '\0' ), X( '\0' ), X( '\0' ), "Control characters are encoded" );
	TEST_VALID_ENCODE( X( '\n' ), X( '\n' ), X( '\n' ), "Control characters are encoded" );
	TEST_VALID_ENCODE( X( 0x7F ), X( 0x7F ), X( 0x7F ), "Control characters are encoded" ); /* DEL */
	
	TEST_VALID_ENCODE( X( 'A' ), X( 'A' ), X( 'A' ), "7-bit characters are encoded" );
	TEST_VALID_ENCODE( X( '9' ), X( '9' ), X( '9' ), "7-bit characters are encoded" );
	TEST_VALID_ENCODE( X( '#' ), X( '#' ), X( '#' ), "7-bit characters are encoded" );
	
	TEST_VALID_ENCODE( X( 0xC2, 0x80             ), X( 0xC2, 0x80             ), X( 0xC2, 0x80             ), "2 byte codepoints are encoded" );
	TEST_VALID_ENCODE( X( 0xDF, 0xBF             ), X( 0xDF, 0xBF             ), X( 0xDF, 0xBF             ), "2 byte codepoints are encoded" );
	TEST_VALID_ENCODE( X( 0xE0, 0xA0, 0x80       ), X( 0xE0, 0xA0, 0x80       ), X( 0xE0, 0xA0, 0x80       ), "3 byte codepoints are encoded" );
	TEST_VALID_ENCODE( X( 0xEF, 0xBF, 0xBF       ), X( 0xEF, 0xBF, 0xBF       ), X( 0xEF, 0xBF, 0xBF       ), "3 byte codepoints are encoded" );
	TEST_VALID_ENCODE( X( 0xF0, 0x90, 0x80, 0x80 ), X( 0xF0, 0x90, 0x80, 0x80 ), X( 0xF0, 0x90, 0x80, 0x80 ), "4 byte codepoints are encoded" );
	TEST_VALID_ENCODE( X( 0xF0, 0xA0, 0x80, 0x80 ), X( 0xF0, 0xA0, 0x80, 0x80 ), X( 0xF0, 0xA0, 0x80, 0x80 ), "4 byte codepoints are encoded" );
	
	TEST_INVALID_ENCODE( X( 0x80, 0xC2             ), "misaligned 2 byte codepoints are rejected" );
	TEST_INVALID_ENCODE( X( 0xBF, 0xDF             ), "misaligned 2 byte codepoints are rejected" );
	TEST_INVALID_ENCODE( X( 0xA0, 0x80, 0xE0       ), "misaligned 3 byte codepoints are rejected" );
	TEST_INVALID_ENCODE( X( 0xBF, 0xEF, 0xBF       ), "misaligned 3 byte codepoints are rejected" );
	TEST_INVALID_ENCODE( X( 0x80, 0x80, 0xF0, 0x90 ), "misaligned 4 byte codepoints are rejected" );
	TEST_INVALID_ENCODE( X( 0x80, 0xF0, 0xA0, 0x80 ), "misaligned 4 byte codepoints are rejected" );
	
	TEST_VALID_ENCODE( X( '\r', '\n'                  ), X( '\r'                   ), X( '\r'                   ), "Trailing characters are ignored" );
	TEST_VALID_ENCODE( X( 'Z', 'X'                    ), X( 'Z'                    ), X( 'Z'                    ), "Trailing characters are ignored" );
	TEST_VALID_ENCODE( X( 0xC2, 0x80, 'Q'             ), X( 0xC2, 0x80             ), X( 0xC2, 0x80             ), "Trailing characters are ignored" );
	TEST_VALID_ENCODE( X( 0xEF, 0xBF, 0xBF, '0'       ), X( 0xEF, 0xBF, 0xBF       ), X( 0xEF, 0xBF, 0xBF       ), "Trailing characters are ignored" );
	TEST_VALID_ENCODE( X( 0xF0, 0xA0, 0x80, 0x80, 'A' ), X( 0xF0, 0xA0, 0x80, 0x80 ), X( 0xF0, 0xA0, 0x80, 0x80 ), "Trailing characters are ignored" );
	
	TEST_INVALID_ENCODE( X( 0xC0, 0xAF                         ), "Overlong sequences are rejected" );
	TEST_INVALID_ENCODE( X( 0xE0, 0x80, 0xAF                   ), "Overlong sequences are rejected" );
	TEST_INVALID_ENCODE( X( 0xF0, 0x80, 0x80, 0xAF             ), "Overlong sequences are rejected" );
	TEST_INVALID_ENCODE( X( 0xF8, 0x80, 0x80, 0xAF             ), "Overlong sequences are rejected" );
	TEST_INVALID_ENCODE( X( 0xFC, 0x80, 0x80, 0x80, 0x80, 0xAF ), "Overlong sequences are rejected" );
}

TEST(CharacterEncoderUTF16LE, Decode)
{
	CharacterEncoderIconv encoder("UTF-16LE", 2, false);
	
	TEST_VALID_DECODE( X( '\0', 0x00 ), X( '\0', 0x00 ), X( '\0' ), "Control characters are decoded" );
	TEST_VALID_DECODE( X( '\n', 0x00 ), X( '\n', 0x00 ), X( '\n' ), "Control characters are decoded" );
	TEST_VALID_DECODE( X( 0x7F, 0x00 ), X( 0x7F, 0x00 ), X( 0x7F ), "Control characters are decoded" ); /* DEL */
	
	TEST_VALID_DECODE( X( 'A', 0x00 ), X( 'A', 0x00 ), X( 'A' ), "7-bit characters are decoded" );
	TEST_VALID_DECODE( X( '9', 0x00 ), X( '9', 0x00 ), X( '9' ), "7-bit characters are decoded" );
	TEST_VALID_DECODE( X( '#', 0x00 ), X( '#', 0x00 ), X( '#' ), "7-bit characters are decoded" );
	
	TEST_VALID_DECODE( X( 0xA3, 0x00             ), X( 0xA3, 0x00             ), X( 0xC2, 0xA3             ), "2 byte codepoints are decoded" );
	TEST_VALID_DECODE( X( 0xB0, 0x00             ), X( 0xB0, 0x00             ), X( 0xC2, 0xB0             ), "2 byte codepoints are decoded" );
	TEST_VALID_DECODE( X( 0x00, 0xD8, 0x00, 0xDC ), X( 0x00, 0xD8, 0x00, 0xDC ), X( 0xF0, 0x90, 0x80, 0x80 ), "4 byte codepoints are decoded" );
	TEST_VALID_DECODE( X( 0x40, 0xD8, 0x00, 0xDC ), X( 0x40, 0xD8, 0x00, 0xDC ), X( 0xF0, 0xA0, 0x80, 0x80 ), "4 byte codepoints are decoded" );
	
	TEST_VALID_DECODE( X( '\r', 0x00, '\n', 0x00            ), X( '\r', 0x00             ), X( '\r'                   ), "Trailing characters are ignored" );
	TEST_VALID_DECODE( X( 'Z',  0x00, 'X',  0x00            ), X( 'Z',  0x00             ), X( 'Z'                    ), "Trailing characters are ignored" );
	TEST_VALID_DECODE( X( 0xB0, 0x00, 'Q',  0x00            ), X( 0xB0, 0x00             ), X( 0xC2, 0xB0             ), "Trailing characters are ignored" );
	TEST_VALID_DECODE( X( 0x40, 0xD8, 0x00, 0xDC, 'A', 0x00 ), X( 0x40, 0xD8, 0x00, 0xDC ), X( 0xF0, 0xA0, 0x80, 0x80 ), "Trailing characters are ignored" );
}

TEST(CharacterEncoderUTF16LE, Encode)
{
	CharacterEncoderIconv encoder("UTF-16LE", 2, false);
	
	TEST_VALID_ENCODE( X( '\0' ), X( '\0', 0x00 ), X( '\0' ), "Control characters are encoded" );
	TEST_VALID_ENCODE( X( '\n' ), X( '\n', 0x00 ), X( '\n' ), "Control characters are encoded" );
	TEST_VALID_ENCODE( X( 0x7F ), X( 0x7F, 0x00 ), X( 0x7F ), "Control characters are encoded" ); /* DEL */
	
	TEST_VALID_ENCODE( X( 'A' ), X( 'A', 0x00 ), X( 'A' ), "7-bit characters are encoded" );
	TEST_VALID_ENCODE( X( '9' ), X( '9', 0x00 ), X( '9' ), "7-bit characters are encoded" );
	TEST_VALID_ENCODE( X( '#' ), X( '#', 0x00 ), X( '#' ), "7-bit characters are encoded" );
	
	TEST_VALID_ENCODE( X( 0xC2, 0xA3             ), X( 0xA3, 0x00             ), X( 0xC2, 0xA3             ), "2 byte codepoints are encoded" );
	TEST_VALID_ENCODE( X( 0xC2, 0xB0             ), X( 0xB0, 0x00             ), X( 0xC2, 0xB0             ), "2 byte codepoints are encoded" );
	TEST_VALID_ENCODE( X( 0xF0, 0x90, 0x80, 0x80 ), X( 0x00, 0xD8, 0x00, 0xDC ), X( 0xF0, 0x90, 0x80, 0x80 ), "4 byte codepoints are encoded" );
	TEST_VALID_ENCODE( X( 0xF0, 0xA0, 0x80, 0x80 ), X( 0x40, 0xD8, 0x00, 0xDC ), X( 0xF0, 0xA0, 0x80, 0x80 ), "4 byte codepoints are encoded" );
	
	TEST_VALID_ENCODE( X( '\r', '\n',                 ), X( '\r', 0x00             ), X( '\r'                   ), "Trailing characters are ignored" );
	TEST_VALID_ENCODE( X( 'Z',  'X',                  ), X( 'Z',  0x00             ), X( 'Z'                    ), "Trailing characters are ignored" );
	TEST_VALID_ENCODE( X( 0xC2, 0xB0, 'Q',            ), X( 0xB0, 0x00             ), X( 0xC2, 0xB0             ), "Trailing characters are ignored" );
	TEST_VALID_ENCODE( X( 0xF0, 0xA0, 0x80, 0x80, 'A' ), X( 0x40, 0xD8, 0x00, 0xDC ), X( 0xF0, 0xA0, 0x80, 0x80 ), "Trailing characters are ignored" );
}

TEST(CharacterEncoderUTF32BE, Decode)
{
	CharacterEncoderIconv encoder("UTF-32BE", 4, true);
	
	TEST_VALID_DECODE( X( 0x00, 0x00, 0x00, '\0' ), X( 0x00, 0x00, 0x00, '\0' ), X( '\0' ), "Control characters are decoded" );
	TEST_VALID_DECODE( X( 0x00, 0x00, 0x00, '\n' ), X( 0x00, 0x00, 0x00, '\n' ), X( '\n' ), "Control characters are decoded" );
	TEST_VALID_DECODE( X( 0x00, 0x00, 0x00, 0x7F ), X( 0x00, 0x00, 0x00, 0x7F ), X( 0x7F ), "Control characters are decoded" ); /* DEL */
	
	TEST_VALID_DECODE( X( 0x00, 0x00, 0x00, 'A' ), X( 0x00, 0x00, 0x00, 'A' ), X( 'A' ), "7-bit characters are decoded" );
	TEST_VALID_DECODE( X( 0x00, 0x00, 0x00, '9' ), X( 0x00, 0x00, 0x00, '9' ), X( '9' ), "7-bit characters are decoded" );
	TEST_VALID_DECODE( X( 0x00, 0x00, 0x00, '#' ), X( 0x00, 0x00, 0x00, '#' ), X( '#' ), "7-bit characters are decoded" );
	
	TEST_VALID_DECODE( X( 0x00, 0x00, 0x00, 0xA3 ), X( 0x00, 0x00, 0x00, 0xA3 ), X( 0xC2, 0xA3             ), "codepoints are decoded" );
	TEST_VALID_DECODE( X( 0x00, 0x00, 0x00, 0xB0 ), X( 0x00, 0x00, 0x00, 0xB0 ), X( 0xC2, 0xB0             ), "codepoints are decoded" );
	TEST_VALID_DECODE( X( 0x00, 0x01, 0x00, 0x00 ), X( 0x00, 0x01, 0x00, 0x00 ), X( 0xF0, 0x90, 0x80, 0x80 ), "codepoints are decoded" );
	TEST_VALID_DECODE( X( 0x00, 0x02, 0x00, 0x00 ), X( 0x00, 0x02, 0x00, 0x00 ), X( 0xF0, 0xA0, 0x80, 0x80 ), "codepoints are decoded" );
	
	TEST_VALID_DECODE( X( 0x00, 0x00, 0x00, '\r', 0x00, 0x00, 0x00, '\n' ), X( 0x00, 0x00, 0x00, '\r' ), X( '\r'                   ), "Trailing characters are ignored" );
	TEST_VALID_DECODE( X( 0x00, 0x00, 0x00, 'Z',  0x00, 0x00, 0x00, 'X', ), X( 0x00, 0x00, 0x00, 'Z'  ), X( 'Z'                    ), "Trailing characters are ignored" );
	TEST_VALID_DECODE( X( 0x00, 0x00, 0x00, 0xB0, 0x00, 0x00, 0x00, 'Q'  ), X( 0x00, 0x00, 0x00, 0xB0 ), X( 0xC2, 0xB0             ), "Trailing characters are ignored" );
	TEST_VALID_DECODE( X( 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 'A'  ), X( 0x00, 0x02, 0x00, 0x00 ), X( 0xF0, 0xA0, 0x80, 0x80 ), "Trailing characters are ignored" );
}

TEST(CharacterEncoderUTF32BE, Encode)
{
	CharacterEncoderIconv encoder("UTF-32BE", 4, true);
	
	TEST_VALID_ENCODE( X( '\0' ), X( 0x00, 0x00, 0x00, '\0' ), X( '\0' ), "Control characters are encoded" );
	TEST_VALID_ENCODE( X( '\n' ), X( 0x00, 0x00, 0x00, '\n' ), X( '\n' ), "Control characters are encoded" );
	TEST_VALID_ENCODE( X( 0x7F ), X( 0x00, 0x00, 0x00, 0x7F ), X( 0x7F ), "Control characters are encoded" ); /* DEL */
	
	TEST_VALID_ENCODE( X( 'A' ), X( 0x00, 0x00, 0x00, 'A' ), X( 'A' ), "7-bit characters are encoded" );
	TEST_VALID_ENCODE( X( '9' ), X( 0x00, 0x00, 0x00, '9' ), X( '9' ), "7-bit characters are encoded" );
	TEST_VALID_ENCODE( X( '#' ), X( 0x00, 0x00, 0x00, '#' ), X( '#' ), "7-bit characters are encoded" );
	
	TEST_VALID_ENCODE( X( 0xC2, 0xA3             ), X( 0x00, 0x00, 0x00, 0xA3 ), X( 0xC2, 0xA3             ), "codepoints are encoded" );
	TEST_VALID_ENCODE( X( 0xC2, 0xB0             ), X( 0x00, 0x00, 0x00, 0xB0 ), X( 0xC2, 0xB0             ), "codepoints are encoded" );
	TEST_VALID_ENCODE( X( 0xF0, 0x90, 0x80, 0x80 ), X( 0x00, 0x01, 0x00, 0x00 ), X( 0xF0, 0x90, 0x80, 0x80 ), "codepoints are encoded" );
	TEST_VALID_ENCODE( X( 0xF0, 0xA0, 0x80, 0x80 ), X( 0x00, 0x02, 0x00, 0x00 ), X( 0xF0, 0xA0, 0x80, 0x80 ), "codepoints are encoded" );
	
	TEST_VALID_ENCODE( X( '\r',                   '\n' ), X( 0x00, 0x00, 0x00, '\r' ), X( '\r'                   ), "Trailing characters are ignored" );
	TEST_VALID_ENCODE( X( 'Z',                    'X', ), X( 0x00, 0x00, 0x00, 'Z'  ), X( 'Z'                    ), "Trailing characters are ignored" );
	TEST_VALID_ENCODE( X( 0xC2, 0xB0,             'Q'  ), X( 0x00, 0x00, 0x00, 0xB0 ), X( 0xC2, 0xB0             ), "Trailing characters are ignored" );
	TEST_VALID_ENCODE( X( 0xF0, 0xA0, 0x80, 0x80, 'A'  ), X( 0x00, 0x02, 0x00, 0x00 ), X( 0xF0, 0xA0, 0x80, 0x80 ), "Trailing characters are ignored" );
}
