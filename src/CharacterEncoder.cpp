/* Reverse Engineer's Hex Editor
 * Copyright (C) 2021-2022 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "platform.hpp"

#include <assert.h>
#include <memory>
#include <stdexcept>
#include <stdio.h>
#include <string.h>

#include "App.hpp"
#include "CharacterEncoder.hpp"
#include "DataType.hpp"

std::map<std::string, const REHex::CharacterEncoding*> *REHex::CharacterEncoding::registrations = NULL;

REHex::CharacterEncoding::CharacterEncoding(const std::string &key, const std::string &label, const CharacterEncoder *encoder, const std::vector<std::string> &groups):
	key(key),
	groups(groups),
	label(label),
	encoder(encoder)
{
	if(registrations != NULL && registrations->find(key) != registrations->end())
	{
		throw std::runtime_error(std::string("A character encoding with key '") + key + "' is already registered");
	}
	
	if(registrations == NULL)
	{
		registrations = new std::map<std::string, const CharacterEncoding*>();
	}
	
	registrations->emplace(key, this);
}

REHex::CharacterEncoding::~CharacterEncoding()
{
	registrations->erase(key);
	
	if(registrations->empty())
	{
		delete registrations;
		registrations = NULL;
	}
}

const REHex::CharacterEncoding *REHex::CharacterEncoding::encoding_by_key(const std::string &key)
{
	if(registrations == NULL)
	{
		return NULL;
	}
	
	auto it = registrations->find(key);
	return it != registrations->end() ? it->second : NULL;
}

std::vector<const REHex::CharacterEncoding*> REHex::CharacterEncoding::all_encodings()
{
	if(registrations == NULL)
	{
		return std::vector<const CharacterEncoding*>(); /* Empty vector. */
	}
	
	std::vector<const CharacterEncoding*> sorted_registrations;
	sorted_registrations.reserve(registrations->size());
	
	for(auto r = registrations->begin(); r != registrations->end(); ++r)
	{
		sorted_registrations.push_back(r->second);
	}
	
	std::sort(sorted_registrations.begin(), sorted_registrations.end(),
		[](const CharacterEncoding *a, const CharacterEncoding *b)
		{
			if(a->groups != b->groups)
			{
				return a->groups < b->groups;
			}
			else{
				return a->label < b->label;
			}
		});
	
	return sorted_registrations;
}

REHex::CharacterEncoder::~CharacterEncoder() {}

REHex::EncodedCharacter REHex::CharacterEncoderASCII::decode(const void *data, size_t len) const
{
	if(len == 0)
	{
		/* Attempted to decode an empty buffer. */
		return EncodedCharacter();
	}
	
	unsigned char raw_char = *(const unsigned char*)(data);
	
	if(raw_char <= 0x7F)
	{
		return EncodedCharacter(std::string(1, raw_char), std::string(1, raw_char));
	}
	else{
		/* 8-bit character. */
		return EncodedCharacter();
	}
}

REHex::EncodedCharacter REHex::CharacterEncoderASCII::encode(const std::string &utf8_char) const
{
	if(utf8_char.size() >= 1 && utf8_char[0] >= 0 && utf8_char[0] <= 0x7F)
	{
		std::string first_byte = utf8_char.substr(0,1);
		return EncodedCharacter(first_byte, first_byte);
	}
	else{
		return EncodedCharacter();
	}
}

#if 0
REHex::CharacterEncoder8Bit::CharacterEncoder8Bit(const char *utf8_chars[])
{
	for(int i = 0; i < 256; ++i)
	{
		to_utf8[i] = utf8_chars[i];
		
		if(utf8_chars[i] != NULL)
		{
			from_utf8.emplace(utf8_chars[i], i);
		}
	}
}

REHex::EncodedCharacter REHex::CharacterEncoder8Bit::decode(const void *data, size_t len) const
{
	if(len == 0)
	{
		throw InvalidCharacter("Attempted to decode an empty buffer");
	}
	
	unsigned char raw_char = *(const unsigned char*)(data);
	
	if(to_utf8[raw_char] != NULL)
	{
		return EncodedCharacter(std::string((const char*)(&raw_char), 1), to_utf8[raw_char]);
	}
	else{
		char err[64];
		snprintf(err, sizeof(err), "Attempted to decode invalid 8-bit character 0x%02X", (unsigned int)(raw_char));
		
		throw InvalidCharacter(err);
	}
}

REHex::EncodedCharacter REHex::CharacterEncoder8Bit::encode(const std::string &utf8_char) const
{
	auto i = from_utf8.find(utf8_char);
	if(i != from_utf8.end())
	{
		return EncodedCharacter(std::string((const char*)&(i->second), 1), utf8_char);
	}
	else{
		char err[64];
		snprintf(err, sizeof(err), "Attempted to encode unrepresentable UTF-8 character %s", utf8_char.c_str());
		
		throw InvalidCharacter(err);
	}
}
#endif

REHex::CharacterEncoderIconv::CharacterEncoderIconv(const char *encoding, size_t word_size, bool mid_char_safe):
	CharacterEncoder(word_size, mid_char_safe),
	encoding(encoding)
{
	to_utf8 = iconv_open("UTF-8", encoding);
	if(to_utf8 == (iconv_t)(-1))
	{
		char err[128];
		snprintf(err, sizeof(err), "Unable to set up %s decoder: %s", encoding, strerror(errno));
		
		throw std::runtime_error(err);
	}
	
	from_utf8 = iconv_open(encoding, "UTF-8");
	if(from_utf8 == (iconv_t)(-1))
	{
		char err[128];
		snprintf(err, sizeof(err), "Unable to set up %s encoder: %s", encoding, strerror(errno));
		
		iconv_close(to_utf8);
		
		throw std::runtime_error(err);
	}
}

REHex::CharacterEncoderIconv::~CharacterEncoderIconv()
{
	iconv_close(from_utf8);
	iconv_close(to_utf8);
}

REHex::EncodedCharacter REHex::CharacterEncoderIconv::decode(const void *data, size_t len) const
{
	if(len == 0)
	{
		return EncodedCharacter();
	}
	
	len = std::min<size_t>(len, MAX_CHAR_SIZE);
	
	char data_copy[MAX_CHAR_SIZE];
	memcpy(data_copy, data, len);
	
	for(size_t clen = 1; clen <= len; ++clen)
	{
		char *inbuf = data_copy;
		size_t inbytesleft = clen;
		
		char utf8[MAX_CHAR_SIZE];
		char *outbuf = utf8;
		size_t outbytesleft = sizeof(utf8);
		
		std::lock_guard<std::mutex> lock_guard(to_utf8_lock);
		
		if(iconv(to_utf8, &inbuf, &inbytesleft, &outbuf, &outbytesleft) != (size_t)(-1))
		{
			return EncodedCharacter(std::string(data_copy, (inbuf - data_copy)), std::string(utf8, (outbuf - utf8)));
		}
	}
	
	return EncodedCharacter();
}

REHex::EncodedCharacter REHex::CharacterEncoderIconv::encode(const std::string &utf8_char) const
{
	char utf8_copy[MAX_CHAR_SIZE];
	memcpy(utf8_copy, utf8_char.data(), std::min<size_t>(utf8_char.size(), MAX_CHAR_SIZE));
	
	size_t utf8_copy_len = std::min<size_t>(utf8_char.size(), MAX_CHAR_SIZE);
	
	for(size_t clen = 1; clen <= utf8_copy_len; ++clen)
	{
		char *inbuf = utf8_copy;
		size_t inbytesleft = clen;
		
		char encoded[MAX_CHAR_SIZE];
		char *outbuf = encoded;
		size_t outbytesleft = sizeof(encoded);
		
		std::lock_guard<std::mutex> lock_guard(from_utf8_lock);
		
		if(iconv(from_utf8, &inbuf, &inbytesleft, &outbuf, &outbytesleft) != (size_t)(-1))
		{
			return EncodedCharacter(std::string(encoded, (outbuf - encoded)), std::string(utf8_copy, (inbuf - utf8_copy)));
		}
	}
	
	return EncodedCharacter();
}

/* CharacterEncoderIconv depends on the system iconv working and accepting whatever encoding it
 * was given at construction time. I don't want a missing iconv encoding causing the application
 * to crash or being silently ignored, so the IconvCharacterEncodingRegistrationHelper class
 * delays the registration of iconv-based character encodings until App::SetupPhase::EARLY and
 * logs errors to the app console.
*/

class IconvCharacterEncodingRegistrationHelper
{
	private:
		std::unique_ptr<REHex::CharacterEncoder> encoder;
		std::unique_ptr<REHex::DataTypeRegistration> dt_registration;
		std::unique_ptr<REHex::CharacterEncoding> ce_registration;
		
		REHex::App::SetupHookRegistration setup_hook;
		void deferred_init(const char *encoding, size_t word_size, bool mid_char_safe, const char *text_group, const char *key, const char *label);
		
	public:
		IconvCharacterEncodingRegistrationHelper(const char *encoding, size_t word_size, bool mid_char_safe, const char *text_group, const char *key, const char *label);
};

IconvCharacterEncodingRegistrationHelper::IconvCharacterEncodingRegistrationHelper(const char *encoding, size_t word_size, bool mid_char_safe, const char *text_group, const char *key, const char *label):
	setup_hook(REHex::App::SetupPhase::EARLY, [this, encoding, word_size, mid_char_safe, text_group, key, label]() { deferred_init(encoding, word_size, mid_char_safe, text_group, key, label); }) {}

void IconvCharacterEncodingRegistrationHelper::deferred_init(const char *encoding, size_t word_size, bool mid_char_safe, const char *text_group, const char *key, const char *label)
{
	try {
		encoder.reset(new REHex::CharacterEncoderIconv(encoding, word_size, mid_char_safe));
		dt_registration.reset(new REHex::DataTypeRegistration(std::string("text:") + key, label, std::vector<std::string>({"Text", text_group}), encoder.get()));
		ce_registration.reset(new REHex::CharacterEncoding(key, label, encoder.get(), std::vector<std::string>({ text_group })));
	}
	catch(const std::exception &e)
	{
		wxGetApp().printf_error("%s\n", e.what());
		wxGetApp().printf_error("Character encoding '%s' will not be available\n", label);
	}
}

const REHex::CharacterEncoderASCII REHex::ascii_encoder;
static REHex::CharacterEncoding ascii_encoding("ASCII", "US-ASCII (7-bit)", &REHex::ascii_encoder);

static REHex::CharacterEncoderIconv utf8_enc_impl("UTF-8", 1, true);
const REHex::CharacterEncoder *REHex::utf8_encoder = &utf8_enc_impl;

static IconvCharacterEncodingRegistrationHelper iso8859_1_r ("ISO-8859-1",  1, true, "8-bit code pages", "ISO-8859-1",  "Latin-1 (ISO-8859-1: Western European)");
static IconvCharacterEncodingRegistrationHelper iso8859_2_r ("ISO-8859-2",  1, true, "8-bit code pages", "ISO-8859-2",  "Latin-2 (ISO-8859-2: Central European)");
static IconvCharacterEncodingRegistrationHelper iso8859_3_r ("ISO-8859-3",  1, true, "8-bit code pages", "ISO-8859-3",  "Latin-3 (ISO-8859-3: South European and Esperanto)");
static IconvCharacterEncodingRegistrationHelper iso8859_4_r ("ISO-8859-4",  1, true, "8-bit code pages", "ISO-8859-4",  "Latin-4 (ISO-8859-4: Baltic, old)");
static IconvCharacterEncodingRegistrationHelper iso8859_5_r ("ISO-8859-5",  1, true, "8-bit code pages", "ISO-8859-5",  "Cyrillic (ISO-8859-5)");
static IconvCharacterEncodingRegistrationHelper iso8859_6_r ("ISO-8859-6",  1, true, "8-bit code pages", "ISO-8859-6",  "Arabic (ISO-8859-6)");
static IconvCharacterEncodingRegistrationHelper iso8859_7_r ("ISO-8859-7",  1, true, "8-bit code pages", "ISO-8859-7",  "Greek (ISO-8859-7)");
static IconvCharacterEncodingRegistrationHelper iso8859_8_r ("ISO-8859-8",  1, true, "8-bit code pages", "ISO-8859-8",  "Hebrew (ISO-8859-8)");
static IconvCharacterEncodingRegistrationHelper iso8859_9_r ("ISO-8859-9",  1, true, "8-bit code pages", "ISO-8859-9",  "Latin-5 (ISO-8859-9: Turkish)");
static IconvCharacterEncodingRegistrationHelper iso8859_10_r("ISO-8859-10", 1, true, "8-bit code pages", "ISO-8859-10", "Latin-6 (ISO-8859-10: Nordic)");
static IconvCharacterEncodingRegistrationHelper iso8859_11_r("ISO-8859-11", 1, true, "8-bit code pages", "ISO-8859-11", "Thai (ISO-8859-11, unofficial)");
static IconvCharacterEncodingRegistrationHelper iso8859_13_r("ISO-8859-13", 1, true, "8-bit code pages", "ISO-8859-13", "Latin-7 (ISO-8859-13: Baltic, new)");
static IconvCharacterEncodingRegistrationHelper iso8859_14_r("ISO-8859-14", 1, true, "8-bit code pages", "ISO-8859-14", "Latin-8 (ISO-8859-14: Celtic)");
static IconvCharacterEncodingRegistrationHelper iso8859_15_r("ISO-8859-15", 1, true, "8-bit code pages", "ISO-8859-15", "Latin-9 (ISO-8859-15: Revised Western European)");
static IconvCharacterEncodingRegistrationHelper cp437_r     ("CP437",       1, true, "8-bit code pages", "CP437",       "Code page 437 (IBM)");
static IconvCharacterEncodingRegistrationHelper cp866_r     ("CP866",       1, true, "8-bit code pages", "CP866",       "Code page 866 (IBM, \"DOS Cyrillic Russian\")");
static IconvCharacterEncodingRegistrationHelper cp1251_r    ("CP1251",      1, true, "8-bit code pages", "CP1251",      "Code page 1251 (Windows)");

static IconvCharacterEncodingRegistrationHelper cp932_r ("CP932", 1, false, "Multibyte code pages", "MSCP932", "Code page 932 (Windows, \"Shift JIS\")");
static IconvCharacterEncodingRegistrationHelper cp936_r ("CP936", 1, false, "Multibyte code pages", "MSCP936", "Code page 936 (Windows, \"GBK\")");
static IconvCharacterEncodingRegistrationHelper cp949_r ("CP949", 1, false, "Multibyte code pages", "MSCP949", "Code page 949 (Windows, \"UHC\")");
static IconvCharacterEncodingRegistrationHelper cp950_r ("CP950", 1, false, "Multibyte code pages", "MSCP950", "Code page 950 (Windows)");

static IconvCharacterEncodingRegistrationHelper utf8_r   ("UTF-8",    1,  true, "Unicode", "UTF-8",    "UTF-8");
static IconvCharacterEncodingRegistrationHelper utf16le_r("UTF-16LE", 2,  true, "Unicode", "UTF-16LE", "UTF-16LE (Little Endian)");
static IconvCharacterEncodingRegistrationHelper utf16be_r("UTF-16BE", 2,  true, "Unicode", "UTF-16BE", "UTF-16BE (Big Endian)");
static IconvCharacterEncodingRegistrationHelper utf32le_r("UTF-32LE", 4,  true, "Unicode", "UTF-32LE", "UTF-32LE (Little Endian)");
static IconvCharacterEncodingRegistrationHelper utf32be_r("UTF-32BE", 4,  true, "Unicode", "UTF-32BE", "UTF-32BE (Big Endian)");
