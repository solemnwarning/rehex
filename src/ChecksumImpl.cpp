/* Reverse Engineer's Hex Editor
 * Copyright (C) 2023 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <botan/build.h>
#include <botan/hash.h>
#include <botan/hex.h>
#include <inttypes.h>
#include <memory>
#include <stdint.h>
#include <string.h>

#if BOTAN_VERSION_MAJOR < 2
#include <botan/md5.h>
#include <botan/sha160.h>
#include <botan/sha2_32.h>
#include <botan/sha2_64.h>
#endif

#define CRCPP_USE_CPP11
#include <CRC.h>

#include "Checksum.hpp"

namespace REHex {
	template<typename CRCType, uint16_t CRCWidth> class ChecksumGeneratorCRC: public ChecksumGenerator
	{
		public:
			ChecksumGeneratorCRC(const CRC::Parameters<CRCType, CRCWidth> &parameters);
			virtual ~ChecksumGeneratorCRC() {}
			
			virtual void add_data(const void *data, size_t size) override;
			virtual void finish() override;
			
			virtual void reset() override;
			
			virtual std::string checksum_hex() const override;
			
		private:
			const CRC::Table<CRCType, CRCWidth> crc_table;
			CRCType crc;
	};
	
	class ChecksumGeneratorBotan: public ChecksumGenerator
	{
		public:
			#if BOTAN_VERSION_MAJOR < 2
			ChecksumGeneratorBotan(Botan::HashFunction *hash_function);
			#else
			ChecksumGeneratorBotan(const std::string &algo_name);
			#endif
			
			virtual ~ChecksumGeneratorBotan() {}
			
			virtual void add_data(const void *data, size_t size) override;
			virtual void finish() override;
			
			virtual void reset() override;
			
			virtual std::string checksum_hex() const override;
			
		private:
			std::unique_ptr<Botan::HashFunction> ctx;
			std::string hash_hex;
	};
	
	class ChecksumGeneratorAdler32: public ChecksumGenerator
	{
		public:
			ChecksumGeneratorAdler32();
			virtual ~ChecksumGeneratorAdler32() {}
			
			virtual void add_data(const void *data, size_t size) override;
			virtual void finish() override;
			
			virtual void reset() override;
			
			virtual std::string checksum_hex() const override;
			
		private:
			uint32_t a, b;
			char hash_hex[12];
	};
}

static REHex::ChecksumAlgorithm ALGOS[] = {
	#if BOTAN_VERSION_MAJOR < 2
	
	#ifdef BOTAN_HAS_MD5
	{ "MD5", "MD5", []() { return new REHex::ChecksumGeneratorBotan(new Botan::MD5()); } },
	#endif
	#ifdef BOTAN_HAS_SHA1
	{ "SHA-1", "SHA-1", []() { return new REHex::ChecksumGeneratorBotan(new Botan::SHA_160()); } },
	#endif
	#ifdef BOTAN_HAS_SHA2_32
	{ "SHA-224", "SHA-224", []() { return new REHex::ChecksumGeneratorBotan(new Botan::SHA_224()); } },
	{ "SHA-256", "SHA-256", []() { return new REHex::ChecksumGeneratorBotan(new Botan::SHA_256()); } },
	#endif
	#ifdef BOTAN_HAS_SHA2_64
	{ "SHA-384", "SHA-384", []() { return new REHex::ChecksumGeneratorBotan(new Botan::SHA_384()); } },
	{ "SHA-512", "SHA-512", []() { return new REHex::ChecksumGeneratorBotan(new Botan::SHA_512()); } },
	#endif
	
	#else
	
	#ifdef BOTAN_HAS_MD5
	{ "MD5", "MD5", []() { return new REHex::ChecksumGeneratorBotan("MD5"); } },
	#endif
	#ifdef BOTAN_HAS_SHA1
	{ "SHA-1", "SHA-1", []() { return new REHex::ChecksumGeneratorBotan("SHA-1"); } },
	#endif
	#ifdef BOTAN_HAS_SHA2_32
	{ "SHA-224", "SHA-224", []() { return new REHex::ChecksumGeneratorBotan("SHA-224"); } },
	{ "SHA-256", "SHA-256", []() { return new REHex::ChecksumGeneratorBotan("SHA-256"); } },
	#endif
	#ifdef BOTAN_HAS_SHA2_64
	{ "SHA-384", "SHA-384", []() { return new REHex::ChecksumGeneratorBotan("SHA-384"); } },
	{ "SHA-512", "SHA-512", []() { return new REHex::ChecksumGeneratorBotan("SHA-512"); } },
	#endif
	
	#endif
	
	{ "CRC-8",                 "CRC",  "CRC-8", []() { return new REHex::ChecksumGeneratorCRC<crcpp_uint8, 8>(CRC::CRC_8()); } },
	
	{ "CRC-16-ARC",            "CRC",  "CRC-16 ARC (aka CRC-16 IBM, CRC-16 LHA)",                         []() { return new REHex::ChecksumGeneratorCRC<crcpp_uint16, 16>(CRC::CRC_16_ARC()); } },
	{ "CRC-16-BUYPASS",        "CRC",  "CRC-16 BUYPASS (aka CRC-16 VERIFONE, CRC-16 UMTS)",               []() { return new REHex::ChecksumGeneratorCRC<crcpp_uint16, 16>(CRC::CRC_16_BUYPASS()); } },
	{ "CRC-16-CCITT-FALSE",    "CRC",  "CRC-16 CCITT FALSE",                                              []() { return new REHex::ChecksumGeneratorCRC<crcpp_uint16, 16>(CRC::CRC_16_CCITTFALSE()); } },
	{ "CRC-16-MCRF4XX",        "CRC",  "CRC-16 MCRF4XX",                                                  []() { return new REHex::ChecksumGeneratorCRC<crcpp_uint16, 16>(CRC::CRC_16_MCRF4XX()); } },
	{ "CRC-16-GENIBUS",        "CRC",  "CRC-16 GENIBUS (aka CRC-16 EPC, CRC-16 I-CODE, CRC-16 DARC)",     []() { return new REHex::ChecksumGeneratorCRC<crcpp_uint16, 16>(CRC::CRC_16_GENIBUS()); } },
	{ "CRC-16-KERMIT",         "CRC",  "CRC-16 KERMIT (aka CRC-16 CCITT, CRC-16 CCITT-TRUE)",             []() { return new REHex::ChecksumGeneratorCRC<crcpp_uint16, 16>(CRC::CRC_16_KERMIT()); } },
	{ "CRC-16-X-25",           "CRC",  "CRC-16 X-25 (aka CRC-16 IBM-SDLC, CRC-16 ISO-HDLC, CRC-16 B)",    []() { return new REHex::ChecksumGeneratorCRC<crcpp_uint16, 16>(CRC::CRC_16_X25()); } },
	{ "CRC-16 XMODEM",         "CRC",  "CRC-16 XMODEM (aka CRC-16 ZMODEM, CRC-16 ACORN, CRC-16 LTE)",     []() { return new REHex::ChecksumGeneratorCRC<crcpp_uint16, 16>(CRC::CRC_16_XMODEM()); } },
	
	{ "CRC-32",                "CRC",  "CRC-32 (aka CRC-32 ADCCP, CRC-32 PKZip)",                         []() { return new REHex::ChecksumGeneratorCRC<crcpp_uint32, 32>(CRC::CRC_32()); } },
	{ "CRC-32-BZIP2",          "CRC",  "CRC-32 BZIP2 (aka CRC-32 AAL5, CRC-32 DECT-B, CRC-32 B-CRC)",     []() { return new REHex::ChecksumGeneratorCRC<crcpp_uint32, 32>(CRC::CRC_32_BZIP2()); } },
	{ "CRC-32-MPEG-2",         "CRC",  "CRC-32 MPEG-2",                                                   []() { return new REHex::ChecksumGeneratorCRC<crcpp_uint32, 32>(CRC::CRC_32_MPEG2()); } },
	{ "CRC-32-POSIX",          "CRC",  "CRC-32 POSIX",                                                    []() { return new REHex::ChecksumGeneratorCRC<crcpp_uint32, 32>(CRC::CRC_32_POSIX()); } },
	
	{ "ADLER-32", "Adler-32", []() { return new REHex::ChecksumGeneratorAdler32(); } },
};

template<typename CRCType, uint16_t CRCWidth> REHex::ChecksumGeneratorCRC<CRCType, CRCWidth>::ChecksumGeneratorCRC(const CRC::Parameters<CRCType, CRCWidth> &parameters):
	crc_table(parameters)
{
	crc = CRC::Calculate(NULL, 0, crc_table);
}

template<typename CRCType, uint16_t CRCWidth> void REHex::ChecksumGeneratorCRC<CRCType, CRCWidth>::add_data(const void *data, size_t size)
{
	crc = CRC::Calculate(data, size, crc_table, crc);
}

template<typename CRCType, uint16_t CRCWidth> void REHex::ChecksumGeneratorCRC<CRCType, CRCWidth>::finish() {}

template<typename CRCType, uint16_t CRCWidth> void REHex::ChecksumGeneratorCRC<CRCType, CRCWidth>::reset()
{
	crc = CRC::Calculate(NULL, 0, crc_table);
}

template<typename CRCType, uint16_t CRCWidth> std::string REHex::ChecksumGeneratorCRC<CRCType, CRCWidth>::checksum_hex() const
{
	char hex[24];
	int hex_len = snprintf(hex, sizeof(hex), "%" PRIX64, (uint64_t)(crc));
	
	const int min_len = ((CRCWidth + 3) / 4);
	
	if(min_len > hex_len)
	{
		int pad_len = min_len - hex_len;
		
		memmove((hex + pad_len), hex, hex_len);
		memset(hex, '0', pad_len);
	}
	
	return std::string(hex);
}

#if BOTAN_VERSION_MAJOR < 2
REHex::ChecksumGeneratorBotan::ChecksumGeneratorBotan(Botan::HashFunction *hash_function):
	ctx(hash_function) {}
#else
REHex::ChecksumGeneratorBotan::ChecksumGeneratorBotan(const std::string &algo_name):
	ctx(Botan::HashFunction::create_or_throw(algo_name)) {}
#endif

void REHex::ChecksumGeneratorBotan::add_data(const void *data, size_t size)
{
	ctx->update((const uint8_t*)(data), size);
}

void REHex::ChecksumGeneratorBotan::finish()
{
	hash_hex = Botan::hex_encode(ctx->final());
}

void REHex::ChecksumGeneratorBotan::reset()
{
	ctx->clear();
	hash_hex.clear();
}

std::string REHex::ChecksumGeneratorBotan::checksum_hex() const
{
	return hash_hex;
}

/* "inefficient but straightforward" Adler-32 implementation taken from Wikipedia. */

REHex::ChecksumGeneratorAdler32::ChecksumGeneratorAdler32():
	a(1), b(0) {}

void REHex::ChecksumGeneratorAdler32::add_data(const void *data, size_t size)
{
	static const uint32_t MOD_ADLER = 65521;
	
	const unsigned char *d = (const unsigned char*)(data);
	
	for(size_t i = 0; i < size; ++i)
	{
		a = (a + d[i]) % MOD_ADLER;
		b = (b + a) % MOD_ADLER;
	}
}

void REHex::ChecksumGeneratorAdler32::finish()
{
	uint32_t c = (b << 16) | a;
	snprintf(hash_hex, sizeof(hash_hex), "%08" PRIX32, c);
}

void REHex::ChecksumGeneratorAdler32::reset()
{
	a = 1;
	b = 0;
}

std::string REHex::ChecksumGeneratorAdler32::checksum_hex() const
{
	return std::string(hash_hex);
}
