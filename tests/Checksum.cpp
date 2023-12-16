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

#include "../src/platform.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <string.h>

#include "../src/Checksum.hpp"

using namespace REHex;

TEST(Checksum, MD5)
{
	/* MD5 reference checksums from Wikipedia */
	
	const ChecksumAlgorithm *md5_algo = ChecksumAlgorithm::by_name("MD5");
	ASSERT_NE(md5_algo, nullptr) << "MD5 algorithm is registered";
	
	{
		ChecksumGenerator *md5_gen = md5_algo->factory();
		
		md5_gen->add_data("The quick brown fox jumps over the lazy dog", strlen("The quick brown fox jumps over the lazy dog"));
		md5_gen->finish();
		
		EXPECT_STRCASEEQ(md5_gen->checksum_hex().c_str(), "9e107d9d372bb6826bd81d3542a419d6");
		
		md5_gen->reset();
		md5_gen->add_data("The quick brown fox jumps over the lazy dog", strlen("The quick brown fox jumps over the lazy dog"));
		md5_gen->finish();
		
		EXPECT_STRCASEEQ(md5_gen->checksum_hex().c_str(), "9e107d9d372bb6826bd81d3542a419d6");
	}
	
	{
		ChecksumGenerator *md5_gen = md5_algo->factory();
		
		md5_gen->add_data("The quick brown fox", strlen("The quick brown fox"));
		md5_gen->add_data(" jumps over the lazy dog", strlen(" jumps over the lazy dog"));
		md5_gen->finish();
		
		EXPECT_STRCASEEQ(md5_gen->checksum_hex().c_str(), "9e107d9d372bb6826bd81d3542a419d6");
	}
}

TEST(Checksum, SHA1)
{
	/* SHA-1 reference checksums from NIST */
	
	const ChecksumAlgorithm *sha1_algo = ChecksumAlgorithm::by_name("SHA-1");
	ASSERT_NE(sha1_algo, nullptr) << "SHA-1 algorithm is registered";
	
	{
		ChecksumGenerator *sha1_gen = sha1_algo->factory();
		
		sha1_gen->add_data("abc", strlen("abc"));
		sha1_gen->finish();
		
		EXPECT_STRCASEEQ(sha1_gen->checksum_hex().c_str(), "a9993e364706816aba3e25717850c26c9cd0d89d");
		
		sha1_gen->reset();
		sha1_gen->add_data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", strlen("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
		sha1_gen->finish();
		
		EXPECT_STRCASEEQ(sha1_gen->checksum_hex().c_str(), "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
	}
	
	{
		ChecksumGenerator *sha1_gen = sha1_algo->factory();
		
		sha1_gen->add_data("abcdbcdecdef", strlen("abcdbcdecdef"));
		sha1_gen->add_data("defgefghfghighi", strlen("defgefghfghighi"));
		sha1_gen->add_data("jhijkijkljklmklmnlmnomnopnop", strlen("jhijkijkljklmklmnlmnomnopnop"));
		sha1_gen->add_data("q", strlen("q"));
		sha1_gen->finish();
		
		EXPECT_STRCASEEQ(sha1_gen->checksum_hex().c_str(), "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
	}
}

TEST(Checksum, SHA224)
{
	/* SHA-224 reference checksums generated using GNU coreutils */
	
	const ChecksumAlgorithm *sha224_algo = ChecksumAlgorithm::by_name("SHA-224");
	ASSERT_NE(sha224_algo, nullptr) << "SHA-224 algorithm is registered";
	
	{
		ChecksumGenerator *sha224_gen = sha224_algo->factory();
		
		sha224_gen->add_data("The quick brown fox jumps over the lazy dog", strlen("The quick brown fox jumps over the lazy dog"));
		sha224_gen->finish();
		
		EXPECT_STRCASEEQ(sha224_gen->checksum_hex().c_str(), "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525");
		
		sha224_gen->reset();
		sha224_gen->add_data("The", strlen("The"));
		sha224_gen->finish();
		
		EXPECT_STRCASEEQ(sha224_gen->checksum_hex().c_str(), "4ca418aae2895663b98731f2b7fa5bef3bf3ea46ae6e1c6c6990288c");
	}
	
	{
		ChecksumGenerator *sha224_gen = sha224_algo->factory();
		
		sha224_gen->add_data("The quick brown fox jumps ", strlen("The quick brown fox jumps "));
		sha224_gen->add_data("over the lazy dog", strlen("over the lazy dog"));
		sha224_gen->finish();
		
		EXPECT_STRCASEEQ(sha224_gen->checksum_hex().c_str(), "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525");
	}
}

TEST(Checksum, SHA256)
{
	/* SHA-256 reference checksums generated using GNU coreutils */
	
	const ChecksumAlgorithm *sha256_algo = ChecksumAlgorithm::by_name("SHA-256");
	ASSERT_NE(sha256_algo, nullptr) << "SHA-256 algorithm is registered";
	
	{
		ChecksumGenerator *sha256_gen = sha256_algo->factory();
		
		sha256_gen->add_data("The quick brown fox jumps over the lazy dog", strlen("The quick brown fox jumps over the lazy dog"));
		sha256_gen->finish();
		
		EXPECT_STRCASEEQ(sha256_gen->checksum_hex().c_str(), "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
		
		sha256_gen->reset();
		sha256_gen->add_data("The", strlen("The"));
		sha256_gen->finish();
		
		EXPECT_STRCASEEQ(sha256_gen->checksum_hex().c_str(), "b344d80e24a3679999fa964450b34bc24d1578a35509f934c1418b0a20d21a67");
	}
	
	{
		ChecksumGenerator *sha256_gen = sha256_algo->factory();
		
		sha256_gen->add_data("The quick brown fox jumps ", strlen("The quick brown fox jumps "));
		sha256_gen->add_data("over the lazy dog", strlen("over the lazy dog"));
		sha256_gen->finish();
		
		EXPECT_STRCASEEQ(sha256_gen->checksum_hex().c_str(), "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
	}
}

TEST(Checksum, SHA384)
{
	/* SHA-384 reference checksums generated using GNU coreutils */
	
	const ChecksumAlgorithm *sha384_algo = ChecksumAlgorithm::by_name("SHA-384");
	ASSERT_NE(sha384_algo, nullptr) << "SHA-384 algorithm is registered";
	
	{
		ChecksumGenerator *sha384_gen = sha384_algo->factory();
		
		sha384_gen->add_data("The quick brown fox jumps over the lazy dog", strlen("The quick brown fox jumps over the lazy dog"));
		sha384_gen->finish();
		
		EXPECT_STRCASEEQ(sha384_gen->checksum_hex().c_str(), "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1");
		
		sha384_gen->reset();
		sha384_gen->add_data("The", strlen("The"));
		sha384_gen->finish();
		
		EXPECT_STRCASEEQ(sha384_gen->checksum_hex().c_str(), "549608d5e5f1ed4de18574ad672fdfe4e90adee52212900d6aa7dee0da385ad52fb01f4a7e3389a878abb06f179856cf");
	}
	
	{
		ChecksumGenerator *sha384_gen = sha384_algo->factory();
		
		sha384_gen->add_data("The quick brown fox jumps ", strlen("The quick brown fox jumps "));
		sha384_gen->add_data("over the lazy dog", strlen("over the lazy dog"));
		sha384_gen->finish();
		
		EXPECT_STRCASEEQ(sha384_gen->checksum_hex().c_str(), "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1");
	}
}

TEST(Checksum, SHA512)
{
	/* SHA-512 reference checksums generated using GNU coreutils */
	
	const ChecksumAlgorithm *sha512_algo = ChecksumAlgorithm::by_name("SHA-512");
	ASSERT_NE(sha512_algo, nullptr) << "SHA-512 algorithm is registered";
	
	{
		ChecksumGenerator *sha512_gen = sha512_algo->factory();
		
		sha512_gen->add_data("The quick brown fox jumps over the lazy dog", strlen("The quick brown fox jumps over the lazy dog"));
		sha512_gen->finish();
		
		EXPECT_STRCASEEQ(sha512_gen->checksum_hex().c_str(), "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6");
		
		sha512_gen->reset();
		sha512_gen->add_data("The", strlen("The"));
		sha512_gen->finish();
		
		EXPECT_STRCASEEQ(sha512_gen->checksum_hex().c_str(), "d1eb8fca18f1ed13c254f228435ba23ba203b42d6fb38bf84aaae54760a3964e671149b5d10317a0d3ecdcd0021053e6c596fb0b05c33214cfd5455d325ab53e");
	}
	
	{
		ChecksumGenerator *sha512_gen = sha512_algo->factory();
		
		sha512_gen->add_data("The quick brown fox jumps ", strlen("The quick brown fox jumps "));
		sha512_gen->add_data("over the lazy dog", strlen("over the lazy dog"));
		sha512_gen->finish();
		
		EXPECT_STRCASEEQ(sha512_gen->checksum_hex().c_str(), "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6");
	}
}

TEST(Checksum, CRC8)
{
	/* CRC reference checksums from CRCpp test suite */
	
	const ChecksumAlgorithm *crc_algo = ChecksumAlgorithm::by_name("CRC-8");
	ASSERT_NE(crc_algo, nullptr) << "CRC-8 algorithm is registered";
	
	{
		ChecksumGenerator *crc_gen = crc_algo->factory();
		
		crc_gen->add_data("123456789", strlen("123456789"));
		crc_gen->finish();
		
		EXPECT_STRCASEEQ(crc_gen->checksum_hex().c_str(), "F4");
		
		crc_gen->reset();
		crc_gen->add_data("The", strlen("The"));
		crc_gen->finish();
		
		EXPECT_STRCASENE(crc_gen->checksum_hex().c_str(), "F4");
		
		crc_gen->reset();
		crc_gen->add_data("123456789", strlen("123456789"));
		crc_gen->finish();
		
		EXPECT_STRCASEEQ(crc_gen->checksum_hex().c_str(), "F4");
	}
	
	{
		ChecksumGenerator *crc_gen = crc_algo->factory();
		
		crc_gen->add_data("123456", strlen("123456"));
		crc_gen->add_data("789", strlen("789"));
		crc_gen->finish();
		
		EXPECT_STRCASEEQ(crc_gen->checksum_hex().c_str(), "F4");
	}
}

TEST(Checksum, CRC32)
{
	/* CRC reference checksums from CRCpp test suite */
	
	const ChecksumAlgorithm *crc_algo = ChecksumAlgorithm::by_name("CRC-32");
	ASSERT_NE(crc_algo, nullptr) << "CRC-32 algorithm is registered";
	
	{
		ChecksumGenerator *crc_gen = crc_algo->factory();
		
		crc_gen->add_data("123456789", strlen("123456789"));
		crc_gen->finish();
		
		EXPECT_STRCASEEQ(crc_gen->checksum_hex().c_str(), "CBF43926");
		
		crc_gen->reset();
		crc_gen->add_data("The", strlen("The"));
		crc_gen->finish();
		
		EXPECT_STRCASENE(crc_gen->checksum_hex().c_str(), "CBF43926");
		
		crc_gen->reset();
		crc_gen->add_data("123456789", strlen("123456789"));
		crc_gen->finish();
		
		EXPECT_STRCASEEQ(crc_gen->checksum_hex().c_str(), "CBF43926");
	}
	
	{
		ChecksumGenerator *crc_gen = crc_algo->factory();
		
		crc_gen->add_data("12", strlen("12"));
		crc_gen->add_data("3456789", strlen("3456789"));
		crc_gen->finish();
		
		EXPECT_STRCASEEQ(crc_gen->checksum_hex().c_str(), "CBF43926");
	}
}

TEST(Checksum, Alder32)
{
	/* Adler32 reference checksums calculated/verified with some online calculators */
	
	const ChecksumAlgorithm *a32_algo = ChecksumAlgorithm::by_name("ADLER-32");
	ASSERT_NE(a32_algo, nullptr) << "Adler-32 algorithm is registered";
	
	{
		ChecksumGenerator *a32_gen = a32_algo->factory();
		
		a32_gen->add_data("test", strlen("test"));
		a32_gen->finish();
		
		EXPECT_STRCASEEQ(a32_gen->checksum_hex().c_str(), "045d01c1");
		
		a32_gen->reset();
		a32_gen->add_data("foo", strlen("foo"));
		a32_gen->finish();
		
		EXPECT_STRCASEEQ(a32_gen->checksum_hex().c_str(), "02820145");
	}
	
	{
		ChecksumGenerator *a32_gen = a32_algo->factory();
		
		a32_gen->add_data("The quick", strlen("The quick"));
		a32_gen->add_data(" brown fox", strlen(" brown fox"));
		a32_gen->add_data(" jumps over the lazy dog", strlen(" jumps over the lazy dog"));
		a32_gen->finish();
		
		EXPECT_STRCASEEQ(a32_gen->checksum_hex().c_str(), "5bdc0fda");
	}
}
