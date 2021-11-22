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

#ifndef REHEX_CHARACTERENCODER_HPP
#define REHEX_CHARACTERENCODER_HPP

#include <iconv.h>
#include <map>
#include <mutex>
#include <stdexcept>
#include <stdlib.h>
#include <string>
#include <vector>

namespace REHex
{
	/* 4 bytes should be enough for any character... so allow double that. */
	static const size_t MAX_CHAR_SIZE = 8;
	static const char * const DEFAULT_ENCODING = "ASCII";
	
	class EncodedCharacter
	{
		private:
			const std::string _encoded_char;
			const std::string _utf8_char;
			
		public:
			const bool valid;  /**< Character was encoded/decoded successfully. */
			
			/** Character encoded in chosen encoding (ISO-8859-1, Shift JIS, etc) */
			const std::string &encoded_char()
			{
				if(valid)
				{
					return _encoded_char;
				}
				else{
					throw std::logic_error("Attempted to read invalid EncodedCharacter::encoded_char");
				}
			}
			
			/** Character encoded in UTF-8 */
			const std::string &utf8_char()
			{
				if(valid)
				{
					return _utf8_char;
				}
				else{
					throw std::logic_error("Attempted to read invalid EncodedCharacter::utf8_char");
				}
			}
			
			EncodedCharacter(const std::string &encoded_char, const std::string &utf8_char):
				_encoded_char(encoded_char),
				_utf8_char(utf8_char),
				valid(true) {}
			
			EncodedCharacter():
				valid(false) {}
	};
	
	/**
	 * @brief Interface that can encode/decode single characters from an encoding.
	*/
	class CharacterEncoder
	{
		public:
			const size_t word_size;
			
			/**
			 * @brief Decode a single character from a buffer to UTF-8.
			 *
			 * Decodes a single character, up to len bytes in length. If the input
			 * character doesn't occupy the entire buffer, its size can be determined
			 * from encoded_char.size() in the returned EncodedCharacter object.
			 *
			 * Returns an EncodedCharacter with valid=false on error.
			*/
			virtual EncodedCharacter decode(const void *data, size_t len) const = 0;
			
			/**
			 * @brief Encode a single character from UTF-8.
			 *
			 * Encodes a single provided UTF-8 character and returns the encoded form
			 * as an EncodedCharacter object.
			 *
			 * Returns an EncodedCharacter with valid=false on error.
			*/
			virtual EncodedCharacter encode(const std::string &utf8_char) const = 0;
			
		protected:
			CharacterEncoder(size_t word_size): word_size(word_size) {}
	};
	
	/**
	 * @brief A text encoding.
	 *
	 * Constructing an instance of this class registers a new text encoding with an associated
	 * CharacterEncoder instance.
	*/
	class CharacterEncoding
	{
		public:
			std::string key;
			
			std::vector<std::string> groups;
			std::string label;
			
			const CharacterEncoder *encoder;
			
			CharacterEncoding(const std::string &key, const std::string &label, const CharacterEncoder *encoder, const std::vector<std::string> &groups = {});
			~CharacterEncoding();
			
			CharacterEncoding(const CharacterEncoding &src) = delete;
			
			/**
			 * @brief Get the encoding with the requested key.
			*/
			static const CharacterEncoding *encoding_by_key(const std::string &key);
			
			/**
			 * @brief Get a (sorted) vector containing all registered encodings.
			*/
			static std::vector<const CharacterEncoding*> all_encodings();
			
		private:
			/* The registrations map is created by the first registration and destroyed
			 * when the last one is removed. This is to avoid depending on global
			 * variable initialisation order.
			*/
			
			static std::map<std::string, const CharacterEncoding*> *registrations;
	};
	
	/**
	 * @brief ASCII (7-bit) CharacterEncoder implementation.
	 *
	 * Simply passes through any bytes in the range 0-127 unmodified, failing if the high bit
	 * is set.
	*/
	class CharacterEncoderASCII: public CharacterEncoder
	{
		public:
			CharacterEncoderASCII(): CharacterEncoder(1) {}
			
			virtual EncodedCharacter decode(const void *data, size_t len) const override;
			virtual EncodedCharacter encode(const std::string &utf8_char) const override;
	};
	
	#if 0
	class CharacterEncoder8Bit: public CharacterEncoder
	{
		private:
			const char *to_utf8[256];
			std::map<std::string, unsigned char> from_utf8;
			
		public:
			CharacterEncoder8Bit(const char *utf8_chars[]);
			
			virtual EncodedCharacter decode(const void *data, size_t len) const override;
			virtual EncodedCharacter encode(const std::string &utf8_char) const override;
	};
	#endif
	
	/**
	 * @brief iconv-based CharacterEncoder implementation.
	 *
	 * Handles decoding and encoding of characters using iconv with the given encoding.
	*/
	class CharacterEncoderIconv: public CharacterEncoder
	{
		private:
			std::string encoding;
			
			iconv_t to_utf8;
			mutable std::mutex to_utf8_lock;
			
			iconv_t from_utf8;
			mutable std::mutex from_utf8_lock;
			
		public:
			CharacterEncoderIconv(const char *encoding, size_t word_size);
			~CharacterEncoderIconv();
			
			CharacterEncoderIconv(const CharacterEncoderIconv&) = delete;
			
			virtual EncodedCharacter decode(const void *data, size_t len) const override;
			virtual EncodedCharacter encode(const std::string &utf8_char) const override;
	};
	
	extern const CharacterEncoderASCII ascii_encoder;
}

#endif /* !REHEX_CHARACTERENCODER_HPP */
