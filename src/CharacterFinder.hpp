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

#ifndef REHEX_CHARACTERFINDER_HPP
#define REHEX_CHARACTERFINDER_HPP

#include <atomic>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <thread>
#include <vector>

#include "LRUCache.hpp"
#include "SharedDocumentPointer.hpp"

namespace REHex
{
	/**
	 * @brief Finds the beginning and end of characters in a range of bytes in a Document.
	 *
	 * Any byte ranges that don't decode as valid characters will be recorded as a sequence of
	 * single byte "characters".
	*/
	class CharacterFinder
	{
		public:
			static const size_t DEFAULT_CHUNK_SIZE = 512 * 1024; /* 512KiB */
			static const size_t DEFAULT_LRU_CACHE_SIZE = 4;
			
			CharacterFinder(SharedDocumentPointer &document, off_t base, off_t length, size_t chunk_size = DEFAULT_CHUNK_SIZE, size_t lru_cache_size = DEFAULT_LRU_CACHE_SIZE);
			~CharacterFinder();
			
			/**
			 * @brief Get the start offset and length of a character in the Document.
			 *
			 * Returns a pair containing the start offset and length, or -1 and -1 if
			 * the requested character hasn't been processed yet.
			*/
			std::pair<off_t,off_t> get_char_range(off_t offset);
			
			/**
			 * @brief Get the start offset of a character in the Document.
			 *
			 * Returns the start offset of the character, or -1 if the character hasn't
			 * been processed yet.
			*/
			off_t get_char_start(off_t offset);
			
			/**
			 * @brief Get the length of a character in the Document.
			 *
			 * Returns the length of the character in bytes, or -1 if the character
			 * hasn't been processed yet.
			*/
			off_t get_char_length(off_t offset);
			
			bool finished();
			
		private:
			SharedDocumentPointer &document;
			
			const off_t base, length;
			const size_t chunk_size;
			
			size_t t1_size;
			std::unique_ptr< std::atomic<off_t>[] > t1;
			
			volatile bool t1_filling;
			volatile bool t1_done;
			std::thread t1_worker;
			
			LRUCache< off_t, std::vector<size_t> > t2;
			
			void start_worker();
			void stop_worker();
			void reset_from(off_t offset);
	};
}

#endif /* !REHEX_CHARACTERFINDER_HPP */
