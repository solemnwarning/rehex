/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_BUFFER_HPP
#define REHEX_BUFFER_HPP

#include <string>
#include <vector>

namespace REHex {
	class Buffer
	{
		private:
			FILE *fh;
			
		#ifdef UNIT_TEST
		/* Make the block list public when unit testing so we can examine the
		 * contents directly rather than trying to cover all possible iterations
		 * end-to-end.
		*/
		public:
		#endif
			class Block
			{
				public:
					const size_t real_offset;
					
					size_t virt_offset;
					size_t virt_length;
					
					enum State {
						UNLOADED,
						CLEAN,
						DIRTY,
					};
					
					State state;
					
					std::vector<unsigned char> data;
					
					Block(size_t offset, size_t length);
					
					void grow(size_t min_size);
					void trim();
			};
			
			std::vector<Block> blocks;
			
		private:
			Block *_block_by_virt_offset(size_t virt_offset);
			void _load_block(Block *block);
			
		public:
			static const unsigned int DEFAULT_BLOCK_SIZE = 4194304; /* 4MiB */
			const size_t block_size;
			
			Buffer();
			Buffer(const std::string &filename, size_t block_size = DEFAULT_BLOCK_SIZE);
			
			void write_inplace();
			void write_replace();
			void write_copy(const std::string &filename);
			
			size_t length();
			
			std::vector<unsigned char> read_data(size_t offset, size_t max_length);
			
			bool overwrite_data(size_t offset, unsigned const char *data, size_t length);
			bool insert_data(size_t offset, unsigned const char *data, size_t length);
			bool erase_data(size_t offset, size_t length);
	};
}

#endif /* !REHEX_BUFFER_HPP */
