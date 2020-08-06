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

#include <list>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace REHex {
	class Buffer
	{
		private:
			FILE *fh;
			std::string filename;
			std::mutex lock;
			
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
					off_t real_offset;
					
					off_t virt_offset;
					off_t virt_length;
					
					enum State {
						UNLOADED,
						CLEAN,
						DIRTY,
					};
					
					State state;
					
					std::vector<unsigned char> data;
					
					Block(off_t offset, off_t length);
					
					void grow(size_t min_size);
					void trim();
			};
			
			std::vector<Block> blocks;
			
			/* last_accessed_blocks is a list of the most recently loaded CLEAN blocks.
			 *
			 * last_accessed_blocks_map is a map of Block* pointers to iterators within
			 * last_accessed_blocks.
			 *
			 * When the number of loaded clean blocks in last_accessed_blocks exceeds
			 * MAX_CLEAN_BLOCKS, the oldest block in last_accessed_blocks is unloaded to
			 * save memory.
			 *
			 * When a block is unloaded or dirtied it is removed from last_accessed_blocks
			 * to make it no longer eligible for unloading.
			*/
			
			std::list<Block*> last_accessed_blocks;
			std::map< Block*, std::list<Block*>::iterator > last_accessed_blocks_map;
			
		private:
			Block *_block_by_virt_offset(off_t virt_offset);
			void _load_block(Block *block);
			
			off_t _length();
			
			void _last_access_bump(Block *block);
			void _last_access_remove(Block *block);
			
			static bool _same_file(FILE *file1, const std::string &name1, FILE *file2, const std::string &name2);
			
		public:
			static const unsigned int DEFAULT_BLOCK_SIZE = 4194304; /* 4MiB */
			static const unsigned int MAX_CLEAN_BLOCKS   = 4;
			
			const off_t block_size;
			
			Buffer();
			Buffer(const std::string &filename, off_t block_size = DEFAULT_BLOCK_SIZE);
			~Buffer();
			
			void write_inplace();
			void write_inplace(const std::string &filename);
			void write_copy(const std::string &filename);
			
			off_t length();
			
			std::vector<unsigned char> read_data(off_t offset, off_t max_length);
			
			bool overwrite_data(off_t offset, unsigned const char *data, off_t length);
			bool insert_data(off_t offset, unsigned const char *data, off_t length);
			bool erase_data(off_t offset, off_t length);
	};
}

#endif /* !REHEX_BUFFER_HPP */
