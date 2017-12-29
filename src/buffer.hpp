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
			std::string filename;
			
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
					const off_t real_offset;
					
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
					
					void grow(off_t min_size);
					void trim();
			};
			
			std::vector<Block> blocks;
			
		private:
			Block *_block_by_virt_offset(off_t virt_offset);
			void _load_block(Block *block);
			
		public:
			static const unsigned int DEFAULT_BLOCK_SIZE = 4194304; /* 4MiB */
			const off_t block_size;
			
			Buffer();
			Buffer(const std::string &filename, off_t block_size = DEFAULT_BLOCK_SIZE);
			
			void write_inplace();
			void write_inplace(const std::string &filename, bool force = true);
			void write_copy(const std::string &filename);
			
			off_t length();
			
			std::vector<unsigned char> read_data(off_t offset, off_t max_length);
			
			bool overwrite_data(off_t offset, unsigned const char *data, off_t length);
			bool insert_data(off_t offset, unsigned const char *data, off_t length);
			bool erase_data(off_t offset, off_t length);
	};
}

#endif /* !REHEX_BUFFER_HPP */
