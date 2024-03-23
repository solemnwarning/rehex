/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <time.h>
#include <vector>
#include <wx/event.h>
#include <wx/timer.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include "BitOffset.hpp"

namespace REHex {
	wxDECLARE_EVENT(BACKING_FILE_DELETED, wxCommandEvent);
	wxDECLARE_EVENT(BACKING_FILE_MODIFIED, wxCommandEvent);
	
	/**
	 * @brief Paged read-write access to a file on disk.
	 *
	 * This class provides scalable read/write access to a file on disk - paging sections in
	 * and out as necessary to fulfil read requests without keeping the whole file in memory.
	 *
	 * Blocks which have been modified are not paged out and will remain resident until the
	 * file is written out.
	*/
	class Buffer: public wxEvtHandler
	{
		private:
			FILE *fh;
			std::string filename;
			std::mutex lock;
			
			struct FileTime: public timespec
			{
				public:
					FileTime();
					FileTime(const timespec &ts);
					
					#ifdef _WIN32
					FileTime(const FILETIME &ft);
					#endif
					
					bool operator==(const FileTime &rhs) const;
					bool operator!=(const FileTime &rhs) const;
			};
			
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
			
			bool _file_deleted, _file_modified;
			FileTime last_mtime;
			wxTimer timer;
			
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
			
			void _reinit_blocks(off_t file_length);
			
			void OnTimerTick(wxTimerEvent &timer);
			
			static bool _same_file(FILE *file1, const std::string &name1, FILE *file2, const std::string &name2);
			static FileTime _get_file_mtime(FILE *fh, const std::string &filename);
			
		public:
			static const unsigned int DEFAULT_BLOCK_SIZE = 4194304; /* 4MiB */
			static const unsigned int MAX_CLEAN_BLOCKS   = 4;
			static const unsigned int BLOCK_TRIM_THRESH  = 262144; /* 256KiB */
			static const unsigned int FILE_CHECK_INTERVAL_MS = 1000;
			
			const off_t block_size;
			
			/**
			 * @brief Create an empty Buffer with no backing file.
			*/
			Buffer();
			
			/**
			 * @brief Create a Buffer with a backing file on disk.
			*/
			Buffer(const std::string &filename, off_t block_size = DEFAULT_BLOCK_SIZE);
			
			~Buffer();
			
			/**
			 * @brief Reload the file, discarding any changes made.
			*/
			void reload();
			
			/**
			 * @brief Write changes to backing file.
			 *
			 * Writes pending changes to the current backing file.
			 *
			 * Throws on I/O errors.
			*/
			void write_inplace();
			
			/**
			 * @brief Write out buffer to a new backing file.
			 *
			 * @param filename Filename of new backing file.
			 *
			 * Writes out the current buffer state to a file and makes it the new
			 * backing file of the buffer. The old backing file is unchanged.
			 *
			 * Throws on I/O errors.
			*/
			void write_inplace(const std::string &filename);
			
			/**
			 * @brief Write out buffer to a file.
			 *
			 * @param filename Filename of file.
			 *
			 * Writes out the current buffer state to a file, leaving the backing file
			 * unchanged and all changes to it still pending.
			 *
			 * Throws on I/O errors.
			*/
			void write_copy(const std::string &filename);
			
			/**
			 * @brief Get the length of the Buffer.
			*/
			off_t length();
			
			/**
			 * @brief Read data from the Buffer.
			 *
			 * @param offset      Offset to read from.
			 * @param max_length  Maximum number of bytes to read.
			 *
			 * Reads data from the Buffer, paging blocks in from disk if necessary.
			 *
			 * Returns a vector containing up to the requested number of bytes from the
			 * given offset, ending early only if the end of file is reached.
			 *
			 * Throws on I/O or memory allocation error.
			*/
			std::vector<unsigned char> read_data(const BitOffset &offset, off_t max_length);
			
			/**
			 * @brief Read data from the Buffer.
			 *
			 * @param off_t       Offset to read from.
			 * @param max_length  Maximum number of BITS to read.
			 *
			 * Reads data from the Buffer, paging blocks in from disk if necessary.
			 *
			 * Returns a vector containing up to the requested number of bits from the
			 * given offset, ending early only if the end of file is reached.
			 *
			 * Throws on I/O or memory allocation error.
			*/
			std::vector<bool> read_bits(const BitOffset &offset, size_t max_length);
			
			/**
			 * @brief Overwrite a series of bytes in the Buffer.
			 *
			 * @param offset  Offset to write from.
			 * @param data    Data to write into the buffer.
			 * @param length  Length of data to write.
			 *
			 * Overwrites the given range of data in the buffer, returning true if the
			 * write was successful, false if the offset and/or length are beyond the
			 * current size of the buffer.
			 *
			 * Throws on I/O or memory allocation error.
			*/
			bool overwrite_data(BitOffset offset, unsigned const char *data, off_t length);
			
			/**
			 * @brief Overwrite a series of bits in the Buffer.
			 *
			 * @param offset  Offset to write from.
			 * @param data    Data to write into the buffer.
			 *
			 * Overwrites the given range of data in the buffer, returning true if the
			 * write was successful, false if the offset and/or length are beyond the
			 * current size of the buffer.
			 *
			 * This can be used for writing sub-byte quantities of data into the
			 * buffer, up to the last bit in the file.
			*/
			bool overwrite_bits(BitOffset offset, const std::vector<bool> &data);
			
			/**
			 * @brief Insert a series of bytes into the buffer.
			 *
			 * @param offset  Offset to write from.
			 * @param data    Data to write into the buffer.
			 * @param length  Length of data to write.
			 *
			 * Inserts the given range of data into the buffer, returning true if the
			 * write was successful, false if the offset is beyond the current size of
			 * buffer.
			 *
			 * Throws on I/O or memory allocation error.
			*/
			bool insert_data(off_t offset, unsigned const char *data, off_t length);
			
			/**
			 * @brief Erase a series of bytes from the buffer.
			 *
			 * @param offset  Offset to erase from.
			 * @param length  Length of range to erase.
			 *
			 * Erases the given range from the buffer, returning true if the erase was
			 * successful, false if the offset and/or length are beyond the current
			 * size of the buffer.
			 *
			 * Throws on I/O or memory allocation error.
			*/
			bool erase_data(off_t offset, off_t length);
			
			/**
			 * @brief Returns true if the backing file has been deleted.
			*/
			bool file_deleted() const;
			
			/**
			 * @brief Returns true if the backing file has been modified externally.
			*/
			bool file_modified() const;
	};
}

#endif /* !REHEX_BUFFER_HPP */
