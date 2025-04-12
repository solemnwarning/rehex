/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <atomic>
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
#include "MacFileName.hpp"
#include "shared_mutex.hpp"

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
			struct Handle
			{
				bool locked;  /**< Whether this handle is locked for use by a thread. */
				FILE *fh;     /**< FILE handle with read access, may be NULL. */
				
				Handle():
					locked(false),
					fh(NULL) {}
			};
			
			class HandlePtr
			{
				private:
					Buffer *buffer;
					Handle *handle;
					
				public:
					HandlePtr(Buffer *buffer, Handle *handle, const std::unique_lock<std::mutex> &hm_guard);
					~HandlePtr();
					
					HandlePtr(const HandlePtr&) = delete;
					HandlePtr &operator=(const HandlePtr&) = delete;
					
					HandlePtr(HandlePtr&&);
					HandlePtr &operator=(HandlePtr&&);
					
					operator FILE*() const;
			};
			
			/**
			 * @brief Maximum number of handles that may be opened for parallel read operations.
			*/
			static constexpr size_t MAX_READ_HANDLES = 8;
			
			/**
			 * List of open file handles used for reading.
			 *
			 * If the Buffer has a backing file, there will be at least one FILE
			 * handle opened to it, stored in handles[0].fh, additional handles may be
			 * opened as necessary for parallel read operations in different threads.
			 *
			 * All accesses to the handles array are serialised using handles_mutex.
			 *
			 * When a handle being used for a read operation is released, the
			 * handle_released condition_variable will notify one waiting thread.
			*/
			Handle handles[MAX_READ_HANDLES];
			std::mutex handles_mutex;
			std::condition_variable handle_released;
			
			std::string filename;
			
			#ifdef __APPLE__
			MacFileName file_access_guard;
			#endif
			
			/**
			 * All public APIs synchronise access using the general_lock mutex.
			 *
			 * general_lock is a shared mutex which is used to allow multiple threads
			 * to read from the Buffer object concurrently, but only one thread may
			 * perform any kind of write operation at a time.
			*/
			shared_mutex general_lock;
			
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
					
					/* NOTE: volatile for load_block() to spin on it. */
					volatile State state;
					
					std::vector<unsigned char> data;
					
					/**
					 * @brief Number of active references to this block.
					*/
					std::atomic<int> refcount;
					
					Block(off_t offset, off_t length);
					Block(Block&&);
					
					void grow(size_t min_size);
					void trim();
			};
			
			/**
			 * @brief Reference-counting Block reference class.
			 *
			 * This class provides RAII-style locking and shared access to individual
			 * Block objects. Call Buffer::load_block() to acquire one.
			*/
			class BlockPtr
			{
				private:
					Buffer *buffer;
					Block *block;
					
				public:
					BlockPtr(Buffer *buffer, Block *block);
					~BlockPtr();
					
					BlockPtr(const BlockPtr&);
					BlockPtr &operator=(const BlockPtr&);
			};
			
			std::vector<Block> blocks;
			
			bool _file_deleted, _file_modified;
			FileTime last_mtime;
			wxTimer timer;
			
			/* last_accessed_blocks is a list of recently released CLEAN blocks, sorted
			 * from oldest to newest.
			 *
			 * When the number of loaded clean blocks in last_accessed_blocks exceeds
			 * MAX_CLEAN_BLOCKS, the oldest block in last_accessed_blocks is unloaded to
			 * save memory.
			 *
			 * When a block is unloaded or dirtied it is removed from last_accessed_blocks
			 * to make it no longer eligible for unloading.
			*/
			
			std::vector<Block*> last_accessed_blocks;
			std::mutex lab_mutex;
			
		private:
			Block *_block_by_virt_offset(off_t virt_offset);
			
			/**
			 * @brief Ensure a Block is loaded and locked into memory.
			 *
			 * This method loads the block into memory (if not already loaded) and
			 * returns a reference object which can be held to prevent it from being
			 * paged out.
			*/
			BlockPtr load_block(Block *block);
			
			void release_block(Block *block);
			
			HandlePtr acquire_read_handle();
			void close_handles();
			
			off_t _length();
			
			void _last_access_remove(Block *block);
			
			void _reinit_blocks(off_t file_length);
			
			void OnTimerTick(wxTimerEvent &timer);
			
			static bool _same_file(FILE *file1, const std::string &name1, FILE *file2, const std::string &name2);
			static FileTime _get_file_mtime(FILE *fh, const std::string &filename);
			static FILE *reopen_file(FILE *fh, const std::string &name);
			
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
			
			#ifdef __APPLE__
			/**
			 * @brief Create a Buffer with a backing file on disk.
			*/
			Buffer(MacFileName &&filename, off_t block_size = DEFAULT_BLOCK_SIZE);
			#endif
			
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
