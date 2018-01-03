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

#include <assert.h>
#include <fcntl.h>
#include <list>
#include <stdio.h>
#include <string>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#ifdef _WIN32
#define O_NOCTTY 0
#endif

#include "buffer.hpp"

REHex::Buffer::Block *REHex::Buffer::_block_by_virt_offset(off_t virt_offset)
{
	if(virt_offset >= this->length())
	{
		/* Been asked for an offset beyond the end of the file. */
		return nullptr;
	}
	
	off_t begin = 0, end = blocks.size();
	off_t at = end / 2;
	
	while(1)
	{
		if(blocks[at].virt_offset > virt_offset)
		{
			/* This block begins past the offset we want. */
			end = at;
		}
		else if((blocks[at].virt_offset + blocks[at].virt_length) <= virt_offset)
		{
			/* This block ends before the offset we want. */
			begin = at + 1;
		}
		else{
			/* This block is the one we want. */
			return &(blocks[at]);
		}
		
		assert(begin != end);
		
		/* Reset to the middle of our new search area. */
		at = begin + ((end - begin) / 2);
	}
}

void REHex::Buffer::_load_block(Block *block)
{
	if(block->state != Block::UNLOADED)
	{
		return;
	}
	
	/* TODO: Cycle out not-recently-used CLEAN data buffers if we have a
	 * lot loaded in.
	*/
	
	if(block->virt_length > 0)
	{
		assert(fseeko(fh, block->real_offset, SEEK_SET) == 0);
		
		block->grow(block->virt_length);
		
		assert(fread(block->data.data(), block->virt_length, 1, fh) == 1);
	}
	
	block->state = Block::CLEAN;
}

REHex::Buffer::Buffer():
	fh(nullptr),
	block_size(DEFAULT_BLOCK_SIZE)
{
	blocks.push_back(Block(0,0));
	blocks.back().state = Block::CLEAN;
}

REHex::Buffer::Buffer(const std::string &filename, off_t block_size):
	filename(filename), block_size(block_size)
{
	fh = fopen(filename.c_str(), "rb");
	assert(fh);
	
	/* Find out the length of the file. */
	
	assert(fseeko(fh, 0, SEEK_END) == 0);
	
	off_t file_length = ftello(fh);
	assert(file_length != -1);
	
	/* Populate the blocks list with appropriate offsets and sizes. */
	
	for(off_t offset = 0; offset < file_length; offset += block_size)
	{
		blocks.push_back(Block(offset, std::min((file_length - offset), (off_t)(block_size))));
	}
	
	if(file_length == 0)
	{
		blocks.push_back(Block(0,0));
	}
}

REHex::Buffer::~Buffer()
{
	if(fh != NULL)
	{
		fclose(fh);
		fh = NULL;
	}
}

void REHex::Buffer::write_inplace()
{
	write_inplace(filename, false);
}

void REHex::Buffer::write_inplace(const std::string &filename, bool force)
{
	/* Need to open the file with open() since fopen() can't be told to open
	 * the file, creating it if it doesn't exist, WITHOUT truncating and letting
	 * us write at arbitrary positions.
	*/
	int fd = open(filename.c_str(), (O_RDWR | O_CREAT | O_NOCTTY), 0777);
	assert(fd != -1);
	
	FILE *wfh = fdopen(fd, "r+b");
	assert(wfh != NULL);
	
	off_t out_length = this->length();
	
	/* Reserve space in the output file if it isn't already at least as large
	 * as the file we want to write out.
	*/
	
	{
		assert(fseek(wfh, 0, SEEK_END) == 0);
		
		off_t wfh_initial_size = ftello(wfh);
		assert(wfh_initial_size >= 0);
		
		if(wfh_initial_size < out_length)
		{
			assert(ftruncate(fileno(wfh), out_length) == 0);
		}
	}
	
	std::list<Block> pending(blocks.begin(), blocks.end());
	
	for(auto b = pending.begin(); b != pending.end();)
	{
		if(!force && (b->virt_offset == b->real_offset && b->state != Block::DIRTY))
		{
			/* Don't need to rewrite this block */
			b = pending.erase(b);
			continue;
		}
		
		auto next = std::next(b);
		
		if(next != pending.end() && b->virt_offset + b->virt_length > next->real_offset)
		{
			/* Can't flush this block yet; we'd write into
			 * the data of the next one.
			*/
			
			++b;
			continue;
		}
		
		if(b->virt_length > 0)
		{
			_load_block(&(*b));
			
			assert(fseeko(wfh, b->virt_offset, SEEK_SET) == 0);
			assert(fwrite(b->data.data(), b->virt_length, 1, wfh) == 1);
		}
		
		b = pending.erase(b);
		
		if(b != pending.begin())
		{
			/* This isn't the first pending block, so we must've stepped
			 * forwards to make a hole for one or more previous ones.
			 * 
			 * We've made the hole, so start walking backwards and writing
			 * out the new blocks.
			*/
			
			--b;
		}
	}
	
	assert(fflush(wfh) == 0);
	
	assert(ftruncate(fileno(wfh), out_length) == 0);
	
	/* All changes are flushed to disk now. Rebuild the blocks list so we
	 * don't hang on to the old dirty blocks or try loading data from the
	 * old offsets.
	*/
	
	blocks.clear();
	
	for(off_t offset = 0; offset < out_length; offset += block_size)
	{
		blocks.push_back(Block(offset, std::min((out_length - offset), block_size)));
	}
	
	if(out_length == 0)
	{
		blocks.push_back(Block(0,0));
	}
	
	if(fh != NULL)
	{
		fclose(fh);
	}
	
	/* The Buffer is now backed by the new file (which might be the old one). */
	
	fh = wfh;
	this->filename = filename;
}

void REHex::Buffer::write_copy(const std::string &filename)
{
	FILE *out = fopen(filename.c_str(), "wb");
	assert(out);
	
	for(auto b = blocks.begin(); b != blocks.end(); ++b)
	{
		if(b->virt_length > 0)
		{
			_load_block(&(*b));
			assert(fwrite(b->data.data(), b->virt_length, 1, out) == 1);
		}
	}
	
	fclose(out);
}

off_t REHex::Buffer::length()
{
	return blocks.back().virt_offset + blocks.back().virt_length;
}

std::vector<unsigned char> REHex::Buffer::read_data(off_t offset, off_t max_length)
{
	Block *block = _block_by_virt_offset(offset);
	if(block == nullptr)
	{
		return std::vector<unsigned char>();
	}
	
	std::vector<unsigned char> data;
	
	while(block < blocks.data() + blocks.size() && max_length > 0)
	{
		_load_block(block);
		
		off_t block_rel_off = offset - block->virt_offset;
		off_t block_rel_len = block->virt_length - block_rel_off;
		off_t to_copy = std::min(block_rel_len, max_length);
		
		const unsigned char *base = block->data.data() + block_rel_off;
		data.insert(data.end(), base, base + to_copy);
		
		++block;
		
		offset      = block->virt_offset;
		max_length -= to_copy;
	}
	
	return data;
}

bool REHex::Buffer::overwrite_data(off_t offset, unsigned const char *data, off_t length)
{
	if((offset + length) > this->length())
	{
		/* Runs past the end of the buffer. */
		return false;
	}
	
	Block *block = _block_by_virt_offset(offset);
	assert(block != nullptr);
	
	while(length > 0)
	{
		_load_block(block);
		
		off_t block_rel_off = offset - block->virt_offset;
		off_t to_copy = std::min((block->virt_length - block_rel_off), length);
		
		memcpy((block->data.data() + block_rel_off), data, to_copy);
		
		block->state = Block::DIRTY;
		
		data   += to_copy;
		offset += to_copy;
		length -= to_copy;
		
		++block;
	}
	
	return true;
}

bool REHex::Buffer::insert_data(off_t offset, unsigned const char *data, off_t length)
{
	if(offset > this->length())
	{
		/* Starts past the end of the buffer. */
		return false;
	}
	
	/* Need to special-case the block to be the last one when appending. */
	
	Block *block = (offset == this->length()
		? &(blocks.back())
		: _block_by_virt_offset(offset));
	
	assert(block != nullptr);
	
	_load_block(block);
	
	/* Ensure the block's data buffer is large enough */
	
	block->grow(block->virt_length + length);
	
	/* Insert the new data, shifting the rest of the buffer along if necessary */
	
	off_t block_rel_off = offset - block->virt_offset;
	unsigned char *dst = block->data.data() + block_rel_off;
	
	memmove(dst + length, dst, block->virt_length - block_rel_off);
	memcpy(dst, data, length);
	
	block->virt_length += length;
	block->state = Block::DIRTY;
	
	/* Shift the virtual offset of any subsequent blocks along. */
	
	for(++block; block < blocks.data() + blocks.size(); ++block)
	{
		block->virt_offset += length;
	}
	
	return true;
}

bool REHex::Buffer::erase_data(off_t offset, off_t length)
{
	if((offset + length) > this->length())
	{
		/* Runs past the end of the buffer. */
		return false;
	}
	
	Block *block = _block_by_virt_offset(offset);
	assert(block != nullptr);
	
	for(off_t erased = 0; erased < length;)
	{
		off_t block_rel_off = offset - block->virt_offset;
		off_t to_erase = std::min((block->virt_length - block_rel_off), (length - erased));
		
		if(block_rel_off == 0 && to_erase == block->virt_length)
		{
			block->virt_length = 0;
		}
		else{
			_load_block(block);
			
			unsigned char *base = block->data.data() + block_rel_off;
			memmove(base, base + to_erase, block->virt_length - block_rel_off);
			
			block->virt_length -= to_erase;
		}
		
		block->state = Block::DIRTY;
		
		/* Shift the offset back by however many bytes we've already
		 * erased from previous blocks.
		*/
		block->virt_offset -= erased;
		
		erased += to_erase;
		++block;
		
		/* Set the offset to the start of the next block where we'll
		 * pick up the erasing at.
		*/
		offset = block->virt_offset;
	}
	
	/* Shift the virtual offset of any subsequent blocks back. */
	
	for(; block < blocks.data() + blocks.size(); ++block)
	{
		block->virt_offset -= length;
	}
	
	return true;
}

REHex::Buffer::Block::Block(off_t offset, off_t length):
	real_offset(offset),
	virt_offset(offset),
	virt_length(length),
	state(UNLOADED) {}

void REHex::Buffer::Block::grow(off_t min_size)
{
	if(min_size < data.size())
	{
		/* Don't ever shrink the buffer here. */
		return;
	}
	
	if(min_size == data.size() + 1)
	{
		/* If we've been asked to grow the block by one byte, someone
		 * is probably typing new bytes in insert mode. Grow the buffer
		 * by 64 bytes instead so we don't have to grow it and move the
		 * whole buffer around on each keypress.
		*/
		min_size += 63;
	}
	
	data.resize(min_size);
}
