/* Reverse Engineer's Hex Editor
 * Copyright (C) 2026 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <stdio.h>
#include <string>

#include "FileReader.hpp"

REHex::FileReader::FileReader(const char *filename):
	filename(filename)
{
	fh = fopen(filename, "rb");
	if(fh == NULL)
	{
		throw false; // TODO
	}
}

REHex::FileReader::~FileReader()
{
	fclose(fh);
}

size_t REHex::FileReader::read(void *data, size_t max_size, size_t min_size)
{
	size_t current_size = 0;
	
	while(current_size < max_size)
	{
		size_t this_size = fread((((char*)(data)) + current_size), 1, (max_size - current_size), fh);
		if(this_size > 0)
		{
			current_size += this_size;
		}
		else if(ferror(fh))
		{
			throw false; // TODO
		}
		else if(current_size < min_size)
		{
			throw false; // TODO
		}
		else{
			return current_size;
		}
	}
}

void REHex::FileReader::skip(size_t num_bytes)
{
	fseek(fh, num_bytes, SEEK_CUR); // TODO
}
