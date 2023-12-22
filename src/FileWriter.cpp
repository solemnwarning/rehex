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

#include "platform.hpp"

#include <assert.h>
#include <errno.h>
#include <stdexcept>
#include <stdio.h>
#include <string.h>

#ifndef _MSC_VER
#include <unistd.h>
#endif

#include "FileWriter.hpp"

REHex::FileWriter::FileWriter(const char *filename):
	filename(filename)
{
	fh = fopen(filename, "wb");
	if(fh == NULL)
	{
		int fopen_errno = errno;
		throw std::runtime_error(std::string("Error opening ") + filename + ": " + strerror(fopen_errno));
	}
}

REHex::FileWriter::~FileWriter()
{
	if(fh != NULL)
	{
		fclose(fh);
		unlink(filename.c_str());
	}
}

void REHex::FileWriter::write(const void *data, size_t size)
{
	assert(fh != NULL);
	
	if(fwrite(data, size, 1, fh) != 1)
	{
		int fwrite_errno = errno;
		
		fclose(fh);
		fh = NULL;
		
		unlink(filename.c_str());
		
		throw std::runtime_error(std::string("Error writing to ") + filename + ": " + strerror(fwrite_errno));
	}
}

void REHex::FileWriter::commit()
{
	if(fclose(fh) != 0)
	{
		int fclose_errno = errno;
		fh = NULL;
		
		unlink(filename.c_str());
		throw std::runtime_error(std::string("Error writing to ") + filename + ": " + strerror(fclose_errno));
	}
	
	fh = NULL;
}
