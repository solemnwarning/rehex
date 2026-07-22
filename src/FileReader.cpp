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

#include "platform.hpp"

#include <algorithm>
#include <assert.h>
#include <portable_endian.h>
#include <stdio.h>
#include <string>

#include "App.hpp"
#include "FileReader.hpp"

REHex::FileReader::FileReader(const char *filename):
	filename(filename),
	position(0),
	tlv_end(-1)
{
	fh = fopen(filename, "rb");
	if(fh == NULL)
	{
		int fopen_errno = errno;
		throw std::runtime_error(std::string("Error opening ") + filename + ": " + strerror(fopen_errno));
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
		size_t this_size;
		int fread_error;

		if(tlv_end >= 0)
		{
			assert(tlv_end >= position);

			if(position == tlv_end)
			{
				this_size = 0;
				fread_error = 0;
			}
			else{
				this_size = fread((((char*)(data)) + current_size), 1, std::min<size_t>((max_size - current_size), (tlv_end - position)), fh);
				fread_error = errno;
			}
		}
		else{
			this_size = fread((((char*)(data)) + current_size), 1, (max_size - current_size), fh);
			fread_error = errno;
		}

		position += this_size;

		if(this_size > 0)
		{
			current_size += this_size;
		}
		else if(ferror(fh))
		{
			throw std::runtime_error(std::string("Error reading ") + filename + ": " + strerror(fread_error));
		}
		else if(current_size < min_size)
		{
			throw eof_error();
		}
		else{
			return current_size;
		}
	}

	return current_size;
}

bool REHex::FileReader::read_tlv(const std::function<void(const FourCC&,uint32_t)> &func)
{
	char type[4];

	int type_len = read(type, 4, 0);
	if(type_len == 0)
	{
		return false;
	}
	else if(type_len < 4)
	{
		throw eof_error();
	}

	uint32_t length = le32toh(read<uint32_t>());

	if(tlv_end >= 0 && (position + length) > tlv_end)
	{
		throw eof_error();
	}

	off_t saved_tlv_end = tlv_end;

	tlv_end = position + length;

	func(FourCC(type[0], type[1], type[2], type[3]), length);

	if(position < tlv_end)
	{
		skip(tlv_end - position);
	}

	tlv_end = saved_tlv_end;

	return true;
}

static size_t json_from_filereader_callback(void *buffer, size_t buflen, void *data)
{
	REHex::FileReader *file = (REHex::FileReader*)(data);

	try {
		return file->read(buffer, buflen, 0);
	}
	catch(const std::exception &e)
	{
		wxGetApp().printf_error("Exception while loading JSON from FileReader: %s\n", e.what());
		return -1;
	}
}

std::unique_ptr<json_t, void(*)(json_t*)> REHex::FileReader::read_json(bool disable_eof_check)
{
	off_t start_pos = position;

	std::unique_ptr<json_t, void(*)(json_t*)> p(nullptr, json_decref);

	json_error_t json_err;
	p.reset(json_load_callback(&json_from_filereader_callback, this, (disable_eof_check ? JSON_DISABLE_EOF_CHECK : 0), &json_err));
	if(p == NULL)
	{
		throw std::runtime_error(json_err.text);
	}

	off_t new_position = start_pos + json_err.position;
	assert(new_position <= position);

	if(fseeko(fh, new_position, SEEK_SET) != 0)
	{
		int fseek_errno = errno;
		throw std::runtime_error(std::string("Error reading ") + filename + ": " + strerror(fseek_errno));
	}

	position = new_position;

	return p;
}

void REHex::FileReader::skip(size_t num_bytes)
{
	if(fseeko(fh, num_bytes, SEEK_CUR) != 0)
	{
		int fseek_errno = errno;
		throw std::runtime_error(std::string("Error reading ") + filename + ": " + strerror(fseek_errno));
	}

	position += num_bytes;
}

wxFileName REHex::FileReader::get_filename() const
{
	wxFileName fn(filename);
	fn.MakeAbsolute();
	
	return fn;
}
