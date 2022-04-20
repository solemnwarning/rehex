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

#include "platform.hpp"

#include <algorithm>
#include <assert.h>
#include <errno.h>
#include <stdexcept>
#include <stdint.h>
#include <stdio.h>

#include "IntelHexExport.hpp"

#define HEX_FILE_BYTES_PER_LINE 16

class IntelHexFileWriter
{
	/* TODO: Use a temporary file and replace the dest? */
	
	private:
		const std::string filename;
		FILE *fh;
		
		unsigned char write_buf[320];
	
	public:
		IntelHexFileWriter(const std::string &filename);
		~IntelHexFileWriter();
		
		void write_record(REHex::IntelHexRecordType record_type, uint16_t address, const unsigned char *data, unsigned char data_length);
		void finish();
};

IntelHexFileWriter::IntelHexFileWriter(const std::string &filename):
	filename(filename)
{
	fh = fopen(filename.c_str(), "wb");
	if(fh == NULL)
	{
		throw std::runtime_error(strerror(errno));
	}
}

IntelHexFileWriter::~IntelHexFileWriter()
{
	if(fh != NULL)
	{
		unlink(filename.c_str());
		fclose(fh);
	}
}

void IntelHexFileWriter::write_record(REHex::IntelHexRecordType record_type, uint16_t address, const unsigned char *data, unsigned char data_length)
{
	assert(fh != NULL);
	
	unsigned char checksum_accum = 0;
	unsigned int write_len = 0;
	
	auto push_byte = [&](unsigned char byte)
	{
		static const char *nibble_to_hex = "0123456789ABCDEF";
		
		assert((write_len + 2) <= sizeof(write_buf));
		
		write_buf[write_len++] = nibble_to_hex[(byte & 0xF0) >> 4];
		write_buf[write_len++] = nibble_to_hex[byte & 0x0F];
		
		checksum_accum += byte;
	};
	
	assert((write_len + 1) <= sizeof(write_buf));
	write_buf[write_len++] = ':';
	
	push_byte(data_length);
	push_byte((address & 0xFF00) >> 8);
	push_byte(address & 0x00FF);
	push_byte((unsigned char)(record_type));
	
	for(unsigned i = 0; i < data_length; ++i)
	{
		push_byte(data[i]);
	}
	
	push_byte(256 - checksum_accum);
	
	assert((write_len + 1) <= sizeof(write_buf));
	write_buf[write_len++] = '\n';
	
	if(fwrite(write_buf, write_len, 1, fh) != 1)
	{
		int save_errno = errno;
		unlink(filename.c_str());
		
		throw std::runtime_error(strerror(save_errno));
	}
}

void IntelHexFileWriter::finish()
{
	assert(fh != NULL);
	
	bool ok = (fclose(fh) == 0);
	fh = NULL;
	
	if(!ok)
	{
		/* Likely a flush (write) error. */
		
		int save_errno = errno;
		
		unlink(filename.c_str());
		throw std::runtime_error(strerror(save_errno));
	}
}

void REHex::write_hex_file(const std::string &filename, const Document *doc, bool use_segments, IntelHexAddressingMode address_mode, const uint32_t *start_segment_address, const uint32_t *start_linear_address)
{
	IntelHexFileWriter writer(filename);
	
	off_t seg_base = 0;
	off_t seg_end = 0x10000;
	
	auto write_segment = [&](off_t real_base, off_t virt_base, off_t length)
	{
		off_t virt_end = virt_base + length;
		
		if(address_mode == IntelHexAddressingMode::IHA_16BIT && virt_end > 0x10000)
		{
			throw std::runtime_error("16-bit Intel Hex files cannot address beyond 64KiB");
		}
		else if(address_mode == IntelHexAddressingMode::IHA_SEGMENTED && virt_end > 0x100000)
		{
			throw std::runtime_error("Segmented Intel Hex files cannot address beyond 1MiB");
		}
		else if(address_mode == IntelHexAddressingMode::IHA_LINEAR && virt_end > 0x100000000)
		{
			throw std::runtime_error("Linear Intel Hex files cannot address beyond 4GiB");
		}
		
		off_t at = 0;
		
		while(at < length)
		{
			off_t virt_at = virt_base + at;
			
			if(virt_at >= seg_end)
			{
				switch(address_mode)
				{
					case IntelHexAddressingMode::IHA_16BIT:
					{
						/* Initial segment is the full possible range - unreachable */
						abort();
					}
					
					case IntelHexAddressingMode::IHA_SEGMENTED:
					{
						seg_base = virt_at & ~0xFFFF;
						seg_end  = seg_base + 0x10000;
						
						assert(seg_base >= 0);
						assert(seg_base <= 0xFFFF0);
						
						unsigned char data[] = {
							(unsigned char)(((seg_base / 16) & 0xFF00) >> 8),
							(unsigned char)((seg_base / 16) & 0x00FF),
						};
						
						writer.write_record(IntelHexRecordType::IRT_EXTENDED_SEGMENT_ADDRESS, 0x0000, data, 2);
						
						break;
					}
					
					case IntelHexAddressingMode::IHA_LINEAR:
					{
						seg_base = virt_at & 0xFFFF0000;
						seg_end  = seg_base + 0x10000;
						
						unsigned char data[] = {
							(unsigned char)((seg_base & 0xFF000000) >> 24),
							(unsigned char)((seg_base & 0x00FF0000) >> 16),
						};
						
						writer.write_record(IntelHexRecordType::IRT_EXTENDED_LINEAR_ADDRESS, 0x0000, data, 2);
						
						break;
					}
				}
			}
			
			assert(seg_base <= virt_at);
			assert(seg_end > virt_at);
			
			off_t bytes_to_write = std::min((length - at), (off_t)(HEX_FILE_BYTES_PER_LINE));
			if((virt_at + bytes_to_write) > seg_end)
			{
				/* Clamp data record to section bounds to avoid writing data
				 * records spanning multiple segments.
				*/
				
				bytes_to_write = seg_end - virt_at;
			}
			
			assert(bytes_to_write > 0);
			
			/* TODO: Read bigger chunks at a time. */
			
			std::vector<unsigned char> data = doc->read_data((real_base + at), bytes_to_write);
			assert(data.size() == (size_t)(bytes_to_write));
			
			writer.write_record(IntelHexRecordType::IRT_DATA, (virt_at - seg_base), data.data(), data.size());
			
			at += bytes_to_write;
		}
	};
	
	if(start_segment_address != NULL)
	{
		unsigned char buf[] = {
			(unsigned char)((*start_segment_address & 0xFF000000) >> 24),
			(unsigned char)((*start_segment_address & 0x00FF0000) >> 16),
			(unsigned char)((*start_segment_address & 0x0000FF00) >> 8),
			(unsigned char)((*start_segment_address & 0x000000FF)),
		};
		
		writer.write_record(IntelHexRecordType::IRT_START_SEGMENT_ADDRESS, 0x0000, buf, 4);
	}
	
	if(start_linear_address != NULL)
	{
		unsigned char buf[] = {
			(unsigned char)((*start_linear_address & 0xFF000000) >> 24),
			(unsigned char)((*start_linear_address & 0x00FF0000) >> 16),
			(unsigned char)((*start_linear_address & 0x0000FF00) >> 8),
			(unsigned char)((*start_linear_address & 0x000000FF)),
		};
		
		writer.write_record(IntelHexRecordType::IRT_START_LINEAR_ADDRESS, 0x0000, buf, 4);
	}
	
	if(use_segments)
	{
		auto &virt_to_real_segs = doc->get_virt_to_real_segs();
		
		for(auto i = virt_to_real_segs.begin(); i != virt_to_real_segs.end(); ++i)
		{
			write_segment(i->second, i->first.offset, i->first.length);
		}
	}
	else{
		write_segment(0, 0, doc->buffer_length());
	}
	
	writer.write_record(IntelHexRecordType::IRT_EOF, 0, NULL, 0);
	writer.finish();
}
