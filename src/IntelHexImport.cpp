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

#include <assert.h>
#include <errno.h>
#include <stdexcept>
#include <stdio.h>
#include <string.h>

#include "document.hpp"
#include "IntelHexImport.hpp"
#include "SharedDocumentPointer.hpp"

class FileHandleGuard
{
	public:
		FileHandleGuard(FILE *file);
		~FileHandleGuard();
		
	private:
		FILE *file;
};

FileHandleGuard::FileHandleGuard(FILE *file):
	file(file) {}

FileHandleGuard::~FileHandleGuard()
{
	fclose(file);
}

REHex::SharedDocumentPointer REHex::load_hex_file(const std::string &filename)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	FILE *fh = fopen(filename.c_str(), "rb");
	if(fh == NULL)
	{
		throw std::runtime_error(strerror(errno));
	}
	
	FileHandleGuard fh_guard(fh);
	
	char buf[1024];
	size_t len = 0, read_len, file_pos = 0;
	
	uint32_t base_address = 0;
	bool found_eof = false;
	
	off_t real_base = 0;
	size_t virt_base = 0;
	off_t seg_length = 0;
	
	bool uses_segment_addressing = false;
	bool has_segment_start_address = false;
	uint32_t segment_start_address = -1;
	bool uses_linear_addressing = false;
	bool has_linear_start_address = false;
	uint32_t linear_start_address = -1;
	
	while((read_len = fread((buf + len), 1, (sizeof(buf) - len), fh)) > 0)
	{
		len += read_len;
		
		char *record_start = (char*)(memchr(buf, ':', len));
		
		while(record_start != NULL)
		{
			size_t buf_pos = (record_start - buf) + 1;
			
			bool soft_eof = false;
			unsigned char checksum_accum = 0;
			
			auto parse_error = [&]()
			{
				throw std::runtime_error(std::string("Parse error at file position ") + std::to_string(file_pos + buf_pos));
			};
			
			auto read_byte = [&]()
			{
				if((buf_pos + 2) > len)
				{
					if(feof(fh))
					{
						/* Unexpected EOF. */
						parse_error();
					}
					else{
						soft_eof = true;
						return (unsigned char)(0);
					}
				}
				else if(!isxdigit(buf[buf_pos]) || !isxdigit(buf[buf_pos]))
				{
					parse_error();
				}
				
				unsigned char byte = (parse_ascii_nibble(buf[buf_pos]) << 4) | parse_ascii_nibble(buf[buf_pos + 1]);
				buf_pos += 2;
				
				checksum_accum += byte;
				
				return byte;
			};
			
			auto read_u16 = [&]()
			{
				unsigned char b1 = read_byte();
				unsigned char b2 = read_byte();
				
				return (b1 << 8) | b2;
			};
			
			unsigned char data_length = read_byte();
			uint16_t      address     = read_u16();
			unsigned char record_type = read_byte();
			
			unsigned char data[256];
			for(int i = 0; i < data_length; ++i)
			{
				data[i] = read_byte();
			}
			
			read_byte(); /* checksum byte */
			
			if(soft_eof)
			{
				break;
			}
			
			if(checksum_accum != 0)
			{
				throw std::runtime_error(std::string("Checksum error at file position ") + std::to_string(file_pos + (record_start - buf)));
			}
			
			switch(record_type)
			{
				case 0x00:
				{
					/* Data */
					/* TODO: Check for collision. */
					
					off_t real_offset = doc->buffer_length();
					size_t virt_addr = base_address + address;
					
					if((virt_base + seg_length) != virt_addr)
					{
						if(seg_length > 0)
						{
							doc->set_virt_mapping(real_base, virt_base, seg_length);
						}
						
						real_base = real_offset;
						virt_base = virt_addr;
						seg_length = 0;
					}
					
					doc->insert_data(real_offset, data, data_length);
					seg_length += data_length;
					
					break;
				}
				
				case 0x01:
				{
					/* EOF */
					found_eof = true;
					break;
				}
				
				case 0x02:
				{
					/* Extended segment address */
					if(data_length != 2)
					{
						parse_error();
					}
					
					base_address = (((uint32_t)(data[0]) << 8) | (uint32_t)(data[1])) * 16;
					uses_segment_addressing = true;
					break;
				}
				
				case 0x03:
				{
					/* Start segment address */
					if(data_length != 4)
					{
						parse_error();
					}
					
					has_segment_start_address = true;
					segment_start_address = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
					
					break;
				}
				
				case 0x04:
				{
					/* Extended linear address */
					if(data_length != 2)
					{
						parse_error();
					}
					
					base_address = (((uint32_t)(data[0]) << 8) | (uint32_t)(data[1])) << 16;
					uses_linear_addressing = true;
					break;
				}
				
				case 0x05:
				{
					/* Start linear address */
					if(data_length != 4)
					{
						parse_error();
					}
					
					has_linear_start_address = true;
					linear_start_address = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
					
					break;
				}
				
				default:
					/* Unknown record type. */
					break;
			}
			
			record_start = (char*)(memchr((buf + buf_pos), ':', (len - buf_pos)));
		}
		
		if(found_eof)
		{
			break;
		}
		
		if(record_start != NULL)
		{
			assert(record_start > buf);
			
			file_pos += record_start - buf;
			
			memmove(buf, record_start, (buf + len) - record_start);
			len = (buf + len) - record_start;
		}
		else{
			len = 0;
		}
	}
	
	if(ferror(fh))
	{
		throw std::runtime_error(strerror(errno));
	}
	
	if(seg_length > 0 && (virt_base > 0 || !doc->get_virt_to_real_segs().empty()))
	{
		doc->set_virt_mapping(real_base, virt_base, seg_length);
	}
	
	if(!found_eof)
	{
		throw std::runtime_error("No end of file marker found");
	}
	
	std::string header_comment;
	auto header_comment_push = [&](const std::string &text)
	{
		if(!header_comment.empty())
		{
			header_comment += "\n";
		}
		
		header_comment += text;
	};
	
	if(uses_segment_addressing)
	{
		header_comment_push("Extended Segment Addressing");
	}
	
	if(uses_linear_addressing)
	{
		header_comment_push("Extended Linear Addressing");
	}
	
	if(has_segment_start_address)
	{
		char line[64];
		snprintf(line, 64, "Start Segment Address = 0x%08X", (unsigned)(segment_start_address));
		header_comment_push(line);
	}
	
	if(has_linear_start_address)
	{
		char line[64];
		snprintf(line, 64, "Start Linear Address = 0x%08X", (unsigned)(linear_start_address));
		header_comment_push(line);
	}
	
	if(!header_comment.empty())
	{
		doc->set_comment(0, 0, REHex::Document::Comment(header_comment));
	}
	
	size_t last_slash = filename.find_last_of("/\\");
	std::string file_basename = (last_slash != std::string::npos ? filename.substr(last_slash + 1) : filename);
	
	doc->set_title(file_basename + " (imported)");
	doc->reset_to_clean();
	
	return doc;
}
