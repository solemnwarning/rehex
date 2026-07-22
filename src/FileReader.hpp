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

#ifndef REHEX_FILEREADER_HPP
#define REHEX_FILEREADER_HPP

#include <functional>
#include <jansson.h>
#include <memory>
#include <stdexcept>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <wx/filename.h>

#include "FourCC.hpp"

namespace REHex
{
	/**
	 * @brief Helper class for reading data from a file.
	*/
	class FileReader
	{
		private:
			std::string filename;
			FILE *fh;

			off_t position;
			off_t tlv_end;
		
		public:
			class eof_error: public std::runtime_error
			{
				public:
					eof_error(): runtime_error("Unexpected end of file/data") {}
			};

			/**
			 * @brief Create a new FileReader for reading from a filename.
			*/
			FileReader(const char *filename);
			~FileReader();
			
			/**
			 * @brief Read some data from the file.
			 *
			 * @param data      Buffer to receive the data.
			 * @param max_size  Maximum number of bytes to read from the file.
			 * @param min_size  Minimum number of bytes to read from the file.
			 *
			 * Reads data from the file until max_size bytes has been read or the end of the file is reached and
			 * returns the number of bytes read into the buffer. If the end of the file is reached before min_size
			 * bytes has been read, an eof_error exception will be thrown.
			 *
			 * Calling read() again after an exception has been thrown is undefined behaviour.
			*/
			size_t read(void *data, size_t max_size, size_t min_size);
			
			/**
			 * @brief Read a typed value from the file.
			*/
			template<typename T> T read()
			{
				T value;
				read(&value, sizeof(value), sizeof(value));
				
				return value;
			}

			/**
			 * @brief Read some data encapsulated by a type and length header from the file.
			 *
			 * This function reads four byte type and length headers from the file and calls a provided function to
			 * handle reading/processing the payload. Within the function body, reads to the file will be limited by
			 * the length header and it will be treated as the end of the file until the function returns.
			*/
			bool read_tlv(const std::function<void(const FourCC&,uint32_t)> &func);

			/**
			 * @brief Read a JSON document from a file (or TLV chunk).
			*/
			std::unique_ptr<json_t, void(*)(json_t*)> read_json(bool disable_eof_check = false);
			
			/**
			 * @brief Skip over some data in the file.
			 */
			void skip(size_t num_bytes);
			
			/**
			 * @brief Get the name of the file being read.
			*/
			wxFileName get_filename() const;
	};
}

#endif /* !REHEX_FILEREADER_HPP */
