/* Reverse Engineer's Hex Editor
 * Copyright (C) 2023-2026 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_FILEWRITER_HPP
#define REHEX_FILEWRITER_HPP

#include <functional>
#include <stdio.h>
#include <string>
#include <wx/filename.h>

#include "FourCC.hpp"

namespace REHex
{
	/**
	 * @brief Helper class for writing data to a new file.
	 *
	 * This class is a wrapper around stdio for creating/replacing files.
	 *
	 * Once a file is created, the write() method can be called multiple times to stream data
	 * into it, finally calling commit() to finish writing and close the file.
	 *
	 * If the object is destroyed before commit() is called, it is assumed an error occured in
	 * the caller before the file was completed and any data written so far is discarded.
	*/
	class FileWriter
	{
		private:
			std::string filename;
			FILE *fh;

			off_t tell() const;

			void seek(off_t offset);
		
		public:
			/**
			 * @brief Create a new FileWriter for writing to filename.
			*/
			FileWriter(const char *filename);
			~FileWriter();
			
			/**
			 * @brief Write some data to the file.
			 *
			 * Throws on error. Calling write() after a previous error or call to
			 * commit() is undefined behaviour.
			*/
			void write(const void *data, size_t size);
			
			/**
			 * @brief Write a value to the file.
			 *
			 * Throws on error. Calling write() after a previous error or call to
			 * commit() is undefined behaviour.
			*/
			template<typename T> void write(const T &value)
			{
				write(&value, sizeof(value));
			}
			
			/**
			 * @brief Encapsulate some data with a type and length header.
			 *
			 * @brief type  Four byte type identifying the data record.
			 * @brief func  Function which will write data within the record.
			 */
			void write_tlv(const FourCC &type, const std::function<void()> &func);

			/**
			 * @brief Encapsulate some data with a type and length header.
			 *
			 * @brief type  Four byte type identifying the data record.
			 * @brief data  Data pointer.
			 * @brief size  Size of data.
			*/
			void write_tlv(const FourCC &type, const void *data, size_t size);
			
			/**
			 * @brief Commit any outstanding writes to the file and close.
			 *
			 * Throws on error. Calling after a previous error or call to commit() is
			 * undefined behaviour.
			*/
			void commit();
			
			/**
			 * @brief Get the name of the file being created.
			 *
			 * NOTE: The returned name is where the file will be accessible after the commit()
			 * method has been called, before that point there may be nothing there or it may even
			 * be a different file.
			*/
			wxFileName get_filename() const;
	};
}

#endif /* !REHEX_FILEWRITER_HPP */
