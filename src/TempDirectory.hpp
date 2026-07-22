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

#ifndef REHEX_TEMPDIRECTORY_HPP
#define REHEX_TEMPDIRECTORY_HPP

#include <string>

namespace REHex
{
	/**
	 * @brief RAII-managed temporary directory.
	 *
	 * TempDirectory creates an empty directory on the filesystem when
	 * constructed and deletes it (and any child files/directories) when
	 * destroyed.
	*/
	class TempDirectory
	{
		private:
			std::string m_path;
			
		public:
			TempDirectory();
			~TempDirectory();
			
			/**
			 * @brief Get the path to the created directory, with trailing slash.
			*/
			std::string path() const;
	};
}

#endif /* !REHEX_TEMPDIRECTORY_HPP */
