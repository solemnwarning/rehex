/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_UTIL_HPP
#define REHEX_UTIL_HPP

#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>
#include <wx/window.h>

namespace REHex {
	class ParseError: public std::runtime_error
	{
		public:
			ParseError(const char *what);
	};
	
	/**
	 * @brief RAII-style access to the clipboard.
	 *
	 * This class provides an RAII-style wrapper around the Open() and Close() methods of the
	 * wxTheClipboard object.
	*/
	class ClipboardGuard
	{
		private:
			bool open;
			
		public:
			/**
			 * @brief Attempts to open the clipboard. Does not throw an exception on failure.
			*/
			ClipboardGuard();
			
			/**
			 * @brief Closes the clipboard, if open.
			*/
			~ClipboardGuard();
			
			/**
			 * @brief Close the clipboard early.
			*/
			void close();
			
			/**
			 * @brief Check if the clipboard is open.
			*/
			operator bool() const
			{
				return open;
			}
	};
	
	std::vector<unsigned char> parse_hex_string(const std::string &hex_string);
	unsigned char parse_ascii_nibble(char c);
	
	void file_manager_show_file(const std::string &filename);
	
	enum OffsetBase {
		OFFSET_BASE_HEX = 1,
		OFFSET_BASE_DEC = 2,
		
		OFFSET_BASE_MIN = 1,
		OFFSET_BASE_MAX = 2,
	};
	
	std::string format_offset(off_t offset, OffsetBase base, off_t upper_bound = -1);
	
	template<typename T> typename T::iterator const_iterator_to_iterator(typename T::const_iterator &const_iter, T &container)
	{
		/* Workaround for older GCC/libstd++ which don't support passing a const_iterator
		 * to certain STL container erase methods.
		 *
		 * Not 100% sure which version actually fixed it.
		*/
		
		#if !defined(__clang__) && defined(__GNUC__) && (__GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 9))
		return std::next(container.begin(), std::distance(container.cbegin(), const_iter));
		#else
		return container.erase(const_iter, const_iter);
		#endif
	}
	
	class Document;
	class DocumentCtrl;
	
	void copy_from_doc(Document *doc, DocumentCtrl *doc_ctrl, wxWindow *dialog_parent, bool cut);
	
	/**
	 * @brief A wxColour that can be used as a key in a map/etc.
	*/
	class ColourKey
	{
		private:
			wxColour colour;
			unsigned int key;
			
			static unsigned int pack_colour(const wxColour &colour)
			{
				return (unsigned int)(colour.Red())
					| ((unsigned int)(colour.Blue())  <<  8)
					| ((unsigned int)(colour.Green()) << 16)
					| ((unsigned int)(colour.Alpha()) << 24);
			}
			
		public:
			ColourKey(const wxColour &colour):
				colour(colour),
				key(pack_colour(colour)) {}
			
			bool operator<(const ColourKey &rhs) const
			{
				return key < rhs.key;
			}
			
			bool operator==(const ColourKey &rhs) const
			{
				return key == rhs.key;
			}
			
			bool operator!=(const ColourKey &rhs) const
			{
				return key != rhs.key;
			}
			
			operator wxColour() const
			{
				return colour;
			}
	};
}

#endif /* !REHEX_UTIL_HPP */
