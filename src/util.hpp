/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <jansson.h>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>
#include <wx/config.h>
#include <wx/window.h>

#include "BitOffset.hpp"

namespace REHex {
	static constexpr off_t BYTES_PER_KiB = 1024;
	static constexpr off_t BYTES_PER_MiB = 1024 * BYTES_PER_KiB;
	static constexpr off_t BYTES_PER_GiB = 1024 * BYTES_PER_MiB;
	static constexpr off_t BYTES_PER_TiB = 1024 * BYTES_PER_GiB;
	
	static constexpr off_t BYTES_PER_kB = 1000;
	static constexpr off_t BYTES_PER_MB = 1000 * BYTES_PER_kB;
	static constexpr off_t BYTES_PER_GB = 1000 * BYTES_PER_MB;
	static constexpr off_t BYTES_PER_TB = 1000 * BYTES_PER_GB;
	
	class ParseError: public std::runtime_error
	{
		public:
			ParseError(const char *what);
	};
	
	class ParseErrorFormat: public ParseError
	{
		public:
			ParseErrorFormat(): ParseError("Number is not of a known format") {}
	};
	
	class ParseErrorRange: public ParseError
	{
		public:
			ParseErrorRange(): ParseError("Number is out of range") {}
	};
	
	class ParseErrorEmpty: public ParseError
	{
		public:
			ParseErrorEmpty(): ParseError("No number provided") {}
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
	
	float parse_float(const std::string &s);
	double parse_double(const std::string &s);
	
	void file_manager_show_file(const std::string &filename);
	
	enum OffsetBase {
		OFFSET_BASE_HEX = 1,
		OFFSET_BASE_DEC = 2,
		
		OFFSET_BASE_MIN = 1,
		OFFSET_BASE_MAX = 2,
	};
	
	std::string format_offset(off_t offset, OffsetBase base, off_t upper_bound = -1);
	std::string format_offset(BitOffset offset, OffsetBase base, BitOffset upper_bound = BitOffset::INVALID);
	
	enum class SizeUnit
	{
		B = 1,    /**< Byte (8 bits) */
		
		KiB = 11, /**< Kibibyte (1,024 bytes) */
		MiB,      /**< Mebibyte (1,024 KiB) */
		GiB,      /**< Gibibyte (1,024 MiB) */
		TiB,      /**< Tebibyte (1,024 GiB) */
		
		kB = 21,  /**< Kilobyte (1,000 bytes) */
		MB,       /**< Megabyte (1,000 kB) */
		GB,       /**< Gigabyte (1,000 MB) */
		TB,       /**< Terabyte (1,000 GB) */
		
		AUTO_XiB = 31,  /**< Appropriate "binary" unit (B, KiB, MiB, etc) */
		AUTO_XB,        /**< Appropriate "decimal" unit (B, kB, MB, etc) */
	};
	
	/**
	 * @brief Format a size in bytes for display with the users selected units.
	*/
	std::string format_size(off_t size_bytes);
	
	/**
	 * @brief Format a size in bytes for display in a specific unit.
	*/
	std::string format_size(off_t size_bytes, SizeUnit unit);
	
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
	
	void fake_broken_mouse_capture(wxWindow *window);
	
	std::string document_save_as_dialog(wxWindow *modal_parent, Document *document);
	
	struct CarryBits
	{
		unsigned char value;
		unsigned char mask;
		
		CarryBits():
			value(0),
			mask(0) {}
		
		CarryBits(unsigned char value, unsigned char mask):
			value(value),
			mask(mask) {}
	};
	
	/**
	 * @brief Copy memory with left bit shifting.
	 *
	 * @param dst   Destination buffer.
	 * @param src   Source buffer.
	 * @param n     Number of bytes to copy.
	 * @param shift Number of bits to left shift by (0-7).
	 *
	 * @returns The bits removed from the first byte.
	 *
	 * Copies a range of bytes between buffers, left shifting bits through the entire range,
	 * removing the leftmost bits from the first byte and inserting zeros to the rightmost end
	 * of the last byte.
	 *
	 * Any bits shifted off the end of the first byte are returned, shifted ready for being
	 * bitwise OR'd into the end of a buffer preceeding dst when copying in chunks.
	*/
	CarryBits memcpy_left(void *dst, const void *src, size_t n, int shift);
	
	/**
	 * @brief Copy memory with right bit shifting.
	 *
	 * @param dst   Destination buffer.
	 * @param src   Source buffer.
	 * @param n     Number of bytes to copy.
	 * @param shift Number of bits to right shift by (0-7).
	 *
	 * @returns The surplus bits from the end of the last byte.
	 *
	 * Copies a range of bytes between buffers, right shifting bits through the entire range,
	 * removing the rightmost bits from the last byte and preserving the existing bits to the
	 * left of where the bits are placed in the destination buffer.
	 *
	 * Any bits shifted off the end of the last byte are returned, shifted ready for being
	 * bitwise OR'd into the start of a buffer following dst when copying in chunks.
	*/
	CarryBits memcpy_right(void *dst, const void *src, size_t n, int shift);
	
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
	
	template<typename T> T _add_clamp_overflow(T a, T b, bool *overflow, T T_min, T T_max, T T_zero)
	{
		if((a < T_zero) != (b < T_zero))
		{
			/* a and b have differing signs - can't overflow */
			if(overflow != NULL)
			{
				*overflow = false;
			}
			
			return a + b;
		}
		else if(a < T_zero)
		{
			/* a and b are negative */
			
			if((T_min - b) <= a)
			{
				/* a + b >= T_min */
				if(overflow != NULL)
				{
					*overflow = false;
				}
				
				return a + b;
			}
			else{
				/* a + b < T_min (underflow) */
				if(overflow != NULL)
				{
					*overflow = true;
				}
				
				return T_min;
			}
		}
		else{
			/* a and b are positive */
			
			if((T_max - b) >= a)
			{
				/* a + b <= T_max */
				if(overflow != NULL)
				{
					*overflow = false;
				}
				
				return a + b;
			}
			else{
				/* a + b > T_max (overflow) */
				if(overflow != NULL)
				{
					*overflow = true;
				}
				
				return T_max;
			}
		}
	}
	
	/**
	 * @brief Adds two integers together, clamping to the range of the type.
	 *
	 * This function adds two integer-type values together, if the result would overflow or
	 * underflow, the result is clamped to the maximum or minimum value representable by the
	 * type T.
	 *
	 * If the "overflow" parameter is non-NULL, whether or not an overflow (or underflow) was
	 * detected is stored there.
	*/
	template<typename T> T add_clamp_overflow(T a, T b, bool *overflow = NULL)
	{
		return _add_clamp_overflow<T>(a, b, overflow, std::numeric_limits<T>::min(), std::numeric_limits<T>::max(), 0);
	}
	
	/**
	 * @brief Specialisation of add_clamp_overflow<T>() for BitOffset.
	*/
	template<> BitOffset add_clamp_overflow(BitOffset a, BitOffset b, bool *overflow);
	
	/**
	 * @brief Multiply two integers together, clamping to the range of the type.
	 *
	 * This function multiplies two integer-type values together, if the result would overflow
	 * or underflow, the result is clamped to the maximum or minimum value representable by the
	 * type T.
	 *
	 * If the "overflow" parameter is non-NULL, whether or not an overflow (or underflow) was
	 * detected is stored there.
	*/
	template<typename T> T multiply_clamp_overflow(T a, T b, bool *overflow = NULL)
	{
		constexpr T MAX = std::numeric_limits<T>::max();
		constexpr T MIN = std::numeric_limits<T>::min();
		
		if(a == 0 || b == 0)
		{
			return 0;
		}
		
		if(a < 0 && b < 0)
		{
			a *= -1;
			b *= -1;
		}
		
		bool did_overflow;
		T result;
		
		if(a > 0 && b > 0)
		{
			if((MAX / a) < b)
			{
				result = MAX;
				did_overflow = true;
			}
			else{
				result = a * b;
				did_overflow = false;
			}
		}
		else if(a > 0)
		{
			if((MIN / a) > b)
			{
				result = MIN;
				did_overflow = true;
			}
			else{
				result = a * b;
				did_overflow = false;
			}
		}
		else{
			if((MIN / b) > a)
			{
				result = MIN;
				did_overflow = true;
			}
			else{
				result = a * b;
				did_overflow = false;
			}
		}
		
		if(overflow != NULL)
		{
			*overflow = did_overflow;
		}
		
		return result;
	}
	
	json_t *colour_to_json(const wxColour &colour);
	wxColour colour_from_json(const json_t *json);
	
	std::string colour_to_string(const wxColour &colour);
	wxColour colour_from_string(const std::string &s);
	
	enum class Edge
	{
		LEFT,
		RIGHT,
		TOP,
		BOTTOM,
	};
	
	/**
	 * @brief Find the nearest edge to a point specified in a rectangle.
	*/
	Edge find_nearest_edge(const wxPoint &point, const wxRect &rect);
	
	/**
	 * @brief Create directory and any missing path components.
	 *
	 * Creates the directory and any parent directories which don't exist. Returns true if
	 * the directory now exists (or aready did), false on error.
	*/
	bool recursive_mkdir(const std::string &path);
	
	/**
	 * @brief Recursively copy values between wxConfig objects.
	 *
	 * @param dst       Destination wxConfig object to write to.
	 * @param dst_path  Path to write copied groups/entries under.
	 * @param src       Source wxConfig object to read from.
	 * @param src_path  Path to read groups/entries from.
	 *
	 * This function copies all entries/groups under src_path in src to dst_path in dst.
	 *
	 * Both paths may be relative (to the current wxConfig path) or absolute, dst/src may be
	 * the same or different wxConfig objects.
	*/
	void config_copy(wxConfig *dst, const wxString &dst_path, const wxConfig &src, const wxString &src_path);
}

#endif /* !REHEX_UTIL_HPP */
