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

#ifndef REHEX_ENDIAN_CONV_HPP
#define REHEX_ENDIAN_CONV_HPP

#include <portable_endian.h>

namespace REHex
{
	/**
	 * @fn template<typename T> T beXXXtoh_p(const void *p)
	 * @brief Convert a value of type T from big endian to host endian.
	*/
	
	template<typename T>
		typename std::enable_if<sizeof(T) == sizeof(uint16_t), T>::type
		beXXXtoh_p(const void *be_ptr)
	{
		uint16_t be_int;
		memcpy(&be_int, be_ptr, sizeof(T));
		
		uint16_t he_int = be16toh(be_int);
		
		T he_val;
		memcpy(&he_val, &he_int, sizeof(he_int));
		
		return he_val;
	}
	
	template<typename T>
		typename std::enable_if<sizeof(T) == sizeof(uint32_t), T>::type
		beXXXtoh_p(const void *be_ptr)
	{
		uint32_t be_int;
		memcpy(&be_int, be_ptr, sizeof(T));
		
		uint32_t he_int = be32toh(be_int);
		
		T he_val;
		memcpy(&he_val, &he_int, sizeof(he_int));
		
		return he_val;
	}
	
	template<typename T>
		typename std::enable_if<sizeof(T) == sizeof(uint64_t), T>::type
		beXXXtoh_p(const void *be_ptr)
	{
		uint64_t be_int;
		memcpy(&be_int, be_ptr, sizeof(T));
		
		uint64_t he_int = be64toh(be_int);
		
		T he_val;
		memcpy(&he_val, &he_int, sizeof(he_int));
		
		return he_val;
	}
	
	/**
	 * @brief Convert a value of type T from host endian to big endian.
	*/
	template<typename T> T htobeXXX_p(const void *h_ptr)
	{
		return beXXXtoh_p<T>(h_ptr);
	}
	
	/**
	 * @brief Convert a value of type T from big endian to host endian.
	*/
	template<typename T> T beXXXtoh(T be_val)
	{
		return beXXXtoh_p<T>(&be_val);
	}
	
	/**
	 * @brief Convert a value of type T from host endian to big endian.
	*/
	template<typename T> T htobeXXX(T h_val)
	{
		return htobeXXX_p<T>(&h_val);
	}
	
	/**
	 * @fn template<typename T> T leXXXtoh_p(const void *p)
	 * @brief Convert a value of type T from little endian to host endian.
	*/
	
	template<typename T>
		typename std::enable_if<sizeof(T) == sizeof(uint16_t), T>::type
		leXXXtoh_p(const void *le_ptr)
	{
		uint16_t le_int;
		memcpy(&le_int, le_ptr, sizeof(T));
		
		uint16_t he_int = le16toh(le_int);
		
		T he_val;
		memcpy(&he_val, &he_int, sizeof(he_int));
		
		return he_val;
	}
	
	template<typename T>
		typename std::enable_if<sizeof(T) == sizeof(uint32_t), T>::type
		leXXXtoh_p(const void *le_ptr)
	{
		uint32_t le_int;
		memcpy(&le_int, le_ptr, sizeof(T));
		
		uint32_t he_int = le32toh(le_int);
		
		T he_val;
		memcpy(&he_val, &he_int, sizeof(he_int));
		
		return he_val;
	}
	
	template<typename T>
		typename std::enable_if<sizeof(T) == sizeof(uint64_t), T>::type
		leXXXtoh_p(const void *le_ptr)
	{
		uint64_t le_int;
		memcpy(&le_int, le_ptr, sizeof(T));
		
		uint64_t he_int = le64toh(le_int);
		
		T he_val;
		memcpy(&he_val, &he_int, sizeof(he_int));
		
		return he_val;
	}
	
	/**
	 * @brief Convert a value of type T from host endian to little endian.
	*/
	template<typename T> T htoleXXX_p(const void *h_ptr)
	{
		return leXXXtoh_p<T>(h_ptr);
	}
	
	/**
	 * @brief Convert a value of type T from little endian to host endian.
	*/
	template<typename T> T leXXXtoh(T le_val)
	{
		return leXXXtoh_p<T>(&le_val);
	}
	
	/**
	 * @brief Convert a value of type T from host endian to little endian.
	*/
	template<typename T> T htoleXXX(T h_val)
	{
		return htoleXXX_p<T>(&h_val);
	}
}

#endif /* !REHEX_ENDIAN_CONV_HPP */
