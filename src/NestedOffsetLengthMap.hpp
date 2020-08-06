/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018-2020 Daniel Collins <solemnwarning@solemnwarning.net>
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

/* This almost-a-specialisation of std::map is intended for storing values which apply to a range
 * of bytes in a file and may be nested, but must not partially overlap each other.
 *
 * Obvious use cases are highlighting and annotations which apply to selections in the file and
 * may be nested when describing data structures, but may not be split between other annotations
 * because that way madness lies.
*/

#ifndef REHEX_NESTEDOFFSETLENGTHMAP_HPP
#define REHEX_NESTEDOFFSETLENGTHMAP_HPP

#include <iterator>
#include <limits>
#include <list>
#include <map>
#include <stdio.h>

namespace REHex {
	struct NestedOffsetLengthMapKey
	{
		off_t offset;
		off_t length;
		
		NestedOffsetLengthMapKey(off_t offset, off_t length):
			offset(offset), length(length) {}
		
		bool operator<(const NestedOffsetLengthMapKey &rhs) const
		{
			if(offset == rhs.offset)
			{
				return length < rhs.length;
			}
			else{
				return offset < rhs.offset;
			}
		}
		
		bool operator==(const NestedOffsetLengthMapKey &rhs) const
		{
			return offset == rhs.offset && length == rhs.length;
		}
	};
	
	template<typename T> using NestedOffsetLengthMap = std::map<NestedOffsetLengthMapKey, T>;
	
	/* Check if a key can be inserted without overlapping the start/end of another.
	 * Returns true if possible, false if it conflicts.
	*/
	template<typename T> bool NestedOffsetLengthMap_can_set(const NestedOffsetLengthMap<T> &map, off_t offset, off_t length)
	{
		auto i = map.find(NestedOffsetLengthMapKey(offset, length));
		if(i != map.end())
		{
			return true;
		}
		
		off_t end = offset + length;
		
		i = map.lower_bound(NestedOffsetLengthMapKey(offset, 0));
		if(i == map.end() && !map.empty())
		{
			--i;
		}
		
		if(!map.empty())
		{
			for(;; --i)
			{
				off_t i_offset = i->first.offset;
				off_t i_end    = i_offset + i->first.length;
				
				if(i_offset < offset && i_end > offset && i_end < end)
				{
					/* There is an element with a lower offset, which extends into
					 * the new key, but doesn't fully contain it.
					*/
					return false;
				}
				
				if(i == map.begin())
				{
					break;
				}
			}
		}
		
		i = map.upper_bound(NestedOffsetLengthMapKey(offset, std::numeric_limits<off_t>::max()));
		for(; i != map.end(); ++i)
		{
			off_t i_offset = i->first.offset;
			off_t i_end    = i_offset + i->first.length;
			
			if(i_offset >= end)
			{
				break;
			}
			
			if(end < i_end)
			{
				/* We extend into the next element, but do not encompass it. */
				return false;
			}
		}
		
		return true;
	}
	
	/* Attempt to insert or replace a value into the map.
	 * Returns true on success, false if the insertion failed due to an overlap with one or
	 * more existing elements.
	*/
	template<typename T> bool NestedOffsetLengthMap_set(NestedOffsetLengthMap<T> &map, off_t offset, off_t length, const T &value)
	{
		auto i = map.find(NestedOffsetLengthMapKey(offset, length));
		if(i != map.end())
		{
			i->second = value;
			return true;
		}
		
		if(!NestedOffsetLengthMap_can_set(map, offset, length))
		{
			return false;
		}
		
		map.insert(std::make_pair(NestedOffsetLengthMapKey(offset, length), value));
		return true;
	}
	
	/* Search for the most-specific element which encompasses the given offset.
	 * Returns map.end() if no match was found.
	 *
	 * NOTE: Elements with a zero length in the key are NEVER matched by this function.
	*/
	template<typename T> typename NestedOffsetLengthMap<T>::const_iterator NestedOffsetLengthMap_get(const NestedOffsetLengthMap<T> &map, off_t offset)
	{
		auto i = map.lower_bound(NestedOffsetLengthMapKey(offset, 1));
		auto r = map.end();
		
		if(i == map.end() && !map.empty())
		{
			--i;
		}
		
		if(i != map.end())
		{
			for(;; --i)
			{
				off_t i_offset = i->first.offset;
				off_t i_end    = i_offset + i->first.length;
				
				if(r != map.end() && i_offset != r->first.offset)
				{
					break;
				}
				
				if(i_offset <= offset && i_end > offset)
				{
					r = i;
				}
				
				if(i == map.begin())
				{
					break;
				}
			}
		}
		
		return r;
	}
	
	/* Search for any elements which apply to the given offset.
	 * Returns a list of iterators, from most specific to least.
	 *
	 * NOTE: Unlike NestedOffsetLengthMap_get(), this will match keys with
	 * a length of zero.
	*/
	template<typename T> std::list<typename NestedOffsetLengthMap<T>::const_iterator> NestedOffsetLengthMap_get_all(const NestedOffsetLengthMap<T> &map, off_t offset)
	{
		std::list<typename NestedOffsetLengthMap<T>::const_iterator> r;
		
		auto i = map.upper_bound(NestedOffsetLengthMapKey(offset, std::numeric_limits<off_t>::max()));
		if(i == map.end() && !map.empty())
		{
			--i;
		}
		
		if(i != map.end())
		{
			off_t this_off = i->first.offset;
			std::list<typename NestedOffsetLengthMap<T>::const_iterator> this_r;
			
			for(;; --i)
			{
				off_t i_offset = i->first.offset;
				off_t i_end    = i_offset + i->first.length;
				
				if(i_offset != this_off)
				{
					r.insert(r.end(), this_r.begin(), this_r.end());
					this_r.clear();
					
					this_off = i_offset;
				}
				
				if((i_offset <= offset && i_end > offset) || i_offset == offset)
				{
					this_r.push_front(i);
				}
				
				if(i == map.begin())
				{
					break;
				}
			}
			
			r.insert(r.end(), this_r.begin(), this_r.end());
		}
		
		return r;
	}
	
	/* Search for an exact key and any keys within that key's scope.
	 * Returns a list of iterators in the same order as the map.
	*/
	template<typename T> std::list<typename NestedOffsetLengthMap<T>::const_iterator> NestedOffsetLengthMap_get_recursive(const NestedOffsetLengthMap<T> &map, const NestedOffsetLengthMapKey &key)
	{
		std::list<typename NestedOffsetLengthMap<T>::const_iterator> r;
		
		auto i = map.find(key);
		if(i == map.end())
		{
			/* Key not found. */
			return r;
		}
		
		/* Add any keys at the same offset with shorter lengths. */
		for(auto j = i; j != map.begin();)
		{
			--j;
			
			if(j->first.offset == key.offset)
			{
				r.push_front(j);
			}
		}
		
		/* Add the exact key. */
		r.push_back(i);
		
		/* Skip over any keys at the same offset with larger lengths. */
		while(i != map.end() && i->first.offset == key.offset)
		{
			++i;
		}
		
		/* Add any keys with greater offsets within the key's length. */
		while(i != map.end() && i->first.offset < (key.offset + key.length))
		{
			r.push_back(i);
			++i;
		}
		
		return r;
	}
	
	/* Update the keys in the map for data being inserted into the file.
	 * Returns the number of keys MODIFIED.
	*/
	template<typename T> size_t NestedOffsetLengthMap_data_inserted(NestedOffsetLengthMap<T> &map, off_t offset, off_t length)
	{
		NestedOffsetLengthMap<T> new_map;
		size_t keys_modified = 0;
		
		for(auto i = map.begin(); i != map.end(); ++i)
		{
			off_t i_offset = i->first.offset;
			off_t i_length = i->first.length;
			
			if(i_offset >= offset)
			{
				new_map.emplace(NestedOffsetLengthMapKey((i_offset + length), i_length), i->second);
				++keys_modified;
			}
			else if(i_offset < offset && (i_offset + i_length) > offset)
			{
				new_map.emplace(NestedOffsetLengthMapKey(i_offset, (i_length + length)), i->second);
				++keys_modified;
			}
			else{
				new_map.emplace(*i);
			}
		}
		
		map.swap(new_map);
		return keys_modified;
	}
	
	/* Update the keys in the map for data being erased from the file.
	 * Returns the number of keys MODIFIED or ERASED.
	*/
	template<typename T> size_t NestedOffsetLengthMap_data_erased(NestedOffsetLengthMap<T> &map, off_t offset, off_t length)
	{
		off_t end = offset + length;
		
		NestedOffsetLengthMap<T> new_map;
		size_t keys_modified = 0;
		
		for(auto i = map.begin(); i != map.end(); ++i)
		{
			off_t i_offset = i->first.offset;
			off_t i_length = i->first.length;
			
			if(offset <= i_offset && end > (i_offset + i_length - (i_length > 0)))
			{
				/* This key is wholly encompassed by the deleted range. */
				++keys_modified;
				continue;
			}
			
			if(offset >= i_offset && offset < (i_offset + i_length))
			{
				i_length -= std::min(length, (i_length - (offset - i_offset)));
			}
			else if(end > i_offset && end < (i_offset + i_length))
			{
				i_length -= end - i_offset;
			}
			
			if(i_offset > offset)
			{
				i_offset -= std::min(length, (i_offset - offset));
			}
			
			if(i_offset != i->first.offset || i_length != i->first.length)
			{
				++keys_modified;
			}
			
			new_map.emplace(NestedOffsetLengthMapKey(i_offset, i_length), i->second);
		}
		
		map.swap(new_map);
		return keys_modified;
	}
}

#endif /* !REHEX_NESTEDOFFSETLENGTHMAP_HPP */
