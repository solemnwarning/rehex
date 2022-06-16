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

#ifndef REHEX_UNSORTEDMAPVECTOR_HPP
#define REHEX_UNSORTEDMAPVECTOR_HPP

#include <algorithm>
#include <utility>
#include <vector>

namespace REHex
{
	/**
	 * @brief Lookup table built on top of std::vector.
	 *
	 * This implements an associative store built on top of std::vector, which uses
	 * linear search to find elements and compares keys for equality.
	 *
	 * Assuming the vector doesn't need to resize to accomodate new elements, insertions
	 * are cheap and won't require any additional allocations. Searching is expensive
	 * (worst case O(n)), so it is best used for small, shortly-lived datasets that must
	 * be populated quickly, used and then discarded.
	*/
	template<typename K, typename V> class UnsortedMapVector
	{
		private:
			std::vector< std::pair<const K, V> > vec;
			
		public:
			typedef typename std::vector< std::pair<const K, V> >::iterator iterator;
			
			/**
			 * @brief Find an element by key.
			 *
			 * Always returns a reference, inserts a new element using the default constructor
			 * for V if an undefined key is used.
			*/
			V &operator[](const K &key)
			{
				auto i = std::find_if(vec.begin(), vec.end(),
					[&](const std::pair<const K, V> &elem)
					{
						return elem.first == key;
					});
				
				if(i != vec.end())
				{
					return i->second;
				}
				else{
					vec.emplace_back(key, V());
					return vec.back().second;
				}
			}
			
			/**
			 * @brief Returns the begin iterator of the underlying vector.
			*/
			iterator begin()
			{
				return vec.begin();
			}
			
			/**
			 * @brief Returns the end iterator of the underlying vector.
			*/
			iterator end()
			{
				return vec.end();
			}
			
			/**
			 * @brief Insert an element.
			 *
			 * If no element exists with the same key, inserts it into the vector and returns
			 * the iterator and true.
			 *
			 * If an element already exists with the key, the vector is unchanged and an
			 * iterator to the existing element is returned (also false).
			*/
			std::pair<iterator, bool> insert(const std::pair<const K, V> &item)
			{
				auto i = std::find_if(vec.begin(), vec.end(),
					[&](const std::pair<const K, V> &elem)
					{
						return elem.first == item.first;
					});
				
				if(i != vec.end())
				{
					return std::make_pair(i, false);
				}
				else{
					vec.emplace_back(item);
					return std::make_pair(std::prev(vec.end()), true);
				}
			}
	};
}

#endif /* !REHEX_UNSORTEDMAPVECTOR_HPP */
