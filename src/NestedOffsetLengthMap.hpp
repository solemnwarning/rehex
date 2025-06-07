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

#include "ByteRangeTree.hpp"

namespace REHex {
	using NestedOffsetLengthMapKey = ByteRangeTreeKey;
	
	template<typename T> class NestedOffsetLengthMap
	{
		public:
			using Node = typename ByteRangeTree<T>::Node;
			
			ByteRangeTree<T> tree;
			std::map<ByteRangeTreeKey, Node*> sorted_nodes;
			
			class const_iterator
			{
				friend NestedOffsetLengthMap;
				
				protected:
					typename std::map<ByteRangeTreeKey, Node*>::const_iterator it;
					
				public:
					using iterator_category = std::bidirectional_iterator_tag;
					using difference_type   = int;
					using value_type        = Node*;
					using pointer           = value_type*;
					using reference         = value_type&;
					
					const_iterator(const typename std::map<ByteRangeTreeKey, Node*>::const_iterator &it):
						it(it)
					{}
					
					const_iterator(const const_iterator &src):
						it(src.it)
					{}
					
					/* Prefix increment */
					const_iterator &operator++()
					{
						++it;
						return *this;
					}
					
					/* Postfix increment */
					const_iterator operator++(int)
					{
						const_iterator old = *this;
						++(*this);
						
						return old;
					}
					
					/* Prefix decrement */
					const_iterator &operator--()
					{
						--it;
						return *this;
					}
					
					/* Postfix decrement */
					const_iterator operator--(int)
					{
						const_iterator old = *this;
						--(*this);
						
						return old;
					}
					
					bool operator==(const const_iterator &rhs) const
					{
						return it == rhs.it;
					}
					
					bool operator!=(const const_iterator &rhs) const
					{
						return it != rhs.it;
					}
					
					operator const Node*() const
					{
						return it->second;
					}
					
					const Node* operator->() const
					{
						return it->second;
					}
			};
			
			class iterator: public const_iterator
			{
				friend NestedOffsetLengthMap;
				
				public:
					using iterator_category = std::bidirectional_iterator_tag;
					using difference_type   = int;
					using value_type        = Node*;
					using pointer           = value_type*;
					using reference         = value_type&;
					
					iterator(const typename std::map<ByteRangeTreeKey, Node*>::iterator &it):
						const_iterator(it) {}
					
					iterator(const iterator &src):
						const_iterator(src.it) {}
					
					operator Node*() const
					{
						return (Node*)(const_iterator::it->second);
					}
					
					Node* operator->() const
					{
						return (Node*)(const_iterator::it->second);
					}
			};
			
			NestedOffsetLengthMap() {}
			
			NestedOffsetLengthMap(const NestedOffsetLengthMap<T> &src):
				tree(src.tree)
			{
				rebuild_iterators();
			}
			
			NestedOffsetLengthMap<T> &operator=(const NestedOffsetLengthMap &src)
			{
				tree = src.tree;
				rebuild_iterators();
				
				return *this;
			}
			
			iterator begin()
			{
				return iterator(sorted_nodes.begin());
			}
			
			const_iterator begin() const
			{
				return const_iterator(sorted_nodes.begin());
			}
			
			iterator end()
			{
				return iterator(sorted_nodes.end());
			}
			
			const_iterator end() const
			{
				return const_iterator(sorted_nodes.end());
			}
			
			iterator find(const NestedOffsetLengthMapKey &key)
			{
				return iterator(sorted_nodes.find(key));
			}
			
			const_iterator find(const NestedOffsetLengthMapKey &key) const
			{
				return const_iterator(sorted_nodes.find(key));
			}
			
			size_t erase(const NestedOffsetLengthMapKey &key)
			{
				sorted_nodes.erase(key);
				return tree.erase(key);
			}
			
			size_t erase_recursive(const NestedOffsetLengthMapKey &key)
			{
				size_t erased_elements = tree.erase_recursive(key);
				if(erased_elements > 0)
				{
					rebuild_iterators();
				}
				
				return erased_elements;
			}
			
			bool set(off_t offset, off_t length, const T &value)
			{
				bool success = tree.set(offset, length, value);
				if(success)
				{
					ByteRangeTreeKey k(offset, length);
					
					#ifndef NDEBUG
					Node *n =
					#endif
					sorted_nodes[k] = tree.find_node(k);
					assert(n != NULL);
				}
				
				return success;
			}
			
			bool can_set(off_t offset, off_t length) const
			{
				return tree.can_set(offset, length);
			}
			
			size_t size() const
			{
				return tree.size();
			}
			
			bool empty() const
			{
				return tree.empty();
			}
			
			void clear()
			{
				tree.clear();
				sorted_nodes.clear();
			}
			
			void rebuild_iterators()
			{
				sorted_nodes.clear();
				
				for(auto it = tree.begin(); it != tree.end(); ++it)
				{
					sorted_nodes[it->key] = &(*it);
				}
			}
			
			bool operator==(const NestedOffsetLengthMap<T> &rhs) const
			{
				return tree == rhs.tree;
			}
			
			T &operator[](const NestedOffsetLengthMapKey &key)
			{
				return tree[key];
			}
			
			size_t data_inserted(off_t offset, off_t length)
			{
				size_t keys_modified = tree.data_inserted(offset, length);
				rebuild_iterators();
				
				return keys_modified;
			}
			
			size_t data_erased(off_t offset, off_t length)
			{
				size_t keys_modified = tree.data_erased(offset, length);
				rebuild_iterators();
				
				return keys_modified;
			}
			
			Node *find_most_specific_parent(off_t offset)
			{
				return tree.find_most_specific_parent(offset);
			}
			
			const Node *find_most_specific_parent(off_t offset) const
			{
				return tree.find_most_specific_parent(offset);
			}
	};
	
	/* Check if a key can be inserted without overlapping the start/end of another.
	 * Returns true if possible, false if it conflicts.
	*/
	template<typename T> bool NestedOffsetLengthMap_can_set(const NestedOffsetLengthMap<T> &map, off_t offset, off_t length)
	{
		return map.can_set(offset, length);
	}
	
	/* Attempt to insert or replace a value into the map.
	 * Returns true on success, false if the insertion failed due to an overlap with one or
	 * more existing elements.
	*/
	template<typename T> bool NestedOffsetLengthMap_set(NestedOffsetLengthMap<T> &map, off_t offset, off_t length, const T &value)
	{
		return map.set(offset, length, value);
	}
	
	/* Search for the most-specific element which encompasses the given offset.
	 * Returns map.end() if no match was found.
	 *
	 * NOTE: Elements with a zero length in the key are NEVER matched by this function.
	*/
	template<typename T> typename NestedOffsetLengthMap<T>::const_iterator NestedOffsetLengthMap_get(const NestedOffsetLengthMap<T> &map, off_t offset)
	{
		auto i = map.tree.find_most_specific_parent(offset);
		
		if(i != map.tree.end())
		{
			return typename NestedOffsetLengthMap<T>::const_iterator(map.sorted_nodes.find(i->key));
		}
		else{
			return typename NestedOffsetLengthMap<T>::const_iterator(map.sorted_nodes.end());
		}
	}
	
	/* Search for any elements which apply to the given offset.
	 * Returns a list of iterators, from most specific to least.
	 *
	 * NOTE: Unlike NestedOffsetLengthMap_get(), this will match keys with
	 * a length of zero.
	*/
	template<typename T> std::list<typename NestedOffsetLengthMap<T>::const_iterator> NestedOffsetLengthMap_get_all(const NestedOffsetLengthMap<T> &map, off_t offset)
	{
		const typename ByteRangeTree<T>::Node *n = map.tree.find_most_specific_parent(offset);
		
		if(n == NULL)
		{
			return std::list<typename NestedOffsetLengthMap<T>::const_iterator>();
		}
		
		std::list<typename NestedOffsetLengthMap<T>::const_iterator> iterators;
		
		if(n->get_first_child() != NULL && n->get_first_child()->key.offset == offset)
		{
			iterators.emplace_back(map.sorted_nodes.find(n->get_first_child()->key));
		}
		
		iterators.emplace_back(map.sorted_nodes.find(n->key));
		
		for(const typename ByteRangeTree<T>::Node *p = n->get_parent(); p != NULL; p = p->get_parent())
		{
			iterators.emplace_back(map.sorted_nodes.find(p->key));
		}
		
		return iterators;
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
		size_t keys_modified = map.tree.data_inserted(offset, length);
		map.rebuild_iterators();
		
		return keys_modified;
	}
	
	/* Update the keys in the map for data being erased from the file.
	 * Returns the number of keys MODIFIED or ERASED.
	*/
	template<typename T> size_t NestedOffsetLengthMap_data_erased(NestedOffsetLengthMap<T> &map, off_t offset, off_t length)
	{
		size_t keys_modified = map.tree.data_erased(offset, length);
		map.rebuild_iterators();
		
		return keys_modified;
	}
}

#endif /* !REHEX_NESTEDOFFSETLENGTHMAP_HPP */
