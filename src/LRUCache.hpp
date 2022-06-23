/* Reverse Engineer's Hex Editor
 * Copyright (C) 2021-2022 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_LRUCACHE_HPP
#define REHEX_LRUCACHE_HPP

#include <assert.h>
#include <list>
#include <map>

namespace REHex
{
	/**
	 * @brief Least-Recently Used Cache implementation.
	*/
	template<typename K, typename V> class LRUCache
	{
		private:
			const size_t max_items;
			
			/* "queue" contains a list of key/value pairs in the cache, with the more
			 * recently accessed elements nearer the front.
			 *
			 * "map" contains a mapping of keys to iterators within the queue.
			 *
			 * When an element is read or written, it is moved to the front of "queue".
			 *
			 * When an element is added and the cache is full, elements are removed
			 * starting from the back of the queue.
			*/
			
			mutable std::list< std::pair<K, V> > queue;
			
			typedef typename std::list< std::pair<K, V> >::iterator queue_iter_t;
			std::map<K, queue_iter_t> map;
			
		public:
			LRUCache(size_t max_items):
				max_items(max_items) {}
			
			/**
			 * @brief Search the cache for an element with the given key.
			 * @return Pointer to the cached value, or NULL.
			*/
			const V *get(const K &k) const;
			
			/**
			 * @brief Store a value in the cache.
			*/
			const V *set(const K &k, const V &v);
			
			/**
			 * @brief Remove all values from the cache.
			*/
			void clear();
	};
}

template<typename K, typename V> const V *REHex::LRUCache<K,V>::get(const K &k) const
{
	auto i = map.find(k);
	
	if(i != map.end())
	{
		queue.splice(queue.begin(), queue, i->second);
		return &(i->second->second);
	}
	else{
		return NULL;
	}
}

template<typename K, typename V> const V *REHex::LRUCache<K,V>::set(const K &k, const V &v)
{
	/* Check if we already have this key, and move it to the front of queue if we do. */
	const V *old_v = get(k);
	
	if(old_v != NULL)
	{
		/* Replace the existing value. */
		
		assert(!(queue.front().first < k || k < queue.front().first));

		queue.pop_front();
		
		queue.push_front(std::make_pair(k, v));
		map[k] = queue.begin();
	}
	else{
		/* Make space to keep us under the limit (if necessary) and add the new element. */
		
		while(queue.size() >= max_items)
		{
			map.erase(queue.back().first);
			queue.pop_back();
		}
		
		queue.push_front(std::make_pair(k, v));
		map[k] = queue.begin();
	}

	return &(queue.front().second);
}

template<typename K, typename V> void REHex::LRUCache<K,V>::clear()
{
	map.clear();
	queue.clear();
}

#endif /* !REHEX_LRUCACHE_HPP */
