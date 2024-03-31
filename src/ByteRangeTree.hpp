/* Reverse Engineer's Hex Editor
 * Copyright (C) 2023-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_BYTERANGETREE_HPP
#define REHEX_BYTERANGETREE_HPP

#include <algorithm>
#include <assert.h>
#include <functional>
#include <memory>
#include <set>
#include <stdlib.h>
#include <vector>

#include "BitOffset.hpp"

#ifndef NDEBUG
// #define REHEX_BYTERANGETREE_CHECKS
// #define REHEX_BYTERANGETREE_DIAGS
#endif

namespace REHex
{
	template<typename OT> struct RangeTreeKey
	{
		OT offset;
		OT length;
		
		RangeTreeKey(OT offset, OT length):
			offset(offset), length(length) {}
		
		bool operator<(const RangeTreeKey<OT> &rhs) const
		{
			if(offset == rhs.offset)
			{
				return length < rhs.length;
			}
			else{
				return offset < rhs.offset;
			}
		}
		
		bool operator==(const RangeTreeKey<OT> &rhs) const
		{
			return offset == rhs.offset && length == rhs.length;
		}
		
		bool contains(const RangeTreeKey<OT> &inner) const
		{
			return offset <= inner.offset && (offset + length) >= (inner.offset + inner.length);
		}
	};
	
	/**
	 * @brief A store for hierarchical data associated with a byte range.
	 *
	 * This class allows storing and retriving unique values associated with a byte range.
	 *
	 * Elements are implicitly arranged into a hierarchy where elements whose offset/length is
	 * fully encompassed by another are stored under them. Elements may not span the start/end
	 * of an existing element and attempting to insert such an element will fail.
	 *
	 * Unless otherwise noted, iterators and Node* pointers obtained from this class are stable
	 * and will not be invalidated by modifications to other elements.
	*/
	template<typename OT, typename T> class RangeTree
	{
		private:
			struct NodeRef;
			
		public:
			/**
			 * @brief An element in a RangeTree.
			*/
			class Node
			{
				friend RangeTree;
				
				public:
					const RangeTreeKey<OT> key; /**< The key (offset+length) of the element. */
					T value;                    /**< The value of the element. */
					
					/* Compatibility hack for old code written against the
					 * NestedOffsetMap container.
					*/
					const RangeTreeKey<OT> &first;
					T &second;
					
				private:
					Node *parent;
					
					Node *prev_sibling;
					Node *next_sibling;
					
					std::vector<NodeRef> children;
					
					/**
					 * @brief Constructor for new nodes being inserted.
					*/
					Node(OT offset, OT length, const T& value):
						key(offset, length),
						value(value),
						first(key),
						second(this->value),
						parent(NULL),
						prev_sibling(NULL),
						next_sibling(NULL) {}
					
					/**
					 * @brief Constructor for replacing nodes.
					 *
					 * This constructor is used for cases where we need to move
					 * the offset/length of an existing element.
					 *
					 * The value and any children are MOVED to the new element
					 * and any neighbor pointers (and back-pointers) are linked
					 * to/from the new Node.
					 *
					 * This invalidates the contents of the old Node.
					*/
					Node(OT offset, OT length, Node &&node):
						key(offset, length),
						value(std::move(node.value)),
						first(key),
						second(this->value),
						parent(node.parent),
						prev_sibling(node.prev_sibling),
						next_sibling(node.next_sibling),
						children(std::move(node.children))
					{
						if(prev_sibling != NULL)
						{
							assert(prev_sibling->next_sibling == &node);
							prev_sibling->next_sibling = this;
						}
						
						if(next_sibling != NULL)
						{
							assert(next_sibling->prev_sibling == &node);
							next_sibling->prev_sibling = this;
						}
						
						for(auto c = children.begin(); c != children.end(); ++c)
						{
							(*c)->parent = this;
						}
					}
					
				public:
					/**
					 * @brief Get the previous sibling node.
					 * @returns Node pointer, NULL if not found.
					*/
					Node *get_prev()
					{
						return prev_sibling;
					}
					
					const Node *get_prev() const
					{
						return prev_sibling;
					}
					
					/**
					 * @brief Get the next sibling node.
					 * @returns Node pointer, NULL if not found.
					*/
					Node *get_next()
					{
						return next_sibling;
					}
					
					const Node *get_next() const
					{
						return next_sibling;
					}
					
					/**
					 * @brief Get the parent node.
					 * @returns Node pointer, NULL if not found.
					*/
					Node *get_parent()
					{
						return parent;
					}
					
					const Node *get_parent() const
					{
						return parent;
					}
					
					/**
					 * @brief Get the first child of this node.
					 * @returns Node pointer, NULL if not found.
					*/
					Node *get_first_child()
					{
						return children.empty()
							? NULL
							: children.front().node.get();
					}
					
					const Node *get_first_child() const
					{
						return children.empty()
							? NULL
							: children.front().node.get();
					}
					
					/**
					 * @brief Get the last child of this node.
					 * @returns Node pointer, NULL if not found.
					*/
					Node *get_last_child()
					{
						return children.empty()
							? NULL
							: children.back().node.get();
					}
					
					const Node *get_last_child() const
					{
						return children.empty()
							? NULL
							: children.back().node.get();
					}
			};
			
		private:
			struct NodeRef
			{
				RangeTreeKey<OT> key;
				std::unique_ptr<Node> node;
				
				NodeRef(OT offset, OT length):
					key(offset, length) {}
				
				NodeRef(const RangeTreeKey<OT> &key, Node *node = NULL):
					key(key), node(node) {}
				
				NodeRef(NodeRef &&src) = default;
				NodeRef &operator=(NodeRef &&src) = default;
				
				NodeRef(const NodeRef &src) = delete;
				
				operator Node*() const
				{
					assert(node);
					return node.get();
				}
				
				Node* operator->() const
				{
					assert(node);
					return node.get();
				}
				
				static bool offset_lt(const NodeRef &lhs, const NodeRef &rhs)
				{
					return lhs.key.offset < rhs.key.offset;
				}
				
				static bool key_lt(const NodeRef &lhs, const NodeRef &rhs)
				{
					return lhs.key < rhs.key;
				}
			};
			
			std::vector<NodeRef> root;
			size_t total_size;
			
			size_t erase_recursive_impl(Node *node);
			
			void check() const;
			
		public:
			/**
			 * @brief Class for iterating over elements in a RangeTree.
			 *
			 * This class can be used to iterate over the elements in a RangeTree,
			 * in a manner similar to classical C++ iterators - the nodes at all levels
			 * will be visited in order of insertion.
			*/
			class iterator
			{
				friend RangeTree;
				
				protected:
					RangeTree<OT, T> *tree;
					Node *node;
					
				private:
					iterator(RangeTree<OT, T> *tree, Node *node):
						tree(tree),
						node(node) {}
					
					std::vector<NodeRef> &node_container() const
					{
						assert(node != NULL);
						
						if(node->parent != NULL)
						{
							return node->parent->children;
						}
						else{
							return tree->root;
						}
					}
					
				public:
					using iterator_category = std::bidirectional_iterator_tag;
					using difference_type   = ssize_t;
					using value_type        = Node*;
					using pointer           = value_type*;
					using reference         = value_type&;
					
					/* Prefix increment */
					iterator &operator++()
					{
						assert(node != NULL);
						
						node = RangeTree<OT, T>::next_depth_first_node(node);
						return *this;
					}
					
					/* Postfix increment */
					iterator operator++(int)
					{
						iterator old = *this;
						++(*this);
						
						return old;
					}
					
					/* Prefix decrement */
					iterator &operator--()
					{
						if(node == NULL)
						{
							node = tree->last_depth_first_node();
						}
						else{
							node = RangeTree<OT, T>::prev_depth_first_node(node);
							assert(node != NULL);
						}
						
						return *this;
					}
					
					/* Postfix decrement */
					iterator operator--(int)
					{
						iterator old = *this;
						--(*this);
						
						return old;
					}
					
					bool operator==(const iterator &rhs) const
					{
						assert(tree == rhs.tree);
						return node == rhs.node;
					}
					
					bool operator!=(const iterator &rhs) const
					{
						assert(tree == rhs.tree);
						return node != rhs.node;
					}
					
					operator Node*() const
					{
						return node;
					}
					
					Node *operator->() const
					{
						return node;
					}
			};
			
			/**
			 * @brief Class for iterating over elements in a RangeTree.
			 *
			 * This class can be used to iterate over the elements in a RangeTree,
			 * in a manner similar to classical C++ iterators - the nodes at all levels
			 * will be visited in order of insertion.
			*/
			class const_iterator
			{
				friend RangeTree;
				
				protected:
					const RangeTree<OT, T> *tree;
					const Node *node;
					
				private:
					const_iterator(const RangeTree<OT, T> *tree, const Node *node):
						tree(tree),
						node(node) {}
					
					const std::vector<NodeRef> &node_container() const
					{
						assert(node != NULL);
						
						if(node->parent != NULL)
						{
							return node->parent->children;
						}
						else{
							return tree->root;
						}
					}
					
				public:
					using iterator_category = std::bidirectional_iterator_tag;
					using difference_type   = ssize_t;
					using value_type        = Node*;
					using pointer           = value_type*;
					using reference         = value_type&;
					
					const_iterator(const iterator &it):
						tree(it.tree), node(it.node) {}
					
					/* Prefix increment */
					const_iterator &operator++()
					{
						assert(node != NULL);
						
						node = RangeTree<OT, T>::next_depth_first_node(node);
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
						if(node == NULL)
						{
							node = tree->last_depth_first_node();
						}
						else{
							node = RangeTree<OT, T>::prev_depth_first_node(node);
							assert(node != NULL);
						}
						
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
						assert(tree == rhs.tree);
						return node == rhs.node;
					}
					
					bool operator!=(const const_iterator &rhs) const
					{
						assert(tree == rhs.tree);
						return node != rhs.node;
					}
					
					operator const Node*() const
					{
						return node;
					}
					
					const Node *operator->() const
					{
						return node;
					}
			};
			
			RangeTree():
				total_size(0) {}
			
			RangeTree(const RangeTree<OT, T> &rhs):
				total_size(0)
			{
				for(auto it = rhs.begin(); it != rhs.end(); ++it)
				{
					set(it->key.offset, it->key.length, it->value);
				}
			}
			
			RangeTree<OT, T> &operator=(const RangeTree<OT, T> &rhs)
			{
				clear();
				
				for(auto it = rhs.begin(); it != rhs.end(); ++it)
				{
					set(it->key.offset, it->key.length, it->value);
				}
				
				return *this;
			}
			
			/**
			 * @brief Get the begin iterator for all elements.
			 *
			 * Returns an iterator that can be used to iterate over the elements at
			 * every level, in depth-first order.
			*/
			iterator begin()
			{
				if(!root.empty())
				{
					return iterator(this, first_depth_first_node());
				}
				else{
					return end();
				}
			}
			
			const_iterator begin() const
			{
				if(!root.empty())
				{
					return const_iterator(this, first_depth_first_node());
				}
				else{
					return end();
				}
			}
			
			iterator end()
			{
				return iterator(this, NULL);
			}
			
			const_iterator end() const
			{
				return const_iterator(this, NULL);
			}
			
			/**
			 * @brief Returns true if the tree has no elements.
			*/
			bool empty() const
			{
				return total_size == 0;
			}
			
			/**
			 * @brief Get the number of elements in the whole tree.
			*/
			size_t size() const
			{
				return total_size;
			}
			
			/**
			 * @brief Remove all elements from the tree.
			*/
			void clear()
			{
				root.clear();
				total_size = 0;
			}
			
			/**
			 * @brief Get the first node at the root of the tree.
			*/
			Node *first_root_node()
			{
				return root.empty()
					? NULL
					: root.front().node.get();
			}
			
			const Node *first_root_node() const
			{
				return root.empty()
					? NULL
					: root.front().node.get();
			}
			
			/**
			 * @brief Get the last node at the root of the tree.
			*/
			Node *last_root_node()
			{
				return root.empty()
					? NULL
					: root.back().node.get();
			}
			
			const Node *last_root_node() const
			{
				return root.empty()
					? NULL
					: root.back().node.get();
			}
			
			/**
			 * @brief Get the first node for depth-first iteration.
			 *
			 * Returns the first node for iterating the tree in a depth-first manner.
			 * Use next_depth_first_node() to continue.
			*/
			Node *first_depth_first_node()
			{
				return first_root_node();
			}
			
			const Node *first_depth_first_node() const
			{
				return first_root_node();
			}
			
			/**
			 * @brief Get the last node for depth-first iteration.
			 *
			 * Returns the last node for iterating the tree in a depth-first manner.
			 * Use prev_depth_first_node() to continue walking backwards.
			*/
			Node *last_depth_first_node()
			{
				Node *node = last_root_node();
				
				while(node->get_last_child() != NULL)
				{
					node = node->get_last_child();
				}
				
				return node;
			}
			
			const Node *last_depth_first_node() const
			{
				const Node *node = last_root_node();
				
				while(node->get_last_child() != NULL)
				{
					node = node->get_last_child();
				}
				
				return node;
			}
			
			/**
			 * @brief Find the node matching the key exactly.
			 * @returns A Node pointer, or NULL.
			*/
			Node *find_node(const RangeTreeKey<OT> &key);
			const Node *find_node(const RangeTreeKey<OT> &key) const;
			
			/**
			 * @brief Find the smallest/deepest node containing the given offset.
			 *
			 * Searches for the deepest-nested node that encapsulates the offset.
			 * Returns NULL if none match. Does not match zero-length nodes.
			*/
			Node *find_most_specific_parent(OT offset);
			const Node *find_most_specific_parent(OT offset) const;
			
			/**
			 * @brief Find the node matching the key exactly.
			 * @returns An iterator, end() if not found.
			*/
			iterator find(const RangeTreeKey<OT> &key);
			const_iterator find(const RangeTreeKey<OT> &key) const;
			
			/**
			 * @brief Check if a key can be inserted.
			 *
			 * Checks if the given key can be inserted without overlapping the
			 * start/end of another. Returns true if possible, false if it conflicts.
			*/
			bool can_set(OT offset, OT length) const;
			
			/**
			 * @brief Insert or replace a key in the map.
			 *
			 * If the key already exists, it will be replaced. Any existing keys that
			 * fit inside the new one will be moved under it.
			 *
			 * Returns true on success, false if the new key conflicted with an
			 * existing one (i.e. straddled the end of it).
			*/
			bool set(OT offset, OT length, const T &value);
			
			/**
			 * @brief Delete a node from the tree.
			 *
			 * Deletes a single node from the tree, any child nodes under it are moved
			 * up to occupy the position where the deleted node was.
			*/
			size_t erase(Node *node);
			
			/**
			 * @brief Delete a node from the tree.
			 * @returns The next iterator.
			 *
			 * Deletes a single node from the tree, any child nodes under it are moved
			 * up to occupy the position where the deleted node was.
			*/
			iterator erase(const iterator &it)
			{
				assert(it.node != NULL);
				
				iterator next_it = std::next(it);
				erase(it.node);
				
				return next_it;
			}
			
			/**
			 * @brief Delete a node from the tree.
			 * @returns The number of elements deleted.
			 *
			 * Deletes a single node from the tree, any child nodes under it are moved
			 * up to occupy the position where the deleted node was.
			*/
			size_t erase(const RangeTreeKey<OT> &key)
			{
				Node *node = find_node(key);
				if(node != NULL)
				{
					return erase(node);
				}
				else{
					return 0;
				}
			}
			
			/**
			 * @brief Delete a node and all children from the tree.
			 * @returns The number of elements deleted.
			*/
			size_t erase_recursive(Node *node)
			{
				size_t erased_elements = erase_recursive_impl(node);
				check();
				
				return erased_elements;
			}
			
			/**
			 * @brief Delete a node and all children from the tree.
			 * @returns The next iterator.
			*/
			iterator erase_recursive(const iterator &it)
			{
				assert(it.node != NULL);
				
				iterator next_it = std::next(it);
				erase_recursive_impl(it.node);
				
				check();
				
				return next_it;
			}
			
			/**
			 * @brief Delete a node and all children from the tree.
			 * @returns The number of elements deleted.
			*/
			size_t erase_recursive(const RangeTreeKey<OT> &key)
			{
				Node *node = find_node(key);
				if(node != NULL)
				{
					size_t erased_elements = erase_recursive_impl(node);
					check();
					
					return erased_elements;
				}
				else{
					return 0;
				}
			}
			
			/**
			 * @brief Update the keys in the map for data being inserted into the file.
			 * @returns The number of keys MODIFIED.
			 *
			 * Moves or resizes keys of elements in the tree in response to data being
			 * inserted into the file.
			 *
			 * NOTE: All iterators and Node* pointers are invalidated by this method.
			*/
			
			template<typename OT2 = OT>
			inline typename std::enable_if<std::is_same<OT2, off_t>::value, size_t>::type
			data_inserted(off_t offset, off_t length)
			{
				return data_inserted_impl(offset, length);
			}
			
			template<typename OT2 = OT>
			inline typename std::enable_if<std::is_same<OT2, BitOffset>::value, size_t>::type
			data_inserted(off_t offset, off_t length)
			{
				return data_inserted_impl(BitOffset(offset, 0), BitOffset(length, 0));
			}
			
			/**
			 * @brief Update the keys in the map for data being erased from the file.
			 * @returns The number of keys MODIFIED or ERASED.
			 *
			 * Moves, resizes or erases keys of elements in the tree in response to
			 * data being erased from the file.
			 *
			 * NOTE: All iterators and Node* pointers are invalidated by this method.
			*/
			
			template<typename OT2 = OT>
			inline typename std::enable_if<std::is_same<OT2, off_t>::value, size_t>::type
			data_erased(off_t offset, off_t length)
			{
				return data_erased_impl(offset, length);
			}
			
			template<typename OT2 = OT>
			inline typename std::enable_if<std::is_same<OT2, BitOffset>::value, size_t>::type
			data_erased(off_t offset, off_t length)
			{
				return data_erased_impl(BitOffset(offset, 0), BitOffset(length, 0));
			}
			
			/**
			 * @brief Check if the KEYS and VALUES of two trees match.
			*/
			bool operator==(const RangeTree<OT, T> &rhs) const;
			
			/**
			 * @brief Find the next node in the tree, depth-first.
			 * @returns Node pointer of the next node, or NULL.
			*/
			template<typename NT> static NT *next_depth_first_node(NT *node);
			
			/**
			 * @brief Find the previous node in the tree, depth-first.
			 * @returns Node pointer of the previous node, or NULL.
			*/
			template<typename NT> static NT *prev_depth_first_node(NT *node);
		private:
			template<typename NT, typename CT> static NT *find_node_impl(const RangeTreeKey<OT> &key, CT *container);
			template<typename NT, typename CT> static NT *find_most_specific_parent_impl(OT offset, CT *container);
			
			size_t data_inserted_impl(OT offset, OT length);
			size_t data_erased_impl(OT offset, OT length);
	};
	
	template<typename T> using ByteRangeTree = RangeTree<off_t, T>;
	using ByteRangeTreeKey = RangeTreeKey<off_t>;
	
	template<typename T> using BitRangeTree = RangeTree<BitOffset, T>;
	using BitRangeTreeKey = RangeTreeKey<BitOffset>;
}

template<typename OT, typename T>
typename REHex::RangeTree<OT, T>::Node *REHex::RangeTree<OT, T>::find_node(const RangeTreeKey<OT> &key)
{
	return find_node_impl<Node>(key, &root);
}

template<typename OT, typename T>
const typename REHex::RangeTree<OT, T>::Node *REHex::RangeTree<OT, T>::find_node(const RangeTreeKey<OT> &key) const
{
	return find_node_impl<const Node>(key, &root);
}

template<typename OT, typename T> template<typename NT, typename CT>
NT *REHex::RangeTree<OT, T>::find_node_impl(const RangeTreeKey<OT> &key, CT *container)
{
	while(!container->empty())
	{
		NodeRef n_filter(key.offset, 0);
		auto i = std::upper_bound(container->begin(), container->end(), n_filter, &NodeRef::offset_lt);
		
		if(i != container->begin())
		{
			--i;
			
			if((*i)->key == key)
			{
				return *i;
			}
			else if((*i)->key.contains(key))
			{
				container = &((*i)->children);
			}
			else{
				break;
			}
		}
		else{
			break;
		}
	}
	
	return NULL;
}

template<typename OT, typename T>
typename REHex::RangeTree<OT, T>::iterator REHex::RangeTree<OT, T>::find(const RangeTreeKey<OT> &key)
{
	return iterator(this, find_node(key));
}

template<typename OT, typename T>
typename REHex::RangeTree<OT, T>::const_iterator REHex::RangeTree<OT, T>::find(const RangeTreeKey<OT> &key) const
{
	return const_iterator(this, REHex::RangeTree<OT, T>::find_node(key));
}

template<typename OT, typename T>
typename REHex::RangeTree<OT, T>::Node *REHex::RangeTree<OT, T>::find_most_specific_parent(OT offset)
{
	return find_most_specific_parent_impl<Node>(offset, &root);
}

template<typename OT, typename T>
const typename REHex::RangeTree<OT, T>::Node *REHex::RangeTree<OT, T>::find_most_specific_parent(OT offset) const
{
	return find_most_specific_parent_impl<const Node>(offset, &root);
}

template<typename OT, typename T> template<typename NT, typename CT>
NT *REHex::RangeTree<OT, T>::find_most_specific_parent_impl(OT offset, CT *container)
{
	NT *best_match = NULL;
	
	while(!container->empty())
	{
		NodeRef n_filter(offset, 0);
		auto i = std::upper_bound(container->begin(), container->end(), n_filter, &NodeRef::offset_lt);
		
		if(i != container->begin())
		{
			--i;
			
			if((*i)->key.offset <= offset && ((*i)->key.offset + (*i)->key.length) > offset)
			{
				best_match = *i;
				container = &((*i)->children);
			}
			else{
				break;
			}
		}
		else{
			break;
		}
	}
	
	return best_match;
}

template<typename OT, typename T>
bool REHex::RangeTree<OT, T>::can_set(OT offset, OT length) const
{
	const std::vector<NodeRef> *container = &root;
	
	while(true)
	{
		NodeRef n(offset, 0);
		
		/* Find the first node whose offset is greater than ours at this level... */
		
		auto i = std::upper_bound(container->begin(), container->end(), n, &NodeRef::offset_lt);
		
		for(auto j = i; j != container->end() && (offset + length) > (*j)->key.offset; ++j)
		{
			if((offset + length) < ((*j)->key.offset + (*j)->key.length))
			{
				/* We are straddling the start of another node. */
				return false;
			}
		}
		
		if(i != container->begin())
		{
			/* Step back to get the last element with a lesser-or-equal offset at this depth... */
			
			--i;
			
			assert((*i)->key.offset <= offset);
			
			OT i_offset = (*i)->key.offset;
			OT i_end = i_offset + (*i)->key.length;
			
			if(i_offset < offset && i_end > offset && i_end < (offset + length))
			{
				/* We are straddling the end of another node. */
				return false;
			}
			
			if(i_end >= (offset + length))
			{
				/* We are contained by this node, descent to check
				* for any collisions within it.
				*/
				
				container = &((*i)->children);
				continue;
			}
		}
		
		/* No overlapping nodes at this depth. */
		return true;
	}
	
	return false;
}

template<typename OT, typename T>
bool REHex::RangeTree<OT, T>::set(OT offset, OT length, const T &value)
{
	OT end = offset + length;
	
	NodeRef n(offset, length);
	Node *n_parent = NULL;
	
	std::vector<NodeRef> *container = &root;
	
	while(true)
	{
		auto insert_before = std::upper_bound(container->begin(), container->end(), n, &NodeRef::offset_lt);
		
		for(auto j = insert_before; j != container->end() && (offset + length) > (*j)->key.offset; ++j)
		{
			if((offset + length) < ((*j)->key.offset + (*j)->key.length))
			{
				/* We are straddling the start of another node. */
				return false;
			}
		}
		
		auto consume_begin = insert_before;
		auto consume_end = insert_before;
		
		if(insert_before != container->begin())
		{
			auto insert_after = std::prev(insert_before);
			
			Node *ia_node = *insert_after;
			OT ia_offset = ia_node->key.offset;
			OT ia_length = ia_node->key.length;
			OT ia_end = ia_offset + ia_length;
			
			if(ia_offset == offset && ia_length == length)
			{
				/* We should replace this. */
				
				ia_node->value = value;
				check();
				return true;
			}
			else if(ia_end > offset && ia_end >= end)
			{
				/* We should be nested under this. */
				
				n_parent = ia_node;
				container = &(ia_node->children);
				continue;
			}
			else if(ia_offset < offset && ia_end > offset && ia_end < (offset + length))
			{
				/* We are straddling the end of another node. */
				return false;
			}
			
			n.node.reset(new Node(offset, length, value));
			n->parent = n_parent;
			
			if(ia_offset == offset)
			{
				/* We should consume the previous element. */
				consume_begin = insert_after;
				n->prev_sibling = ia_node->prev_sibling;
			}
			else{
				n->prev_sibling = ia_node;
			}
		}
		else{
			n.node.reset(new Node(offset, length, value));
			n->parent = n_parent;
		}
		
		while(consume_end != container->end() && (*consume_end)->key.offset < (offset + length))
		{
			assert(((*consume_end)->key.offset + (*consume_end)->key.length) <= (offset + length));
			++consume_end;
		}
		
		if(consume_begin != consume_end)
		{
			Node *consumed_first = *consume_begin;
			Node *consumed_last = *(std::prev(consume_end));
			
			for(auto c = consume_begin; c != consume_end; ++c)
			{
				(*c)->parent = n.node.get();
			}
			
			n->children.insert(
				n->children.end(),
				std::make_move_iterator(consume_begin),
				std::make_move_iterator(consume_end));
			
			insert_before = container->erase(consume_begin, consume_end);
			
			if(consumed_first->prev_sibling != NULL)
			{
				assert(consumed_first->prev_sibling->next_sibling == consumed_first);
				consumed_first->prev_sibling->next_sibling = consumed_last->next_sibling;
			}
			
			if(consumed_last->next_sibling != NULL)
			{
				assert(consumed_last->next_sibling->prev_sibling == consumed_last);
				consumed_last->next_sibling->prev_sibling = consumed_first->prev_sibling;
			}
			
			consumed_first->prev_sibling = NULL;
			consumed_last->next_sibling = NULL;
		}
		
		if(n->prev_sibling != NULL)
		{
			n->prev_sibling->next_sibling = n.node.get();
		}
		
		if(insert_before != container->end())
		{
			n->next_sibling = *insert_before;
			(*insert_before)->prev_sibling = n.node.get();
		}
		
		container->insert(insert_before, std::move(n));
		++total_size;
		
		break;
	}
	
	check();
	return true;
}

template<typename OT, typename T>
size_t REHex::RangeTree<OT, T>::erase(Node *node)
{
	std::function<void(Node*)> visit_node;
	
	std::vector<NodeRef> &container = node->parent != NULL
		? node->parent->children
		: root;
	
	auto erase_iter = std::lower_bound(container.begin(), container.end(), NodeRef(node->key), &NodeRef::key_lt);
	assert(erase_iter != container.end());
	assert(erase_iter->node.get() == node);
	
	size_t num_children = node->children.size();
	if(num_children > 0)
	{
		Node *first_child = node->children.front();
		Node *last_child = node->children.back();
		
		assert(first_child->prev_sibling == NULL);
		assert(last_child->next_sibling == NULL);
		
		if(node->prev_sibling != NULL)
		{
			assert(node->prev_sibling->next_sibling == node);
			node->prev_sibling->next_sibling = first_child;
			first_child->prev_sibling = node->prev_sibling;
		}
		
		if(node->next_sibling != NULL)
		{
			assert(node->next_sibling->prev_sibling == node);
			node->next_sibling->prev_sibling = last_child;
			last_child->next_sibling = node->next_sibling;
		}
		
		for(auto c = node->children.begin(); c != node->children.end(); ++c)
		{
			(*c)->parent = node->parent;
		}
		
		/* Work around for GCC <4.9 where std::vector::insert() returns
		 * void rather than an iterator to the inserted element.
		 *
		 * https://gcc.gnu.org/bugzilla/show_bug.cgi?id=55817
		*/
		#if !defined(__clang__) && defined(__GNUC__) && (__GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 9))
		size_t first_inserted_idx = std::distance(container.begin(), erase_iter);
		container.insert(
			erase_iter,
			std::make_move_iterator(node->children.begin()),
			std::make_move_iterator(node->children.end()));
		auto first_inserted_elem = std::next(container.begin(), first_inserted_idx);
		#else
		auto first_inserted_elem = container.insert(
			erase_iter,
			std::make_move_iterator(node->children.begin()),
			std::make_move_iterator(node->children.end()));
		#endif
		
		erase_iter = std::next(first_inserted_elem, num_children);
		assert(erase_iter != container.end());
		assert(erase_iter->node.get() == node);
	}
	else{
		if(node->prev_sibling != NULL)
		{
			node->prev_sibling->next_sibling = node->next_sibling;
		}
		
		if(node->next_sibling != NULL)
		{
			node->next_sibling->prev_sibling = node->prev_sibling;
		}
	}
	
	container.erase(erase_iter);
	--total_size;
	
	check();
	
	return 1;
}

template<typename OT, typename T>
size_t REHex::RangeTree<OT, T>::erase_recursive_impl(Node *node)
{
	std::function<void(Node*)> visit_node;
	size_t total_nodes = 0;
	
	visit_node = [&](Node *n)
	{
		++total_nodes;
		
		if(n->prev_sibling != NULL)
		{
			assert(n->prev_sibling->next_sibling == n);
			n->prev_sibling->next_sibling = n->next_sibling;
		}
		
		if(n->next_sibling != NULL)
		{
			assert(n->next_sibling->prev_sibling == n);
			n->next_sibling->prev_sibling = n->prev_sibling;
		}
		
		for(auto it = n->children.begin(); it != n->children.end(); ++it)
		{
			visit_node(it->node.get());
		}
	};
	
	visit_node(node);
	
	std::vector<NodeRef> &container = node->parent != NULL
		? node->parent->children
		: root;
	
	auto erase_iter = std::lower_bound(container.begin(), container.end(), NodeRef(node->key), &NodeRef::key_lt);
	assert(erase_iter != container.end());
	assert(erase_iter->node.get() == node);
	
	container.erase(erase_iter);
	total_size -= total_nodes;
	
	return total_nodes;
}

template<typename OT, typename T>
bool REHex::RangeTree<OT, T>::operator==(const RangeTree<OT, T> &rhs) const
{
	bool matches = true;
	
	std::function<void(const std::vector<NodeRef>&, const std::vector<NodeRef>&)> cmp_container;
	cmp_container = [&](const std::vector<NodeRef> &container_a, const std::vector<NodeRef> &container_b)
	{
		if(container_a.size() != container_b.size())
		{
			matches = false;
			return;
		}
		
		for(auto a = container_a.begin(), b = container_b.begin(); a != container_a.end() && matches; ++a, ++b)
		{
			if(!(a->key == b->key && (*a)->value == (*b)->value))
			{
				matches = false;
				return;
			}
			
			cmp_container((*a)->children, (*b)->children);
		}
	};
	
	cmp_container(root, rhs.root);
	
	return matches;
}

template<typename OT, typename T>
size_t REHex::RangeTree<OT, T>::data_inserted_impl(OT offset, OT length)
{
	size_t keys_modified = 0;
	
	std::function<void(std::vector<NodeRef>&)> process_nodes;
	process_nodes = [&](std::vector<NodeRef> &nodes)
	{
		for(auto it = nodes.begin(); it != nodes.end();)
		{
			NodeRef &n = *(it++);
			
			OT i_offset = n.key.offset;
			OT i_length = n.key.length;
			
			if(i_offset >= offset)
			{
				i_offset += length;
				
				Node *new_node = new Node(i_offset, i_length, std::move(*n));
				
				n.key.offset = i_offset;
				n.node.reset(new_node);
				
				++keys_modified;
			}
			else if(i_offset < offset && (i_offset + i_length) > offset)
			{
				i_length += length;
				
				Node *new_node = new Node(i_offset, i_length, std::move(*n));
				
				n.key.length = i_length;
				n.node.reset(new_node);
				
				++keys_modified;
			}
			
			process_nodes(n->children);
		}
	};
	
	process_nodes(root);
	check();
	
	return keys_modified;
}

template<typename OT, typename T>
size_t REHex::RangeTree<OT, T>::data_erased_impl(OT offset, OT length)
{
	OT end = offset + length;
	
	size_t keys_modified = 0;
	
	std::function<void(std::vector<NodeRef>&)> process_nodes;
	process_nodes = [&](std::vector<NodeRef> &nodes)
	{
		for(size_t i = 0; i < nodes.size();)
		{
			NodeRef &n = nodes[i];
			
			OT i_offset = n.key.offset;
			OT i_length = n.key.length;
			OT i_end = i_offset + i_length;
			
			if(offset <= i_offset && (end > i_end || (i_end > i_offset && end == i_end)))
			{
				/* This key is wholly encompassed by the deleted range. */
				
				keys_modified += erase_recursive_impl(&*n);
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
			
			if(i_offset != n.key.offset || i_length != n.key.length)
			{
				Node *new_node = new Node(i_offset, i_length, std::move(*n));
				
				n.key.offset = i_offset;
				n.key.length = i_length;
				n.node.reset(new_node);
				
				++keys_modified;
			}
			
			process_nodes(n.node->children);
			
			++i;
		}
	};
	
	process_nodes(root);
	check();
	
	return keys_modified;
}

template<typename OT, typename T> template<typename NT>
NT *REHex::RangeTree<OT, T>::next_depth_first_node(NT *node)
{
	if(node->get_first_child() != NULL)
	{
		node = node->get_first_child();
	}
	else{
		while(node->get_next() == NULL && node->get_parent() != NULL)
		{
			node = node->get_parent();
		}
		
		node = node->get_next();
	}
	
	return node;
}

template<typename OT, typename T> template<typename NT>
NT *REHex::RangeTree<OT, T>::prev_depth_first_node(NT *node)
{
	if(node->get_prev() != NULL)
	{
		node = node->get_prev();
		
		while(node->get_last_child() != NULL)
		{
			node = node->get_last_child();
		}
	}
	else{
		node = node->get_parent();
	}
	
	return node;
}

template<typename OT, typename T>
void REHex::RangeTree<OT, T>::check() const
{
	#ifdef REHEX_BYTERANGETREE_CHECKS
	
	#ifdef REHEX_BYTERANGETREE_DIAGS
	fprintf(stderr, "RangeTree %p checking tree...\n", this);
	#endif
	
	/* Iterate over the entire tree, checking all inter-Node pointers are correct. */
	
	std::set<const Node*> seen_nodes;
	
	std::function<void(const Node*, int, const std::vector<NodeRef>&)> check_container;
	check_container = [&](const Node *parent, int depth, const std::vector<NodeRef> &container)
	{
		for(size_t i = 0; i < container.size(); ++i)
		{
			#ifdef REHEX_BYTERANGETREE_DIAGS
			for(int j = 0; j < depth; ++j)
			{
				fprintf(stderr, "  ");
			}
			
			fprintf(stderr, "node %p offset = %zd length = %zd\n", container[i].node.get(), container[i]->key.offset, container[i]->key.length);
			#endif
			
			assert(container[i].key.offset == container[i].node->key.offset);
			assert(container[i].key.length == container[i].node->key.length);
			
			assert(container[i]->parent == parent);
			
			if(parent != NULL)
			{
				assert(parent->key.contains(container[i].key));
			}
			
			if(i > 0)
			{
				assert(container[i]->prev_sibling == container[i - 1]);
				assert(container[i].key.offset > container[i - 1].key.offset);
				assert(container[i].key.offset >= (container[i - 1].key.offset + container[i - 1].key.length));
			}
			if((i + 1) < container.size())
			{
				assert(container[i]->next_sibling == container[i + 1]);
			}
			
			check_container(container[i].node.get(), depth + 1, container[i]->children);
			
			assert(seen_nodes.find(container[i].node.get()) == seen_nodes.end());
			seen_nodes.insert(container[i].node.get());
		}
	};
	
	check_container(NULL, 0, root);
	
	/* Check total_size is correct. */
	assert(total_size == seen_nodes.size());
	
	#endif /* REHEX_BYTERANGETREE_CHECKS */
}

#endif /* !REHEX_BYTERANGETREE_HPP */
