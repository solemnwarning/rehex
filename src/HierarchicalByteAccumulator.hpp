/* Reverse Engineer's Hex Editor
 * Copyright (C) 2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_HIERARCHICALBYTEACCUMULATOR_HPP
#define REHEX_HIERARCHICALBYTEACCUMULATOR_HPP

#include <atomic>

#include "BitOffset.hpp"
#include "ByteAccumulator.hpp"
#include "Events.hpp"
#include "LRUCache.hpp"
#include "RangeProcessor.hpp"
#include "SharedDocumentPointer.hpp"

namespace REHex
{
	/**
	 * @brief Scalable ByteAccumulator for document data regions.
	 *
	 * This class accumulates data from a specified byte range in a Document into a
	 * ByteAccumulator using background worker threads.
	*/
	class HierarchicalByteAccumulator
	{
		public:
			static constexpr size_t CHUNK_SIZE = 4 * 1024 * 1024; /* 4MiB */
			
			static constexpr size_t L1_CACHE_SIZE = 128; /* ~256KiB */
			static constexpr size_t L2_CACHE_SIZE = 512; /* Up to ~1MiB */
			
		private:
			struct L1CacheNode
			{
				ByteAccumulator accumulator;
			};
			
			SharedDocumentPointer document;
			
			BitOffset range_offset;
			off_t range_length;
			
			ByteAccumulator result;
			
			std::atomic<bool> result_rebuild_pending;
			
			/**
			 * The L1 cache.
			 *
			 * The L1 cache breaks the file up into chunks and holds a ByteAccumulator
			 * for each which is used to regenerate the output accumulator as required.
			 *
			 * The byte range is evenly distributed across the L1 cache indices with
			 * the following notes:
			 *
			 *   - All but the final slot in the L1 cache will be a multiple of
			 *     CHUNK_SIZE bytes long.
			*/
			L1CacheNode l1_cache[L1_CACHE_SIZE];
			
			off_t l1_slot_base_size;
			
			size_t l1_slot_count;
			
			ByteRangeSet l1_counted;
			
			std::mutex l1_mutex;
			
			/**
			 * The L2 cache.
			 *
			 * This holds the ByteAccumulator for a range of bytes CHUNK_SIZE
			 * long from when they were last counted, indexed by the offset from
			 * range_offset.
			 *
			 * This is used to REMOVE previously accumulated bytes from the L1 cache
			 * before re-adding them when counting an already-counted range in response
			 * to the file changing - if a required entry is missing from the L2 cache
			 * when the range is modified, the entire L1 cache slot must be re-counted
			 * from scratch.
			*/
			LRUCache<off_t, ByteAccumulator> l2_cache;
			
			std::mutex l2_mutex;
			
			RangeProcessor processor;
			
		public:
			HierarchicalByteAccumulator(const SharedDocumentPointer &document, BitOffset range_offset, off_t range_length);
			
			/**
			 * @brief Get the current result.
			 *
			 * This returns a reference to the final ByteAccumulator object which may
			 * or may not yet have all data, the reference will remain valid until the
			 * next get_result() call.
			*/
			const ByteAccumulator &get_result();
			
			/**
			 * @brief Wait for work queue to be empty.
			 *
			 * This is mostly intended for unit tests. This should not be used from the
			 * application UI thread.
			*/
			void wait_for_completion();
			
		private:
			void process_range(off_t offset, off_t length);
			
			/**
			 * @brief Get the L1 cache slot index encompassing a (relative) offset.
			 *
			 * @param relative_offset  Offset relative to range_offset.
			*/
			size_t relative_offset_to_l1_cache_idx(off_t relative_offset);
			
			/**
			 * @brief Get the base relative offset of an L1 cache slot.
			 *
			 * @param l1_cache_idx  Index into the l1_cache array.
			*/
			off_t l1_cache_idx_relative_offset(size_t l1_cache_idx);
			
			/**
			 * @brief Get the length of data encompassed by an L1 cache slot.
			 *
			 * @param l1_cache_idx  Index into the l1_cache array.
			*/
			off_t l1_cache_idx_length(size_t l1_cache_idx);
			
			void l1_cache_reset_slot(size_t l1_cache_idx);
			
			void OnDataModifying(OffsetLengthEvent &event);
			void OnDataModifyAborted(OffsetLengthEvent &event);
			void OnDataErase(OffsetLengthEvent &event);
			void OnDataInsert(OffsetLengthEvent &event);
			void OnDataOverwrite(OffsetLengthEvent &event);
	};
}

#endif /* !REHEX_HIERARCHICALBYTEACCUMULATOR_HPP */
