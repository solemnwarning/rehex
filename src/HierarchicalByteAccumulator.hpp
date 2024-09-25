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
#include <memory>
#include <vector>

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
			static constexpr size_t L2_CACHE_SIZE = 512; /* Up to ~1MiB */
			
			struct Shard
			{
				BitOffset offset;
				off_t length;
				
				ByteAccumulator result;
				
				Shard(BitOffset offset, off_t length):
					offset(offset),
					length(length) {}
			};
			
		private:
			struct L1CacheNode
			{
				off_t offset;
				off_t length;
				
				std::unique_ptr<ByteAccumulator> accumulator;
				
				L1CacheNode(off_t offset, off_t length, bool init_accumulator):
					offset(offset), length(length)
				{
					if(init_accumulator)
					{
						accumulator.reset(new ByteAccumulator());
					}
				}
			};
			
			SharedDocumentPointer document;
			
			BitOffset range_offset;
			off_t range_length;
			bool whole_file;
			
			size_t target_num_shards;
			
			size_t chunk_size;
			
			ByteAccumulator result;
			
			std::atomic<bool> result_rebuild_pending;
			
			/**
			 * The L1 cache.
			 *
			 * The L1 cache breaks the file up into chunks and holds a ByteAccumulator
			 * for each which is used to regenerate the output accumulator as required.
			*/
			std::vector<L1CacheNode> l1_cache;
			
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
			
			std::unique_ptr<RangeProcessor> processor;
			
		public:
			/**
			 * @brief Construct a HierarchicalByteAccumulator to accumulate a whole file.
			 *
			 * @param document    Document to accumulate data from.
			 * @param num_shards  Number of shards to divide range into.
			*/
			HierarchicalByteAccumulator(const SharedDocumentPointer &document, size_t num_shards = 1);
			
			/**
			 * @brief Construct a HierarchicalByteAccumulator to accumulate a range of bytes.
			 *
			 * @param document      Document to accumulate data from.
			 * @param range_offset  Start offset of range to accumulate data from.
			 * @param range_length  Length of range to accumulate data from, in bytes.
			 * @param num_shards    Number of shards to divide range into.
			*/
			HierarchicalByteAccumulator(const SharedDocumentPointer &document, BitOffset range_offset, off_t range_length, size_t num_shards = 1);
			
			/**
			 * @brief Prepare the HierarchicalByteAccumulator to be destroyed.
			 *
			 * This method stops any further processing from being scheduled and can be
			 * used to speed up the object destruction at a later point.
			*/
			void pre_destroy();
			
			/**
			 * @brief Get the current result.
			 *
			 * This returns a reference to the final ByteAccumulator object which may
			 * or may not yet have all data, the reference will remain valid until the
			 * next get_result() call.
			*/
			const ByteAccumulator &get_result();
			
			/**
			 * @brief Get the shards and their current results.
			 *
			 * This returns a vector of each shard and the the stats accumulated in it
			 * so far, which may or may not yet have all data.
			*/
			std::vector<Shard> get_shards();
			
			/**
			 * @brief Wait for work queue to be empty.
			 *
			 * This is mostly intended for unit tests. This should not be used from the
			 * application UI thread.
			*/
			void wait_for_completion();
			
			void flush_l2_cache();
			
		private:
			std::pair<size_t, size_t> calc_chunk_size();
			void update_chunk_size();
			
			void process_range(off_t offset, off_t length);
			
			/**
			 * @brief Get the L1 cache slot index encompassing a (relative) offset.
			 *
			 * @param relative_offset  Offset relative to range_offset.
			*/
			size_t relative_offset_to_l1_cache_idx(off_t relative_offset);
			
			void OnDataModifying(OffsetLengthEvent &event);
			void OnDataModifyAborted(OffsetLengthEvent &event);
			void OnDataErase(OffsetLengthEvent &event);
			void OnDataInsert(OffsetLengthEvent &event);
			void OnDataOverwrite(OffsetLengthEvent &event);
	};
}

#endif /* !REHEX_HIERARCHICALBYTEACCUMULATOR_HPP */
