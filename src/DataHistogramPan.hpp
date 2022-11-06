#ifndef REHEX_DATAHISTOGRAMPAN_HPP
#define REHEX_DATAHISTOGRAMPAN_HPP

#include <memory>
#include <vector>

#include "DataHistogramAccumulator.hpp"
#include "LRUCache.hpp"

namespace REHex
{
	/**
	 * @brief DataHistogramAccumulatorInterface "panning" class.
	 *
	 * This class is a wrapper around a DataHistogramAccumulatorInterface that abstracts the
	 * accumulator "buckets" for use in a chart and handles "zooming" and "panning" of the data
	 * including descending into more-specific scopes for more precision when zooming in the
	 * chart and paging accumulators in/out as the chart is scrolled horizontally.
	*/
	class DataHistogramPan
	{
		public:
			const size_t buckets_per_accumulator;
			
			DataHistogramPan(DataHistogramAccumulatorInterface *top_accumulator);
			
			/**
			 * @brief Descend into the range of values in a bucket.
			 * @return true if successful
			 *
			 * This method sets up a new accumulator, effectively sub-divinding the
			 * values in a specific bucket across a whole new accumulator and allowing
			 * counting values in smaller groups.
			 *
			 * If this call succeeds, only one accumulator will be in the list.
			*/
			bool descend(size_t bucket_idx);
			
			/**
			 * @brief Ascend up from a bucket.
			 * @return true if successful
			 *
			 * This method is the inverse of descend. The bucket_idx is required so we
			 * know WHICH bucket to ascend out of and center on.
			 *
			 * If this call succeeds, only one accumulator will be in the list.
			*/
			bool ascend(size_t bucket_idx);
			
			size_t grow_left(size_t target_buckets);
			size_t grow_right(size_t target_buckets);
			
			size_t get_num_buckets() const;
			
			off_t get_bucket_count(size_t bucket_idx) const;
			double get_bucket_min_value_as_double(size_t bucket_idx) const;
			std::string get_bucket_min_value_as_string(size_t bucket_idx) const;
			double get_bucket_max_value_as_double(size_t bucket_idx) const;
			std::string get_bucket_max_value_as_string(size_t bucket_idx) const;
			
		private:
			size_t total_buckets;
			
			std::vector< std::shared_ptr<DataHistogramAccumulatorInterface> > accumulators;
			
			LRUCache< DataHistogramAccumulatorScope, std::shared_ptr<DataHistogramAccumulatorInterface> > accumulator_cache;
			
			std::shared_ptr<DataHistogramAccumulatorInterface> get_or_construct_accumulator(const DataHistogramAccumulatorScope &scope);
	};
}

#endif /* !REHEX_DATAHISTOGRAMPAN_HPP */
