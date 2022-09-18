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

#ifndef REHEX_DATAHISTOGRAMACCUMULATOR_HPP
#define REHEX_DATAHISTOGRAMACCUMULATOR_HPP

#include <atomic>
#include <memory>
#include <vector>

#include "RangeProcessor.hpp"
#include "SharedDocumentPointer.hpp"

namespace REHex
{
	template<typename T> class DataHistogramAccumulator
	{
		public:
			struct Bucket
			{
				const T min_value;
				const T max_value;
				
				std::atomic<off_t> count;
				
				Bucket(T min_value, T max_value): min_value(min_value), max_value(max_value), count(0) {}
				Bucket(const Bucket &b): min_value(b.min_value), max_value(b.max_value), count(b.count.load()) {}
			};
			
			DataHistogramAccumulator(SharedDocumentPointer &document, off_t offset, off_t stride, off_t length, unsigned int num_buckets);
			DataHistogramAccumulator(const DataHistogramAccumulator<T> *base, const Bucket *bucket);
			
			const std::vector<Bucket> &get_buckets() const;
			
			void wait_for_completion();
			
		private:
			SharedDocumentPointer document;
			const off_t offset;
			const off_t stride;
			const off_t length;
			
			int value_to_bucket_rshift;
			
			T sub_mask;
			T sub_value;
			
			std::vector<Bucket> buckets;
			std::unique_ptr<RangeProcessor> rp;
			
			static int calc_num_buckets_bit(int num_buckets);
			
			void process_range(off_t window_base, off_t window_size);
	};
}

template<typename T> REHex::DataHistogramAccumulator<T>::DataHistogramAccumulator(SharedDocumentPointer &document, off_t offset, off_t stride, off_t length, unsigned int num_buckets):
	document(document),
	offset(offset),
	stride(stride),
	length(length),
	sub_mask(0),
	sub_value(0)
{
	int num_buckets_bit = calc_num_buckets_bit(num_buckets);
	int value_bits = sizeof(T) * 8;
	
	value_to_bucket_rshift = value_bits - num_buckets_bit;
	
	T next_bucket = 0;
	for(int i = 0; i < num_buckets; ++i)
	{
		T b_min_value = next_bucket;
		
		next_bucket += (T)(1) << value_to_bucket_rshift;
		
		T b_max_value = next_bucket - 1;
		
		buckets.emplace_back(b_min_value, b_max_value);
	}
	
	// TODO: Align window size with word size
	rp = std::unique_ptr<RangeProcessor>(new RangeProcessor([this](off_t window_base, off_t window_size) { process_range(window_base, window_size); }, (2 * 1024 * 1024)));
	rp->queue_range(offset, length);
}

template<typename T> REHex::DataHistogramAccumulator<T>::DataHistogramAccumulator(const DataHistogramAccumulator<T> *base, const Bucket *bucket):
	document(base->document),
	offset(base->offset),
	stride(base->stride),
	length(base->length),
	sub_mask(base->sub_mask)
{
	int num_buckets_bit = calc_num_buckets_bit(base->buckets.size());
	int value_bits = sizeof(T) * 8;
	
	value_to_bucket_rshift = base->value_to_bucket_rshift - num_buckets_bit;
	
	T next_bucket = bucket->min_value;
	for(unsigned int i = 0; i < base->buckets.size(); ++i)
	{
		T b_min_value = next_bucket;
		
		next_bucket += (T)(1) << value_to_bucket_rshift;
		
		T b_max_value = next_bucket - 1;
		
		buckets.emplace_back(b_min_value, b_max_value);
	}
	
	for(int i = 0; i < num_buckets_bit; ++i)
	{
		sub_mask >>= 1;
		sub_mask |= 1 << (value_bits - 1);
	}
	
	sub_value = bucket->min_value;
	
	// TODO: Align window size with word size
	rp = std::unique_ptr<RangeProcessor>(new RangeProcessor([this](off_t window_base, off_t window_size) { process_range(window_base, window_size); }, (2 * 1024 * 1024)));
	rp->queue_range(offset, length);
}

template<typename T> const std::vector< typename REHex::DataHistogramAccumulator<T>::Bucket > &REHex::DataHistogramAccumulator<T>::get_buckets() const
{
	return buckets;
}

template<typename T> int REHex::DataHistogramAccumulator<T>::calc_num_buckets_bit(int num_buckets)
{
	int num_buckets_bit = -1;
	
	for(int i = 1; i < 16; ++i)
	{
		if((1 << i) == num_buckets)
		{
			num_buckets_bit = i;
			break;
		}
	}
	
	assert(num_buckets_bit != -1);
	
	return num_buckets_bit;
}

template<typename T> void REHex::DataHistogramAccumulator<T>::process_range(off_t window_base, off_t window_size)
{
	off_t window_end = window_base + window_size;
	off_t total_end = offset + length;
	
	off_t min_end = std::min(window_end, total_end);
	window_size = min_end - window_base;
	
	std::vector<unsigned char> window_data = document->read_data(window_base, window_size);
	
	for(size_t i = 0; (i + sizeof(T)) <= window_data.size(); i += stride)
	{
		T value;
		memcpy(&value, window_data.data() + i, sizeof(T));
		
		if((value & sub_mask) == sub_value)
		{
			size_t bucket_idx = (value >> value_to_bucket_rshift) & (buckets.size() - 1);
			assert(bucket_idx < buckets.size());
			
			++(buckets[bucket_idx].count);
		}
	}
}

template<typename T> void REHex::DataHistogramAccumulator<T>::wait_for_completion()
{
	rp->wait_for_completion();
}

#endif /* !REHEX_DATAHISTOGRAMACCUMULATOR_HPP */
