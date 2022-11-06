#include <assert.h>
#include <tuple>

#include "DataHistogramPan.hpp"

REHex::DataHistogramPan::DataHistogramPan(DataHistogramAccumulatorInterface *top_accumulator):
	buckets_per_accumulator(top_accumulator->get_num_buckets()),
	accumulator_cache(10)
{
	total_buckets = top_accumulator->get_num_buckets();
	accumulators.emplace_back(top_accumulator);
}

bool REHex::DataHistogramPan::descend(size_t bucket_idx)
{
	assert(bucket_idx < total_buckets);
	
	size_t accumulator_idx = bucket_idx / buckets_per_accumulator;
	bucket_idx %= buckets_per_accumulator;
	
	DataHistogramAccumulatorScope bucket_scope = accumulators[accumulator_idx]->bucket_accumulator_scope(bucket_idx);
	if(bucket_scope.empty())
	{
		return false;
	}
	
	std::shared_ptr<DataHistogramAccumulatorInterface> accumulator = get_or_construct_accumulator(bucket_scope);
	
	while(!accumulators.empty())
	{
		accumulator_cache.set(accumulators.back()->get_scope(), accumulators.back());
		accumulators.pop_back();
	}
	
	accumulators.push_back(accumulator);
	total_buckets = buckets_per_accumulator;
	
	return true;
}

bool REHex::DataHistogramPan::ascend(size_t bucket_idx)
{
	assert(bucket_idx < total_buckets);
	
	size_t accumulator_idx = bucket_idx / buckets_per_accumulator;
	bucket_idx %= buckets_per_accumulator;
	
	DataHistogramAccumulatorScope parent_scope;
	size_t bucket_idx_within_parent;
	
	std::tie(parent_scope, bucket_idx_within_parent) = accumulators[accumulator_idx]->parent_accumulator_scope();
	if(parent_scope.empty())
	{
		return false;
	}
	
	std::shared_ptr<DataHistogramAccumulatorInterface> accumulator = get_or_construct_accumulator(parent_scope);
	
	while(!accumulators.empty())
	{
		accumulator_cache.set(accumulators.back()->get_scope(), accumulators.back());
		accumulators.pop_back();
	}
	
	accumulators.push_back(accumulator);
	total_buckets = buckets_per_accumulator;
	
	return true;
}

size_t REHex::DataHistogramPan::grow_left(size_t target_buckets)
{
	size_t new_buckets = 0;
	
	while(total_buckets < target_buckets)
	{
		DataHistogramAccumulatorScope scope = accumulators.front()->prev_accumulator_scope();
		if(scope.empty())
		{
			break;
		}
		
		accumulators.insert(accumulators.begin(), get_or_construct_accumulator(scope));
		total_buckets += buckets_per_accumulator;
		
		new_buckets += buckets_per_accumulator;
	}
	
	return new_buckets;
}

size_t REHex::DataHistogramPan::grow_right(size_t target_buckets)
{
	size_t new_buckets = 0;
	
	while(total_buckets < target_buckets)
	{
		DataHistogramAccumulatorScope scope = accumulators.back()->next_accumulator_scope();
		if(scope.empty())
		{
			break;
		}
		
		accumulators.insert(accumulators.end(), get_or_construct_accumulator(scope));
		total_buckets += buckets_per_accumulator;
		
		new_buckets += buckets_per_accumulator;
	}
	
	return new_buckets;
}

size_t REHex::DataHistogramPan::get_num_buckets() const
{
	return total_buckets;
}

off_t REHex::DataHistogramPan::get_bucket_count(size_t bucket_idx) const
{
	assert(bucket_idx < total_buckets);
	
	size_t accumulator_idx = bucket_idx / buckets_per_accumulator;
	bucket_idx %= buckets_per_accumulator;
	
	return accumulators[accumulator_idx]->get_bucket_count(bucket_idx);
}

double REHex::DataHistogramPan::get_bucket_min_value_as_double(size_t bucket_idx) const
{
	assert(bucket_idx < total_buckets);
	
	size_t accumulator_idx = bucket_idx / buckets_per_accumulator;
	bucket_idx %= buckets_per_accumulator;
	
	return accumulators[accumulator_idx]->get_bucket_min_value_as_double(bucket_idx);
}

std::string REHex::DataHistogramPan::get_bucket_min_value_as_string(size_t bucket_idx) const
{
	assert(bucket_idx < total_buckets);
	
	size_t accumulator_idx = bucket_idx / buckets_per_accumulator;
	bucket_idx %= buckets_per_accumulator;
	
	return accumulators[accumulator_idx]->get_bucket_min_value_as_string(bucket_idx);
}

double REHex::DataHistogramPan::get_bucket_max_value_as_double(size_t bucket_idx) const
{
	assert(bucket_idx < total_buckets);
	
	size_t accumulator_idx = bucket_idx / buckets_per_accumulator;
	bucket_idx %= buckets_per_accumulator;
	
	return accumulators[accumulator_idx]->get_bucket_max_value_as_double(bucket_idx);
}

std::string REHex::DataHistogramPan::get_bucket_max_value_as_string(size_t bucket_idx) const
{
	assert(bucket_idx < total_buckets);
	
	size_t accumulator_idx = bucket_idx / buckets_per_accumulator;
	bucket_idx %= buckets_per_accumulator;
	
	return accumulators[accumulator_idx]->get_bucket_max_value_as_string(bucket_idx);
}

std::shared_ptr<REHex::DataHistogramAccumulatorInterface> REHex::DataHistogramPan::get_or_construct_accumulator(const DataHistogramAccumulatorScope &scope)
{
	const std::shared_ptr<DataHistogramAccumulatorInterface> *cached_accumulator = accumulator_cache.get(scope);
	if(cached_accumulator != NULL)
	{
		return *cached_accumulator;
	}
	else{
		DataHistogramAccumulatorInterface *new_accumulator = accumulators.front()->new_accumulator_with_scope(scope);
		return std::shared_ptr<DataHistogramAccumulatorInterface>(new_accumulator);
	}
}
