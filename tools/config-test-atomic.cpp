/* Dummy program used to check compiler flags needed for std::atomic. */

#include <atomic>
#include <stdint.h>
#include <stdlib.h>

template<typename T> int do_atomic()
{
	std::atomic<T> x;
	
	x.store(rand());
	x.fetch_add(rand());
	x.fetch_sub(rand());
	
	return x.load();
}

int main()
{
	return do_atomic<int8_t>()
		+ do_atomic<int16_t>()
		+ do_atomic<int32_t>()
		+ do_atomic<int64_t>();
}
