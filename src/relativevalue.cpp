/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <algorithm>
#include <assert.h>
#include <list>
#include <map>
#include <set>
#include <stdint.h>

#include <arpa/inet.h>

#include "buffer.hpp"

namespace REHex {
	enum ValueType {
		VT_U8 = (1 << 0),
		VT_S8 = (1 << 1),
		
		VT_U16BE = (1 << 2),
		VT_U16LE = (1 << 3),
		VT_S16BE = (1 << 4),
		VT_S16LE = (1 << 5),
		
		VT_U32BE = (1 << 6),
		VT_U32LE = (1 << 7),
		VT_S32BE = (1 << 8),
		VT_S32LE = (1 << 9),
	};
	
	namespace Search {
		class RelativeValues
		{
			public:
				RelativeValues(Buffer &buffer, off_t begin, off_t end, off_t align, bool align_rel, std::list<int64_t> values, ValueType types);
				
			private:
				Buffer &buffer;
				off_t cur_pos;
				off_t end_pos;
				
				template<typename T> std::map<T, std::list<off_t> > _build_values_table(bool be)
				{
					std::map<T, std::list<off_t> > values_table;
					
					/* TODO: Should end_pos limit end of T rather than start? */
					for(off_t off = cur_pos; off < end_pos || end_pos < 0; ++off)
					{
						std::vector<unsigned char> data = buffer.read_data(off, sizeof(T));
						if(data.size() < sizeof(T))
						{
							/* EOF */
							break;
						}
						
						T value = *(const T*)(data.data());
						if(be)
						{
							value = ntohl(value);
						}
						
						values_table[value].push_back(off);
					}
					
					return values_table;
				}
		};
	}
}

#define THING(v, T, be) \
	if(types & v) \
	{ \
		auto values_table = _build_values_table<T>(be); \
		for(auto i = values_table.begin(); i != values_table.end(); ++i) \
		{ \
			bool nothere = false; \
			for(auto j = adj_values.begin(); j != adj_values.end(); ++j) \
			{ \
				if(values_table.find(i->first + *j) == values_table.end()) \
				{ \
					nothere = true; \
					break; \
				} \
			} \
			if(nothere) \
			{ \
				continue; \
			} \
			printf("Matched base value: %lld (" #T ")\n", (long long int)(i->first)); \
		} \
	}

REHex::Search::RelativeValues::RelativeValues(Buffer &buffer, off_t begin, off_t end, off_t align, bool align_rel, std::list<int64_t> values, ValueType types):
	buffer(buffer), cur_pos(begin), end_pos(end)
{
	assert(!values.empty());
	
	int64_t min_value = values.front();
	for(auto i = values.begin(); i != values.end(); ++i)
	{
		if(*i < min_value)
		{
			min_value = *i;
		}
	}
	
	std::set<int64_t> adj_values;
	for(auto i = values.begin(); i != values.end(); ++i)
	{
		adj_values.emplace(*i - min_value);
	}
	
	THING(VT_U8,    uint8_t,  false);
	THING(VT_U16LE, uint16_t, false);
	THING(VT_U32LE, uint32_t, false);
	THING(VT_U32BE, uint32_t, true);
}

#include <stdlib.h>

int main(int argc, char **argv)
{
	if(argc < 3)
	{
		printf("Usage: %s <filename> <value> <value> ...\n", argv[0]);
		return 1;
	}
	
	REHex::Buffer b(argv[1]);
	
	std::list<int64_t> values;
	for(int i = 2; i < argc; ++i)
	{
		values.push_back(strtoll(argv[i], NULL, 10));
	}
	
	REHex::Search::RelativeValues rv(b, 0, -1, 1, false, values, (REHex::ValueType)(REHex::VT_U32LE | REHex::VT_U32BE));
	
	return 0;
}
