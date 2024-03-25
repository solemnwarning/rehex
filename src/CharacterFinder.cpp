/* Reverse Engineer's Hex Editor
 * Copyright (C) 2022-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "platform.hpp"

#include <algorithm>

#include "App.hpp"
#include "CharacterEncoder.hpp"
#include "CharacterFinder.hpp"
#include "DataType.hpp"

REHex::CharacterFinder::CharacterFinder(SharedDocumentPointer &document, BitOffset base, off_t length, size_t chunk_size, size_t lru_cache_size):
	document(document),
	base(base),
	length(length),
	chunk_size(chunk_size),
	t1_filling(false),
	t1_done(false),
	t2(lru_cache_size)
{
	t1_size = length / chunk_size;
	if(length > 0 && (length % chunk_size) == 0)
	{
		/* If length is aligned to chunk_size, don't have an empty chunk at the end. */
		--t1_size;
	}
	
	t1.reset(new std::atomic<int64_t>[t1_size]);
	
	reset_from(base);
}

REHex::CharacterFinder::~CharacterFinder()
{
	stop_worker();
}

void REHex::CharacterFinder::start_worker()
{
	if(!t1_worker.joinable())
	{
		if(t1_size == 0)
		{
			t1_filling = false;
			t1_done = true;
			
			return;
		}
		
		t1_filling = true;
		
		auto types = document->get_data_types();
		
		auto type_at_base = types.get_range(base);
		assert(type_at_base != types.end());
		
		BitOffset encoding_base = type_at_base->first.offset;
		assert(encoding_base <= base);
		
		const CharacterEncoder *encoder;
		if(type_at_base->second.name != "")
		{
			auto type = DataTypeRegistry::get_type(type_at_base->second.name, type_at_base->second.options);
			assert(type != NULL);
			
			if(type->encoder != NULL)
			{
				encoder = type->encoder;
			}
		}
		else{
			static REHex::CharacterEncoderASCII ascii_encoder;
			encoder = &ascii_encoder;
		}
		
		t1_worker = std::thread([this, encoding_base, encoder]()
		{
			size_t idx = 0;
			BitOffset base_off = base, target_off = base + BitOffset(chunk_size, 0);
			
			while(t1_filling && target_off < (base + BitOffset(length, 0)))
			{
				assert(target_off >= base_off);
				
				std::vector<unsigned char> data;
				try {
					assert((target_off - base_off).byte_aligned());
					data = document->read_data(base_off, ((target_off - base_off).byte() + MAX_CHAR_SIZE));
				}
				catch(const std::exception &e)
				{
					wxGetApp().printf_error("Exception in REHex::CharacterFinder (worker thread): %s\n", e.what());
					break;
				}
				
				bool ok = false;
				
				BitOffset at_offset = base_off - ((base_off - encoding_base) % encoder->word_size);
				size_t data_off = 0;
				
				while(at_offset < (base + BitOffset(length, 0)) && (size_t)(data_off) < data.size())
				{
					EncodedCharacter ec = encoder->decode((data.data() + data_off), (data.size() - data_off));
					
					int char_size = ec.valid
						? ec.encoded_char().size()
						: encoder->word_size;
					
					at_offset += char_size;
					data_off += char_size;
					
					if(at_offset >= target_off && (at_offset + (off_t)(char_size)) <= (base + length))
					{
						t1[idx] = at_offset.to_int64();
						
						base_off = at_offset;
						target_off += chunk_size;
						++idx;
						
						ok = true;
						break;
					}
				}
				
				if(!ok)
				{
					break;
				}
			}
			
			t1_filling = false;
			t1_done = true;
		});
	}
}

void REHex::CharacterFinder::stop_worker()
{
	if(t1_worker.joinable())
	{
		t1_filling = false;
		t1_worker.join();
	}
}

void REHex::CharacterFinder::reset_from(BitOffset offset)
{
	if(offset < base || offset >= (base + length))
	{
		/* Not in range tracked by this CharacterFinder. */
		return;
	}
	
	stop_worker();
	
	for(size_t i = std::max((((offset - base).byte() / (off_t)(chunk_size)) - 1), (off_t)(0)); i < t1_size; ++i)
	{
		t1[i] = -1;
	}
	
	t1_done = false;
	t2.clear();
	
	start_worker();
}

std::pair<REHex::BitOffset,off_t> REHex::CharacterFinder::get_char_range(BitOffset offset)
{
	if(offset < base || offset >= (base + BitOffset(length, 0)))
	{
		/* Not in range tracked by this CharacterFinder. */
		return std::make_pair(BitOffset::INVALID, -1);
	}
	
	ssize_t t1_idx = ((offset - base).byte() / (off_t)(chunk_size)) - 1;
	assert(t1_idx < (ssize_t)(t1_size));
	
	BitOffset t2_base_offset = t1_idx >= 0
		? BitOffset::from_int64(t1[t1_idx].load())
		: base;
	
	if(t2_base_offset < 0)
	{
		/* t1 slot not filled yet. */
		return std::make_pair(BitOffset::INVALID, -1);
	}
	
	if(t2_base_offset > offset)
	{
		--t1_idx;
		assert(t1_idx < (ssize_t)(t1_size));
		
		t2_base_offset = t1_idx >= 0
			? BitOffset::from_int64(t1[t1_idx].load())
			: base;
	}
	
	BitOffset t2_end_offset = ((t1_idx + 1) < (ssize_t)(t1_size))
		? BitOffset::from_int64(t1[t1_idx + 1].load())
		: base + length;
	
	if(t2_end_offset < 0)
	{
		/* t1 slot not filled yet. */
		return std::make_pair(BitOffset::INVALID, -1);
	}
	
	const std::vector<size_t> *t2_elem = t2.get(t2_base_offset);
	if(t2_elem == NULL)
	{
		std::vector<size_t> new_t2_elem;
		new_t2_elem.reserve(chunk_size);
		
		auto types = document->get_data_types();
		
		auto type_at_base = types.get_range(t2_base_offset);
		assert(type_at_base != types.end());
		
		BitOffset encoding_base = type_at_base->first.offset;
		assert(encoding_base <= t2_base_offset);
		
		static REHex::CharacterEncoderASCII ascii_encoder;
		const CharacterEncoder *encoder = &ascii_encoder;
		if(type_at_base->second.name != "")
		{
			auto type = DataTypeRegistry::get_type(type_at_base->second.name, type_at_base->second.options);
			assert(type != NULL);
			
			if(type->encoder != NULL)
			{
				encoder = type->encoder;
			}
		}
		
		std::vector<unsigned char> data;
		try {
			assert((t2_end_offset - t2_base_offset).byte_aligned());
			data = document->read_data(t2_base_offset, (t2_end_offset - t2_base_offset).byte());
		}
		catch(const std::exception &e)
		{
			wxGetApp().printf_error("Exception in REHex::CharacterFinder::get_char_range: %s\n", e.what());
			return std::make_pair(-1, -1);
		}
		
		BitOffset t2_off = t2_base_offset;
		size_t data_off = 0;
		
		for(; t2_off < t2_end_offset && data_off < data.size();)
		{
			assert((t2_off - t2_base_offset).byte_aligned());
			new_t2_elem.push_back((t2_off - t2_base_offset).byte());
			
			assert(types.get_range(t2_off) == type_at_base);
			
			EncodedCharacter ec = encoder->decode((data.data() + data_off), (data.size() - data_off));
			
			int char_size = ec.valid
				? ec.encoded_char().size()
				: encoder->word_size;
			
			t2_off += char_size;
			data_off += char_size;
		}
		
		t2.set(t2_base_offset, new_t2_elem);
		
		t2_elem = t2.get(t2_base_offset);
		assert(t2_elem != NULL);
	}
	
	assert(!t2_elem->empty());
	
	auto next_char_off = std::upper_bound(t2_elem->begin(), t2_elem->end(), (offset - t2_base_offset));
	auto this_char_off = std::prev(next_char_off);
	
	BitOffset abs_this_char_off = BitOffset(*this_char_off, 0) + t2_base_offset;
	
	if(next_char_off != t2_elem->end())
	{
		return std::make_pair(abs_this_char_off, (*next_char_off - *this_char_off));
	}
	else if(t2_end_offset > t2_base_offset)
	{
		assert((t2_end_offset - abs_this_char_off).byte_aligned());
		return std::make_pair(abs_this_char_off, (t2_end_offset - abs_this_char_off).byte());
	}
	else{
		return std::make_pair(-1, -1);
	}
}

REHex::BitOffset REHex::CharacterFinder::get_char_start(BitOffset offset)
{
	return get_char_range(offset).first;
}

off_t REHex::CharacterFinder::get_char_length(BitOffset offset)
{
	return get_char_range(offset).second;
}

bool REHex::CharacterFinder::finished()
{
	return t1_done;
}
