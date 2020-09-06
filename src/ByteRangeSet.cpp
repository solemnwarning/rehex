/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <assert.h>

#include "ByteRangeSet.hpp"
#include <algorithm>

void REHex::ByteRangeSet::set_range(off_t offset, off_t length)
{
	if(length <= 0)
	{
		return;
	}
	
	Range range(offset, length);
	set_ranges(&range, (&range) + 1);
}

void REHex::ByteRangeSet::clear_range(off_t offset, off_t length)
{
	if(length <= 0)
	{
		return;
	}
	
	/* Find the range of elements overlapping the range to be cleared. */
	
	auto next = std::lower_bound(ranges.begin(), ranges.end(), Range((offset + length), 0));
	
	std::vector<Range>::iterator erase_begin = next;
	std::vector<Range>::iterator erase_end   = next;
	
	while(erase_begin != ranges.begin())
	{
		auto eb_prev = std::prev(erase_begin);
		
		if((eb_prev->offset + eb_prev->length) >= offset)
		{
			erase_begin = eb_prev;
		}
		else{
			break;
		}
	}
	
	/* If the elements to be erased to not fall fully within the given range, then we shall
	 * populate collateral_damage with up to two elements to re-instate the lost ranges.
	*/
	
	std::vector<Range> collateral_damage;
	if(erase_begin != erase_end)
	{
		if(erase_begin->offset < offset)
		{
			/* Clear range is within erase range, so create a new Range from the start
			 * of the range to be erased up to the start of the range to be cleared.
			*/
			
			collateral_damage.push_back(Range(erase_begin->offset, (offset - erase_begin->offset)));
		}
		
		auto erase_last = std::prev(erase_end);
		
		if((erase_last->offset + erase_last->length) > (offset + length))
		{
			/* Clear range falls short of the end of the range to be erased, so create
			 * a range from the end of the clear range to the end of the erase range.
			*/
			
			off_t from = offset + length;
			off_t to   = erase_last->offset + erase_last->length;
			
			assert(to > from);
			
			collateral_damage.push_back(Range(from, (to - from)));
		}
	}
	
	auto insert_pos = ranges.erase(erase_begin, erase_end);
	ranges.insert(insert_pos, collateral_damage.begin(), collateral_damage.end());
}

void REHex::ByteRangeSet::clear_all()
{
	ranges.clear();
}

bool REHex::ByteRangeSet::isset(off_t offset) const
{
	auto lb = std::lower_bound(ranges.begin(), ranges.end(), Range(offset, 0));
	
	if(lb != ranges.end() && lb->offset == offset)
	{
		return true;
	}
	else if(lb != ranges.begin())
	{
		--lb;
		
		if(lb->offset <= offset && (lb->offset + lb->length) > offset)
		{
			return true;
		}
	}
	
	return false;
}

const std::vector<REHex::ByteRangeSet::Range> &REHex::ByteRangeSet::get_ranges() const
{
	return ranges;
}

std::vector<REHex::ByteRangeSet::Range>::const_iterator REHex::ByteRangeSet::begin() const
{
	return ranges.begin();
}

std::vector<REHex::ByteRangeSet::Range>::const_iterator REHex::ByteRangeSet::end() const
{
	return ranges.end();
}

size_t REHex::ByteRangeSet::size() const
{
	return ranges.size();
}

bool REHex::ByteRangeSet::empty() const
{
	return ranges.empty();
}

void REHex::ByteRangeSet::data_inserted(off_t offset, off_t length)
{
	for(auto i = ranges.begin(); i != ranges.end(); ++i)
	{
		if(i->offset >= offset)
		{
			i->offset += length;
		}
		else if(i->offset < offset && (i->offset + i->length) > offset)
		{
			i = ranges.insert(i, Range(i->offset, (offset - i->offset)));
			++i;
			
			i->length -= (offset - i->offset);
			i->offset = offset + length;
		}
	}
}

void REHex::ByteRangeSet::data_erased(off_t offset, off_t length)
{
	/* Find the range of elements overlapping the range to be erased. */
	
	auto next = std::lower_bound(ranges.begin(), ranges.end(), Range((offset + length), 0));
	
	std::vector<Range>::iterator erase_begin = next;
	std::vector<Range>::iterator erase_end   = next;
	
	while(erase_begin != ranges.begin())
	{
		auto sb_prev = std::prev(erase_begin);
		
		if((sb_prev->offset + sb_prev->length) > offset)
		{
			erase_begin = sb_prev;
		}
		else{
			break;
		}
	}
	
	/* Add a single range encompassing the existing range(s) immediately before or after the
	 * erase window (if any exist).
	*/
	
	if(erase_begin != erase_end)
	{
		auto erase_last = std::prev(erase_end);
		
		off_t begin = std::min(erase_begin->offset, offset);
		off_t end   = erase_last->offset + erase_last->length;
		
		erase_end = ranges.erase(erase_begin, erase_end);
		
		if(end > (offset + length))
		{
			end -= length;
			erase_end = ranges.insert(erase_end, Range(begin, (end - begin)));
			++erase_end;
		}
		else if(begin < offset)
		{
			end = offset;
			erase_end = ranges.insert(erase_end, Range(begin, (end - begin)));
			++erase_end;
		}
	}
	
	/* Adjust the offset of ranges after the erase window. */
	
	while(erase_end != ranges.end())
	{
		erase_end->offset -= length;
		++erase_end;
	}
}
