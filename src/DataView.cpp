/* Reverse Engineer's Hex Editor
 * Copyright (C) 2024-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <limits>
#include <tuple>

#include "ByteRangeSet.hpp"
#include "DataView.hpp"
#include "Range.hpp"
#include "util.hpp"

wxDEFINE_EVENT(REHex::DATA_MODIFY_BEGIN, wxCommandEvent);
wxDEFINE_EVENT(REHex::DATA_MODIFY_END,   wxCommandEvent);

REHex::FlatDocumentView::FlatDocumentView(const SharedDocumentPointer &document):
	document(document)
{
	this->document.auto_cleanup_bind(DATA_ERASING,           &REHex::FlatDocumentView::OnBeginEvent, this);
	this->document.auto_cleanup_bind(DATA_ERASE_ABORTED,     &REHex::FlatDocumentView::OnAbortEvent, this);
	this->document.auto_cleanup_bind(DATA_ERASE,             &REHex::FlatDocumentView::OnDataEvent,  this);
	
	this->document.auto_cleanup_bind(DATA_INSERTING,         &REHex::FlatDocumentView::OnBeginEvent, this);
	this->document.auto_cleanup_bind(DATA_INSERT_ABORTED,    &REHex::FlatDocumentView::OnAbortEvent, this);
	this->document.auto_cleanup_bind(DATA_INSERT,            &REHex::FlatDocumentView::OnDataEvent,  this);
	
	this->document.auto_cleanup_bind(DATA_OVERWRITING,       &REHex::FlatDocumentView::OnBeginEvent, this);
	this->document.auto_cleanup_bind(DATA_OVERWRITE_ABORTED, &REHex::FlatDocumentView::OnAbortEvent, this);
	this->document.auto_cleanup_bind(DATA_OVERWRITE,         &REHex::FlatDocumentView::OnDataEvent,  this);
}

off_t REHex::FlatDocumentView::view_length() const
{
	return document->buffer_length();
}

std::vector<unsigned char> REHex::FlatDocumentView::read_data(BitOffset view_offset, off_t max_length) const
{
	return document->read_data(view_offset, max_length);
}

std::vector<bool> REHex::FlatDocumentView::read_bits(BitOffset view_offset, size_t max_length) const
{
	return document->read_bits(view_offset, max_length);
}

REHex::BitOffset REHex::FlatDocumentView::view_offset_to_real_offset(BitOffset view_offset) const
{
	return view_offset;
}

REHex::BitOffset REHex::FlatDocumentView::real_offset_to_view_offset(BitOffset real_offset) const
{
	return real_offset;
}

REHex::BitOffset REHex::FlatDocumentView::view_offset_to_virt_offset(BitOffset view_offset) const
{
	return view_offset;
}

REHex::BitOffset REHex::FlatDocumentView::virt_offset_to_view_offset(BitOffset virt_offset) const
{
	return virt_offset;
}

void REHex::FlatDocumentView::OnBeginEvent(OffsetLengthEvent &event)
{
	wxCommandEvent dmb_event(DATA_MODIFY_BEGIN);
	dmb_event.SetEventObject(this);
	ProcessEvent(dmb_event);
	
	event.Skip(); /* Continue original event propagation. */
}

void REHex::FlatDocumentView::OnAbortEvent(OffsetLengthEvent &event)
{
	wxCommandEvent dme_event(DATA_MODIFY_END);
	dme_event.SetEventObject(this);
	ProcessEvent(dme_event);
	
	event.Skip(); /* Continue original event propagation. */
}

void REHex::FlatDocumentView::OnDataEvent(OffsetLengthEvent &event)
{
	OffsetLengthEvent our_event(this, event.GetEventType(), event.offset, event.length);
	ProcessEvent(our_event);
	
	wxCommandEvent dme_event(DATA_MODIFY_END);
	dme_event.SetEventObject(this);
	ProcessEvent(dme_event);
	
	event.Skip(); /* Continue original event propagation. */
}

REHex::FlatRangeView::FlatRangeView(const SharedDocumentPointer &document, BitOffset base_offset, off_t max_length):
	document(document),
	m_base_offset(base_offset),
	m_max_length(max_length)
{
	assert(base_offset >= BitOffset::ZERO);
	assert(max_length >= 0);
	
	m_length = std::max<off_t>(0, std::min((document->buffer_length() - m_base_offset.byte_round_up()), m_max_length));
	
	this->document.auto_cleanup_bind(DATA_ERASING,           &REHex::FlatRangeView::OnBeginIEEvent, this);
	this->document.auto_cleanup_bind(DATA_ERASE_ABORTED,     &REHex::FlatRangeView::OnAbortIEEvent, this);
	this->document.auto_cleanup_bind(DATA_ERASE,             &REHex::FlatRangeView::OnDataIEEvent,  this);
	
	this->document.auto_cleanup_bind(DATA_INSERTING,         &REHex::FlatRangeView::OnBeginIEEvent, this);
	this->document.auto_cleanup_bind(DATA_INSERT_ABORTED,    &REHex::FlatRangeView::OnAbortIEEvent, this);
	this->document.auto_cleanup_bind(DATA_INSERT,            &REHex::FlatRangeView::OnDataIEEvent,  this);
	
	this->document.auto_cleanup_bind(DATA_OVERWRITING,       &REHex::FlatRangeView::OnBeginOEvent, this);
	this->document.auto_cleanup_bind(DATA_OVERWRITE_ABORTED, &REHex::FlatRangeView::OnAbortOEvent, this);
	this->document.auto_cleanup_bind(DATA_OVERWRITE,         &REHex::FlatRangeView::OnDataOEvent,  this);
}

off_t REHex::FlatRangeView::view_length() const
{
	off_t buffer_length_from_base = std::max<off_t>((document->buffer_length() - m_base_offset.byte_round_up()), 0);
	return std::min(buffer_length_from_base, m_max_length);
}

std::vector<unsigned char> REHex::FlatRangeView::read_data(BitOffset view_offset, off_t max_length) const
{
	assert(view_offset >= BitOffset::ZERO);
	
	off_t clamped_length = std::min(max_length, (m_max_length - view_offset.byte_round_up()));
	return document->read_data((m_base_offset + view_offset), clamped_length);
}

std::vector<bool> REHex::FlatRangeView::read_bits(BitOffset view_offset, size_t max_length) const
{
	assert(view_offset >= BitOffset::ZERO);
	
	BitOffset buffer_length_from_offset = std::max((BitOffset(view_length(), 0) - view_offset), BitOffset::ZERO);
	if(buffer_length_from_offset < BitOffset::ZERO)
	{
		return std::vector<bool>();
	}
	
	int64_t blfo_bits = buffer_length_from_offset.total_bits();
	
	if((uint64_t)(blfo_bits) <= (uint64_t)(std::numeric_limits<size_t>::max()) && max_length > (size_t)(blfo_bits))
	{
		max_length = blfo_bits;
	}
	
	return document->read_bits((m_base_offset + view_offset), max_length);
}

REHex::BitOffset REHex::FlatRangeView::view_offset_to_real_offset(BitOffset view_offset) const
{
	return m_base_offset + view_offset;
}

REHex::BitOffset REHex::FlatRangeView::real_offset_to_view_offset(BitOffset real_offset) const
{
	if(real_offset >= m_base_offset && real_offset < (m_base_offset + BitOffset(m_length, 0)))
	{
		return real_offset - m_base_offset;
	}
	else{
		return BitOffset::INVALID;
	}
}

REHex::BitOffset REHex::FlatRangeView::view_offset_to_virt_offset(BitOffset view_offset) const
{
	return m_base_offset + view_offset;
}

REHex::BitOffset REHex::FlatRangeView::virt_offset_to_view_offset(BitOffset virt_offset) const
{
	return real_offset_to_view_offset(virt_offset);
}

void REHex::FlatRangeView::OnBeginOEvent(OffsetLengthEvent &event)
{
	BitRange event_range(BitOffset(event.offset, 0), BitOffset(event.length, 0));
	BitRange our_range(m_base_offset, BitOffset(view_length(), 0));
	
	if(event_range.overlaps(our_range))
	{
		wxCommandEvent dmb_event(DATA_MODIFY_BEGIN);
		dmb_event.SetEventObject(this);
		ProcessEvent(dmb_event);
	}
	
	event.Skip(); /* Continue original event propagation. */
}

void REHex::FlatRangeView::OnAbortOEvent(OffsetLengthEvent &event)
{
	BitRange event_range(BitOffset(event.offset, 0), BitOffset(event.length, 0));
	BitRange our_range(m_base_offset, BitOffset(view_length(), 0));
	
	if(event_range.overlaps(our_range))
	{
		wxCommandEvent dme_event(DATA_MODIFY_END);
		dme_event.SetEventObject(this);
		ProcessEvent(dme_event);
	}
	
	event.Skip(); /* Continue original event propagation. */
}

void REHex::FlatRangeView::OnDataOEvent(OffsetLengthEvent &event)
{
	BitRange event_range(BitOffset(event.offset, 0), BitOffset(event.length, 0));
	BitRange our_range(m_base_offset, BitOffset(view_length(), 0));
	
	BitRange intersection = BitRange::intersection(event_range, our_range);
	
	assert(intersection.offset.byte_aligned());
	assert(intersection.length.byte_aligned());
	
	if(!(intersection.empty()))
	{
		OffsetLengthEvent our_event(this, event.GetEventType(),
			(intersection.offset - m_base_offset).byte(), intersection.length.byte());
		ProcessEvent(our_event);
		
		wxCommandEvent dme_event(DATA_MODIFY_END);
		dme_event.SetEventObject(this);
		ProcessEvent(dme_event);
	}
	
	event.Skip(); /* Continue original event propagation. */
}

void REHex::FlatRangeView::OnBeginIEEvent(OffsetLengthEvent &event)
{
	if(event.offset < (m_base_offset.byte_round_up() + m_max_length))
	{
		wxCommandEvent dmb_event(DATA_MODIFY_BEGIN);
		dmb_event.SetEventObject(this);
		ProcessEvent(dmb_event);
	}
	
	event.Skip(); /* Continue original event propagation. */
}

void REHex::FlatRangeView::OnAbortIEEvent(OffsetLengthEvent &event)
{
	if(event.offset < (m_base_offset.byte_round_up() + m_max_length))
	{
		wxCommandEvent dme_event(DATA_MODIFY_END);
		dme_event.SetEventObject(this);
		ProcessEvent(dme_event);
	}
	
	event.Skip(); /* Continue original event propagation. */
}

void REHex::FlatRangeView::OnDataIEEvent(OffsetLengthEvent &event)
{
	if(event.offset < (m_base_offset.byte_round_up() + m_max_length))
	{
		off_t translated_offset = event.offset > m_base_offset.byte() ? (event.offset - m_base_offset.byte_round_up()) : 0;
		
		if(event.GetEventType() == DATA_ERASE)
		{
			off_t num_erase = std::min(event.length, (m_length - translated_offset));
			
			if(num_erase > 0)
			{
				
				m_length -= num_erase;
				
				OffsetLengthEvent erase_event(this, DATA_ERASE, translated_offset, num_erase);
				ProcessEvent(erase_event);
			}
			
			off_t grow_available = document->buffer_length() - m_base_offset.byte_round_up() - m_length;
			
			if(m_length < m_max_length && grow_available > 0)
			{
				off_t num_insert = std::min((m_max_length - m_length), grow_available);
				m_length += num_insert;
				
				OffsetLengthEvent insert_event(this, DATA_INSERT, (m_length - num_insert), num_insert);
				ProcessEvent(insert_event);
			}
		}
		else{
			assert(event.GetEventType() == DATA_INSERT);
			
			BitOffset length_from_base = std::min((BitOffset(document->buffer_length(), 0) - m_base_offset), BitOffset(event.length, 0));
			
			if(length_from_base >= BitOffset(1, 0))
			{
				off_t num_insert = std::min(length_from_base.byte(), (m_max_length - translated_offset));
				m_length += num_insert;
				
				OffsetLengthEvent insert_event(this, DATA_INSERT, translated_offset, num_insert);
				ProcessEvent(insert_event);
			}
			
			if(m_length > m_max_length)
			{
				off_t excess = m_length - m_max_length;
				m_length -= excess;
				
				OffsetLengthEvent erase_event(this, DATA_ERASE, m_length, excess);
				ProcessEvent(erase_event);
			}
		}
		
		wxCommandEvent dme_event(DATA_MODIFY_END);
		dme_event.SetEventObject(this);
		ProcessEvent(dme_event);
	}
	
	event.Skip(); /* Continue original event propagation. */
}

REHex::LinearVirtualDocumentView::LinearVirtualDocumentView(const SharedDocumentPointer &document):
	document(document),
	total_view_length(0)
{
	this->document.auto_cleanup_bind(DATA_ERASING,           &REHex::LinearVirtualDocumentView::OnDataErasing,          this);
	this->document.auto_cleanup_bind(DATA_ERASE_ABORTED,     &REHex::LinearVirtualDocumentView::OnDataEraseAborted,     this);
	this->document.auto_cleanup_bind(DATA_ERASE_DONE,        &REHex::LinearVirtualDocumentView::OnDataEraseDone,        this);
	
	this->document.auto_cleanup_bind(DATA_INSERTING,         &REHex::LinearVirtualDocumentView::OnDataInserting,        this);
	this->document.auto_cleanup_bind(DATA_INSERT_ABORTED,    &REHex::LinearVirtualDocumentView::OnDataInsertAborted,    this);
	this->document.auto_cleanup_bind(DATA_INSERT_DONE,       &REHex::LinearVirtualDocumentView::OnDataInsertDone,       this);
	
	this->document.auto_cleanup_bind(DATA_OVERWRITING,       &REHex::LinearVirtualDocumentView::OnDataOverwriting,      this);
	this->document.auto_cleanup_bind(DATA_OVERWRITE_ABORTED, &REHex::LinearVirtualDocumentView::OnDataOverwriteAborted, this);
	this->document.auto_cleanup_bind(DATA_OVERWRITE,         &REHex::LinearVirtualDocumentView::OnDataOverwrite,        this);
	
	this->document.auto_cleanup_bind(EV_MAPPINGS_CHANGED,    &REHex::LinearVirtualDocumentView::OnMappingsChanged,      this);
	
	load_segments(document->get_virt_to_real_segs(), std::unique_lock<shared_mutex>(mutex));
}

void REHex::LinearVirtualDocumentView::load_segments(const ByteRangeMap<off_t> &virt_to_real_segs, const std::unique_lock<shared_mutex> &lock_guard)
{
	this->virt_to_real_segs = virt_to_real_segs;
	
	real_to_view_segs.clear();
	view_to_real_segs.clear();
	
	off_t next_view_offset = 0;
	
	for(auto it = virt_to_real_segs.begin(); it != virt_to_real_segs.end(); ++it)
	{
		real_to_view_segs.set_range(it->second, it->first.length, next_view_offset);
		view_to_real_segs.set_range(next_view_offset, it->first.length, it->second);
		
		next_view_offset += it->first.length;
	}
	
	total_view_length = next_view_offset;
}

void REHex::LinearVirtualDocumentView::check_segments()
{
	const ByteRangeMap<off_t> &new_virt_to_real_segs = document->get_virt_to_real_segs();
	
	if(virt_to_real_segs != new_virt_to_real_segs)
	{
		{
			wxCommandEvent dmb_event(DATA_MODIFY_BEGIN);
			dmb_event.SetEventObject(this);
			ProcessEvent(dmb_event);
		}
		
		off_t old_view_length = total_view_length;
		
		load_segments(new_virt_to_real_segs, std::unique_lock<shared_mutex>(mutex));
		
		{
			OffsetLengthEvent data_event(this, DATA_ERASE, 0, old_view_length);
			ProcessEvent(data_event);
		}
		
		{
			OffsetLengthEvent data_event(this, DATA_INSERTING, 0, total_view_length);
			ProcessEvent(data_event);
		}
		
		{
			OffsetLengthEvent data_event(this, DATA_INSERT, 0, total_view_length);
			ProcessEvent(data_event);
		}
		
		{
			wxCommandEvent dme_event(DATA_MODIFY_END);
			dme_event.SetEventObject(this);
			ProcessEvent(dme_event);
		}
	}
}

off_t REHex::LinearVirtualDocumentView::view_length() const
{
	shared_lock lock_guard(mutex);
	return total_view_length;
}

std::vector<unsigned char> REHex::LinearVirtualDocumentView::read_data(BitOffset view_offset, off_t max_length) const
{
	int shift = view_offset.bit();
	
	shared_lock lock_guard(mutex);
	
	std::vector<unsigned char> data;
	
	for(auto it = view_to_real_segs.get_range(view_offset.byte()); it != view_to_real_segs.end() && max_length > 0; ++it)
	{
		BitOffset seg_offset = view_offset - BitOffset(it->first.offset, 0);
		off_t seg_read = std::min(max_length, ((it->first.offset + it->first.length) - view_offset.byte_round_up()));
		
		std::vector<unsigned char> seg_data = document->read_data((it->second + seg_offset.byte()), (seg_read + !seg_offset.byte_aligned()));
		assert((off_t)(seg_data.size()) >= seg_read);
		
		size_t insertion_point = data.size();
		data.resize(insertion_point + seg_data.size());
		
		CarryBits carry = memcpy_left((data.data() + insertion_point), seg_data.data(), seg_data.size(), shift);
		
		if(insertion_point > 0)
		{
			data[insertion_point - 1] |= carry.value;
		}
		
		max_length -= seg_read;
		view_offset = BitOffset((it->first.offset + it->first.length), 0);
	}
	
	if(shift != 0)
	{
		data.pop_back();
	}
	
	return data;
}

std::vector<bool> REHex::LinearVirtualDocumentView::read_bits(BitOffset view_offset, size_t max_length) const
{
	std::vector<bool> data;
	
	for(auto it = view_to_real_segs.get_range(view_offset.byte()); it != view_to_real_segs.end() && max_length > 0; ++it)
	{
		BitOffset seg_offset = view_offset - BitOffset(it->first.offset);
		int64_t seg_read = std::min<int64_t>((BitOffset((it->first.offset + it->first.length), 0) - view_offset).total_bits(), max_length);
		
		std::vector<bool> seg_data = document->read_bits((BitOffset(it->second, 0) + seg_offset), seg_read);
		data.insert(data.end(), seg_data.begin(), seg_data.end());
		
		max_length -= seg_read;
		view_offset += BitOffset::from_int64(seg_read);
	}
	
	return data;
}

REHex::BitOffset REHex::LinearVirtualDocumentView::view_offset_to_real_offset(BitOffset view_offset) const
{
	shared_lock lock_guard(mutex);
	
	auto it = view_to_real_segs.get_range(view_offset.byte());
	if(it == view_to_real_segs.end())
	{
		view_to_real_segs.get_range(view_offset.byte() - 1);
	}
	
	assert(it != view_to_real_segs.end());
	
	return BitOffset((it->second + (view_offset.byte() - it->first.offset)), view_offset.bit());
}

REHex::BitOffset REHex::LinearVirtualDocumentView::real_offset_to_view_offset(BitOffset real_offset) const
{
	shared_lock lock_guard(mutex);
	
	auto it = real_to_view_segs.get_range(real_offset.byte());
	
	if(it != real_to_view_segs.end())
	{
		return BitOffset((it->second + (real_offset.byte() - it->first.offset)), real_offset.bit());
	}
	else{
		return BitOffset::INVALID;
	}
}

REHex::BitOffset REHex::LinearVirtualDocumentView::view_offset_to_virt_offset(BitOffset view_offset) const
{
	BitOffset real_offset = view_offset_to_real_offset(view_offset);
	
	return BitOffset(document->real_to_virt_offset(real_offset.byte()), view_offset.bit());
}

REHex::BitOffset REHex::LinearVirtualDocumentView::virt_offset_to_view_offset(BitOffset virt_offset) const
{
	shared_lock lock_guard(mutex);
	
	auto it = virt_to_real_segs.get_range(virt_offset.byte());
	
	if(it != virt_to_real_segs.end())
	{
		BitOffset real_offset = BitOffset((it->second + (virt_offset.byte() - it->first.offset)), virt_offset.bit());
		lock_guard.unlock();
		
		return real_offset_to_view_offset(real_offset);
	}
	else{
		return BitOffset::INVALID;
	}
}

REHex::ByteRangeSet REHex::LinearVirtualDocumentView::find_event_ranges(const OffsetLengthEvent &event, const std::unique_lock<shared_mutex> &lock_guard)
{
	off_t event_end = event.offset + event.length;
	
	ByteRangeSet ranges;
	
	for(
		auto it = real_to_view_segs.get_range_in(event.offset, event.length);
		it != real_to_view_segs.end() && it->first.offset < event_end;
		++it)
	{
		off_t overlap_offset, overlap_length;
		std::tie(overlap_offset, overlap_length) = event.get_clamped_range(it->first.offset, it->first.length);
		
		assert(overlap_length > 0);
		
		off_t overlap_offset_from_seg_base = overlap_offset - it->first.offset;
		
		ranges.set_range((it->second + overlap_offset_from_seg_base), overlap_length);
	}
	
	return ranges;
}

void REHex::LinearVirtualDocumentView::process_event_for_ranges_asc(wxEventType type, const ByteRangeSet &ranges)
{
	for(auto it = ranges.begin(); it != ranges.end(); ++it)
	{
		OffsetLengthEvent range_event(this, type, it->offset, it->length);
		ProcessEvent(range_event);
	}
}

void REHex::LinearVirtualDocumentView::process_event_for_ranges_desc(wxEventType type, const ByteRangeSet &ranges)
{
	if(!ranges.empty())
	{
		auto it = ranges.end();
		do {
			--it;
			
			OffsetLengthEvent range_event(this, type, it->offset, it->length);
			ProcessEvent(range_event);
		} while(it != ranges.begin());;
	}
}

void REHex::LinearVirtualDocumentView::OnDataErasing(OffsetLengthEvent &event)
{
	wxCommandEvent dmb_event(DATA_MODIFY_BEGIN);
	dmb_event.SetEventObject(this);
	ProcessEvent(dmb_event);
	
	event.Skip(); /* Continue original event propagation. */
}

void REHex::LinearVirtualDocumentView::OnDataEraseAborted(OffsetLengthEvent &event)
{
	ByteRangeSet ranges = find_event_ranges(event, std::unique_lock<shared_mutex>(mutex));
	
	wxCommandEvent dme_event(DATA_MODIFY_END);
	dme_event.SetEventObject(this);
	ProcessEvent(dme_event);
	
	event.Skip(); /* Continue original event propagation. */
}

void REHex::LinearVirtualDocumentView::OnDataEraseDone(OffsetLengthEvent &event)
{
	std::unique_lock<shared_mutex> lock_guard(mutex);
	
	ByteRangeSet ranges = find_event_ranges(event, lock_guard);
	load_segments(document->get_virt_to_real_segs(), lock_guard);
	
	lock_guard.unlock();
	
	process_event_for_ranges_desc(DATA_ERASE, ranges);
	
	wxCommandEvent dme_event(DATA_MODIFY_END);
	dme_event.SetEventObject(this);
	ProcessEvent(dme_event);
	
	event.Skip(); /* Continue original event propagation. */
}

void REHex::LinearVirtualDocumentView::OnDataInserting(OffsetLengthEvent &event)
{
	wxCommandEvent dmb_event(DATA_MODIFY_BEGIN);
	dmb_event.SetEventObject(this);
	ProcessEvent(dmb_event);
	
	event.Skip(); /* Continue original event propagation. */
}

void REHex::LinearVirtualDocumentView::OnDataInsertAborted(OffsetLengthEvent &event)
{
	wxCommandEvent dme_event(DATA_MODIFY_END);
	dme_event.SetEventObject(this);
	ProcessEvent(dme_event);
	
	event.Skip(); /* Continue original event propagation. */
}

void REHex::LinearVirtualDocumentView::OnDataInsertDone(OffsetLengthEvent &event)
{
	load_segments(document->get_virt_to_real_segs(), std::unique_lock<shared_mutex>(mutex));
	
	wxCommandEvent dme_event(DATA_MODIFY_END);
	dme_event.SetEventObject(this);
	ProcessEvent(dme_event);
	
	event.Skip(); /* Continue original event propagation. */
}

void REHex::LinearVirtualDocumentView::OnDataOverwriting(OffsetLengthEvent &event)
{
	ByteRangeSet ranges = find_event_ranges(event, std::unique_lock<shared_mutex>(mutex));
	
	if(!ranges.empty())
	{
		wxCommandEvent dmb_event(DATA_MODIFY_BEGIN);
		dmb_event.SetEventObject(this);
		ProcessEvent(dmb_event);
	}
	
	event.Skip(); /* Continue original event propagation. */
}

void REHex::LinearVirtualDocumentView::OnDataOverwriteAborted(OffsetLengthEvent &event)
{
	ByteRangeSet ranges = find_event_ranges(event, std::unique_lock<shared_mutex>(mutex));
	
	if(!ranges.empty())
	{
		wxCommandEvent dme_event(DATA_MODIFY_END);
		dme_event.SetEventObject(this);
		ProcessEvent(dme_event);
	}
	
	event.Skip(); /* Continue original event propagation. */
}

void REHex::LinearVirtualDocumentView::OnDataOverwrite(OffsetLengthEvent &event)
{
	ByteRangeSet ranges = find_event_ranges(event, std::unique_lock<shared_mutex>(mutex));
	
	if(!ranges.empty())
	{
		process_event_for_ranges_asc(event.GetEventType(), ranges);
		
		wxCommandEvent dme_event(DATA_MODIFY_END);
		dme_event.SetEventObject(this);
		ProcessEvent(dme_event);
	}
	
	event.Skip(); /* Continue original event propagation. */
}

void REHex::LinearVirtualDocumentView::OnMappingsChanged(wxCommandEvent &event)
{
	check_segments();
	event.Skip(); /* Continue original event propagation. */
}
