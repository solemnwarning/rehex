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

#ifndef REHEX_DATAVIEW_HPP
#define REHEX_DATAVIEW_HPP

#include <vector>

#include "BitOffset.hpp"
#include "ByteRangeMap.hpp"
#include "ByteRangeSet.hpp"
#include "Events.hpp"
#include "shared_mutex.hpp"
#include "SharedDocumentPointer.hpp"

namespace REHex
{
	wxDECLARE_EVENT(DATA_MODIFY_BEGIN, wxCommandEvent);
	wxDECLARE_EVENT(DATA_MODIFY_END,   wxCommandEvent);
	
	class DataView: public wxEvtHandler
	{
		public:
			virtual ~DataView() = default;
			
			virtual off_t view_length() const = 0;
			
			virtual std::vector<unsigned char> read_data(BitOffset view_offset, off_t max_length) const = 0;
			
			virtual std::vector<bool> read_bits(BitOffset view_offset, size_t max_length) const = 0;
	};
	
	class FlatDocumentView: public DataView
	{
		private:
			SharedDocumentPointer document;
			
		public:
			FlatDocumentView(const SharedDocumentPointer &document);
			
			virtual off_t view_length() const override;
			
			virtual std::vector<unsigned char> read_data(BitOffset view_offset, off_t max_length) const override;
			
			virtual std::vector<bool> read_bits(BitOffset view_offset, size_t max_length) const override;
			
		private:
			void OnBeginEvent(OffsetLengthEvent &event);
			void OnAbortEvent(OffsetLengthEvent &event);
			void OnDataEvent(OffsetLengthEvent &event);
	};
	
	class LinearVirtualDocumentView: public DataView
	{
		private:
			SharedDocumentPointer document;
			
			mutable shared_mutex mutex;
			
			ByteRangeMap<off_t> virt_to_real_segs;
			
			ByteRangeMap<off_t> real_to_view_segs;
			ByteRangeMap<off_t> view_to_real_segs;
			
			off_t total_view_length;
			
		public:
			LinearVirtualDocumentView(const SharedDocumentPointer &document);
			
			virtual off_t view_length() const override;
			
			virtual std::vector<unsigned char> read_data(BitOffset view_offset, off_t max_length) const override;
			
			virtual std::vector<bool> read_bits(BitOffset view_offset, size_t max_length) const override;
			
		private:
			void load_segments(const ByteRangeMap<off_t> &virt_to_real_segs, const std::unique_lock<shared_mutex> &lock_guard);
			void check_segments();
			
			ByteRangeSet find_event_ranges(const OffsetLengthEvent &event, const std::unique_lock<shared_mutex> &lock_guard);
			void process_event_for_ranges_asc(wxEventType type, const ByteRangeSet &ranges);
			void process_event_for_ranges_desc(wxEventType type, const ByteRangeSet &ranges);
			
			void OnDataErasing(OffsetLengthEvent &event);
			void OnDataEraseAborted(OffsetLengthEvent &event);
			void OnDataEraseDone(OffsetLengthEvent &event);
			
			void OnDataInserting(OffsetLengthEvent &event);
			void OnDataInsertAborted(OffsetLengthEvent &event);
			void OnDataInsertDone(OffsetLengthEvent &event);
			
			void OnDataOverwriting(OffsetLengthEvent &event);
			void OnDataOverwriteAborted(OffsetLengthEvent &event);
			void OnDataOverwrite(OffsetLengthEvent &event);
			
			void OnMappingsChanged(wxCommandEvent &event);
	};
};

#endif /* !REHEX_DATAVIEW_HPP */
