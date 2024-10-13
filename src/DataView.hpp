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
	class DataViewInterface: public wxEvtHandler
	{
		public:
			virtual ~DataViewInterface() = default;
			
			virtual off_t view_length() const = 0;
			
			virtual std::vector<unsigned char> read_data(BitOffset view_offset, off_t max_length) const = 0;
			
			virtual std::vector<bool> read_bits(BitOffset view_offset, size_t max_length) const = 0;
	};
	
	class FlatDocumentView: public DataViewInterface
	{
		private:
			SharedDocumentPointer document;
			
		public:
			FlatDocumentView(const SharedDocumentPointer &document);
			
			virtual off_t view_length() const override;
			
			virtual std::vector<unsigned char> read_data(BitOffset view_offset, off_t max_length) const override;
			
			virtual std::vector<bool> read_bits(BitOffset view_offset, size_t max_length) const override;
			
		private:
			void OnDataEvent(OffsetLengthEvent &event);
	};
	
	class LinearVirtualDocumentView: public DataViewInterface
	{
		private:
			SharedDocumentPointer document;
			
			mutable shared_mutex mutex;
			
			ByteRangeMap<off_t> virt_to_real_segs;
			
			ByteRangeMap<off_t> real_to_view_segs;
			ByteRangeMap<off_t> view_to_real_segs;
			
			off_t total_view_length;
			
			off_t pending_erase_offset;
			off_t pending_erase_length;
			
		public:
			LinearVirtualDocumentView(const SharedDocumentPointer &document);
			
			virtual off_t view_length() const override;
			
			virtual std::vector<unsigned char> read_data(BitOffset view_offset, off_t max_length) const override;
			
			virtual std::vector<bool> read_bits(BitOffset view_offset, size_t max_length) const override;
			
		private:
			void load_segments();
			
			ByteRangeSet find_event_ranges(const OffsetLengthEvent &event);
			void process_event_for_ranges_asc(wxEventType type, const ByteRangeSet &ranges);
			void process_event_for_ranges_desc(wxEventType type, const ByteRangeSet &ranges);
			
			void OnDataErasing(OffsetLengthEvent &event);
			void OnDataEraseAborted(OffsetLengthEvent &event);
			void OnDataEraseDone(OffsetLengthEvent &event);
			
			void OnDataInserting(OffsetLengthEvent &event);
			void OnDataInsertAborted(OffsetLengthEvent &event);
			void OnDataInsert(OffsetLengthEvent &event);
			
			void OnDataOverwriteEvent(OffsetLengthEvent &event);
			
			void OnMappingsChanged(wxCommandEvent &event);
	};
};

#endif /* !REHEX_DATAVIEW_HPP */
