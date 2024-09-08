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

#ifndef REHEX_DATAMAPSOURCE_HPP
#define REHEX_DATAMAPSOURCE_HPP

#include <memory>
#include <vector>
#include <wx/colour.h>

#include "BitOffset.hpp"
#include "ByteRangeMap.hpp"
#include "HierarchicalByteAccumulator.hpp"
#include "SharedDocumentPointer.hpp"

namespace REHex
{
	/**
	 * @brief Base interface for "Data Map" classes.
	 *
	 * Data Map classes present an overview of a file by mapping bit ranges to colours.
	*/
	class DataMapSource: public wxEvtHandler
	{
		public:
			/**
			 * @brief Get the bit range to colour mapping.
			*/
			virtual BitRangeMap<wxColour> get_data_map() = 0;
	};
	
	/**
	 * @brief DataMapSource implementation for displaying data entropy.
	*/
	class EntropyDataMapSource: public DataMapSource
	{
		public:
			/**
			 * @brief Construct an EntropyDataMapSource covering a whole file.
			 *
			 * @param document    Document to accumulate data from.
			 * @param max_points  Maximum number of data points to output.
			*/
			EntropyDataMapSource(const SharedDocumentPointer &document, size_t max_points);
			
			/**
			 * @brief Construct an EntropyDataMapSource covering a range within a file.
			 *
			 * @param document      Document to accumulate data from.
			 * @param range_offset  Offset within file to accumulate data from.
			 * @param range_length  Length of range to accumulate data from.
			 * @param max_points    Maximum number of data points to output.
			*/
			EntropyDataMapSource(const SharedDocumentPointer &document, BitOffset range_offset, off_t range_length, size_t max_points);
			
			virtual ~EntropyDataMapSource();
			
			virtual BitRangeMap<wxColour> get_data_map() override;
			
		private:
			struct SubRange
			{
				off_t rel_offset;
				off_t length;
				
				std::unique_ptr<HierarchicalByteAccumulator> accumulator;
				
				SubRange(const SharedDocumentPointer &doc, BitOffset base_offset, off_t rel_offset, off_t length):
					rel_offset(rel_offset),
					length(length),
					accumulator(new HierarchicalByteAccumulator(doc, (base_offset + BitOffset(rel_offset, 0)), length)) {}
			};
			
			SharedDocumentPointer document;
			
			BitOffset range_offset;
			off_t range_length;
			
			size_t max_points;
			
			std::vector<SubRange> sub_ranges;
			
			void repopulate_sub_ranges();
			
			void OnDocumentDataErase(OffsetLengthEvent &event);
			void OnDocumentDataInsert(OffsetLengthEvent &event);
	};
}

#endif /* !REHEX_DATAMAPSOURCE_HPP */
