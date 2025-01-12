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
#include <wx/colour.h>

#include "BitOffset.hpp"
#include "ByteRangeMap.hpp"
#include "DataView.hpp"
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
			struct MapValue
			{
				wxColour colour;
				std::string description;
				
				MapValue() = default;
				
				MapValue(const wxColour &colour, const std::string &description):
					colour(colour),
					description(description) {}
				
				bool operator==(const MapValue &rhs) const
				{
					return colour == rhs.colour && description == rhs.description;
				}
				
				bool operator!=(const MapValue &rhs) const
				{
					return !(*this == rhs);
				}
			};
			
			/**
			 * @brief Get the bit range to colour mapping.
			*/
			virtual BitRangeMap<MapValue> get_data_map() = 0;
			
			virtual void reset_max_points(size_t max_points) = 0;
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
			EntropyDataMapSource(const SharedEvtHandler<DataView> &view, size_t max_points, double log_multi = 1.0f);
			
			/**
			 * @brief Construct an EntropyDataMapSource covering a range within a file.
			 *
			 * @param document      Document to accumulate data from.
			 * @param range_offset  Offset within file to accumulate data from.
			 * @param range_length  Length of range to accumulate data from.
			 * @param max_points    Maximum number of data points to output.
			*/
			EntropyDataMapSource(const SharedEvtHandler<DataView> &view, BitOffset range_offset, off_t range_length, size_t max_points);
			
			virtual ~EntropyDataMapSource() = default;
			
			virtual BitRangeMap<MapValue> get_data_map() override;
			
			virtual void reset_max_points(size_t max_points) override;
			
		private:
			SharedEvtHandler<DataView> view;
			
			size_t max_points;
			double log_multi;
			
			std::unique_ptr<HierarchicalByteAccumulator> accumulator;
	};
	
	/**
	 * @brief DataMapSource implementation for displaying data entropy.
	*/
	class BasicStatDataMapSource: public DataMapSource
	{
		public:
			/**
			 * @brief Construct an EntropyDataMapSource covering a whole file.
			 *
			 * @param document    Document to accumulate data from.
			 * @param max_points  Maximum number of data points to output.
			*/
			BasicStatDataMapSource(const SharedEvtHandler<DataView> &view, size_t max_points);
			
			/**
			 * @brief Construct an EntropyDataMapSource covering a range within a file.
			 *
			 * @param document      Document to accumulate data from.
			 * @param range_offset  Offset within file to accumulate data from.
			 * @param range_length  Length of range to accumulate data from.
			 * @param max_points    Maximum number of data points to output.
			*/
			BasicStatDataMapSource(const SharedEvtHandler<DataView> &view, BitOffset range_offset, off_t range_length, size_t max_points);
			
			virtual ~BasicStatDataMapSource() = default;
			
			virtual BitRangeMap<MapValue> get_data_map() override;
			
		private:
			std::unique_ptr<HierarchicalByteAccumulator> accumulator;
	};
}

#endif /* !REHEX_DATAMAPSOURCE_HPP */
