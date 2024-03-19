/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_DATATYPE_HPP
#define REHEX_DATATYPE_HPP

#include <functional>
#include <map>
#include <string>
#include <vector>

#include "BitOffset.hpp"
#include "CharacterEncoder.hpp"
#include "document.hpp"
#include "DocumentCtrl.hpp"

namespace REHex
{
	class DataTypeRegistration;
	class DataTypeRegistry
	{
		public:
			static std::map<std::string, const DataTypeRegistration*>::const_iterator begin();
			static std::map<std::string, const DataTypeRegistration*>::const_iterator end();
			
			static const DataTypeRegistration *by_name(const std::string &name);
			
			static std::vector<const DataTypeRegistration*> sorted_by_group();
			
		private:
			/* The registrations map is created by the first DataTypeRegistration and
			 * destroyed when the last one in it removes itself. This is to avoid
			 * depending on global variable initialisation order.
			 *
			 * The no_registrations map is always empty and used to return iterators
			 * to an empty map when no registrations exist.
			*/
			
			static std::map<std::string, const DataTypeRegistration*> *registrations;
			static const std::map<std::string, const DataTypeRegistration*> no_registrations;
			
		friend DataTypeRegistration;
	};
	
	class DataTypeRegistration
	{
		public:
			typedef std::function<DocumentCtrl::Region*(SharedDocumentPointer &document, BitOffset offset, BitOffset length, BitOffset virt_offset)> RegionFactoryFunction;
			
			std::string name;
			std::string label;
			
			std::vector<std::string> groups;
			
			RegionFactoryFunction region_factory;
			const CharacterEncoder *encoder;
			
			BitOffset region_fixed_size;
			BitOffset region_multi_size;
			
			DataTypeRegistration(const std::string &name, const std::string &label, RegionFactoryFunction region_factory, const std::vector<std::string> &groups = {});
			DataTypeRegistration(const std::string &name, const std::string &label, const std::vector<std::string> &groups, const CharacterEncoder *encoder);
			~DataTypeRegistration();
			
			DataTypeRegistration(const DataTypeRegistration &src) = delete;
			
			DataTypeRegistration &make_region_fixed_size(BitOffset size);
			DataTypeRegistration &make_region_multi_size(BitOffset size);
	};
}

#endif /* !REHEX_DATATYPE_HPP */
