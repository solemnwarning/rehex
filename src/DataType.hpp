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

#ifndef REHEX_DATATYPE_HPP
#define REHEX_DATATYPE_HPP

#include <map>
#include <string>

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
			typedef DocumentCtrl::Region* (*RegionFactoryFunction)(SharedDocumentPointer &document, off_t offset, off_t length);
			
			std::string name;
			std::string label;
			
			RegionFactoryFunction region_factory;
			
			off_t fixed_size;
			
			DataTypeRegistration(const std::string &name, const std::string &label, RegionFactoryFunction region_factory, off_t fixed_size = -1);
			~DataTypeRegistration();
			
			DataTypeRegistration(const DataTypeRegistration &src) = delete;
	};
}

#endif /* !REHEX_DATATYPE_HPP */
