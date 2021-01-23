/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2021 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <utility>

#include "DataType.hpp"

std::map<std::string, const REHex::DataTypeRegistration*> *REHex::DataTypeRegistry::registrations = NULL;
const std::map<std::string, const REHex::DataTypeRegistration*> REHex::DataTypeRegistry::no_registrations;

std::map<std::string, const REHex::DataTypeRegistration*>::const_iterator REHex::DataTypeRegistry::begin()
{
	return registrations != NULL
		? registrations->begin()
		: no_registrations.begin();
}

std::map<std::string, const REHex::DataTypeRegistration*>::const_iterator REHex::DataTypeRegistry::end()
{
	return registrations != NULL
		? registrations->end()
		: no_registrations.end();
}

const REHex::DataTypeRegistration *REHex::DataTypeRegistry::by_name(const std::string &name)
{
	if(registrations == NULL)
	{
		return NULL;
	}
	
	auto i = registrations->find(name);
	if(i != registrations->end())
	{
		return i->second;
	}
	else{
		return NULL;
	}
}

std::vector<const REHex::DataTypeRegistration*> REHex::DataTypeRegistry::sorted_by_group()
{
	if(registrations == NULL)
	{
		return std::vector<const DataTypeRegistration*>(); /* Empty vector. */
	}
	
	std::vector<const DataTypeRegistration*> sorted_registrations;
	sorted_registrations.reserve(registrations->size());
	
	for(auto r = registrations->begin(); r != registrations->end(); ++r)
	{
		sorted_registrations.push_back(r->second);
	}
	
	std::sort(sorted_registrations.begin(), sorted_registrations.end(),
		[](const DataTypeRegistration *a, const DataTypeRegistration *b)
		{
			if(a->group != b->group)
			{
				return a->group < b->group;
			}
			else{
				return a->label < b->label;
			}
		});
	
	return sorted_registrations;
}

REHex::DataTypeRegistration::DataTypeRegistration(const std::string &name, const std::string &label, RegionFactoryFunction region_factory, const std::string &group, off_t fixed_size):
	name(name),
	label(label),
	region_factory(region_factory),
	group(group),
	fixed_size(fixed_size)
{
	if(DataTypeRegistry::registrations == NULL)
	{
		DataTypeRegistry::registrations = new std::map<std::string, const REHex::DataTypeRegistration*>();
	}
	
	DataTypeRegistry::registrations->insert(std::make_pair(name, this));
}

REHex::DataTypeRegistration::~DataTypeRegistration()
{
	DataTypeRegistry::registrations->erase(name);
	
	if(DataTypeRegistry::registrations->empty())
	{
		delete DataTypeRegistry::registrations;
		DataTypeRegistry::registrations = NULL;
	}
}
