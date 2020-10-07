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

REHex::DataTypeRegistration::DataTypeRegistration(const std::string &name, const std::string &label, RegionFactoryFunction region_factory, off_t fixed_size):
	name(name),
	label(label),
	region_factory(region_factory),
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
