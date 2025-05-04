/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include "DocumentCtrl.hpp"

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

const REHex::DataTypeRegistration *REHex::DataTypeRegistry::get_registration(const std::string &name)
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

std::shared_ptr<const REHex::DataType> REHex::DataTypeRegistry::get_type(const std::string &name, const json_t *options)
{
	const DataTypeRegistration *reg = get_registration(name);
	if(reg != NULL)
	{
		return reg->get_type(options);
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
			if(a->groups != b->groups)
			{
				return a->groups < b->groups;
			}
			else{
				return a->label < b->label;
			}
		});
	
	return sorted_registrations;
}

REHex::ScopedDataTypeRegistry::ScopedDataTypeRegistry()
{
	registrations = DataTypeRegistry::registrations;
	DataTypeRegistry::registrations = NULL;
}

REHex::ScopedDataTypeRegistry::~ScopedDataTypeRegistry()
{
	assert(DataTypeRegistry::registrations == NULL);
	DataTypeRegistry::registrations = registrations;
}

static REHex::CharacterEncoderASCII ascii_encoder;

REHex::DataTypeRegistration::DataTypeRegistration(const std::string &name, const std::string &label, const std::vector<std::string> &groups):
	name(name),
	label(label),
	groups(groups)
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

REHex::DataType::DataType():
	word_size(REHex::BitOffset::ZERO),
	region_fixed_size(REHex::BitOffset::ZERO),
	encoder(NULL) {}

REHex::DataType REHex::DataType::WithWordSize(BitOffset word_size)
{
	assert(word_size > BitOffset::ZERO);
	assert(this->word_size == BitOffset::ZERO);
	
	DataType dt_copy(*this);
	dt_copy.word_size = word_size;
	
	return dt_copy;
}

REHex::DataType REHex::DataType::WithVariableSizeRegion(const RegionFactoryFunction &region_factory)
{
	assert(!this->region_factory);
	
	DataType dt_copy(*this);
	dt_copy.region_factory = region_factory;
	
	return dt_copy;
}

REHex::DataType REHex::DataType::WithFixedSizeRegion(const RegionFactoryFunction &region_factory, BitOffset region_fixed_size)
{
	assert(!this->region_factory);
	
	DataType dt_copy(*this);
	dt_copy.region_factory = region_factory;
	dt_copy.region_fixed_size = region_fixed_size;
	
	return dt_copy;
}

REHex::DataType REHex::DataType::WithCharacterEncoder(const CharacterEncoder *encoder)
{
	assert(this->encoder == NULL);
	
	DataType dt_copy(*this);
	dt_copy.encoder = encoder;
	
	return dt_copy;
}

REHex::StaticDataTypeRegistration::StaticDataTypeRegistration(const std::string &name, const std::string &label, const std::vector<std::string> &groups, DataType type):
	DataTypeRegistration(name, label, groups),
	m_type(std::make_shared<DataType>(type))
{
	assert(type.word_size > BitOffset::ZERO);
}

std::shared_ptr<const REHex::DataType> REHex::StaticDataTypeRegistration::get_type(const json_t *options) const
{
	if(options != NULL)
	{
		throw std::invalid_argument("Attempt to construct a static DataType with options");
	}
	
	return m_type;
}

bool REHex::StaticDataTypeRegistration::configurable() const
{
	return false;
}

json_t *REHex::StaticDataTypeRegistration::configure(wxWindow *parent) const
{
	throw std::logic_error("Attempt to configure a static data type");
}

REHex::ConfigurableDataTypeRegistration::ConfigurableDataTypeRegistration(
const std::string &name, const std::string &label,
const DynamicDataTypeConfigurator &configurator, const DynamicDataTypeFactory &factory):
	DataTypeRegistration(name, label, {}),
	m_configurator(configurator),
	m_factory(factory) {}

REHex::ConfigurableDataTypeRegistration::ConfigurableDataTypeRegistration(
const std::string &name, const std::string &label, const std::vector<std::string> &groups,
const DynamicDataTypeConfigurator &configurator, const DynamicDataTypeFactory &factory):
	DataTypeRegistration(name, label, groups),
	m_configurator(configurator),
	m_factory(factory) {}

std::shared_ptr<const REHex::DataType> REHex::ConfigurableDataTypeRegistration::get_type(const json_t *options) const
{
	return std::make_shared<DataType>(m_factory(options));
}

bool REHex::ConfigurableDataTypeRegistration::configurable() const
{
	return true;
}

json_t *REHex::ConfigurableDataTypeRegistration::configure(wxWindow *parent) const
{
	return m_configurator(parent);
}
