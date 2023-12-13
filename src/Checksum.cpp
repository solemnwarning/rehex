/* Reverse Engineer's Hex Editor
 * Copyright (C) 2023 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "Checksum.hpp"

std::map<std::string, const REHex::ChecksumAlgorithm*> *REHex::ChecksumAlgorithm::registrations = NULL;
const std::map<std::string, const REHex::ChecksumAlgorithm*> REHex::ChecksumAlgorithm::no_registrations;

REHex::ChecksumAlgorithm::ChecksumAlgorithm(const std::string &name, const std::string &group, const std::string &label, const FactoryFunction &factory):
	name(name),
	group(group),
	label(label),
	factory(factory)
{
	if(registrations == NULL)
	{
		registrations = new std::map<std::string, const REHex::ChecksumAlgorithm*>();
	}
	
	if(registrations->find(name) != registrations->end())
	{
		abort();
	}
	
	registrations->insert(std::make_pair(name, this));
}

REHex::ChecksumAlgorithm::ChecksumAlgorithm(const std::string &name, const std::string &label, const FactoryFunction &factory):
	ChecksumAlgorithm(name, "", label, factory) {}

REHex::ChecksumAlgorithm::~ChecksumAlgorithm()
{
	registrations->erase(name);
	
	if(registrations->empty())
	{
		delete registrations;
		registrations = NULL;
	}
}

std::map<std::string, const REHex::ChecksumAlgorithm*>::const_iterator REHex::ChecksumAlgorithm::begin()
{
	if(registrations == NULL)
	{
		return no_registrations.begin();
	}
	else{
		return registrations->begin();
	}
}

std::map<std::string, const REHex::ChecksumAlgorithm*>::const_iterator REHex::ChecksumAlgorithm::end()
{
	if(registrations == NULL)
	{
		return no_registrations.end();
	}
	else{
		return registrations->end();
	}
}

const REHex::ChecksumAlgorithm *REHex::ChecksumAlgorithm::by_name(const std::string &name)
{
	if(registrations == NULL)
	{
		return NULL;
	}
	else{
		auto it = registrations->find(name);
		
		if(it != registrations->end())
		{
			return it->second;
		}
		else{
			return NULL;
		}
	}
}

std::vector<const REHex::ChecksumAlgorithm*> REHex::ChecksumAlgorithm::all_algos()
{
	if(registrations == NULL)
	{
		return std::vector<const ChecksumAlgorithm*>(); /* Empty vector. */
	}
	
	std::vector<const ChecksumAlgorithm*> sorted_registrations;
	sorted_registrations.reserve(registrations->size());
	
	for(auto r = registrations->begin(); r != registrations->end(); ++r)
	{
		sorted_registrations.push_back(r->second);
	}
	
	std::sort(sorted_registrations.begin(), sorted_registrations.end(),
		[](const ChecksumAlgorithm *a, const ChecksumAlgorithm *b)
		{
			return (a->group + a->label) < (b->group + b->label);
		});
	
	return sorted_registrations;
}
