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

#ifndef REHEX_CHECKSUM_HPP
#define REHEX_CHECKSUM_HPP

#include <functional>
#include <map>
#include <stdlib.h>
#include <string>
#include <vector>

namespace REHex {
	/**
	 * @brief Base class of all checksum generators.
	*/
	class ChecksumGenerator
	{
		public:
			virtual ~ChecksumGenerator() {}
			
			virtual void add_data(const void *data, size_t size) = 0;
			virtual void finish() = 0;
			
			virtual void reset() = 0;
			
			virtual std::string checksum_hex() const = 0;
	};
	
	/**
	 * @brief Checksum algorithm registration.
	 *
	 * This class is used to register a checksum algorithm and associated ChecksumGenerator
	 * factory function for computing it.
	 *
	 * This class is usually constructed during early program initialisation as a static global
	 * variable in the implementation of the checksum algorithm.
	*/
	class ChecksumAlgorithm
	{
		public:
			typedef std::function<ChecksumGenerator*()> FactoryFunction;
			
			std::string name;
			
			std::string group;
			std::string label;
			
			FactoryFunction factory;
			
			ChecksumAlgorithm(const std::string &name, const std::string &group, const std::string &label, const FactoryFunction &factory);
			ChecksumAlgorithm(const std::string &name, const std::string &label, const FactoryFunction &factory);
			~ChecksumAlgorithm();
			
			/* No copy c'tor or assignment operator. */
			ChecksumAlgorithm(const ChecksumAlgorithm&) = delete;
			ChecksumAlgorithm &operator=(const ChecksumAlgorithm&) = delete;
			
			/**
			 * @brief Get an iterator to the first registered algorithm.
			*/
			static std::map<std::string, const ChecksumAlgorithm*>::const_iterator begin();
			
			/**
			 * @brief Get an iterator to the end of the registrations.
			*/
			static std::map<std::string, const ChecksumAlgorithm*>::const_iterator end();
			
			/**
			 * @brief Search for a ChecksumAlgorithm by its internal name.
			 *
			 * @return ChecksumAlgorithm pointer, NULL if not found.
			*/
			static const ChecksumAlgorithm *by_name(const std::string &name);
			
			/**
			 * @brief Return a (sorted) list of all registered algorithms.
			*/
			static std::vector<const ChecksumAlgorithm*> all_algos();
			
		private:
			/* The registrations map is created by the first ChecksumAlgorithm and
			 * destroyed when the last one in it removes itself. This is to avoid
			 * depending on global variable initialisation order.
			 *
			 * The no_registrations map is always empty and used to return iterators
			 * to an empty map when no registrations exist.
			*/
			
			static std::map<std::string, const ChecksumAlgorithm*> *registrations;
			static const std::map<std::string, const ChecksumAlgorithm*> no_registrations;
	};
}

#endif /* !REHEX_CHECKSUM_HPP*/
