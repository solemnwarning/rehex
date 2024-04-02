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
#include <jansson.h>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "BitOffset.hpp"
#include "CharacterEncoder.hpp"
#include "document.hpp"
#include "DocumentCtrl.hpp"

namespace REHex
{
	class DataType;
	class DataTypeRegistration;
	
	/**
	 * @brief DataTypeRegistry testing helper.
	 *
	 * This class dynamically scopes the global DataTypeRegistry so any
	 * existing registrations are hidden and registrations which are made
	 * within the scope must be removed before it is closed.
	 *
	 * This class is for unit test use only.
	*/
	class ScopedDataTypeRegistry
	{
		private:
			std::map<std::string, const DataTypeRegistration*> *registrations;
			
		public:
			ScopedDataTypeRegistry();
			~ScopedDataTypeRegistry();
	};
	
	/**
	 * @brief Data type registry.
	 *
	 * This class allows enumerating active DataTypeRegistration instances
	 * and fetching/constructing their DataType classes.
	*/
	class DataTypeRegistry
	{
		public:
			static std::map<std::string, const DataTypeRegistration*>::const_iterator begin();
			static std::map<std::string, const DataTypeRegistration*>::const_iterator end();
			
			/**
			 * @brief Fetch a DataTypeRegistration pointer.
			 *
			 * Returns a pointer to the DataTypeRegistration class for the requested
			 * (internal) type name. Returns NULL if the name isn't registered.
			*/
			static const DataTypeRegistration *get_registration(const std::string &name);
			
			/**
			 * @brief Fetch a DataType pointer.
			 *
			 * Returns a DataType class pointer for the requested (internal) type name.
			 *
			 * For "configurable" types, the configuration should be provided via the
			 * options parameter, for non-configurable types, the options parameter
			 * must be NULL.
			 *
			 * Throws an exception if the type name isn't recognised or if there is a
			 * problem with the configuration.
			*/
			static std::shared_ptr<const DataType> get_type(const std::string &name, const json_t *options);
			
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
		friend ScopedDataTypeRegistry;
	};
	
	typedef std::function<DocumentCtrl::Region*(SharedDocumentPointer &document, BitOffset offset, BitOffset length, BitOffset virt_offset)> RegionFactoryFunction;
	
	/**
	 * @brief An instance of a data type.
	 *
	 * This class describes the characteristics of the data and how to interact with it. These
	 * are typically constructed by and returned from the DataTypeRegistration classes.
	*/
	class DataType
	{
		public:
			/**
			 * @brief Size of a word/unit in this type.
			 *
			 * This is the size of a single unit of storage in this type.
			 *
			 * Data type assignments will only be made on multiples of this size but
			 * there are conditions where this can be bypassed, so consider it a soft
			 * constraint.
			 *
			 * If a region_factory is provided but region_fixed_size is not set, then
			 * the instantiated Region classes will be a multiple of this size.
			*/
			BitOffset word_size;
			
			/**
			 * @brief Region class factory function.
			 *
			 * This function creates a Region class for viewing this data type. If not
			 * specified, the generic "Data" Region will be used.
			*/
			RegionFactoryFunction region_factory;
			
			/**
			 * @brief Force Region length.
			 *
			 * If this is specified, the Region classes created using region_factory
			 * will be exactly this length.
			*/
			BitOffset region_fixed_size;
			
			/**
			 * @brief Character encoder.
			 *
			 * If specified, this CharacterEncoder instance will be used to encode and
			 * decode text within the region. If not specified, text will (usually) be
			 * treated as ASCII.
			*/
			const CharacterEncoder *encoder;
			
			/**
			 * @brief Initialise a DataType with nothing set.
			*/
			DataType();
			
			/**
			 * @brief Specify a word_size (mandatory).
			*/
			DataType WithWordSize(BitOffset word_size);
			
			/**
			 * @brief Specify a Region factory.
			*/
			DataType WithVariableSizeRegion(const RegionFactoryFunction &region_factory);
			
			/**
			 * @brief Specify a Region factory.
			*/
			DataType WithFixedSizeRegion(const RegionFactoryFunction &region_factory, BitOffset region_fixed_size);
			
			/**
			 * @brief Specify a CharacterEncoder instance.
			 *
			 * The CharacterEncoder pointer provided must remain valid for the lifetime
			 * of the DataType object.
			*/
			DataType WithCharacterEncoder(const CharacterEncoder *encoder);
	};
	
	/**
	 * @brief Data type registration base class.
	 *
	 * Data types are registered through subclasses of this class, usually
	 * constructed as static objects or otherwise created during startup.
	 *
	 * This class stores the internal name and human-readable label of the
	 * data type and provides methods for constructing the DataType which
	 * deals with the actual data structure.
	*/
	class DataTypeRegistration
	{
		public:
			std::string name;                 /**< Internal name of this type. */
			std::string label;                /**< Display name of this type. */
			std::vector<std::string> groups;  /**< Display names of groups in the type hierarchy above this type. */
			
			DataTypeRegistration(const std::string &name, const std::string &label, const std::vector<std::string> &groups);
			virtual ~DataTypeRegistration();
			
			DataTypeRegistration(const DataTypeRegistration &src) = delete;
			
			/**
			 * @brief Get a DataType object describing this data type.
			 *
			 * @param options  The configuration to create a DataType for, if applicable.
			 *
			 * This method returns a pointer to the DataType object for this data type.
			 *
			 * In the case of "configurable" data types, a configuration must be
			 * provided in the options parameter and a DataType specifically for the
			 * requested configuration will be returned.
			 *
			 * For non-configurable types, the options parameter must be NULL.
			*/
			virtual std::shared_ptr<const DataType> get_type(const json_t *options) const = 0;
			
			/**
			 * @brief Check if this data type is configurable.
			*/
			virtual bool configurable() const = 0;
			
			/**
			 * @brief Get a configuration for this data type from the user.
			 *
			 * @param parent  Parent window for any created dialogs.
			 *
			 * This method will ask the user to configure this data type (usually via
			 * a modal dialog) and return it when they are done. If they cancel it or
			 * an error occurs, NULL will be returned.
			 *
			 * Calling this method on a non-configurable data type will throw a
			 * std::logic_error exception.
			*/
			virtual json_t *configure(wxWindow *parent) const = 0;
	};
	
	/**
	 * @brief Registration for a non-configurable data type.
	*/
	class StaticDataTypeRegistration: public DataTypeRegistration
	{
		private:
			std::shared_ptr<DataType> m_type;
			
		public:
			/**
			 * @brief Registers a non-configurable data type.
			 *
			 * @param name    Internal name of the type.
			 * @param label   Display name of the type.
			 * @param groups  Display names of groups in the type hierarchy above this type.
			 * @param type    DataType object for the type.
			*/
			StaticDataTypeRegistration(const std::string &name, const std::string &label, const std::vector<std::string> &groups, DataType type);
			
			virtual std::shared_ptr<const DataType> get_type(const json_t *options) const override;
			virtual bool configurable() const override;
			virtual json_t *configure(wxWindow *parent) const override;
	};
	
	typedef std::function<json_t*(wxWindow*)> DynamicDataTypeConfigurator;
	typedef std::function<DataType(const json_t *options)> DynamicDataTypeFactory;
	
	/**
	 * @brief Registration for a "configurable" data type.
	*/
	class ConfigurableDataTypeRegistration: public DataTypeRegistration
	{
		private:
			DynamicDataTypeConfigurator m_configurator;
			DynamicDataTypeFactory m_factory;
			
		public:
			/**
			 * @brief Registers a configurable data type.
			 *
			 * @param name          Internal name of the type.
			 * @param label         Display name of the type.
			 * @param configurator  Configuration function (see DataTypeRegistration::configure).
			 * @param factory       DataType factory function (See DataTypeRegistration::get_type).
			*/
			ConfigurableDataTypeRegistration(
				const std::string &name, const std::string &label,
				const DynamicDataTypeConfigurator &configurator, const DynamicDataTypeFactory &factory);
			
			/**
			 * @brief Registers a configurable data type.
			 *
			 * @param name          Internal name of the type.
			 * @param label         Display name of the type.
			 * @param groups        Display names of groups in the type hierarchy above this type.
			 * @param configurator  Configuration function (see DataTypeRegistration::configure).
			 * @param factory       DataType factory function (See DataTypeRegistration::get_type).
			*/
			ConfigurableDataTypeRegistration(
				const std::string &name, const std::string &label, const std::vector<std::string> &groups,
				const DynamicDataTypeConfigurator &configurator, const DynamicDataTypeFactory &factory);
			
			virtual std::shared_ptr<const DataType> get_type(const json_t *options) const override;
			virtual bool configurable() const override;
			virtual json_t *configure(wxWindow *parent) const override;
	};
}

#endif /* !REHEX_DATATYPE_HPP */
