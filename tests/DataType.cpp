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

#include "../src/platform.hpp"
#include <gtest/gtest.h>

#include "../src/DataType.hpp"
#include "testutil.hpp"

using namespace REHex;

TEST(DataTypeRegistry, TypeRegistration)
{
	ScopedDataTypeRegistry sdtr;
	
	{
		std::vector< std::pair<std::string, const DataTypeRegistration*> > registrations(
			DataTypeRegistry::begin(), DataTypeRegistry::end());
		std::vector< std::pair<std::string, const DataTypeRegistration*> > no_registrations;
		
		EXPECT_EQ(registrations, no_registrations) << "DataTypeRegistry begin() and end() methods return an empty set when no types are registered";
	}
	
	{
		std::vector<const DataTypeRegistration*> no_registrations;
		EXPECT_EQ(DataTypeRegistry::sorted_by_group(), no_registrations) << "DataTypeRegistry sorted_by_group() method returns an empty set when no types are registered";
	}
	
	StaticDataTypeRegistration type5("type5", "Type 5", { "Group 1" }, DataType().WithWordSize(BitOffset(1, 0)));
	StaticDataTypeRegistration type1("type1", "Type 1", {},            DataType().WithWordSize(BitOffset(1, 0)));
	StaticDataTypeRegistration type2("type2", "Type 2", { "Group 1" }, DataType().WithWordSize(BitOffset(1, 0)));
	StaticDataTypeRegistration type3("type3", "Type 3", {},            DataType().WithWordSize(BitOffset(1, 0)));
	StaticDataTypeRegistration type4("type4", "Type 4", { "Group 2" }, DataType().WithWordSize(BitOffset(1, 0)));
	
	{
		std::vector< std::pair<std::string, const DataTypeRegistration*> > registrations(
			DataTypeRegistry::begin(), DataTypeRegistry::end());
		
		std::vector< std::pair<std::string, const DataTypeRegistration*> > expected_registrations = {
			std::make_pair<std::string, const DataTypeRegistration*>("type1", &type1),
			std::make_pair<std::string, const DataTypeRegistration*>("type2", &type2),
			std::make_pair<std::string, const DataTypeRegistration*>("type3", &type3),
			std::make_pair<std::string, const DataTypeRegistration*>("type4", &type4),
			std::make_pair<std::string, const DataTypeRegistration*>("type5", &type5),
		};
		
		EXPECT_EQ(registrations, expected_registrations) << "DataTypeRegistry begin() and end() methods return registered types ordered by name";
	}
	
	{
		std::vector<const DataTypeRegistration*> expected_registrations = {
			&type1, /* Type 1 */
			&type3, /* Type 3 */
			&type2, /* Group 1 > Type 2 */
			&type5, /* Group 1 > Type 5 */
			&type4, /* Group 2 > Type 4 */
		};
		
		EXPECT_EQ(DataTypeRegistry::sorted_by_group(), expected_registrations) << "DataTypeRegistry sorted_by_group() method returns registered types in correct order";
	}
	
	EXPECT_EQ(DataTypeRegistry::get_registration("type1"), &type1) << "DataTypeRegistry get_registration() method returns registered type";
	EXPECT_EQ(DataTypeRegistry::get_registration("type2"), &type2) << "DataTypeRegistry get_registration() method returns registered type";
	EXPECT_EQ(DataTypeRegistry::get_registration("type5"), &type5) << "DataTypeRegistry get_registration() method returns registered type";
	
	EXPECT_EQ(DataTypeRegistry::get_registration("type10"), nullptr) << "DataTypeRegistry get_registration() method returns NULL for unknown type";
}

TEST(DataTypeRegistry, GetStaticType)
{
	ScopedDataTypeRegistry sdtr;
	
	StaticDataTypeRegistration type1("type1", "Type 1", {}, DataType().WithWordSize(BitOffset(10, 0)));
	StaticDataTypeRegistration type2("type2", "Type 2", { "Group 1" }, DataType().WithWordSize(BitOffset(20, 0)));
	
	std::shared_ptr<const DataType> t1 = DataTypeRegistry::get_type("type1", NULL);
	ASSERT_NE(t1.get(), nullptr);
	EXPECT_EQ(t1->word_size, BitOffset(10, 0));
	
	std::shared_ptr<const DataType> t2 = DataTypeRegistry::get_type("type2", NULL);
	ASSERT_NE(t2.get(), nullptr);
	EXPECT_EQ(t2->word_size, BitOffset(20, 0));
	
	AutoJSON options("{ \"foo\": 123 }");
	
	EXPECT_THROW({
		DataTypeRegistry::get_type("type2", options.json);
	}, std::logic_error) << "DataTypeRegistry get_type() method throws an exception for a static type with non-NULL options parameter";
	
	std::shared_ptr<const DataType> t99 = DataTypeRegistry::get_type("type99", NULL);
	EXPECT_EQ(t99.get(), nullptr) << "DataTypeRegistry get_type() method returns NULL for unknown types";
}

TEST(DataTypeRegistry, MakeConfigurableType)
{
	ScopedDataTypeRegistry sdtr;
	
	ConfigurableDataTypeRegistration type1(
		"variable-size-type", "Variable Size Type", {},
		
		/* configurator */
		[](wxWindow *parent)
		{
			return (json_t*)(NULL);
		},
		
		/* type factory */
		[](const json_t *options)
		{
			int size = json_integer_value(json_object_get(options, "size"));
			
			return DataType()
				.WithWordSize(BitOffset(size, 0));
		});
	
	AutoJSON options1("{ \"size\": 5 }");
	std::shared_ptr<const DataType> t1 = DataTypeRegistry::get_type("variable-size-type", options1.json);
	ASSERT_NE(t1.get(), nullptr);
	EXPECT_EQ(t1->word_size, BitOffset(5, 0));
	
	AutoJSON options2("{ \"size\": 20 }");
	std::shared_ptr<const DataType> t2 = DataTypeRegistry::get_type("variable-size-type", options2.json);
	ASSERT_NE(t2.get(), nullptr);
	EXPECT_EQ(t2->word_size, BitOffset(20, 0));
}
