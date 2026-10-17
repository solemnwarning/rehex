/* Reverse Engineer's Hex Editor
 * Copyright (C) 2026 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <vector>

#include "../src/DataType.hpp"
#include "../src/document.hpp"
#include "../src/SharedDocumentPointer.hpp"

using namespace REHex;

class DataAnalyserTest: public ::testing::Test
{
	protected:
		SharedDocumentPointer document;
		
		class TestAnalyser: public DataAnalyser
		{
			public:
				static int g_next_instance;
				static std::vector<int> g_destroyed_instances;
				
				const int m_instance;
				
				BitOffset m_offset;
				const BitOffset m_length;
				
				bool m_paused;
				int m_pause_count;
				
				TestAnalyser(BitOffset offset, BitOffset length):
					m_instance(g_next_instance++),
					m_offset(offset),
					m_length(length),
					m_paused(false),
					m_pause_count(0) {}
				
				virtual ~TestAnalyser() override
				{
					g_destroyed_instances.push_back(m_instance);
				}
				
				virtual void pause() override
				{
					if(m_paused)
					{
						throw std::logic_error("Pausing already-paused analyser");
					}
					
					m_paused = true;
					++m_pause_count;
				}
				
				virtual void resume() override
				{
					if(!m_paused)
					{
						throw std::logic_error("Resuming not-paused analyser");
					}
					
					m_paused = false;
				}
				
				virtual void rebase(BitOffset offset) override
				{
					if(!m_paused)
					{
						throw std::logic_error("Rebasing not-paused analyser");
					}
					
					m_offset = offset;
				}
		};
		
		ScopedDataTypeRegistry sdtr;
		
		StaticDataTypeRegistration type1reg;
		StaticDataTypeRegistration type2reg;
		
		DataAnalyserTest():
			document(SharedDocumentPointer::make()),
			
			type1reg("type1", "Data Type 1", {}, DataType()
				.WithWordSize(1)
				.WithDataAnalyser([](Document *document, BitOffset offset, BitOffset length)
				{
					std::unique_ptr<TestAnalyser> p;
					p.reset(new TestAnalyser(offset, length));
					
					return p;
				})),
			
			type2reg("type2", "Data Type 2", {}, DataType()
				.WithWordSize(1)
				.WithDataAnalyser([](Document *document, BitOffset offset, BitOffset length)
				{
					std::unique_ptr<TestAnalyser> p;
					p.reset(new TestAnalyser(offset, length));
					
					return p;
				}))
		{
			TestAnalyser::g_next_instance = 0;
			TestAnalyser::g_destroyed_instances.clear();
			
			std::vector<unsigned char> zero_1k(1024, 0);
			document->insert_data(0, zero_1k.data(), zero_1k.size());
		}
		
		TestAnalyser *get_analyser(BitOffset offset)
		{
			DataAnalyser *a = document->get_analyser(offset);
			if(a == NULL)
			{
				return NULL;
			}
			
			assert(dynamic_cast<TestAnalyser*>(a) != NULL);
			TestAnalyser *ta = static_cast<TestAnalyser*>(a);
			
			return ta;
		}
};

int DataAnalyserTest::TestAnalyser::g_next_instance = 0;
std::vector<int> DataAnalyserTest::TestAnalyser::g_destroyed_instances;

TEST_F(DataAnalyserTest, CreatesAnalysers)
{
	EXPECT_EQ(document->get_analyser(BitOffset(10, 0)), nullptr) << "No DataAnalyser constructed initially";
	
	document->set_data_type(BitOffset(10, 0), BitOffset(5, 0), "type1");
	
	{
		DataAnalyser *a1 = document->get_analyser(10);
		ASSERT_NE(a1, nullptr) << "DataAnalyser constructed when data type is assigned";
		
		TestAnalyser *ta1 = dynamic_cast<TestAnalyser*>(a1);
		ASSERT_NE(ta1, nullptr) << "DataAnalyser class is of correct type";
		
		EXPECT_EQ(ta1->m_instance, 0);
		EXPECT_EQ(ta1->m_offset, BitOffset(10, 0));
		EXPECT_EQ(ta1->m_length, BitOffset(5, 0));
	}
	
	document->set_data_type(BitOffset(20, 4), BitOffset(10, 4), "type2");
	
	{
		DataAnalyser *a1 = document->get_analyser(10);
		ASSERT_NE(a1, nullptr) << "DataAnalyser constructed when data type is assigned";
		
		TestAnalyser *ta1 = dynamic_cast<TestAnalyser*>(a1);
		ASSERT_NE(ta1, nullptr) << "DataAnalyser class is of correct type";
		
		EXPECT_EQ(ta1->m_instance, 0) << "Unaffected DataAnalyser not destroyed";
		EXPECT_EQ(ta1->m_offset, BitOffset(10, 0));
		EXPECT_EQ(ta1->m_length, BitOffset(5, 0));
	}
	
	{
		DataAnalyser *a2 = document->get_analyser(BitOffset(21, 0));
		ASSERT_NE(a2, nullptr) << "DataAnalyser constructed when data type is assigned";
		
		TestAnalyser *ta2 = dynamic_cast<TestAnalyser*>(a2);
		ASSERT_NE(ta2, nullptr) << "DataAnalyser class is of correct type";
		
		EXPECT_EQ(ta2->m_instance, 1);
		EXPECT_EQ(ta2->m_offset, BitOffset(20, 4));
		EXPECT_EQ(ta2->m_length, BitOffset(10, 4));
	}
	
	EXPECT_EQ(TestAnalyser::g_destroyed_instances, std::vector<int>({}));
	
	// TODO: Undo
}

TEST_F(DataAnalyserTest, DestroysAnalysers)
{
	EXPECT_EQ(document->get_analyser(BitOffset(10, 0)), nullptr) << "No DataAnalyser constructed initially";
	
	document->set_data_type(BitOffset(10, 0), BitOffset(5, 0), "type1");
	
	{
		DataAnalyser *a1 = document->get_analyser(BitOffset(10, 0));
		ASSERT_NE(a1, nullptr) << "DataAnalyser constructed when data type is assigned";
		
		TestAnalyser *ta1 = dynamic_cast<TestAnalyser*>(a1);
		ASSERT_NE(ta1, nullptr) << "DataAnalyser class is of correct type";
		
		EXPECT_EQ(ta1->m_instance, 0);
		EXPECT_EQ(ta1->m_offset, BitOffset(10, 0));
		EXPECT_EQ(ta1->m_length, BitOffset(5, 0));
	}
	
	document->set_data_type(BitOffset(10, 0), BitOffset(5, 0), "");
	
	EXPECT_EQ(document->get_analyser(BitOffset(10, 0)), nullptr);
	EXPECT_EQ(TestAnalyser::g_destroyed_instances, std::vector<int>({ 0 }));
}

TEST_F(DataAnalyserTest, CreatesAdjacentDisparateAnalysers)
{
	EXPECT_EQ(document->get_analyser(BitOffset(10, 0)), nullptr) << "No DataAnalyser constructed initially";
	
	document->set_data_type(BitOffset(20, 0), BitOffset(10, 0), "type1");
	document->set_data_type(BitOffset(10, 0), BitOffset(10, 0), "type2");
	document->set_data_type(BitOffset(30, 0), BitOffset(10, 0), "type2");
	
	{
		TestAnalyser *ta1 = get_analyser(BitOffset(10, 0));
		ASSERT_NE(ta1, nullptr);
		
		EXPECT_EQ(ta1->m_instance, 1);
		EXPECT_EQ(ta1->m_offset, BitOffset(10, 0));
		EXPECT_EQ(ta1->m_length, BitOffset(10, 0));
	}
	
	{
		TestAnalyser *ta2 = get_analyser(BitOffset(20, 0));
		ASSERT_NE(ta2, nullptr);
		
		EXPECT_EQ(ta2->m_instance, 0);
		EXPECT_EQ(ta2->m_offset, BitOffset(20, 0));
		EXPECT_EQ(ta2->m_length, BitOffset(10, 0));
	}
	
	{
		TestAnalyser *ta3 = get_analyser(BitOffset(30, 0));
		ASSERT_NE(ta3, nullptr);
		
		EXPECT_EQ(ta3->m_instance, 2);
		EXPECT_EQ(ta3->m_offset, BitOffset(30, 0));
		EXPECT_EQ(ta3->m_length, BitOffset(10, 0));
	}
	
	EXPECT_EQ(TestAnalyser::g_destroyed_instances, std::vector<int>({}));
	
	document->undo();
	
	EXPECT_EQ(TestAnalyser::g_destroyed_instances, std::vector<int>({ 2 }));
	
	{
		TestAnalyser *ta1 = get_analyser(BitOffset(10, 0));
		ASSERT_NE(ta1, nullptr);
		
		EXPECT_EQ(ta1->m_instance, 1);
		EXPECT_EQ(ta1->m_offset, BitOffset(10, 0));
		EXPECT_EQ(ta1->m_length, BitOffset(10, 0));
	}
	
	{
		TestAnalyser *ta2 = get_analyser(BitOffset(20, 0));
		ASSERT_NE(ta2, nullptr);
		
		EXPECT_EQ(ta2->m_instance, 0);
		EXPECT_EQ(ta2->m_offset, BitOffset(20, 0));
		EXPECT_EQ(ta2->m_length, BitOffset(10, 0));
	}
	
	EXPECT_EQ(get_analyser(BitOffset(30, 0)), nullptr);
	
	document->undo();
	
	EXPECT_EQ(TestAnalyser::g_destroyed_instances, std::vector<int>({ 2, 1 }));
	
	EXPECT_EQ(get_analyser(BitOffset(10, 0)), nullptr);
	
	{
		TestAnalyser *ta2 = get_analyser(BitOffset(20, 0));
		ASSERT_NE(ta2, nullptr);
		
		EXPECT_EQ(ta2->m_instance, 0);
		EXPECT_EQ(ta2->m_offset, BitOffset(20, 0));
		EXPECT_EQ(ta2->m_length, BitOffset(10, 0));
	}
	
	EXPECT_EQ(get_analyser(BitOffset(30, 0)), nullptr);
	
	document->undo();
	
	EXPECT_EQ(TestAnalyser::g_destroyed_instances, std::vector<int>({ 2, 1, 0 }));
	
	EXPECT_EQ(get_analyser(BitOffset(10, 0)), nullptr);
	EXPECT_EQ(get_analyser(BitOffset(20, 0)), nullptr);
	EXPECT_EQ(get_analyser(BitOffset(30, 0)), nullptr);
}

TEST_F(DataAnalyserTest, MergesAdjacentAnalysers)
{
	EXPECT_EQ(document->get_analyser(BitOffset(10, 0)), nullptr) << "No DataAnalyser constructed initially";
	
	document->set_data_type(BitOffset(20, 0), BitOffset(10, 0), "type1");
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(20, 0));
		ASSERT_NE(ta, nullptr);
		
		EXPECT_EQ(ta->m_instance, 0);
		EXPECT_EQ(ta->m_offset, BitOffset(20, 0));
		EXPECT_EQ(ta->m_length, BitOffset(10, 0));
	}
	
	EXPECT_EQ(TestAnalyser::g_destroyed_instances, std::vector<int>({}));
	
	document->set_data_type(BitOffset(10, 0), BitOffset(10, 0), "type1");
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(10, 0));
		ASSERT_NE(ta, nullptr);
		
		EXPECT_EQ(ta->m_instance, 1);
		EXPECT_EQ(ta->m_offset, BitOffset(10, 0));
		EXPECT_EQ(ta->m_length, BitOffset(20, 0));
	}
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(29, 7));
		ASSERT_NE(ta, nullptr);
		
		EXPECT_EQ(ta->m_instance, 1);
		EXPECT_EQ(ta->m_offset, BitOffset(10, 0));
		EXPECT_EQ(ta->m_length, BitOffset(20, 0));
	}
	
	EXPECT_EQ(TestAnalyser::g_destroyed_instances, std::vector<int>({ 0 }));
	
	document->set_data_type(BitOffset(30, 0), BitOffset(10, 0), "type1");
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(10, 0));
		ASSERT_NE(ta, nullptr);
		
		EXPECT_EQ(ta->m_instance, 2);
		EXPECT_EQ(ta->m_offset, BitOffset(10, 0));
		EXPECT_EQ(ta->m_length, BitOffset(30, 0));
	}
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(20, 0));
		ASSERT_NE(ta, nullptr);
		
		EXPECT_EQ(ta->m_instance, 2);
		EXPECT_EQ(ta->m_offset, BitOffset(10, 0));
		EXPECT_EQ(ta->m_length, BitOffset(30, 0));
	}
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(35, 0));
		ASSERT_NE(ta, nullptr);
		
		EXPECT_EQ(ta->m_instance, 2);
		EXPECT_EQ(ta->m_offset, BitOffset(10, 0));
		EXPECT_EQ(ta->m_length, BitOffset(30, 0));
	}
	
	EXPECT_EQ(TestAnalyser::g_destroyed_instances, std::vector<int>({ 0, 1 }));
	
	document->undo();
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(10, 0));
		ASSERT_NE(ta, nullptr);
		
		EXPECT_EQ(ta->m_instance, 3);
		EXPECT_EQ(ta->m_offset, BitOffset(10, 0));
		EXPECT_EQ(ta->m_length, BitOffset(20, 0));
	}
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(20, 0));
		ASSERT_NE(ta, nullptr);
		
		EXPECT_EQ(ta->m_instance, 3);
		EXPECT_EQ(ta->m_offset, BitOffset(10, 0));
		EXPECT_EQ(ta->m_length, BitOffset(20, 0));
	}
	
	EXPECT_EQ(get_analyser(BitOffset(35, 0)), nullptr);
	
	EXPECT_EQ(TestAnalyser::g_destroyed_instances, std::vector<int>({ 0, 1, 2 }));
	
	document->undo();
	
	EXPECT_EQ(get_analyser(BitOffset(10, 0)), nullptr);
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(20, 0));
		ASSERT_NE(ta, nullptr);
		
		EXPECT_EQ(ta->m_instance, 4);
		EXPECT_EQ(ta->m_offset, BitOffset(20, 0));
		EXPECT_EQ(ta->m_length, BitOffset(10, 0));
	}
	
	EXPECT_EQ(get_analyser(BitOffset(35, 0)), nullptr);
	
	EXPECT_EQ(TestAnalyser::g_destroyed_instances, std::vector<int>({ 0, 1, 2, 3 }));
	
	document->undo();
	
	EXPECT_EQ(get_analyser(BitOffset(10, 0)), nullptr);
	EXPECT_EQ(get_analyser(BitOffset(20, 0)), nullptr);
	EXPECT_EQ(get_analyser(BitOffset(35, 0)), nullptr);
	
	EXPECT_EQ(TestAnalyser::g_destroyed_instances, std::vector<int>({ 0, 1, 2, 3, 4 }));
	
	document->redo();
	
	EXPECT_EQ(get_analyser(BitOffset(10, 0)), nullptr);
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(20, 0));
		ASSERT_NE(ta, nullptr);
		
		EXPECT_EQ(ta->m_instance, 5);
		EXPECT_EQ(ta->m_offset, BitOffset(20, 0));
		EXPECT_EQ(ta->m_length, BitOffset(10, 0));
	}
	
	EXPECT_EQ(get_analyser(BitOffset(35, 0)), nullptr);
	
	EXPECT_EQ(TestAnalyser::g_destroyed_instances, std::vector<int>({ 0, 1, 2, 3, 4 }));
	
	document->redo();
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(10, 0));
		ASSERT_NE(ta, nullptr);
		
		EXPECT_EQ(ta->m_instance, 6);
		EXPECT_EQ(ta->m_offset, BitOffset(10, 0));
		EXPECT_EQ(ta->m_length, BitOffset(20, 0));
	}
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(20, 0));
		ASSERT_NE(ta, nullptr);
		
		EXPECT_EQ(ta->m_instance, 6);
		EXPECT_EQ(ta->m_offset, BitOffset(10, 0));
		EXPECT_EQ(ta->m_length, BitOffset(20, 0));
	}
	
	EXPECT_EQ(get_analyser(BitOffset(35, 0)), nullptr);
	
	EXPECT_EQ(TestAnalyser::g_destroyed_instances, std::vector<int>({ 0, 1, 2, 3, 4, 5 }));
}

// TODO: Create analysers when loading metadata

TEST_F(DataAnalyserTest, OverwritePausesAnalysersIntersectingRange)
{
	std::vector<std::tuple<BitOffset, BitOffset, Document::TypeInfo> > types;
	types.emplace_back(BitOffset(10, 0), BitOffset(10, 0), Document::TypeInfo("type2"));
	types.emplace_back(BitOffset(30, 0), BitOffset(10, 0), Document::TypeInfo("type1"));
	types.emplace_back(BitOffset(40, 0), BitOffset(10, 0), Document::TypeInfo("type2"));
	types.emplace_back(BitOffset(50, 0), BitOffset(10, 0), Document::TypeInfo("type1"));
	
	document->set_data_type_bulk(std::move(types));
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(10, 0));
		ASSERT_NE(ta, nullptr);
		
		ASSERT_EQ(ta->m_offset, BitOffset(10, 0));
		ASSERT_EQ(ta->m_length, BitOffset(10, 0));
		
		ASSERT_FALSE(ta->m_paused);
		ASSERT_EQ(ta->m_pause_count, 0);
	}
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(30, 0));
		ASSERT_NE(ta, nullptr);
		
		ASSERT_EQ(ta->m_offset, BitOffset(30, 0));
		ASSERT_EQ(ta->m_length, BitOffset(10, 0));
		
		ASSERT_FALSE(ta->m_paused);
		ASSERT_EQ(ta->m_pause_count, 0);
	}
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(40, 0));
		ASSERT_NE(ta, nullptr);
		
		ASSERT_EQ(ta->m_offset, BitOffset(40, 0));
		ASSERT_EQ(ta->m_length, BitOffset(10, 0));
		
		ASSERT_FALSE(ta->m_paused);
		ASSERT_EQ(ta->m_pause_count, 0);
	}
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(50, 0));
		ASSERT_NE(ta, nullptr);
		
		ASSERT_EQ(ta->m_offset, BitOffset(50, 0));
		ASSERT_EQ(ta->m_length, BitOffset(10, 0));
		
		ASSERT_FALSE(ta->m_paused);
		ASSERT_EQ(ta->m_pause_count, 0);
	}
	
	char z21[21];
	memset(z21, 0, 21);
	
	document->overwrite_data(BitOffset(20, 0), z21, 21);
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(10, 0));
		ASSERT_NE(ta, nullptr);
		
		ASSERT_EQ(ta->m_offset, BitOffset(10, 0));
		ASSERT_EQ(ta->m_length, BitOffset(10, 0));
		
		EXPECT_FALSE(ta->m_paused);
		EXPECT_EQ(ta->m_pause_count, 0);
	}
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(30, 0));
		ASSERT_NE(ta, nullptr);
		
		ASSERT_EQ(ta->m_offset, BitOffset(30, 0));
		ASSERT_EQ(ta->m_length, BitOffset(10, 0));
		
		EXPECT_FALSE(ta->m_paused);
		EXPECT_EQ(ta->m_pause_count, 1);
	}
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(40, 0));
		ASSERT_NE(ta, nullptr);
		
		ASSERT_EQ(ta->m_offset, BitOffset(40, 0));
		ASSERT_EQ(ta->m_length, BitOffset(10, 0));
		
		EXPECT_FALSE(ta->m_paused);
		EXPECT_EQ(ta->m_pause_count, 1);
	}
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(50, 0));
		ASSERT_NE(ta, nullptr);
		
		ASSERT_EQ(ta->m_offset, BitOffset(50, 0));
		ASSERT_EQ(ta->m_length, BitOffset(10, 0));
		
		EXPECT_FALSE(ta->m_paused);
		EXPECT_EQ(ta->m_pause_count, 0);
	}
	
	document->undo();
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(10, 0));
		ASSERT_NE(ta, nullptr);
		
		ASSERT_EQ(ta->m_offset, BitOffset(10, 0));
		ASSERT_EQ(ta->m_length, BitOffset(10, 0));
		
		EXPECT_FALSE(ta->m_paused);
		EXPECT_EQ(ta->m_pause_count, 0);
	}
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(30, 0));
		ASSERT_NE(ta, nullptr);
		
		ASSERT_EQ(ta->m_offset, BitOffset(30, 0));
		ASSERT_EQ(ta->m_length, BitOffset(10, 0));
		
		EXPECT_FALSE(ta->m_paused);
		EXPECT_EQ(ta->m_pause_count, 2);
	}
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(40, 0));
		ASSERT_NE(ta, nullptr);
		
		ASSERT_EQ(ta->m_offset, BitOffset(40, 0));
		ASSERT_EQ(ta->m_length, BitOffset(10, 0));
		
		EXPECT_FALSE(ta->m_paused);
		EXPECT_EQ(ta->m_pause_count, 2);
	}
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(50, 0));
		ASSERT_NE(ta, nullptr);
		
		ASSERT_EQ(ta->m_offset, BitOffset(50, 0));
		ASSERT_EQ(ta->m_length, BitOffset(10, 0));
		
		EXPECT_FALSE(ta->m_paused);
		EXPECT_EQ(ta->m_pause_count, 0);
	}
}

TEST_F(DataAnalyserTest, InsertPausesAnalysersAfterInsertionPoint)
{
	std::vector<std::tuple<BitOffset, BitOffset, Document::TypeInfo> > types;
	types.emplace_back(BitOffset(10, 0), BitOffset(10, 0), Document::TypeInfo("type2"));
	types.emplace_back(BitOffset(30, 0), BitOffset(10, 0), Document::TypeInfo("type1"));
	types.emplace_back(BitOffset(50, 0), BitOffset(10, 0), Document::TypeInfo("type2"));
	
	document->set_data_type_bulk(std::move(types));
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(10, 0));
		ASSERT_NE(ta, nullptr);
		
		ASSERT_EQ(ta->m_offset, BitOffset(10, 0));
		ASSERT_EQ(ta->m_length, BitOffset(10, 0));
		
		ASSERT_FALSE(ta->m_paused);
		ASSERT_EQ(ta->m_pause_count, 0);
	}
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(30, 0));
		ASSERT_NE(ta, nullptr);
		
		ASSERT_EQ(ta->m_offset, BitOffset(30, 0));
		ASSERT_EQ(ta->m_length, BitOffset(10, 0));
		
		ASSERT_FALSE(ta->m_paused);
		ASSERT_EQ(ta->m_pause_count, 0);
	}
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(50, 0));
		ASSERT_NE(ta, nullptr);
		
		ASSERT_EQ(ta->m_offset, BitOffset(50, 0));
		ASSERT_EQ(ta->m_length, BitOffset(10, 0));
		
		ASSERT_FALSE(ta->m_paused);
		ASSERT_EQ(ta->m_pause_count, 0);
	}
	
	char z21[21];
	memset(z21, 0, 21);
	
	document->insert_data(20, z21, 21);
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(10, 0));
		ASSERT_NE(ta, nullptr);
		
		EXPECT_EQ(ta->m_offset, BitOffset(10, 0));
		EXPECT_EQ(ta->m_length, BitOffset(10, 0));
		
		EXPECT_FALSE(ta->m_paused);
		EXPECT_EQ(ta->m_pause_count, 0);
	}
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(51, 0));
		ASSERT_NE(ta, nullptr);
		
		EXPECT_EQ(ta->m_offset, BitOffset(51, 0));
		EXPECT_EQ(ta->m_length, BitOffset(10, 0));
		
		EXPECT_FALSE(ta->m_paused);
		EXPECT_EQ(ta->m_pause_count, 1);
	}
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(71, 0));
		ASSERT_NE(ta, nullptr);
		
		EXPECT_EQ(ta->m_offset, BitOffset(71, 0));
		EXPECT_EQ(ta->m_length, BitOffset(10, 0));
		
		EXPECT_FALSE(ta->m_paused);
		EXPECT_EQ(ta->m_pause_count, 1);
	}
	
	document->undo();
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(10, 0));
		ASSERT_NE(ta, nullptr);
		
		EXPECT_EQ(ta->m_offset, BitOffset(10, 0));
		EXPECT_EQ(ta->m_length, BitOffset(10, 0));
		
		EXPECT_FALSE(ta->m_paused);
		EXPECT_EQ(ta->m_pause_count, 0);
	}
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(30, 0));
		ASSERT_NE(ta, nullptr);
		
		EXPECT_EQ(ta->m_offset, BitOffset(30, 0));
		EXPECT_EQ(ta->m_length, BitOffset(10, 0));
		
		EXPECT_FALSE(ta->m_paused);
		EXPECT_EQ(ta->m_pause_count, 2);
	}
	
	{
		TestAnalyser *ta = get_analyser(BitOffset(50, 0));
		ASSERT_NE(ta, nullptr);
		
		EXPECT_EQ(ta->m_offset, BitOffset(50, 0));
		EXPECT_EQ(ta->m_length, BitOffset(10, 0));
		
		EXPECT_FALSE(ta->m_paused);
		EXPECT_EQ(ta->m_pause_count, 2);
	}
}

// TODO: Test insert destroys/splits intersecting analysers

// TODO: Erase pauses analysers after insertion point

// TODO: Erase merges adjacent analysers
