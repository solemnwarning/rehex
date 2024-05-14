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

#include <wx/fileconf.h>
#include <wx/sstream.h>

#include "testutil.hpp"
#include "../src/HighlightColourMap.hpp"

using namespace REHex;

TEST(HighlightColourMap, BasicTests)
{
	HighlightColourMap hcm;
	
	/* Verify map has no elements by default. */
	
	EXPECT_EQ(hcm.size(), 0U) << "HighlightColourMap is empty by default";
	EXPECT_EQ(hcm.begin(), hcm.end()) << "HighlightColourMap is empty by default";
	
	/* Instantiate and verify some default colours. */
	
	EXPECT_EQ(   hcm[7].primary_colour,   wxColour(0x00, 0xFF, 0xA8)) << "Colour instantiated with operator[] has correct primary colour";
	EXPECT_TRUE( hcm[7].primary_colour_is_default)                    << "Colour instantiated with operator[] has default secondary colour";
	EXPECT_EQ(   hcm[7].secondary_colour, wxColour(0x00, 0x00, 0x00)) << "Colour instantiated with operator[] has correct secondary colour";
	EXPECT_TRUE( hcm[7].secondary_colour_is_default)                  << "Colour instantiated with operator[] has default secondary colour";
	EXPECT_EQ(   hcm[7].label, "Highlight 8")                         << "Colour instantiated with operator[] has correct label";
	EXPECT_TRUE( hcm[7].label_is_default)                             << "Colour instantiated with operator[] has default label";
	
	EXPECT_EQ(   hcm[0].primary_colour,   wxColour(0xFF, 0x00, 0x00)) << "Colour instantiated with operator[] has correct primary colour";
	EXPECT_TRUE( hcm[0].primary_colour_is_default)                    << "Colour instantiated with operator[] has default secondary colour";
	EXPECT_EQ(   hcm[0].secondary_colour, wxColour(0xFF, 0xFF, 0xFF)) << "Colour instantiated with operator[] has correct secondary colour";
	EXPECT_TRUE( hcm[0].secondary_colour_is_default)                  << "Colour instantiated with operator[] has default secondary colour";
	EXPECT_EQ(   hcm[0].label, "Red")                                 << "Colour instantiated with operator[] has correct label";
	EXPECT_TRUE( hcm[0].label_is_default)                             << "Colour instantiated with operator[] has default label";
	
	EXPECT_EQ(   hcm[3].primary_colour,   wxColour(0x02, 0xFE, 0x07)) << "Colour instantiated with operator[] has correct primary colour";
	EXPECT_TRUE( hcm[3].primary_colour_is_default)                    << "Colour instantiated with operator[] has default secondary colour";
	EXPECT_EQ(   hcm[3].secondary_colour, wxColour(0x00, 0x00, 0x00)) << "Colour instantiated with operator[] has correct secondary colour";
	EXPECT_TRUE( hcm[3].secondary_colour_is_default)                  << "Colour instantiated with operator[] has default secondary colour";
	EXPECT_EQ(   hcm[3].label, "Green")                               << "Colour instantiated with operator[] has correct label";
	EXPECT_TRUE( hcm[3].label_is_default)                             << "Colour instantiated with operator[] has default label";
	
	ASSERT_EQ(hcm.size(), 3U);
	
	/* Verify iterator access. */
	
	EXPECT_EQ(std::next(hcm.begin(), 0)->first, 0U);
	EXPECT_EQ(std::next(hcm.begin(), 0)->second.label, "Red");
	
	EXPECT_EQ(std::next(hcm.begin(), 1)->first, 3U);
	EXPECT_EQ(std::next(hcm.begin(), 1)->second.label, "Green");
	
	EXPECT_EQ(std::next(hcm.begin(), 2)->first, 7U);
	EXPECT_EQ(std::next(hcm.begin(), 2)->second.label, "Highlight 8");
	
	EXPECT_EQ(std::next(hcm.begin(), 3), hcm.end());
	
	/* Verify find() method. */
	
	EXPECT_EQ(hcm.find(0), std::next(hcm.begin(), 0));
	EXPECT_EQ(hcm.find(3), std::next(hcm.begin(), 1));
	EXPECT_EQ(hcm.find(7), std::next(hcm.begin(), 2));
	EXPECT_EQ(hcm.find(2), hcm.end());
	
	/* Verify add fills in the next available index with default. */
	
	auto it = hcm.add();
	
	EXPECT_EQ(it->first, 1U);
	
	EXPECT_EQ(   it->second.primary_colour,   wxColour(0xFE, 0x63, 0x00)) << "Colour added by add() method has correct primary colour";
	EXPECT_TRUE( it->second.primary_colour_is_default)                    << "Colour added by add() method has default secondary colour";
	EXPECT_EQ(   it->second.secondary_colour, wxColour(0xFF, 0xFF, 0xFF)) << "Colour added by add() method has correct secondary colour";
	EXPECT_TRUE( it->second.secondary_colour_is_default)                  << "Colour added by add() method has default secondary colour";
	EXPECT_EQ(   it->second.label, "Orange")                              << "Colour added by add() method has correct label";
	EXPECT_TRUE( it->second.label_is_default)                             << "Colour added by add() method has default label";
	
	ASSERT_EQ(hcm.size(), 4U);
	
	/* Verify iterators reflect added member. */
	
	EXPECT_EQ(std::next(hcm.begin(), 0)->first, 0U);
	EXPECT_EQ(std::next(hcm.begin(), 0)->second.label, "Red");
	
	EXPECT_EQ(std::next(hcm.begin(), 1)->first, 1U);
	EXPECT_EQ(std::next(hcm.begin(), 1)->second.label, "Orange");
	EXPECT_EQ(std::next(hcm.begin(), 1), it);
	
	EXPECT_EQ(std::next(hcm.begin(), 2)->first, 3U);
	EXPECT_EQ(std::next(hcm.begin(), 2)->second.label, "Green");
	
	EXPECT_EQ(std::next(hcm.begin(), 3)->first, 7U);
	EXPECT_EQ(std::next(hcm.begin(), 3)->second.label, "Highlight 8");
	
	EXPECT_EQ(std::next(hcm.begin(), 4), hcm.end());
	
	/* Verify erase (by index and by iterator) works. */
	
	hcm.erase(7);
	hcm.erase(it);
	
	ASSERT_EQ(hcm.size(), 2U);
	
	EXPECT_EQ(std::next(hcm.begin(), 0)->first, 0U);
	EXPECT_EQ(std::next(hcm.begin(), 0)->second.label, "Red");
	
	EXPECT_EQ(std::next(hcm.begin(), 1)->first, 3U);
	EXPECT_EQ(std::next(hcm.begin(), 1)->second.label, "Green");
	
	EXPECT_EQ(std::next(hcm.begin(), 2), hcm.end());
}

TEST(HighlightColourMap, SerialiseJSON)
{
	HighlightColourMap hcm;
	
	/* Instantiate some colours with default values. */
	
	hcm[0];
	hcm[2];
	hcm[3];
	hcm[4];
	
	ASSERT_EQ(hcm.size(), 4U);
	
	/* Replace some values. */
	
	hcm[0].set_primary_colour(wxColour(0xAB, 0xCD, 0xEF));
	hcm[0].set_secondary_colour(wxColour(0xFE, 0xCD, 0xBA));
	
	hcm[2].set_secondary_colour(wxColour(0x12, 0x34, 0x56));
	
	hcm[4].set_label("Hello");
	
	/* Validate serialised JSON is correct. */
	
	EXPECT_EQ(AutoJSON(hcm.to_json()), AutoJSON(
		R"([
			{
				"index": 0,
				"primary_colour": "abcdef",
				"secondary_colour": "fecdba"
			},
			{
				"index": 2,
				"secondary_colour": "123456"
			},
			{
				"index": 3
			},
			{
				"index": 4,
				"label": "Hello"
			}
		])"));
}

TEST(HighlightColourMap, DeserialiseJSON)
{
	HighlightColourMap hcm = HighlightColourMap::from_json(
		AutoJSON(R"([
			{
				"index": 0,
				"primary_colour": "abcdef",
				"secondary_colour": "fecdba"
			},
			{
				"index": 2,
				"secondary_colour": "123456"
			},
			{
				"index": 3
			},
			{
				"index": 4,
				"label": "Hello"
			}
		])").json);
	
	ASSERT_EQ(hcm.size(), 4U);
	
	EXPECT_EQ(std::next(hcm.begin(), 0)->first, 0U);
	EXPECT_EQ(std::next(hcm.begin(), 0)->second.primary_colour, wxColour(0xAB, 0xCD, 0xEF));
	EXPECT_EQ(std::next(hcm.begin(), 0)->second.secondary_colour, wxColour(0xFE, 0xCD, 0xBA));
	EXPECT_EQ(std::next(hcm.begin(), 0)->second.label, "Red");
	
	EXPECT_EQ(std::next(hcm.begin(), 1)->first, 2U);
	EXPECT_EQ(std::next(hcm.begin(), 1)->second.primary_colour, wxColour(0xFC, 0xFF, 0x00));
	EXPECT_EQ(std::next(hcm.begin(), 1)->second.secondary_colour, wxColour(0x12, 0x34, 0x56));
	EXPECT_EQ(std::next(hcm.begin(), 1)->second.label, "Yellow");
	
	EXPECT_EQ(std::next(hcm.begin(), 2)->first, 3U);
	EXPECT_EQ(std::next(hcm.begin(), 2)->second.primary_colour, wxColour(0x02, 0xFE, 0x07));
	EXPECT_EQ(std::next(hcm.begin(), 2)->second.secondary_colour, wxColour(0x00, 0x00, 0x00));
	EXPECT_EQ(std::next(hcm.begin(), 2)->second.label, "Green");
	
	EXPECT_EQ(std::next(hcm.begin(), 3)->first, 4U);
	EXPECT_EQ(std::next(hcm.begin(), 3)->second.primary_colour, wxColour(0xFD, 0x00, 0xFF));
	EXPECT_EQ(std::next(hcm.begin(), 3)->second.secondary_colour, wxColour(0xFF, 0xFF, 0xFF));
	EXPECT_EQ(std::next(hcm.begin(), 3)->second.label, "Hello");
	
	EXPECT_EQ(std::next(hcm.begin(), 4), hcm.end());
}

TEST(HighlightColourMap, DeserialiseJSONNotAnArray)
{
	EXPECT_THROW({
		HighlightColourMap::from_json(
			AutoJSON(R"({})").json);
	}, std::invalid_argument);
}

TEST(HighlightColourMap, DeserialiseJSONArrayElementNotObject)
{
	EXPECT_THROW({
		HighlightColourMap::from_json(
			AutoJSON(R"([
				{
					"index": 0,
					"primary_colour": "abcdef",
					"secondary_colour": "fecdba"
				},
				"foo",
				{
					"index": 2,
					"secondary_colour": "123456"
				},
				{
					"index": 3
				},
				{
					"index": 4,
					"label": "Hello"
				}
			])").json);
		}, std::invalid_argument);
}

TEST(HighlightColourMap, DeserialiseJSONMissingIndex)
{
	EXPECT_THROW({
		HighlightColourMap::from_json(
			AutoJSON(R"([
				{
					"primary_colour": "abcdef",
					"secondary_colour": "fecdba"
				},
				{
					"index": 2,
					"secondary_colour": "123456"
				},
				{
					"index": 3
				},
				{
					"index": 4,
					"label": "Hello"
				}
			])").json);
		}, std::invalid_argument);
}

TEST(HighlightColourMap, DeserialiseJSONIndexOutOfRange)
{
	EXPECT_THROW({
		HighlightColourMap::from_json(
			AutoJSON(R"([
				{
					"index": 100,
					"primary_colour": "abcdef",
					"secondary_colour": "fecdba"
				},
				{
					"index": 2,
					"secondary_colour": "123456"
				},
				{
					"index": 3
				},
				{
					"index": 4,
					"label": "Hello"
				}
			])").json);
		}, std::invalid_argument);
}

TEST(HighlightColourMap, DeserialiseJSONInvalidPrimaryColour)
{
	EXPECT_THROW({
		HighlightColourMap::from_json(
			AutoJSON(R"([
				{
					"index": 0,
					"primary_colour": "abcdefa",
					"secondary_colour": "fecdba"
				},
				{
					"index": 2,
					"secondary_colour": "123456"
				},
				{
					"index": 3
				},
				{
					"index": 4,
					"label": "Hello"
				}
			])").json);
		}, std::invalid_argument);
}

TEST(HighlightColourMap, DeserialiseJSONInvalidSecondaryColour)
{
	EXPECT_THROW({
		HighlightColourMap::from_json(
			AutoJSON(R"([
				{
					"index": 0,
					"primary_colour": "abcdef",
					"secondary_colour": "fecdba"
				},
				{
					"index": 2,
					"secondary_colour": 123456
				},
				{
					"index": 3
				},
				{
					"index": 4,
					"label": "Hello"
				}
			])").json);
		}, std::invalid_argument);
}

TEST(HighlightColourMap, DeserialiseJSONInvalidLabel)
{
	EXPECT_THROW({
		HighlightColourMap::from_json(
			AutoJSON(R"([
				{
					"index": 0,
					"primary_colour": "abcdef",
					"secondary_colour": "fecdba"
				},
				{
					"index": 2,
					"secondary_colour": "123456"
				},
				{
					"index": 3
				},
				{
					"index": 4,
					"label": []
				}
			])").json);
		}, std::invalid_argument);
}

TEST(HighlightColourMap, SerialiseConfig)
{
	HighlightColourMap hcm;
	
	/* Instantiate some colours with default values. */
	
	hcm[0];
	hcm[2];
	hcm[3];
	hcm[4];
	
	ASSERT_EQ(hcm.size(), 4U);
	
	/* Replace some values. */
	
	hcm[0].set_primary_colour(wxColour(0xAB, 0xCD, 0xEF));
	hcm[0].set_secondary_colour(wxColour(0xFE, 0xCD, 0xBA));
	
	hcm[2].set_secondary_colour(wxColour(0x12, 0x34, 0x56));
	
	hcm[4].set_label("crown");
	
	/* Validate serialised config is correct. */
	
	wxStringInputStream empty_ss(wxEmptyString);
	wxFileConfig config(empty_ss, wxConvUTF8);
	config.SetPath("snakes");
	
	hcm.to_config(&config);
	
	wxStringOutputStream config_ss;
	config.Save(config_ss, wxConvUTF8);
	
	EXPECT_EQ(config_ss.GetString().ToStdString(),
		"[snakes]" CONFIG_EOL
		"[snakes/0]" CONFIG_EOL
		"primary_colour=abcdef" CONFIG_EOL
		"secondary_colour=fecdba" CONFIG_EOL
		"[snakes/2]" CONFIG_EOL
		"secondary_colour=123456" CONFIG_EOL
		"[snakes/3]" CONFIG_EOL
		"all_default=1" CONFIG_EOL
		"[snakes/4]" CONFIG_EOL
		"label=crown" CONFIG_EOL);
}

TEST(HighlightColourMap, DeserialiseConfig)
{
	wxStringInputStream config_ss(
		"[snakes]" CONFIG_EOL
		"[snakes/0]" CONFIG_EOL
		"primary_colour=abcdef" CONFIG_EOL
		"secondary_colour=fecdba" CONFIG_EOL
		"[snakes/2]" CONFIG_EOL
		"secondary_colour=123456" CONFIG_EOL
		"[snakes/3]" CONFIG_EOL
		"all_default=1" CONFIG_EOL
		"[snakes/4]" CONFIG_EOL
		"label=crown" CONFIG_EOL
		"[analyze/5]" CONFIG_EOL
		"label=muddled" CONFIG_EOL);
	
	wxFileConfig config(config_ss);
	config.SetPath("snakes");
	
	HighlightColourMap hcm = HighlightColourMap::from_config(&config);
	
	ASSERT_EQ(hcm.size(), 4U);
	
	EXPECT_EQ(std::next(hcm.begin(), 0)->first, 0U);
	EXPECT_EQ(std::next(hcm.begin(), 0)->second.primary_colour, wxColour(0xAB, 0xCD, 0xEF));
	EXPECT_EQ(std::next(hcm.begin(), 0)->second.secondary_colour, wxColour(0xFE, 0xCD, 0xBA));
	EXPECT_EQ(std::next(hcm.begin(), 0)->second.label, "Red");
	
	EXPECT_EQ(std::next(hcm.begin(), 1)->first, 2U);
	EXPECT_EQ(std::next(hcm.begin(), 1)->second.primary_colour, wxColour(0xFC, 0xFF, 0x00));
	EXPECT_EQ(std::next(hcm.begin(), 1)->second.secondary_colour, wxColour(0x12, 0x34, 0x56));
	EXPECT_EQ(std::next(hcm.begin(), 1)->second.label, "Yellow");
	
	EXPECT_EQ(std::next(hcm.begin(), 2)->first, 3U);
	EXPECT_EQ(std::next(hcm.begin(), 2)->second.primary_colour, wxColour(0x02, 0xFE, 0x07));
	EXPECT_EQ(std::next(hcm.begin(), 2)->second.secondary_colour, wxColour(0x00, 0x00, 0x00));
	EXPECT_EQ(std::next(hcm.begin(), 2)->second.label, "Green");
	
	EXPECT_EQ(std::next(hcm.begin(), 3)->first, 4U);
	EXPECT_EQ(std::next(hcm.begin(), 3)->second.primary_colour, wxColour(0xFD, 0x00, 0xFF));
	EXPECT_EQ(std::next(hcm.begin(), 3)->second.secondary_colour, wxColour(0xFF, 0xFF, 0xFF));
	EXPECT_EQ(std::next(hcm.begin(), 3)->second.label.ToStdString(), "crown");
	
	EXPECT_EQ(std::next(hcm.begin(), 4), hcm.end());
}

TEST(HighlightColourMap, DeserialiseConfigIndexOutOfRange)
{
	wxStringInputStream config_ss(
		"[snakes]" CONFIG_EOL
		"[snakes/100]" CONFIG_EOL
		"primary_colour=abcdef" CONFIG_EOL
		"secondary_colour=fecdba" CONFIG_EOL
		"[snakes/2]" CONFIG_EOL
		"secondary_colour=123456" CONFIG_EOL
		"[snakes/3]" CONFIG_EOL
		"all_default=1" CONFIG_EOL
		"[snakes/4]" CONFIG_EOL
		"label=crown" CONFIG_EOL
		"[analyze/5]" CONFIG_EOL
		"label=muddled" CONFIG_EOL);
	
	wxFileConfig config(config_ss);
	config.SetPath("snakes");
	
	EXPECT_THROW({ HighlightColourMap::from_config(&config); }, std::invalid_argument);
}

TEST(HighlightColourMap, DeserialiseConfigInvalidPrimaryColour)
{
	wxStringInputStream config_ss(
		"[snakes]" CONFIG_EOL
		"[snakes/0]" CONFIG_EOL
		"primary_colour=abcde" CONFIG_EOL
		"secondary_colour=fecdba" CONFIG_EOL
		"[snakes/2]" CONFIG_EOL
		"secondary_colour=123456" CONFIG_EOL
		"[snakes/3]" CONFIG_EOL
		"all_default=1" CONFIG_EOL
		"[snakes/4]" CONFIG_EOL
		"label=crown" CONFIG_EOL
		"[analyze/5]" CONFIG_EOL
		"label=muddled" CONFIG_EOL);
	
	wxFileConfig config(config_ss);
	config.SetPath("snakes");
	
	EXPECT_THROW({ HighlightColourMap::from_config(&config); }, std::invalid_argument);
}
