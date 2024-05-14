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
#include "../src/ByteColourMap.hpp"

using namespace REHex;

TEST(ByteColourMap, Colour)
{
	EXPECT_TRUE(ByteColourMap::Colour(Palette::PAL_NORMAL_TEXT_FG).is_palette_colour());
	EXPECT_FALSE(ByteColourMap::Colour(Palette::PAL_NORMAL_TEXT_FG).is_custom_colour());
	EXPECT_EQ(ByteColourMap::Colour(Palette::PAL_NORMAL_TEXT_FG).get_palette_colour(), Palette::PAL_NORMAL_TEXT_FG);
	
	EXPECT_FALSE(ByteColourMap::Colour(wxColour(0x00, 0x00, 0x00)).is_palette_colour());
	EXPECT_TRUE(ByteColourMap::Colour(wxColour(0x00, 0x00, 0x00)).is_custom_colour());
	EXPECT_EQ(ByteColourMap::Colour(wxColour(0x00, 0x00, 0x00)).get_custom_colour(), wxColour(0x00, 0x00, 0x00));
	
	EXPECT_FALSE(ByteColourMap::Colour(wxColour(0x10, 0x10, 0x10)).is_palette_colour());
	EXPECT_TRUE(ByteColourMap::Colour(wxColour(0x10, 0x10, 0x10)).is_custom_colour());
	EXPECT_EQ(ByteColourMap::Colour(wxColour(0x10, 0x10, 0x10)).get_custom_colour(), wxColour(0x10, 0x10, 0x10));
	
	EXPECT_TRUE(ByteColourMap::Colour(Palette::PAL_NORMAL_TEXT_FG) == ByteColourMap::Colour(Palette::PAL_NORMAL_TEXT_FG));
	
	EXPECT_TRUE( ByteColourMap::Colour(wxColour(0x00, 0x00, 0x00)) == ByteColourMap::Colour(wxColour(0x00, 0x00, 0x00)));
	EXPECT_TRUE( ByteColourMap::Colour(wxColour(0x10, 0x10, 0x10)) == ByteColourMap::Colour(wxColour(0x10, 0x10, 0x10)));
	EXPECT_FALSE(ByteColourMap::Colour(wxColour(0x00, 0x00, 0x00)) == ByteColourMap::Colour(wxColour(0x10, 0x10, 0x10)));
	EXPECT_FALSE(ByteColourMap::Colour(wxColour(0x10, 0x10, 0x10)) == ByteColourMap::Colour(wxColour(0x00, 0x00, 0x00)));
	
	EXPECT_FALSE(ByteColourMap::Colour(Palette::PAL_NORMAL_TEXT_FG) == ByteColourMap::Colour(wxColour(0x00, 0x00, 0x00)));
	EXPECT_FALSE(ByteColourMap::Colour(wxColour(0x00, 0x00, 0x00)) == ByteColourMap::Colour(Palette::PAL_NORMAL_TEXT_FG));
}

TEST(ByteColourMap, BasicTests)
{
	ByteColourMap bcm;
	
	/* Verify map elements are all initialised to default. */
	
	for(int i = 0; i < 256; ++i)
	{
		const ByteColourMap::Value &value = bcm[i];
		
		EXPECT_EQ(value.colour1, ByteColourMap::Colour(Palette::PAL_NORMAL_TEXT_FG));
		EXPECT_EQ(value.colour2, ByteColourMap::Colour(Palette::PAL_NORMAL_TEXT_FG));
		EXPECT_EQ(value.colour_delta_steps, 0);
		EXPECT_EQ(value.colour_delta_pos, 0);
		
		EXPECT_TRUE(value.is_single());
		EXPECT_FALSE(value.is_start());
		EXPECT_FALSE(value.is_end());
	}
	
	/* Set some single byte colours. */
	
	bcm.set_colour(1, ByteColourMap::Colour(wxColour(0x11, 0x00, 0x00)));
	bcm.set_colour(2, ByteColourMap::Colour(wxColour(0x66, 0x00, 0x00)));
	
	EXPECT_EQ(bcm[1].colour1, ByteColourMap::Colour(wxColour(0x11, 0x00, 0x00)));
	EXPECT_EQ(bcm[1].colour2, ByteColourMap::Colour(wxColour(0x11, 0x00, 0x00)));
	EXPECT_EQ(bcm[1].colour_delta_steps, 0);
	EXPECT_EQ(bcm[1].colour_delta_pos, 0);
	
	EXPECT_TRUE(bcm[1].is_single());
	EXPECT_FALSE(bcm[1].is_start());
	EXPECT_FALSE(bcm[1].is_end());
	
	EXPECT_EQ(bcm[2].colour1, ByteColourMap::Colour(wxColour(0x66, 0x00, 0x00)));
	EXPECT_EQ(bcm[2].colour2, ByteColourMap::Colour(wxColour(0x66, 0x00, 0x00)));
	EXPECT_EQ(bcm[2].colour_delta_steps, 0);
	EXPECT_EQ(bcm[2].colour_delta_pos, 0);
	
	EXPECT_TRUE(bcm[2].is_single());
	EXPECT_FALSE(bcm[2].is_start());
	EXPECT_FALSE(bcm[2].is_end());
	
	/* Set a range to a single colour. */
	
	bcm.set_colour_range(10, 20, ByteColourMap::Colour(wxColour(0x22, 0x00, 0x00)));
	
	for(int i = 10; i <= 20; ++i)
	{
		const ByteColourMap::Value &value = bcm[i];
		
		EXPECT_EQ(value.colour1, ByteColourMap::Colour(wxColour(0x22, 0x00, 0x00)));
		EXPECT_EQ(value.colour2, ByteColourMap::Colour(wxColour(0x22, 0x00, 0x00)));
		EXPECT_EQ(value.colour_delta_steps, 0);
		EXPECT_EQ(value.colour_delta_pos, 0);
		
		EXPECT_TRUE(value.is_single());
		EXPECT_FALSE(value.is_start());
		EXPECT_FALSE(value.is_end());
	}
	
	/* Verify range didn't leak. */
	
	EXPECT_EQ(bcm[9].colour1, ByteColourMap::Colour(Palette::PAL_NORMAL_TEXT_FG));
	EXPECT_EQ(bcm[9].colour2, ByteColourMap::Colour(Palette::PAL_NORMAL_TEXT_FG));
	EXPECT_EQ(bcm[9].colour_delta_steps, 0);
	EXPECT_EQ(bcm[9].colour_delta_pos, 0);
	
	EXPECT_EQ(bcm[21].colour1, ByteColourMap::Colour(Palette::PAL_NORMAL_TEXT_FG));
	EXPECT_EQ(bcm[21].colour2, ByteColourMap::Colour(Palette::PAL_NORMAL_TEXT_FG));
	EXPECT_EQ(bcm[21].colour_delta_steps, 0);
	EXPECT_EQ(bcm[21].colour_delta_pos, 0);
	
	/* Set a range to a gradient. */
	
	bcm.set_colour_gradient(30, 39, ByteColourMap::Colour(wxColour(0x77, 0x00, 0x00)), ByteColourMap::Colour(wxColour(0x88, 0x00, 0x00)));
	
	for(int i = 30; i <= 39; ++i)
	{
		const ByteColourMap::Value &value = bcm[i];
		
		EXPECT_EQ(value.colour1, ByteColourMap::Colour(wxColour(0x77, 0x00, 0x00)));
		EXPECT_EQ(value.colour2, ByteColourMap::Colour(wxColour(0x88, 0x00, 0x00)));
		EXPECT_EQ(value.colour_delta_steps, 9);
		EXPECT_EQ(value.colour_delta_pos, (i - 30));
		
		EXPECT_FALSE(value.is_single());
	}
	
	EXPECT_TRUE(bcm[30].is_start());
	EXPECT_FALSE(bcm[30].is_end());
	
	EXPECT_FALSE(bcm[31].is_start());
	EXPECT_FALSE(bcm[31].is_end());
	
	EXPECT_FALSE(bcm[39].is_start());
	EXPECT_TRUE(bcm[39].is_end());
	
	/* Verify range didn't leak. */
	
	EXPECT_EQ(bcm[29].colour1, ByteColourMap::Colour(Palette::PAL_NORMAL_TEXT_FG));
	EXPECT_EQ(bcm[29].colour2, ByteColourMap::Colour(Palette::PAL_NORMAL_TEXT_FG));
	EXPECT_EQ(bcm[29].colour_delta_steps, 0);
	EXPECT_EQ(bcm[29].colour_delta_pos, 0);
	
	EXPECT_EQ(bcm[40].colour1, ByteColourMap::Colour(Palette::PAL_NORMAL_TEXT_FG));
	EXPECT_EQ(bcm[40].colour2, ByteColourMap::Colour(Palette::PAL_NORMAL_TEXT_FG));
	EXPECT_EQ(bcm[40].colour_delta_steps, 0);
	EXPECT_EQ(bcm[40].colour_delta_pos, 0);
	
	/* Set a single byte "gradient" */
	
	bcm.set_colour_gradient(50, 50, ByteColourMap::Colour(wxColour(0x77, 0x00, 0x00)), ByteColourMap::Colour(wxColour(0x88, 0x00, 0x00)));
	
	EXPECT_EQ(bcm[50].colour1, ByteColourMap::Colour(wxColour(0x77, 0x00, 0x00)));
	EXPECT_EQ(bcm[50].colour2, ByteColourMap::Colour(wxColour(0x77, 0x00, 0x00)));
	EXPECT_EQ(bcm[50].colour_delta_steps, 0);
	EXPECT_EQ(bcm[50].colour_delta_pos, 0);
	
	EXPECT_TRUE(bcm[50].is_single());
	EXPECT_FALSE(bcm[50].is_start());
	EXPECT_FALSE(bcm[50].is_end());
	
	/* Set a range to single-colour "gradient" */
	
	bcm.set_colour_gradient(60, 69, ByteColourMap::Colour(wxColour(0x77, 0x00, 0x00)), ByteColourMap::Colour(wxColour(0x77, 0x00, 0x00)));
	
	for(int i = 60; i <= 69; ++i)
	{
		const ByteColourMap::Value &value = bcm[i];
		
		EXPECT_EQ(value.colour1, ByteColourMap::Colour(wxColour(0x77, 0x00, 0x00)));
		EXPECT_EQ(value.colour2, ByteColourMap::Colour(wxColour(0x77, 0x00, 0x00)));
		EXPECT_EQ(value.colour_delta_steps, 0);
		EXPECT_EQ(value.colour_delta_pos, 0);
		
		EXPECT_TRUE(value.is_single());
		EXPECT_FALSE(value.is_start());
		EXPECT_FALSE(value.is_end());
	}
}

TEST(ByteColourMap, Save)
{
	ByteColourMap bcm;
	
	/* Replace some values. */
	
	bcm.set_label("chocolate");
	
	/* Set a couple of values to a solid colour. */
	bcm.set_colour(0, ByteColourMap::Colour(wxColour(0x11, 0x00, 0x00)));
	bcm.set_colour(1, ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_2_FG));
	
	/* Set another value to a colour, then reset it back to default. */
	bcm.set_colour(3, ByteColourMap::Colour(wxColour(0x44, 0x00, 0x00)));
	bcm.set_colour(3, ByteColourMap::Colour(Palette::PAL_NORMAL_TEXT_FG));
	
	/* Set a range of values to a gradient. */
	bcm.set_colour_gradient(10, 14,
		ByteColourMap::Colour(wxColour(0x44, 0x00, 0x00)),
		ByteColourMap::Colour(wxColour(0x55, 0x00, 0x00)));
	
	/* Validate serialised config is correct. */
	
	wxStringInputStream empty_ss(wxEmptyString);
	wxFileConfig config(empty_ss, wxConvUTF8);
	config.SetPath("earsplitting");
	
	bcm.save(&config);
	
	wxStringOutputStream config_ss;
	config.Save(config_ss, wxConvUTF8);
	
	EXPECT_EQ(config_ss.GetString().ToStdString(),
		"[earsplitting]" CONFIG_EOL
		"label=chocolate" CONFIG_EOL
		"[earsplitting/0]" CONFIG_EOL
		"colour1=#110000" CONFIG_EOL
		"colour2=#110000" CONFIG_EOL
		"colour_delta_steps=0" CONFIG_EOL
		"colour_delta_pos=0" CONFIG_EOL
		"[earsplitting/1]" CONFIG_EOL
		"colour1=PAL_CONTRAST_TEXT_2_FG" CONFIG_EOL
		"colour2=PAL_CONTRAST_TEXT_2_FG" CONFIG_EOL
		"colour_delta_steps=0" CONFIG_EOL
		"colour_delta_pos=0" CONFIG_EOL
		"[earsplitting/10]" CONFIG_EOL
		"colour1=#440000" CONFIG_EOL
		"colour2=#550000" CONFIG_EOL
		"colour_delta_steps=4" CONFIG_EOL
		"colour_delta_pos=0" CONFIG_EOL
		"[earsplitting/11]" CONFIG_EOL
		"colour1=#440000" CONFIG_EOL
		"colour2=#550000" CONFIG_EOL
		"colour_delta_steps=4" CONFIG_EOL
		"colour_delta_pos=1" CONFIG_EOL
		"[earsplitting/12]" CONFIG_EOL
		"colour1=#440000" CONFIG_EOL
		"colour2=#550000" CONFIG_EOL
		"colour_delta_steps=4" CONFIG_EOL
		"colour_delta_pos=2" CONFIG_EOL
		"[earsplitting/13]" CONFIG_EOL
		"colour1=#440000" CONFIG_EOL
		"colour2=#550000" CONFIG_EOL
		"colour_delta_steps=4" CONFIG_EOL
		"colour_delta_pos=3" CONFIG_EOL
		"[earsplitting/14]" CONFIG_EOL
		"colour1=#440000" CONFIG_EOL
		"colour2=#550000" CONFIG_EOL
		"colour_delta_steps=4" CONFIG_EOL
		"colour_delta_pos=4" CONFIG_EOL);
}

TEST(ByteColourMap, Load)
{
	wxStringInputStream config_ss(
		"[earsplitting]" CONFIG_EOL
		"label=chocolate" CONFIG_EOL
		"[earsplitting/0]" CONFIG_EOL
		"colour1=PAL_CONTRAST_TEXT_2_FG" CONFIG_EOL
		"colour2=PAL_CONTRAST_TEXT_2_FG" CONFIG_EOL
		"colour_delta_steps=0" CONFIG_EOL
		"colour_delta_pos=0" CONFIG_EOL
		"[earsplitting/1]" CONFIG_EOL
		"colour1=#440000" CONFIG_EOL
		"colour2=#440000" CONFIG_EOL
		"colour_delta_steps=0" CONFIG_EOL
		"colour_delta_pos=0" CONFIG_EOL
		"[earsplitting/10]" CONFIG_EOL
		"colour1=#440000" CONFIG_EOL
		"colour2=#550000" CONFIG_EOL
		"colour_delta_steps=4" CONFIG_EOL
		"colour_delta_pos=0" CONFIG_EOL
		"[earsplitting/11]" CONFIG_EOL
		"colour1=#440000" CONFIG_EOL
		"colour2=#550000" CONFIG_EOL
		"colour_delta_steps=4" CONFIG_EOL
		"colour_delta_pos=1" CONFIG_EOL
		"[earsplitting/12]" CONFIG_EOL
		"colour1=#440000" CONFIG_EOL
		"colour2=#550000" CONFIG_EOL
		"colour_delta_steps=4" CONFIG_EOL
		"colour_delta_pos=2" CONFIG_EOL
		"[earsplitting/13]" CONFIG_EOL
		"colour1=#440000" CONFIG_EOL
		"colour2=#550000" CONFIG_EOL
		"colour_delta_steps=4" CONFIG_EOL
		"colour_delta_pos=3" CONFIG_EOL
		"[earsplitting/14]" CONFIG_EOL
		"colour1=#440000" CONFIG_EOL
		"colour2=#550000" CONFIG_EOL
		"colour_delta_steps=4" CONFIG_EOL
		"colour_delta_pos=4" CONFIG_EOL);
	
	wxFileConfig config(config_ss);
	config.SetPath("earsplitting");
	
	ByteColourMap bcm = ByteColourMap::load(&config);
	
	EXPECT_EQ(bcm.get_label().ToStdString(), "chocolate");
	
	EXPECT_EQ(bcm[0].colour1, ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_2_FG)) << "Simple colour is loaded correctly";
	EXPECT_EQ(bcm[0].colour2, ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_2_FG)) << "Simple colour is loaded correctly";
	EXPECT_EQ(bcm[0].colour_delta_steps, 0) << "Simple colour is loaded correctly";
	EXPECT_EQ(bcm[0].colour_delta_pos, 0) << "Simple colour is loaded correctly";
	
	EXPECT_EQ(bcm[1].colour1, ByteColourMap::Colour(wxColour(0x44, 0x00, 0x00))) << "Simple colour is loaded correctly";
	EXPECT_EQ(bcm[1].colour2, ByteColourMap::Colour(wxColour(0x44, 0x00, 0x00))) << "Simple colour is loaded correctly";
	EXPECT_EQ(bcm[1].colour_delta_steps, 0) << "Simple colour is loaded correctly";
	EXPECT_EQ(bcm[1].colour_delta_pos, 0) << "Simple colour is loaded correctly";
	
	EXPECT_EQ(bcm[2].colour1, ByteColourMap::Colour(Palette::PAL_NORMAL_TEXT_FG)) << "Unspecified byte has default colour";
	EXPECT_EQ(bcm[2].colour2, ByteColourMap::Colour(Palette::PAL_NORMAL_TEXT_FG)) << "Unspecified byte has default colour";
	EXPECT_EQ(bcm[2].colour_delta_steps, 0) << "Unspecified byte has default colour";
	EXPECT_EQ(bcm[2].colour_delta_pos, 0) << "Unspecified byte has default colour";
	
	EXPECT_EQ(bcm[10].colour1, ByteColourMap::Colour(wxColour(0x44, 0x00, 0x00))) << "Gradient range is loaded correctly";
	EXPECT_EQ(bcm[10].colour2, ByteColourMap::Colour(wxColour(0x55, 0x00, 0x00))) << "Gradient range is loaded correctly";
	EXPECT_EQ(bcm[10].colour_delta_steps, 4) << "Gradient range is loaded correctly";
	EXPECT_EQ(bcm[10].colour_delta_pos, 0) << "Gradient range is loaded correctly";
	
	EXPECT_EQ(bcm[11].colour1, ByteColourMap::Colour(wxColour(0x44, 0x00, 0x00))) << "Gradient range is loaded correctly";
	EXPECT_EQ(bcm[11].colour2, ByteColourMap::Colour(wxColour(0x55, 0x00, 0x00))) << "Gradient range is loaded correctly";
	EXPECT_EQ(bcm[11].colour_delta_steps, 4) << "Gradient range is loaded correctly";
	EXPECT_EQ(bcm[11].colour_delta_pos, 1) << "Gradient range is loaded correctly";
	
	EXPECT_EQ(bcm[12].colour1, ByteColourMap::Colour(wxColour(0x44, 0x00, 0x00))) << "Gradient range is loaded correctly";
	EXPECT_EQ(bcm[12].colour2, ByteColourMap::Colour(wxColour(0x55, 0x00, 0x00))) << "Gradient range is loaded correctly";
	EXPECT_EQ(bcm[12].colour_delta_steps, 4) << "Gradient range is loaded correctly";
	EXPECT_EQ(bcm[12].colour_delta_pos, 2) << "Gradient range is loaded correctly";
	
	EXPECT_EQ(bcm[13].colour1, ByteColourMap::Colour(wxColour(0x44, 0x00, 0x00))) << "Gradient range is loaded correctly";
	EXPECT_EQ(bcm[13].colour2, ByteColourMap::Colour(wxColour(0x55, 0x00, 0x00))) << "Gradient range is loaded correctly";
	EXPECT_EQ(bcm[13].colour_delta_steps, 4) << "Gradient range is loaded correctly";
	EXPECT_EQ(bcm[13].colour_delta_pos, 3) << "Gradient range is loaded correctly";
	
	EXPECT_EQ(bcm[14].colour1, ByteColourMap::Colour(wxColour(0x44, 0x00, 0x00))) << "Gradient range is loaded correctly";
	EXPECT_EQ(bcm[14].colour2, ByteColourMap::Colour(wxColour(0x55, 0x00, 0x00))) << "Gradient range is loaded correctly";
	EXPECT_EQ(bcm[14].colour_delta_steps, 4) << "Gradient range is loaded correctly";
	EXPECT_EQ(bcm[14].colour_delta_pos, 4) << "Gradient range is loaded correctly";
}
