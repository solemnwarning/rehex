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

#include <tuple>

#include "../src/HSVColour.hpp"

using namespace REHex;

/* We allow some rounding error when convering between HSV/RGB. */
static constexpr float HSV_EPSILON = 0.015625f;
static constexpr unsigned char RGB_EPSILON = 1;

TEST(HSVColour, ConstructHSV)
{
	{
		HSVColour hsv(128.0f, 0.75f, 0.5f);
		
		EXPECT_FLOAT_EQ(hsv.h, 128.0f);
		EXPECT_FLOAT_EQ(hsv.s, 0.75f);
		EXPECT_FLOAT_EQ(hsv.v, 0.5f);
	}
	
	{
		HSVColour hsv(1000.0f, 1.0f, 0.5f);
		EXPECT_FLOAT_EQ(hsv.h, 280.0f) << "HSVColour::HSVColour(float h, float s, float v) wraps large hue";
	}
	
	{
		HSVColour hsv(100.0f, 2.0f, 0.5f);
		EXPECT_FLOAT_EQ(hsv.s, 1.0f) << "HSVColour::HSVColour(float h, float s, float v) clamps large saturation";
	}
	
	{
		HSVColour hsv(100.0f, -1.0f, 0.5f);
		EXPECT_FLOAT_EQ(hsv.s, 0.0f) << "HSVColour::HSVColour(float h, float s, float v) clamps negative saturation";
	}
	
	{
		HSVColour hsv(100.0f, 1.0f, 2.0f);
		EXPECT_FLOAT_EQ(hsv.v, 1.0f) << "HSVColour::HSVColour(float h, float s, float v) clamps large values";
	}
	
	{
		HSVColour hsv(100.0f, 1.0f, -0.5f);
		EXPECT_FLOAT_EQ(hsv.v, 0.0f) << "HSVColour::HSVColour(float h, float s, float v) clamps negative values";
	}
}

TEST(HSVColour, ConvertFromRGB)
{
	{
		HSVColour hsv(wxColour(0xFF, 0x00, 0x00)); /* Red */
		
		EXPECT_NEAR(hsv.h, 0.0f, HSV_EPSILON);
		EXPECT_NEAR(hsv.s, 1.0f, HSV_EPSILON);
		EXPECT_NEAR(hsv.v, 1.0f, HSV_EPSILON);
	}
	
	{
		HSVColour hsv(wxColour(0x00, 0xFF, 0x00)); /* Green */
		
		EXPECT_NEAR(hsv.h, 120.0f, HSV_EPSILON);
		EXPECT_NEAR(hsv.s, 1.0f, HSV_EPSILON);
		EXPECT_NEAR(hsv.v, 1.0f, HSV_EPSILON);
	}
	
	{
		HSVColour hsv(wxColour(0x00, 0x00, 0xFF)); /* Blue */
		
		EXPECT_NEAR(hsv.h, 240.0f, HSV_EPSILON);
		EXPECT_NEAR(hsv.s, 1.0f, HSV_EPSILON);
		EXPECT_NEAR(hsv.v, 1.0f, HSV_EPSILON);
	}
	
	{
		HSVColour hsv(wxColour(0x00, 0x00, 0x80)); /* Dark blue */
		
		EXPECT_NEAR(hsv.h, 240.0f, HSV_EPSILON);
		EXPECT_NEAR(hsv.s, 1.0f, HSV_EPSILON);
		EXPECT_NEAR(hsv.v, 0.5f, HSV_EPSILON);
	}
	
	{
		HSVColour hsv(wxColour(0xFF, 0xFF, 0x00)); /* Yellow */
		
		EXPECT_NEAR(hsv.h, 60.0f, HSV_EPSILON);
		EXPECT_NEAR(hsv.s, 1.0f, HSV_EPSILON);
		EXPECT_NEAR(hsv.v, 1.0f, HSV_EPSILON);
	}
	
	{
		HSVColour hsv(wxColour(0xFF, 0xFF, 0xFF)); /* White */
		
		EXPECT_NEAR(hsv.h, 0.0f, HSV_EPSILON);
		EXPECT_NEAR(hsv.s, 0.0f, HSV_EPSILON);
		EXPECT_NEAR(hsv.v, 1.0f, HSV_EPSILON);
	}
	
	{
		HSVColour hsv(wxColour(0xC3, 0xC3, 0xC3)); /* Light grey */
		
		EXPECT_NEAR(hsv.h, 0.0f, HSV_EPSILON);
		EXPECT_NEAR(hsv.s, 0.0f, HSV_EPSILON);
		EXPECT_NEAR(hsv.v, 0.765f, HSV_EPSILON);
	}
	
	{
		HSVColour hsv(wxColour(0x80, 0x80, 0x80)); /* Dark grey */
		
		EXPECT_NEAR(hsv.h, 0.0f, HSV_EPSILON);
		EXPECT_NEAR(hsv.s, 0.0f, HSV_EPSILON);
		EXPECT_NEAR(hsv.v, 0.5f, HSV_EPSILON);
	}
	
	{
		HSVColour hsv(wxColour(0x00, 0x00, 0x00)); /* Black */
		
		EXPECT_NEAR(hsv.h, 0.0f, HSV_EPSILON);
		EXPECT_NEAR(hsv.s, 0.0f, HSV_EPSILON);
		EXPECT_NEAR(hsv.v, 0.0f, HSV_EPSILON);
	}
}

TEST(HSVColour, ConvertToRGB)
{
	{
		HSVColour hsv(0.0f, 1.0f, 1.0f); /* Red */
		wxColour rgb = hsv.to_rgb();
		
		EXPECT_NEAR(rgb.Red(), 0xFF, RGB_EPSILON);
		EXPECT_NEAR(rgb.Green(), 0x00, RGB_EPSILON);
		EXPECT_NEAR(rgb.Blue(), 0x00, RGB_EPSILON);
	}
	
	{
		HSVColour hsv(120.0f, 1.0f, 1.0f); /* Green */
		wxColour rgb = hsv.to_rgb();
		
		EXPECT_NEAR(rgb.Red(), 0x00, RGB_EPSILON);
		EXPECT_NEAR(rgb.Green(), 0xFF, RGB_EPSILON);
		EXPECT_NEAR(rgb.Blue(), 0x00, RGB_EPSILON);
	}
	
	{
		HSVColour hsv(240.0f, 1.0f, 1.0f); /* Blue */
		wxColour rgb = hsv.to_rgb();
		
		EXPECT_NEAR(rgb.Red(), 0x00, RGB_EPSILON);
		EXPECT_NEAR(rgb.Green(), 0x00, RGB_EPSILON);
		EXPECT_NEAR(rgb.Blue(), 0xFF, RGB_EPSILON);
	}
	
	{
		HSVColour hsv(240.0f, 1.0f, 0.5f); /* Dark blue */
		wxColour rgb = hsv.to_rgb();
		
		EXPECT_NEAR(rgb.Red(), 0x00, RGB_EPSILON);
		EXPECT_NEAR(rgb.Green(), 0x00, RGB_EPSILON);
		EXPECT_NEAR(rgb.Blue(), 0x80, RGB_EPSILON);
	}
	
	{
		HSVColour hsv(60.0f, 1.0f, 1.0f); /* Yellow */
		wxColour rgb = hsv.to_rgb();
		
		EXPECT_NEAR(rgb.Red(), 0xFF, RGB_EPSILON);
		EXPECT_NEAR(rgb.Green(), 0xFF, RGB_EPSILON);
		EXPECT_NEAR(rgb.Blue(), 0x00, RGB_EPSILON);
	}
	
	{
		HSVColour hsv(0.0f, 0.0f, 1.0f); /* White */
		wxColour rgb = hsv.to_rgb();
		
		EXPECT_NEAR(rgb.Red(), 0xFF, RGB_EPSILON);
		EXPECT_NEAR(rgb.Green(), 0xFF, RGB_EPSILON);
		EXPECT_NEAR(rgb.Blue(), 0xFF, RGB_EPSILON);
	}
	
	{
		HSVColour hsv(0.0f, 0.0f, 0.765f); /* Light grey */
		wxColour rgb = hsv.to_rgb();
		
		EXPECT_NEAR(rgb.Red(), 0xC3, RGB_EPSILON);
		EXPECT_NEAR(rgb.Green(), 0xC3, RGB_EPSILON);
		EXPECT_NEAR(rgb.Blue(), 0xC3, RGB_EPSILON);
	}
	
	{
		HSVColour hsv(0.0f, 0.0f, 0.5f); /* Dark grey */
		wxColour rgb = hsv.to_rgb();
		
		EXPECT_NEAR(rgb.Red(), 0x80, RGB_EPSILON);
		EXPECT_NEAR(rgb.Green(), 0x80, RGB_EPSILON);
		EXPECT_NEAR(rgb.Blue(), 0x80, RGB_EPSILON);
	}
	
	{
		HSVColour hsv(0.0f, 0.0f, 0.0f); /* Black */
		wxColour rgb = hsv.to_rgb();
		
		EXPECT_NEAR(rgb.Red(), 0x00, RGB_EPSILON);
		EXPECT_NEAR(rgb.Green(), 0x00, RGB_EPSILON);
		EXPECT_NEAR(rgb.Blue(), 0x00, RGB_EPSILON);
	}
}

TEST(HSVColour, PickContrastingHue)
{
	{
		float hue, diff;
		std::tie(hue, diff) = HSVColour::pick_contrasting_hue(std::vector<float>({}));
		
		EXPECT_FLOAT_EQ(hue, 0.0f);
		EXPECT_FLOAT_EQ(diff, 360.0f);
	}
	
	{
		float hue, diff;
		std::tie(hue, diff) = HSVColour::pick_contrasting_hue(std::vector<float>({ 0.0f }));
		
		EXPECT_FLOAT_EQ(hue, 180.0f);
		EXPECT_FLOAT_EQ(diff, 180.0f);
	}
	
	{
		float hue, diff;
		std::tie(hue, diff) = HSVColour::pick_contrasting_hue(std::vector<float>({ 180.0f }));
		
		EXPECT_FLOAT_EQ(hue, 0.0f);
		EXPECT_FLOAT_EQ(diff, 180.0f);
	}
	
	{
		float hue, diff;
		std::tie(hue, diff) = HSVColour::pick_contrasting_hue(std::vector<float>({ 240.0f }));
		
		EXPECT_FLOAT_EQ(hue, 60.0f);
		EXPECT_FLOAT_EQ(diff, 180.0f);
	}
	
	{
		float hue, diff;
		std::tie(hue, diff) = HSVColour::pick_contrasting_hue(std::vector<float>({ 360.0f }));
		
		EXPECT_FLOAT_EQ(hue, 180.0f);
		EXPECT_FLOAT_EQ(diff, 180.0f);
	}
	
	{
		float hue, diff;
		std::tie(hue, diff) = HSVColour::pick_contrasting_hue(std::vector<float>({ 0.0f, 180.0f }));
		
		EXPECT_FLOAT_EQ(hue, 90.0f);
		EXPECT_FLOAT_EQ(diff, 90.0f);
	}
	
	{
		float hue, diff;
		std::tie(hue, diff) = HSVColour::pick_contrasting_hue(std::vector<float>({ 120.0f, 180.0f }));
		
		EXPECT_FLOAT_EQ(hue, 330.0f);
		EXPECT_FLOAT_EQ(diff, 150.0f);
	}
}
