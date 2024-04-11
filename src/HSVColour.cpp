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

#include <algorithm>
#include <math.h>

#include "HSVColour.hpp"

float REHex::HSVColour::wrap_h(float h)
{
	return h - (360.0f * floorf(h / 360.f));
}

float REHex::HSVColour::clamp_sv(float sv)
{
	return std::max(0.0f, std::min(sv, 1.0f));
}

REHex::HSVColour::HSVColour(float h, float s, float v):
	h(wrap_h(h)),
	s(clamp_sv(s)),
	v(clamp_sv(v)) {}

REHex::HSVColour::HSVColour(const wxColour &rgb)
{
	/* https://www.geeksforgeeks.org/program-change-rgb-color-model-hsv-color-model/ */
	
	float r = (float)(rgb.Red()) / 255.0f;
	float g = (float)(rgb.Green()) / 255.0f;
	float b = (float)(rgb.Blue()) / 255.0f;
	
	float cmax = std::max({ r, g, b });
	float cmin = std::min({ r, g, b });
	float cdiff = cmax - cmin;
	
	if(cmax == cmin)
	{
		h = 0.0f;
	}
	else if(cmax == r)
	{
		h = wrap_h(60.0f * ((g - b) / cdiff) + 360.0f);
	}
	else if(cmax == g)
	{
		h = wrap_h(60.0f * ((b - r) / cdiff) + 120.0f);
	}
	else{
		assert(cmax == b);
		h = wrap_h(60.0f * ((r - g) / cdiff) + 240.0f);
	}
	
	if(cmax == 0.0f)
	{
		s = 0.0f;
	}
	else{
		s = cdiff / cmax;
	}
	
	v = cmax;
}

wxColour REHex::HSVColour::to_rgb() const
{
	/* HSV to RGB conversion Copyright (c) 2014, Jan Winkler <winkler@cs.uni-bremen.de>
	 * https://gist.github.com/fairlight1337/4935ae72bcbcc1ba5c72
	*/
	
	float fR, fG, fB;
	
	float fH = wrap_h(h);
	float fS = clamp_sv(s);
	float fV = clamp_sv(v);
	
	float fC = fV * fS; // Chroma
	float fHPrime = fmod(fH / 60.0, 6);
	float fX = fC * (1 - fabs(fmod(fHPrime, 2) - 1));
	float fM = fV - fC;
	
	if(0 <= fHPrime && fHPrime < 1) {
		fR = fC;
		fG = fX;
		fB = 0;
	} else if(1 <= fHPrime && fHPrime < 2) {
		fR = fX;
		fG = fC;
		fB = 0;
	} else if(2 <= fHPrime && fHPrime < 3) {
		fR = 0;
		fG = fC;
		fB = fX;
	} else if(3 <= fHPrime && fHPrime < 4) {
		fR = 0;
		fG = fX;
		fB = fC;
	} else if(4 <= fHPrime && fHPrime < 5) {
		fR = fX;
		fG = 0;
		fB = fC;
	} else if(5 <= fHPrime && fHPrime < 6) {
		fR = fC;
		fG = 0;
		fB = fX;
	} else {
		fR = 0;
		fG = 0;
		fB = 0;
	}
	
	fR += fM;
	fG += fM;
	fB += fM;
	
	fR *= 255.0;
	fG *= 255.0;
	fB *= 255.0;
	
	return wxColour(fR, fG, fB);
}

std::pair<float, float> REHex::HSVColour::pick_contrasting_hue(const std::vector<float> &existing_hues)
{
	if(existing_hues.empty())
	{
		/* No reference colours. Pick an arbitrary hue. */
		return std::make_pair(0.0f, 360.0f);
	}
	
	/* First, wrap all values into the space of 0.0-359.9 and sort them. */
	
	std::vector<float> sorted_hues;
	sorted_hues.reserve(existing_hues.size());
	
	for(auto i = existing_hues.begin(); i != existing_hues.end(); ++i)
	{
		sorted_hues.push_back(wrap_h(*i));
	}
	
	std::sort(sorted_hues.begin(), sorted_hues.end());
	
	/* Then we iterate over each one hue, and pick the mid-point between
	 * the two most distant points.
	*/
	
	float hue = 0.0f;
	float hue_gap = 0.0f;
	
	for(size_t i = 0; i < sorted_hues.size(); ++i)
	{
		float this_hue = sorted_hues[i];
		float next_hue = sorted_hues.size() > (i + 1) ? sorted_hues[i + 1] : (360.0f + sorted_hues[0]);
		
		float this_gap = (next_hue - this_hue) / 2.0f;
		float this_midpoint = this_hue + this_gap;
		
		if(this_gap > hue_gap)
		{
			hue = wrap_h(this_midpoint);
			hue_gap = this_gap;
		}
	}
	
	return std::make_pair(hue, hue_gap);
}
