/* Reverse Engineer's Hex Editor
 * Copyright (C) 2022 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <stdio.h>
#include <vector>
#include <wx/dcmemory.h>

#include "../src/FastRectangleFiller.hpp"

using namespace REHex;

class FastRectangleFillerTestMockDC
{
	public:
		const wxBrush &GetBrush() const;
		void SetBrush(const wxBrush &brush);
		
		const wxPen &GetPen() const;
		void SetPen(const wxPen &pen);
		
		void DrawRectangle(const wxRect &rect);
		
		std::vector<std::string> get_calls();
		void clear_calls();
		
	private:
		wxBrush brush;
		wxPen pen;
		
		std::vector<std::string> calls;
};

const wxBrush &FastRectangleFillerTestMockDC::GetBrush() const
{
	return brush;
}

void FastRectangleFillerTestMockDC::SetBrush(const wxBrush &brush)
{
	this->brush = brush;
	
	char call[128];
	snprintf(call, sizeof(call), "SetBrush(%s, %d)", brush.GetColour().GetAsString(wxC2S_CSS_SYNTAX).ToStdString().c_str(), (int)(brush.GetStyle()));
	calls.push_back(call);
}

const wxPen &FastRectangleFillerTestMockDC::GetPen() const
{
	return pen;
}

static std::string wxPen_to_string(const wxPen &pen)
{
	return pen.GetColour().GetAsString(wxC2S_CSS_SYNTAX).ToStdString()
		+ ", " + std::to_string(pen.GetWidth())
		+ ", " + std::to_string((int)(pen.GetStyle()));
}

void FastRectangleFillerTestMockDC::SetPen(const wxPen &pen)
{
	this->pen = pen;
	
	calls.push_back("SetPen(" + wxPen_to_string(pen) + ")");
}

void FastRectangleFillerTestMockDC::DrawRectangle(const wxRect &rect)
{
	char call[128];
	snprintf(call, sizeof(call), "DrawRectangle({ %d, %d, %d, %d })", rect.x, rect.y, rect.width, rect.height);
	calls.push_back(call);
}

std::vector<std::string> FastRectangleFillerTestMockDC::get_calls()
{
	return calls;
}

void FastRectangleFillerTestMockDC::clear_calls()
{
	calls.clear();
}

TEST(FastRectangleFiller, NoRectangles)
{
	FastRectangleFillerTestMockDC dc;
	
	{
		FastRectangleFillerImpl<FastRectangleFillerTestMockDC> frf(dc);
	}
	
	EXPECT_EQ(dc.get_calls(), std::vector<std::string>());
}

TEST(FastRectangleFiller, OneRectangle)
{
	FastRectangleFillerTestMockDC dc;
	
	{
		FastRectangleFillerImpl<FastRectangleFillerTestMockDC> frf(dc);
		frf.fill_rectangle(wxRect(10, 20, 5, 6), wxColour(255, 255, 255));
		
		EXPECT_EQ(dc.get_calls(), std::vector<std::string>());
	}
	
	EXPECT_EQ(dc.get_calls(), std::vector<std::string>({
		"SetBrush(rgb(255, 255, 255), " + std::to_string(wxBRUSHSTYLE_SOLID) + ")",
		"SetPen(" + wxPen_to_string(*wxTRANSPARENT_PEN) + ")",
		"DrawRectangle({ 10, 20, 5, 6 })",
	}));
}

TEST(FastRectangleFiller, OneRectangleInitiallyCorrectBrush)
{
	FastRectangleFillerTestMockDC dc;
	dc.SetBrush(wxBrush(wxColour(255, 255, 255)));
	dc.clear_calls();
	
	{
		FastRectangleFillerImpl<FastRectangleFillerTestMockDC> frf(dc);
		frf.fill_rectangle(wxRect(10, 20, 5, 6), wxColour(255, 255, 255));
		
		EXPECT_EQ(dc.get_calls(), std::vector<std::string>());
	}
	
	EXPECT_EQ(dc.get_calls(), std::vector<std::string>({
		"SetPen(" + wxPen_to_string(*wxTRANSPARENT_PEN) + ")",
		"DrawRectangle({ 10, 20, 5, 6 })",
	}));
}

TEST(FastRectangleFiller, OneRectangleInitiallyCorrectPen)
{
	FastRectangleFillerTestMockDC dc;
	dc.SetPen(*wxTRANSPARENT_PEN);
	dc.clear_calls();
	
	{
		FastRectangleFillerImpl<FastRectangleFillerTestMockDC> frf(dc);
		frf.fill_rectangle(wxRect(10, 20, 5, 6), wxColour(255, 255, 255));
		
		EXPECT_EQ(dc.get_calls(), std::vector<std::string>());
	}
	
	EXPECT_EQ(dc.get_calls(), std::vector<std::string>({
		"SetBrush(rgb(255, 255, 255), " + std::to_string(wxBRUSHSTYLE_SOLID) + ")",
		"DrawRectangle({ 10, 20, 5, 6 })",
	}));
}

TEST(FastRectangleFiller, DistinctRectangles)
{
	FastRectangleFillerTestMockDC dc;
	
	{
		FastRectangleFillerImpl<FastRectangleFillerTestMockDC> frf(dc);
		
		/* To the right */
		frf.fill_rectangle(wxRect(10, 10, 10, 10), wxColour(255, 255, 255));
		frf.fill_rectangle(wxRect(21, 10, 10, 10), wxColour(255, 255, 255));
		
		/* To the left */
		frf.fill_rectangle(wxRect(90, 10, 10, 10), wxColour(255, 255, 255));
		frf.fill_rectangle(wxRect(79, 10, 10, 10), wxColour(255, 255, 255));
		
		/* Above */
		frf.fill_rectangle(wxRect(10, 90, 20, 10), wxColour(255, 255, 255));
		frf.fill_rectangle(wxRect(10, 80, 20,  9), wxColour(255, 255, 255));
		
		/* Below */
		frf.fill_rectangle(wxRect(31, 80, 20, 10), wxColour(255, 255, 255));
		frf.fill_rectangle(wxRect(31, 91, 20, 10), wxColour(255, 255, 255));
	}
	
	EXPECT_EQ(dc.get_calls(), std::vector<std::string>({
		"SetBrush(rgb(255, 255, 255), " + std::to_string(wxBRUSHSTYLE_SOLID) + ")",
		"SetPen(" + wxPen_to_string(*wxTRANSPARENT_PEN) + ")",
		"DrawRectangle({ 10, 10, 10, 10 })",
		"DrawRectangle({ 21, 10, 10, 10 })",
		"DrawRectangle({ 90, 10, 10, 10 })",
		"DrawRectangle({ 79, 10, 10, 10 })",
		"DrawRectangle({ 10, 90, 20, 10 })",
		"DrawRectangle({ 10, 80, 20, 9 })",
		"DrawRectangle({ 31, 80, 20, 10 })",
		"DrawRectangle({ 31, 91, 20, 10 })",
	}));
}

TEST(FastRectangleFiller, AdjacentRectangles)
{
	FastRectangleFillerTestMockDC dc;
	
	{
		FastRectangleFillerImpl<FastRectangleFillerTestMockDC> frf(dc);
		
		/* To the right */
		frf.fill_rectangle(wxRect(10, 10, 10, 10), wxColour(255, 255, 255));
		frf.fill_rectangle(wxRect(20, 10, 10, 10), wxColour(255, 255, 255));
		
		/* To the left */
		frf.fill_rectangle(wxRect(90, 10, 10, 10), wxColour(255, 255, 255));
		frf.fill_rectangle(wxRect(80, 10, 10, 10), wxColour(255, 255, 255));
		
		/* Above */
		frf.fill_rectangle(wxRect(10, 90, 20, 10), wxColour(255, 255, 255));
		frf.fill_rectangle(wxRect(10, 80, 20, 10), wxColour(255, 255, 255));
		
		/* Below */
		frf.fill_rectangle(wxRect(31, 80, 20, 10), wxColour(255, 255, 255));
		frf.fill_rectangle(wxRect(31, 90, 20, 10), wxColour(255, 255, 255));
	}
	
	EXPECT_EQ(dc.get_calls(), std::vector<std::string>({
		"SetBrush(rgb(255, 255, 255), " + std::to_string(wxBRUSHSTYLE_SOLID) + ")",
		"SetPen(" + wxPen_to_string(*wxTRANSPARENT_PEN) + ")",
		"DrawRectangle({ 10, 10, 20, 10 })",
		"DrawRectangle({ 80, 10, 20, 10 })",
		"DrawRectangle({ 10, 80, 20, 20 })",
		"DrawRectangle({ 31, 80, 20, 20 })",
	}));
}

TEST(FastRectangleFiller, AdjacentRectanglesDifferentColours)
{
	FastRectangleFillerTestMockDC dc;
	
	{
		FastRectangleFillerImpl<FastRectangleFillerTestMockDC> frf(dc);
		
		/* To the right */
		frf.fill_rectangle(wxRect(10, 10, 10, 10), wxColour(255, 255, 255));
		frf.fill_rectangle(wxRect(20, 10, 10, 10), wxColour(255, 0, 0));
		
		/* To the left */
		frf.fill_rectangle(wxRect(90, 10, 10, 10), wxColour(0, 255, 0));
		frf.fill_rectangle(wxRect(80, 10, 10, 10), wxColour(0, 0, 255));
	}
	
	EXPECT_EQ(dc.get_calls(), std::vector<std::string>({
		"SetBrush(rgb(255, 255, 255), " + std::to_string(wxBRUSHSTYLE_SOLID) + ")",
		"SetPen(" + wxPen_to_string(*wxTRANSPARENT_PEN) + ")",
		"DrawRectangle({ 10, 10, 10, 10 })",
		
		"SetBrush(rgb(255, 0, 0), " + std::to_string(wxBRUSHSTYLE_SOLID) + ")",
		"DrawRectangle({ 20, 10, 10, 10 })",
		
		"SetBrush(rgb(0, 255, 0), " + std::to_string(wxBRUSHSTYLE_SOLID) + ")",
		"DrawRectangle({ 90, 10, 10, 10 })",
		
		"SetBrush(rgb(0, 0, 255), " + std::to_string(wxBRUSHSTYLE_SOLID) + ")",
		"DrawRectangle({ 80, 10, 10, 10 })",
	}));
}

TEST(FastRectangleFiller, AdjacentRectanglesIncompatible)
{
	FastRectangleFillerTestMockDC dc;
	
	{
		FastRectangleFillerImpl<FastRectangleFillerTestMockDC> frf(dc);
		
		/* To the right (bottom edge misaligned) */
		frf.fill_rectangle(wxRect(10, 10, 10, 10), wxColour(255, 255, 255));
		frf.fill_rectangle(wxRect(20, 10, 10, 11), wxColour(255, 255, 255));
		
		/* To the left (top edge misaligned) */
		frf.fill_rectangle(wxRect(90, 10, 10, 10), wxColour(255, 255, 255));
		frf.fill_rectangle(wxRect(80, 11, 10,  9), wxColour(255, 255, 255));
		
		/* Above (right edge misaligned) */
		frf.fill_rectangle(wxRect(10, 90, 20, 10), wxColour(255, 255, 255));
		frf.fill_rectangle(wxRect(10, 80, 21, 10), wxColour(255, 255, 255));
		
		/* Below (left and right edge misaligned) */
		frf.fill_rectangle(wxRect(41, 80, 20, 10), wxColour(255, 255, 255));
		frf.fill_rectangle(wxRect(40, 90, 20, 10), wxColour(255, 255, 255));
	}
	
	EXPECT_EQ(dc.get_calls(), std::vector<std::string>({
		"SetBrush(rgb(255, 255, 255), " + std::to_string(wxBRUSHSTYLE_SOLID) + ")",
		"SetPen(" + wxPen_to_string(*wxTRANSPARENT_PEN) + ")",
		"DrawRectangle({ 10, 10, 10, 10 })",
		"DrawRectangle({ 20, 10, 10, 11 })",
		"DrawRectangle({ 90, 10, 10, 10 })",
		"DrawRectangle({ 80, 11, 10, 9 })",
		"DrawRectangle({ 10, 90, 20, 10 })",
		"DrawRectangle({ 10, 80, 21, 10 })",
		"DrawRectangle({ 41, 80, 20, 10 })",
		"DrawRectangle({ 40, 90, 20, 10 })",
	}));
}

TEST(FastRectangleFiller, OverlappingRectangles)
{
	FastRectangleFillerTestMockDC dc;
	
	{
		FastRectangleFillerImpl<FastRectangleFillerTestMockDC> frf(dc);
		
		/* A intersects B */
		frf.fill_rectangle(wxRect(10, 10, 10, 10), wxColour(255, 255, 255));
		frf.fill_rectangle(wxRect(15, 10, 10, 10), wxColour(255, 255, 255));
		
		/* A is inside B */
		frf.fill_rectangle(wxRect(15, 35, 10, 10), wxColour(255, 255, 255));
		frf.fill_rectangle(wxRect(10, 30, 20, 20), wxColour(255, 255, 255));
		
		/* B is inside A */
		frf.fill_rectangle(wxRect(40, 10, 20, 20), wxColour(255, 255, 255));
		frf.fill_rectangle(wxRect(45, 15, 10, 10), wxColour(255, 255, 255));
		
		/* A matches B exactly */
		frf.fill_rectangle(wxRect(40, 40, 20, 20), wxColour(255, 255, 255));
		frf.fill_rectangle(wxRect(40, 40, 20, 20), wxColour(255, 255, 255));
	}
	
	EXPECT_EQ(dc.get_calls(), std::vector<std::string>({
		"SetBrush(rgb(255, 255, 255), " + std::to_string(wxBRUSHSTYLE_SOLID) + ")",
		"SetPen(" + wxPen_to_string(*wxTRANSPARENT_PEN) + ")",
		
		"DrawRectangle({ 10, 10, 15, 10 })",
		"DrawRectangle({ 10, 30, 20, 20 })",
		"DrawRectangle({ 40, 10, 20, 20 })",
		"DrawRectangle({ 40, 40, 20, 20 })",
	}));
}

TEST(FastRectangleFiller, OverlappingRectanglesIncompatible)
{
	FastRectangleFillerTestMockDC dc;
	
	{
		FastRectangleFillerImpl<FastRectangleFillerTestMockDC> frf(dc);
		
		/* A intersects B, but cannot be merged */
		frf.fill_rectangle(wxRect(10, 10, 10, 10), wxColour(255, 255, 255));
		frf.fill_rectangle(wxRect(15, 10, 10,  2), wxColour(255, 255, 255));
	}
	
	EXPECT_EQ(dc.get_calls(), std::vector<std::string>({
		"SetBrush(rgb(255, 255, 255), " + std::to_string(wxBRUSHSTYLE_SOLID) + ")",
		"SetPen(" + wxPen_to_string(*wxTRANSPARENT_PEN) + ")",
		
		"DrawRectangle({ 10, 10, 10, 10 })",
		"DrawRectangle({ 15, 10, 10, 2 })",
	}));
}
