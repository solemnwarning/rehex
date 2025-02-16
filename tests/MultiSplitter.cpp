/* Reverse Engineer's Hex Editor
 * Copyright (C) 2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <wx/frame.h>
#include <wx/panel.h>

#include "../src/MultiSplitter.hpp"

using namespace REHex;

class MultiSplitterTest: public ::testing::Test
{
protected:
	wxFrame *m_frame;

	MultiSplitter *m_splitter;

	typedef MultiSplitter::Cell Cell;

	Cell *get_root_cell()
	{
		return m_splitter->m_cells.get();
	}

public:
	MultiSplitterTest();
	virtual ~MultiSplitterTest();
};

MultiSplitterTest::MultiSplitterTest()
{
	m_frame = new wxFrame(NULL, wxID_ANY, "MultiSplitter test");

	m_splitter = new MultiSplitter(m_frame);
	m_splitter->SetClientSize(1024, 768);
	
	m_splitter->SetSashSize(5);
}

MultiSplitterTest::~MultiSplitterTest()
{
	m_frame->Destroy();
}

class MultiSplitterTestHorizontalLayout: public MultiSplitterTest
{
protected:
	/* +------------+--------------------------------+
	 * |            | +--------------+-------------+ |
	 * | left_panel | | middle_panel | right_panel | |
	 * |            | +--------------+-------------+ |
	 * +------------+--------------------------------+
	*/
	
	wxPanel *left_panel;
	wxPanel *middle_panel;
	wxPanel *right_panel;
	
	Cell *left_cell;
	Cell *middle_cell;
	Cell *right_cell;
	
public:
	virtual void SetUp() override
	{
		MultiSplitterTest::SetUp();
		
		left_panel = new wxPanel(m_splitter, wxID_ANY);
		middle_panel = new wxPanel(m_splitter, wxID_ANY);
		right_panel = new wxPanel(m_splitter, wxID_ANY);
		
		m_splitter->AddFirst(left_panel);
		m_splitter->AddRightOf(right_panel, left_panel);
		m_splitter->AddLeftOf(middle_panel, right_panel);
		
		/* Make sure the cell hierarchy is set up correctly. */
		
		Cell *cell = get_root_cell();
		
		ASSERT_TRUE(cell->IsVerticalSplit());
		EXPECT_FALSE(cell->IsHorizontalSplit());
		
		left_cell = cell->GetLeftChild();
		ASSERT_TRUE(left_cell->IsWindow());
		ASSERT_EQ(left_cell->GetWindow(), left_panel);
		
		ASSERT_TRUE(cell->GetRightChild()->IsVerticalSplit());
		
		middle_cell = cell->GetRightChild()->GetLeftChild();
		ASSERT_TRUE(middle_cell->IsWindow());
		ASSERT_EQ(middle_cell->GetWindow(), middle_panel);
		
		right_cell = cell->GetRightChild()->GetRightChild();
		ASSERT_TRUE(right_cell->IsWindow());
		ASSERT_EQ(right_cell->GetWindow(), right_panel);
		
		/* Make sure windows are sized/positioned correctly. */
		
		wxRect left_panel_rect = left_panel->GetRect();
		wxRect middle_panel_rect = middle_panel->GetRect();
		wxRect right_panel_rect = right_panel->GetRect();
		
		EXPECT_EQ(left_panel_rect.x, 0);
		EXPECT_EQ(left_panel_rect.y, 0);
		EXPECT_EQ(left_panel_rect.width, 510);
		EXPECT_EQ(left_panel_rect.height, 768);
		
		EXPECT_EQ(middle_panel_rect.x, 515);
		EXPECT_EQ(middle_panel_rect.y, 0);
		EXPECT_EQ(middle_panel_rect.width, 251);
		EXPECT_EQ(middle_panel_rect.height, 768);
		
		EXPECT_EQ(right_panel_rect.x, 771);
		EXPECT_EQ(right_panel_rect.y, 0);
		EXPECT_EQ(right_panel_rect.width, 253);
		EXPECT_EQ(right_panel_rect.height, 768);
	}
};

class MultiSplitterTestVerticalLayout: public MultiSplitterTest
{
protected:
	/* +------------------+
	 * | +--------------+ |
	 * | |  top_panel   | |
	 * | +--------------+ |
	 * | | middle_panel | |
	 * | +--------------+ |
	 * +------------------+
	 * |   bottom_panel   |
	 * +------------------+
	*/
	
	wxPanel *top_panel;
	wxPanel *middle_panel;
	wxPanel *bottom_panel;
	
	Cell *top_cell;
	Cell *middle_cell;
	Cell *bottom_cell;
	
public:
	virtual void SetUp() override
	{
		top_panel = new wxPanel(m_splitter, wxID_ANY);
		middle_panel = new wxPanel(m_splitter, wxID_ANY);
		bottom_panel = new wxPanel(m_splitter, wxID_ANY);
		
		m_splitter->AddFirst(bottom_panel);
		m_splitter->AddAbove(top_panel, bottom_panel);
		m_splitter->AddBelow(middle_panel, top_panel);
		
		/* Make sure the cell hierarchy is set up correctly. */
		
		Cell *cell = get_root_cell();
		
		ASSERT_TRUE(cell->IsHorizontalSplit());
		EXPECT_FALSE(cell->IsVerticalSplit());
		
		bottom_cell = cell->GetBottomChild();
		ASSERT_TRUE(bottom_cell->IsWindow());
		ASSERT_EQ(bottom_cell->GetWindow(), bottom_panel);
		
		ASSERT_TRUE(cell->GetTopChild()->IsHorizontalSplit());
		EXPECT_FALSE(cell->GetTopChild()->IsVerticalSplit());
		
		middle_cell = cell->GetTopChild()->GetBottomChild();
		ASSERT_TRUE(middle_cell->IsWindow());
		ASSERT_EQ(middle_cell->GetWindow(), middle_panel);
		
		top_cell = cell->GetTopChild()->GetTopChild();
		ASSERT_TRUE(top_cell->IsWindow());
		ASSERT_EQ(top_cell->GetWindow(), top_panel);
		
		/* Make sure windows are sized/positioned correctly. */
		
		wxRect top_panel_rect = top_panel->GetRect();
		wxRect middle_panel_rect = middle_panel->GetRect();
		wxRect bottom_panel_rect = bottom_panel->GetRect();
		
		EXPECT_EQ(top_panel_rect.x, 0);
		EXPECT_EQ(top_panel_rect.y, 0);
		EXPECT_EQ(top_panel_rect.width, 1024);
		EXPECT_EQ(top_panel_rect.height, 190);
		
		EXPECT_EQ(middle_panel_rect.x, 0);
		EXPECT_EQ(middle_panel_rect.y, 195);
		EXPECT_EQ(middle_panel_rect.width, 1024);
		EXPECT_EQ(middle_panel_rect.height, 187);
		
		EXPECT_EQ(bottom_panel_rect.x, 0);
		EXPECT_EQ(bottom_panel_rect.y, 387);
		EXPECT_EQ(bottom_panel_rect.width, 1024);
		EXPECT_EQ(bottom_panel_rect.height, 381);
	}
};

TEST_F(MultiSplitterTestHorizontalLayout, NeighborSearch)
{
	/* Test the neighbor search methods. */

	EXPECT_EQ(left_cell->GetLeftNeighbor(), nullptr);
	EXPECT_EQ(left_cell->GetRightNeighbor(), middle_cell->GetParent());
	EXPECT_EQ(left_cell->GetTopNeighbor(), nullptr);
	EXPECT_EQ(left_cell->GetBottomNeighbor(), nullptr);

	EXPECT_EQ(middle_cell->GetLeftNeighbor(), left_cell);
	EXPECT_EQ(middle_cell->GetRightNeighbor(), right_cell);
	EXPECT_EQ(middle_cell->GetTopNeighbor(), nullptr);
	EXPECT_EQ(middle_cell->GetBottomNeighbor(), nullptr);

	EXPECT_EQ(right_cell->GetLeftNeighbor(), middle_cell);
	EXPECT_EQ(right_cell->GetRightNeighbor(), nullptr);
	EXPECT_EQ(right_cell->GetTopNeighbor(), nullptr);
	EXPECT_EQ(right_cell->GetBottomNeighbor(), nullptr);
}

TEST_F(MultiSplitterTestHorizontalLayout, IsXXXOf)
{
	/* Test IsLeftOf() etc methods. */
	
	EXPECT_FALSE(left_cell->IsLeftOf(left_cell));
	EXPECT_TRUE(left_cell->IsLeftOf(middle_cell));
	EXPECT_TRUE(left_cell->IsLeftOf(right_cell));
	
	EXPECT_FALSE(left_cell->IsRightOf(left_cell));
	EXPECT_FALSE(left_cell->IsRightOf(middle_cell));
	EXPECT_FALSE(left_cell->IsRightOf(right_cell));
	
	EXPECT_FALSE(left_cell->IsAbove(left_cell));
	EXPECT_FALSE(left_cell->IsAbove(middle_cell));
	EXPECT_FALSE(left_cell->IsAbove(right_cell));
	
	EXPECT_FALSE(left_cell->IsBelow(left_cell));
	EXPECT_FALSE(left_cell->IsBelow(middle_cell));
	EXPECT_FALSE(left_cell->IsBelow(right_cell));
	
	EXPECT_FALSE(middle_cell->IsLeftOf(left_cell));
	EXPECT_FALSE(middle_cell->IsLeftOf(middle_cell));
	EXPECT_TRUE(middle_cell->IsLeftOf(right_cell));
	
	EXPECT_TRUE(middle_cell->IsRightOf(left_cell));
	EXPECT_FALSE(middle_cell->IsRightOf(middle_cell));
	EXPECT_FALSE(middle_cell->IsRightOf(right_cell));
	
	EXPECT_FALSE(middle_cell->IsAbove(left_cell));
	EXPECT_FALSE(middle_cell->IsAbove(middle_cell));
	EXPECT_FALSE(middle_cell->IsAbove(right_cell));
	
	EXPECT_FALSE(middle_cell->IsBelow(left_cell));
	EXPECT_FALSE(middle_cell->IsBelow(middle_cell));
	EXPECT_FALSE(middle_cell->IsBelow(right_cell));
	
	EXPECT_FALSE(right_cell->IsLeftOf(left_cell));
	EXPECT_FALSE(right_cell->IsLeftOf(middle_cell));
	EXPECT_FALSE(right_cell->IsLeftOf(right_cell));
	
	EXPECT_TRUE(right_cell->IsRightOf(left_cell));
	EXPECT_TRUE(right_cell->IsRightOf(middle_cell));
	EXPECT_FALSE(right_cell->IsRightOf(right_cell));
	
	EXPECT_FALSE(right_cell->IsAbove(left_cell));
	EXPECT_FALSE(right_cell->IsAbove(middle_cell));
	EXPECT_FALSE(right_cell->IsAbove(right_cell));
	
	EXPECT_FALSE(right_cell->IsBelow(left_cell));
	EXPECT_FALSE(right_cell->IsBelow(middle_cell));
	EXPECT_FALSE(right_cell->IsBelow(right_cell));
}

TEST_F(MultiSplitterTestHorizontalLayout, NeighborSearchHidden)
{
	/* Test the neighbor seaarch methods' handling of hidden cells. */
	
	middle_panel->Hide();
	
	EXPECT_EQ(left_cell->GetRightNeighbor(), right_cell->GetParent());
	EXPECT_EQ(right_cell->GetLeftNeighbor(), left_cell);
	
	left_panel->Hide();
	
	EXPECT_EQ(right_cell->GetLeftNeighbor(), nullptr);
	
	left_panel->Show();
	right_panel->Hide();
	
	EXPECT_EQ(left_cell->GetRightNeighbor(), nullptr);
}

TEST_F(MultiSplitterTestVerticalLayout, NeighborSearch)
{
	/* Test the neighbor search methods. */
	
	EXPECT_EQ(top_cell->GetLeftNeighbor(), nullptr);
	EXPECT_EQ(top_cell->GetRightNeighbor(), nullptr);
	EXPECT_EQ(top_cell->GetTopNeighbor(), nullptr);
	EXPECT_EQ(top_cell->GetBottomNeighbor(), middle_cell);

	EXPECT_EQ(middle_cell->GetLeftNeighbor(), nullptr);
	EXPECT_EQ(middle_cell->GetRightNeighbor(), nullptr);
	EXPECT_EQ(middle_cell->GetTopNeighbor(), top_cell);
	EXPECT_EQ(middle_cell->GetBottomNeighbor(), bottom_cell);

	EXPECT_EQ(bottom_cell->GetLeftNeighbor(), nullptr);
	EXPECT_EQ(bottom_cell->GetRightNeighbor(), nullptr);
	EXPECT_EQ(bottom_cell->GetTopNeighbor(), middle_cell->GetParent());
	EXPECT_EQ(bottom_cell->GetBottomNeighbor(), nullptr);
}

TEST_F(MultiSplitterTestVerticalLayout, IsXXXOf)
{
	/* Test IsLeftOf() etc methods. */
	
	EXPECT_FALSE(top_cell->IsLeftOf(top_cell));
	EXPECT_FALSE(top_cell->IsLeftOf(middle_cell));
	EXPECT_FALSE(top_cell->IsLeftOf(bottom_cell));
	
	EXPECT_FALSE(top_cell->IsRightOf(top_cell));
	EXPECT_FALSE(top_cell->IsRightOf(middle_cell));
	EXPECT_FALSE(top_cell->IsRightOf(bottom_cell));
	
	EXPECT_FALSE(top_cell->IsAbove(top_cell));
	EXPECT_TRUE(top_cell->IsAbove(middle_cell));
	EXPECT_TRUE(top_cell->IsAbove(bottom_cell));
	
	EXPECT_FALSE(top_cell->IsBelow(top_cell));
	EXPECT_FALSE(top_cell->IsBelow(middle_cell));
	EXPECT_FALSE(top_cell->IsBelow(bottom_cell));
	
	EXPECT_FALSE(middle_cell->IsLeftOf(top_cell));
	EXPECT_FALSE(middle_cell->IsLeftOf(middle_cell));
	EXPECT_FALSE(middle_cell->IsLeftOf(bottom_cell));
	
	EXPECT_FALSE(middle_cell->IsRightOf(top_cell));
	EXPECT_FALSE(middle_cell->IsRightOf(middle_cell));
	EXPECT_FALSE(middle_cell->IsRightOf(bottom_cell));
	
	EXPECT_FALSE(middle_cell->IsAbove(top_cell));
	EXPECT_FALSE(middle_cell->IsAbove(middle_cell));
	EXPECT_TRUE(middle_cell->IsAbove(bottom_cell));
	
	EXPECT_TRUE(middle_cell->IsBelow(top_cell));
	EXPECT_FALSE(middle_cell->IsBelow(middle_cell));
	EXPECT_FALSE(middle_cell->IsBelow(bottom_cell));
	
	EXPECT_FALSE(bottom_cell->IsLeftOf(top_cell));
	EXPECT_FALSE(bottom_cell->IsLeftOf(middle_cell));
	EXPECT_FALSE(bottom_cell->IsLeftOf(bottom_cell));
	
	EXPECT_FALSE(bottom_cell->IsRightOf(top_cell));
	EXPECT_FALSE(bottom_cell->IsRightOf(middle_cell));
	EXPECT_FALSE(bottom_cell->IsRightOf(bottom_cell));
	
	EXPECT_FALSE(bottom_cell->IsAbove(top_cell));
	EXPECT_FALSE(bottom_cell->IsAbove(middle_cell));
	EXPECT_FALSE(bottom_cell->IsAbove(bottom_cell));
	
	EXPECT_TRUE(bottom_cell->IsBelow(top_cell));
	EXPECT_TRUE(bottom_cell->IsBelow(middle_cell));
	EXPECT_FALSE(bottom_cell->IsBelow(bottom_cell));
}

TEST_F(MultiSplitterTestVerticalLayout, NeighborSearchHidden)
{
	/* Test the neighbor seaarch methods' handling of hidden cells. */
	
	middle_panel->Hide();
	
	EXPECT_EQ(top_cell->GetBottomNeighbor(), bottom_cell);
	EXPECT_EQ(bottom_cell->GetTopNeighbor(), top_cell->GetParent());
	
	top_panel->Hide();
	
	EXPECT_EQ(bottom_cell->GetTopNeighbor(), nullptr);
	
	top_panel->Show();
	bottom_panel->Hide();
	
	EXPECT_EQ(top_cell->GetBottomNeighbor(), nullptr);
}
