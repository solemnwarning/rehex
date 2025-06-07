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
	
	const Cell *left_cell;
	const Cell *middle_cell;
	const Cell *right_cell;
	
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
	
	const Cell *top_cell;
	const Cell *middle_cell;
	const Cell *bottom_cell;
	
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

TEST_F(MultiSplitterTestHorizontalLayout, FindCellByWindow)
{
	EXPECT_EQ(m_splitter->FindCellByWindow(left_panel), left_cell);
	EXPECT_EQ(m_splitter->FindCellByWindow(middle_panel), middle_cell);
	EXPECT_EQ(m_splitter->FindCellByWindow(right_panel), right_cell);
	
	EXPECT_EQ(m_splitter->FindCellByWindow(NULL), nullptr);
	EXPECT_EQ(m_splitter->FindCellByWindow(m_frame), nullptr);
}

TEST_F(MultiSplitterTestHorizontalLayout, FindCellByPoint)
{
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(0, 0)), left_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(511, 0)), left_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(0, 767)), left_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(511, 767)), left_cell);
	
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(512, 0)), middle_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(767, 0)), middle_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(512, 767)), middle_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(767, 767)), middle_cell);
	
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(768, 0)), right_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(1023, 0)), right_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(768, 767)), right_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(1023, 767)), right_cell);
	
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(-1, 0)), nullptr);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(0, -1)), nullptr);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(1024, 0)), nullptr);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(0, 768)), nullptr);
}

TEST_F(MultiSplitterTestHorizontalLayout, FindCellByPointHiddenWindow)
{
	middle_panel->Hide();
	
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(512, 0)), right_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(767, 0)), right_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(512, 767)), right_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(767, 767)), right_cell);
	
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(768, 0)), right_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(1023, 0)), right_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(768, 767)), right_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(1023, 767)), right_cell);
}

TEST_F(MultiSplitterTestHorizontalLayout, GetMinSize)
{
	/* With no minimum sizes set, each cell's minimum size accomodate the sashes. */
	
	left_panel->SetMinSize(wxDefaultSize);
	middle_panel->SetMinSize(wxDefaultSize);
	right_panel->SetMinSize(wxDefaultSize);
	
	EXPECT_EQ(left_cell->GetMinSize(), wxSize(2, 0));
	EXPECT_EQ(middle_cell->GetMinSize(), wxSize(5, 0));
	EXPECT_EQ(right_cell->GetMinSize(), wxSize(3, 0));
	
	EXPECT_EQ(middle_cell->GetParent()->GetMinSize(), wxSize(8, 0));
	EXPECT_EQ(m_splitter->GetRootCell()->GetMinSize(), wxSize(10, 0));
	
	/* Now try with minimum sizes on the windows... */
	
	left_panel->SetMinSize(wxSize(100, 300));
	middle_panel->SetMinSize(wxSize(200, 200));
	right_panel->SetMinSize(wxSize(100, 100));
	
	EXPECT_EQ(left_cell->GetMinSize(), wxSize(102, 300));
	EXPECT_EQ(middle_cell->GetMinSize(), wxSize(205, 200));
	EXPECT_EQ(right_cell->GetMinSize(), wxSize(103, 100));
	
	EXPECT_EQ(middle_cell->GetParent()->GetMinSize(), wxSize(308, 200));
	EXPECT_EQ(m_splitter->GetRootCell()->GetMinSize(), wxSize(410, 300));
	
	/* Check hiding a window takes it out of play. */
	
	middle_panel->Hide();
	
	EXPECT_EQ(left_cell->GetMinSize(), wxSize(102, 300));
	EXPECT_EQ(middle_cell->GetMinSize(), wxSize(0, 0));
	EXPECT_EQ(right_cell->GetMinSize(), wxSize(103, 100));
	
	EXPECT_EQ(middle_cell->GetParent()->GetMinSize(), wxSize(103, 100));
	EXPECT_EQ(m_splitter->GetRootCell()->GetMinSize(), wxSize(205, 300));
}

TEST_F(MultiSplitterTestHorizontalLayout, GetMaxSize)
{
	/* With no maximum sizes set, each cell should have an unlimited max size. */
	
	left_panel->SetMaxSize(wxDefaultSize);
	middle_panel->SetMaxSize(wxDefaultSize);
	right_panel->SetMaxSize(wxDefaultSize);
	
	EXPECT_EQ(left_cell->GetMaxSize(), wxDefaultSize);
	EXPECT_EQ(middle_cell->GetMaxSize(), wxDefaultSize);
	EXPECT_EQ(right_cell->GetMaxSize(), wxDefaultSize);
	
	EXPECT_EQ(middle_cell->GetParent()->GetMaxSize(), wxDefaultSize);
	EXPECT_EQ(m_splitter->GetRootCell()->GetMaxSize(), wxDefaultSize);
	
	/* Now we set a maximum size on two siblings, they have a maximum size of their windows
	 * plus sash, the direct parent has a maximum size of their sum and the root cell only has
	 * to limit size on the non-resizable axis because the remaining unconstrained window can
	 * take any extra height.
	*/
	
	middle_panel->SetMaxSize(wxSize(100, 300));
	right_panel->SetMaxSize(wxSize(200, 200));
	
	EXPECT_EQ(left_cell->GetMaxSize(), wxDefaultSize);
	EXPECT_EQ(middle_cell->GetMaxSize(), wxSize(105, 300));
	EXPECT_EQ(right_cell->GetMaxSize(), wxSize(203, 200));
	
	EXPECT_EQ(middle_cell->GetParent()->GetMaxSize(), wxSize(308, 200));
	EXPECT_EQ(m_splitter->GetRootCell()->GetMaxSize(), wxSize(-1, 200));
	
	/* Constrain the width of the remaining window, the root cell should then have a max size
	 * of all windows and sashes combined but no additional constraint on the width.
	*/
	
	left_panel->SetMaxSize(wxSize(50, -1));
	
	EXPECT_EQ(left_cell->GetMaxSize(), wxSize(52, -1));
	EXPECT_EQ(middle_cell->GetMaxSize(), wxSize(105, 300));
	EXPECT_EQ(right_cell->GetMaxSize(), wxSize(203, 200));
	
	EXPECT_EQ(middle_cell->GetParent()->GetMaxSize(), wxSize(308, 200));
	EXPECT_EQ(m_splitter->GetRootCell()->GetMaxSize(), wxSize(360, 200));
	
	/* Constrain the height of left_panel and unconstrain the height of the others. */
	
	left_panel->SetMaxSize(wxSize(50, 300));
	middle_panel->SetMaxSize(wxSize(100, -1));
	right_panel->SetMaxSize(wxSize(200, -1));
	
	EXPECT_EQ(left_cell->GetMaxSize(), wxSize(52, 300));
	EXPECT_EQ(middle_cell->GetMaxSize(), wxSize(105, -1));
	EXPECT_EQ(right_cell->GetMaxSize(), wxSize(203, -1));
	
	EXPECT_EQ(middle_cell->GetParent()->GetMaxSize(), wxSize(308, -1));
	EXPECT_EQ(m_splitter->GetRootCell()->GetMaxSize(), wxSize(360, 300));
	
	/* Check hiding a window takes it out of play. */
	
	right_panel->Hide();
	
	EXPECT_EQ(left_cell->GetMaxSize(), wxSize(52, 300));
	EXPECT_EQ(middle_cell->GetMaxSize(), wxSize(103, -1));
	EXPECT_EQ(right_cell->GetMaxSize(), wxDefaultSize);
	
	EXPECT_EQ(middle_cell->GetParent()->GetMaxSize(), wxSize(103, -1));
	EXPECT_EQ(m_splitter->GetRootCell()->GetMaxSize(), wxSize(155, 300));
}

TEST_F(MultiSplitterTestHorizontalLayout, ReAddChild)
{
	m_splitter->AddLeftOf(right_panel, left_panel);
	m_splitter->AddRightOf(left_panel, middle_panel);
	
	left_cell = m_splitter->FindCellByWindow(left_panel);
	middle_cell = m_splitter->FindCellByWindow(middle_panel);
	right_cell = m_splitter->FindCellByWindow(right_panel);
	
	/* New layout:
	 *
	 * +-------------+--------------------------------+
	 * |             | +---------------+------------+ |
	 * | right_panel | |  middle_panel | left_panel | |
	 * |             | +---------------+------------+ |
	 * +-------------+--------------------------------+
	*/
	
	const Cell *root = m_splitter->GetRootCell();
	
	EXPECT_EQ(root->GetLeftChild(), right_cell);
	
	ASSERT_NE(root->GetRightChild(), nullptr);
	EXPECT_EQ(root->GetRightChild()->GetLeftChild(), middle_cell);
	EXPECT_EQ(root->GetRightChild()->GetRightChild(), left_cell);
}

TEST_F(MultiSplitterTestHorizontalLayout, ResizeEqualWeights)
{
	m_splitter->SetClientSize(wxSize(724, 384));
	
	EXPECT_EQ(left_cell->GetRect(), wxRect(0, 0, 412, 384));
	EXPECT_EQ(left_panel->GetRect(), wxRect(0, 0, 410, 384));
	
	EXPECT_EQ(middle_cell->GetRect(), wxRect(412, 0, 156, 384));
	EXPECT_EQ(middle_panel->GetRect(), wxRect(415, 0, 151, 384));
	
	EXPECT_EQ(right_cell->GetRect(), wxRect(568, 0, 156, 384));
	EXPECT_EQ(right_panel->GetRect(), wxRect(571, 0, 153, 384));
	
	m_splitter->SetClientSize(wxSize(1024, 768));
	
	EXPECT_EQ(left_cell->GetRect(), wxRect(0, 0, 512, 768));
	EXPECT_EQ(left_panel->GetRect(), wxRect(0, 0, 510, 768));
	
	EXPECT_EQ(middle_cell->GetRect(), wxRect(512, 0, 256, 768));
	EXPECT_EQ(middle_panel->GetRect(), wxRect(515, 0, 251, 768));
	
	EXPECT_EQ(right_cell->GetRect(), wxRect(768, 0, 256, 768));
	EXPECT_EQ(right_panel->GetRect(), wxRect(771, 0, 253, 768));
}

TEST_F(MultiSplitterTestHorizontalLayout, ResizeDifferentWeights)
{
	m_splitter->SetWindowWeight(left_panel, 0.5f);
	m_splitter->SetWindowWeight(middle_panel, 0.5f);
	m_splitter->SetWindowWeight(right_panel, 1.0f);
	
	m_splitter->SetClientSize(wxSize(824, 384));
	
	EXPECT_EQ(left_cell->GetRect(), wxRect(0, 0, 462, 384));
	EXPECT_EQ(left_panel->GetRect(), wxRect(0, 0, 460, 384));
	
	EXPECT_EQ(middle_cell->GetRect(), wxRect(462, 0, 206, 384));
	EXPECT_EQ(middle_panel->GetRect(), wxRect(465, 0, 201, 384));
	
	EXPECT_EQ(right_cell->GetRect(), wxRect(668, 0, 156, 384));
	EXPECT_EQ(right_panel->GetRect(), wxRect(671, 0, 153, 384));
	
	m_splitter->SetClientSize(wxSize(1024, 768));
	
	EXPECT_EQ(left_cell->GetRect(), wxRect(0, 0, 512, 768));
	EXPECT_EQ(left_panel->GetRect(), wxRect(0, 0, 510, 768));
	
	EXPECT_EQ(middle_cell->GetRect(), wxRect(512, 0, 256, 768));
	EXPECT_EQ(middle_panel->GetRect(), wxRect(515, 0, 251, 768));
	
	EXPECT_EQ(right_cell->GetRect(), wxRect(768, 0, 256, 768));
	EXPECT_EQ(right_panel->GetRect(), wxRect(771, 0, 253, 768));
}

TEST_F(MultiSplitterTestHorizontalLayout, ResizeZeroWeights)
{
	m_splitter->SetWindowWeight(left_panel, 0.0f);
	m_splitter->SetWindowWeight(middle_panel, 1.0f);
	m_splitter->SetWindowWeight(right_panel, 1.0f);
	
	m_splitter->SetClientSize(wxSize(824, 384));
	
	EXPECT_EQ(left_cell->GetRect(), wxRect(0, 0, 512, 384));
	EXPECT_EQ(left_panel->GetRect(), wxRect(0, 0, 510, 384));
	
	EXPECT_EQ(middle_cell->GetRect(), wxRect(512, 0, 156, 384));
	EXPECT_EQ(middle_panel->GetRect(), wxRect(515, 0, 151, 384));
	
	EXPECT_EQ(right_cell->GetRect(), wxRect(668, 0, 156, 384));
	EXPECT_EQ(right_panel->GetRect(), wxRect(671, 0, 153, 384));
	
	m_splitter->SetClientSize(wxSize(1024, 768));
	
	EXPECT_EQ(left_cell->GetRect(), wxRect(0, 0, 512, 768));
	EXPECT_EQ(left_panel->GetRect(), wxRect(0, 0, 510, 768));
	
	EXPECT_EQ(middle_cell->GetRect(), wxRect(512, 0, 256, 768));
	EXPECT_EQ(middle_panel->GetRect(), wxRect(515, 0, 251, 768));
	
	EXPECT_EQ(right_cell->GetRect(), wxRect(768, 0, 256, 768));
	EXPECT_EQ(right_panel->GetRect(), wxRect(771, 0, 253, 768));
}

TEST_F(MultiSplitterTestHorizontalLayout, ApplySizeConstraintsNone)
{
	left_panel->SetMinSize(wxDefaultSize);
	left_panel->SetMaxSize(wxDefaultSize);
	
	middle_panel->SetMinSize(wxDefaultSize);
	middle_panel->SetMaxSize(wxDefaultSize);
	
	right_panel->SetMinSize(wxDefaultSize);
	right_panel->SetMaxSize(wxDefaultSize);
	
	m_splitter->ApplySizeConstraints();
	
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

TEST_F(MultiSplitterTestHorizontalLayout, ApplySizeConstraintsMinWidth)
{
	left_panel->SetMinSize(wxSize(600, 1000));
	left_panel->SetMaxSize(wxDefaultSize);
	
	middle_panel->SetMinSize(wxDefaultSize);
	middle_panel->SetMaxSize(wxDefaultSize);
	
	right_panel->SetMinSize(wxSize(300, -1));
	right_panel->SetMaxSize(wxDefaultSize);
	
	m_splitter->ApplySizeConstraints();
	
	wxRect left_panel_rect = left_panel->GetRect();
	wxRect middle_panel_rect = middle_panel->GetRect();
	wxRect right_panel_rect = right_panel->GetRect();
	
	EXPECT_EQ(left_panel_rect.x, 0);
	EXPECT_EQ(left_panel_rect.y, 0);
	EXPECT_EQ(left_panel_rect.width, 600);
	EXPECT_EQ(left_panel_rect.height, 768);
	
	EXPECT_EQ(middle_panel_rect.x, 605);
	EXPECT_EQ(middle_panel_rect.y, 0);
	EXPECT_EQ(middle_panel_rect.width, 114);
	EXPECT_EQ(middle_panel_rect.height, 768);
	
	EXPECT_EQ(right_panel_rect.x, 724);
	EXPECT_EQ(right_panel_rect.y, 0);
	EXPECT_EQ(right_panel_rect.width, 300);
	EXPECT_EQ(right_panel_rect.height, 768);
}

TEST_F(MultiSplitterTestHorizontalLayout, ApplySizeConstraintsMinWidthAlreadySatisfied)
{
	left_panel->SetMinSize(wxSize(200, 1000));
	left_panel->SetMaxSize(wxDefaultSize);
	
	middle_panel->SetMinSize(wxDefaultSize);
	middle_panel->SetMaxSize(wxDefaultSize);
	
	right_panel->SetMinSize(wxSize(100, -1));
	right_panel->SetMaxSize(wxDefaultSize);
	
	m_splitter->ApplySizeConstraints();
	
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

TEST_F(MultiSplitterTestHorizontalLayout, ApplySizeConstraintsMaxWidth)
{
	left_panel->SetMinSize(wxDefaultSize);
	left_panel->SetMaxSize(wxSize(500, 1000));
	
	middle_panel->SetMinSize(wxDefaultSize);
	middle_panel->SetMaxSize(wxDefaultSize);
	
	right_panel->SetMinSize(wxDefaultSize);
	right_panel->SetMaxSize(wxSize(200, -1));
	
	m_splitter->ApplySizeConstraints();
	
	wxRect left_panel_rect = left_panel->GetRect();
	wxRect middle_panel_rect = middle_panel->GetRect();
	wxRect right_panel_rect = right_panel->GetRect();
	
	EXPECT_EQ(left_panel_rect.x, 0);
	EXPECT_EQ(left_panel_rect.y, 0);
	EXPECT_EQ(left_panel_rect.width, 500);
	EXPECT_EQ(left_panel_rect.height, 768);
	
	EXPECT_EQ(middle_panel_rect.x, 505);
	EXPECT_EQ(middle_panel_rect.y, 0);
	EXPECT_EQ(middle_panel_rect.width, 314);
	EXPECT_EQ(middle_panel_rect.height, 768);
	
	EXPECT_EQ(right_panel_rect.x, 824);
	EXPECT_EQ(right_panel_rect.y, 0);
	EXPECT_EQ(right_panel_rect.width, 200);
	EXPECT_EQ(right_panel_rect.height, 768);
}

TEST_F(MultiSplitterTestHorizontalLayout, ApplySizeConstraintsMaxWidthAlreadySatisfied)
{
	left_panel->SetMinSize(wxDefaultSize);
	left_panel->SetMaxSize(wxSize(600, 1000));
	
	middle_panel->SetMinSize(wxDefaultSize);
	middle_panel->SetMaxSize(wxDefaultSize);
	
	right_panel->SetMinSize(wxDefaultSize);
	right_panel->SetMaxSize(wxSize(300, -1));
	
	m_splitter->ApplySizeConstraints();
	
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

TEST_F(MultiSplitterTestVerticalLayout, FindCellByWindow)
{
	EXPECT_EQ(m_splitter->FindCellByWindow(top_panel), top_cell);
	EXPECT_EQ(m_splitter->FindCellByWindow(middle_panel), middle_cell);
	EXPECT_EQ(m_splitter->FindCellByWindow(bottom_panel), bottom_cell);
	
	EXPECT_EQ(m_splitter->FindCellByWindow(NULL), nullptr);
	EXPECT_EQ(m_splitter->FindCellByWindow(m_frame), nullptr);
}

TEST_F(MultiSplitterTestVerticalLayout, FindCellByPoint)
{
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(0, 0)), top_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(1023, 0)), top_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(0, 191)), top_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(1023, 191)), top_cell);
	
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(0, 192)), middle_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(1023, 192)), middle_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(0, 383)), middle_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(1023, 383)), middle_cell);
	
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(0, 384)), bottom_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(1023, 384)), bottom_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(0, 767)), bottom_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(1023, 767)), bottom_cell);
	
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(-1, 0)), nullptr);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(0, -1)), nullptr);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(1024, 0)), nullptr);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(0, 768)), nullptr);
}

TEST_F(MultiSplitterTestVerticalLayout, FindCellByPointHiddenWindow)
{
	bottom_panel->Hide();
	
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(0, 0)), top_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(1023, 0)), top_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(0, 383)), top_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(1023, 383)), top_cell);
	
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(0, 384)), middle_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(1023, 384)), middle_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(0, 767)), middle_cell);
	EXPECT_EQ(m_splitter->FindCellByPoint(wxPoint(1023, 767)), middle_cell);
}

TEST_F(MultiSplitterTestVerticalLayout, GetMinSize)
{
	/* With no minimum sizes set, each cell's minimum size accomodate the sashes. */
	
	top_panel->SetMinSize(wxDefaultSize);
	middle_panel->SetMinSize(wxDefaultSize);
	bottom_panel->SetMinSize(wxDefaultSize);
	
	EXPECT_EQ(top_cell->GetMinSize(), wxSize(0, 2));
	EXPECT_EQ(middle_cell->GetMinSize(), wxSize(0, 5));
	EXPECT_EQ(bottom_cell->GetMinSize(), wxSize(0, 3));
	
	EXPECT_EQ(middle_cell->GetParent()->GetMinSize(), wxSize(0, 7));
	EXPECT_EQ(m_splitter->GetRootCell()->GetMinSize(), wxSize(0, 10));
	
	/* Now try with minimum sizes on the windows... */
	
	top_panel->SetMinSize(wxSize(100, 300));
	middle_panel->SetMinSize(wxSize(200, 200));
	bottom_panel->SetMinSize(wxSize(100, 100));
	
	EXPECT_EQ(top_cell->GetMinSize(), wxSize(100, 302));
	EXPECT_EQ(middle_cell->GetMinSize(), wxSize(200, 205));
	EXPECT_EQ(bottom_cell->GetMinSize(), wxSize(100, 103));
	
	EXPECT_EQ(middle_cell->GetParent()->GetMinSize(), wxSize(200, 507));
	EXPECT_EQ(m_splitter->GetRootCell()->GetMinSize(), wxSize(200, 610));
	
	/* Check hiding a window takes it out of play. */
	
	middle_panel->Hide();
	
	EXPECT_EQ(top_cell->GetMinSize(), wxSize(100, 302));
	EXPECT_EQ(middle_cell->GetMinSize(), wxSize(0, 0));
	EXPECT_EQ(bottom_cell->GetMinSize(), wxSize(100, 103));
	
	EXPECT_EQ(middle_cell->GetParent()->GetMinSize(), wxSize(100, 302));
	EXPECT_EQ(m_splitter->GetRootCell()->GetMinSize(), wxSize(100, 405));
}

TEST_F(MultiSplitterTestVerticalLayout, GetMaxSize)
{
	/* With no maximum sizes set, each cell should have an unlimited max size. */
	
	top_panel->SetMaxSize(wxDefaultSize);
	middle_panel->SetMaxSize(wxDefaultSize);
	bottom_panel->SetMaxSize(wxDefaultSize);
	
	EXPECT_EQ(top_cell->GetMaxSize(), wxDefaultSize);
	EXPECT_EQ(middle_cell->GetMaxSize(), wxDefaultSize);
	EXPECT_EQ(bottom_cell->GetMaxSize(), wxDefaultSize);
	
	EXPECT_EQ(middle_cell->GetParent()->GetMaxSize(), wxDefaultSize);
	EXPECT_EQ(m_splitter->GetRootCell()->GetMaxSize(), wxDefaultSize);
	
	/* Now we set a maximum size on two siblings, they have a maximum size of their windows
	 * plus sash, the direct parent has a maximum size of their sum and the root cell only has
	 * to limit size on the non-resizable axis because the remaining unconstrained window can
	 * take any extra height.
	*/
	
	top_panel->SetMaxSize(wxSize(100, 300));
	middle_panel->SetMaxSize(wxSize(200, 200));
	
	EXPECT_EQ(top_cell->GetMaxSize(), wxSize(100, 302));
	EXPECT_EQ(middle_cell->GetMaxSize(), wxSize(200, 205));
	EXPECT_EQ(bottom_cell->GetMaxSize(), wxDefaultSize);
	
	EXPECT_EQ(middle_cell->GetParent()->GetMaxSize(), wxSize(100, 507));
	EXPECT_EQ(m_splitter->GetRootCell()->GetMaxSize(), wxSize(100, -1));
	
	/* Constrain the height of the remaining window, the root cell should then have a max size
	 * of all windows and sashes combined but no additional constraint on the width.
	*/
	
	bottom_panel->SetMaxSize(wxSize(-1, 50));
	
	EXPECT_EQ(top_cell->GetMaxSize(), wxSize(100, 302));
	EXPECT_EQ(middle_cell->GetMaxSize(), wxSize(200, 205));
	EXPECT_EQ(bottom_cell->GetMaxSize(), wxSize(-1, 53));
	
	EXPECT_EQ(middle_cell->GetParent()->GetMaxSize(), wxSize(100, 507));
	EXPECT_EQ(m_splitter->GetRootCell()->GetMaxSize(), wxSize(100, 560));
	
	/* Constrain the width of bottom_panel and unconstrain the width of the others. */
	
	top_panel->SetMaxSize(wxSize(-1, 300));
	middle_panel->SetMaxSize(wxSize(-1, 200));
	bottom_panel->SetMaxSize(wxSize(60, 50));
	
	EXPECT_EQ(top_cell->GetMaxSize(), wxSize(-1, 302));
	EXPECT_EQ(middle_cell->GetMaxSize(), wxSize(-1, 205));
	EXPECT_EQ(bottom_cell->GetMaxSize(), wxSize(60, 53));
	
	EXPECT_EQ(middle_cell->GetParent()->GetMaxSize(), wxSize(-1, 507));
	EXPECT_EQ(m_splitter->GetRootCell()->GetMaxSize(), wxSize(60, 560));
	
	/* Check hiding a window takes it out of play. */
	
	top_panel->Hide();
	
	EXPECT_EQ(top_cell->GetMaxSize(), wxDefaultSize);
	EXPECT_EQ(middle_cell->GetMaxSize(), wxSize(-1, 202));
	EXPECT_EQ(bottom_cell->GetMaxSize(), wxSize(60, 53));
	
	EXPECT_EQ(middle_cell->GetParent()->GetMaxSize(), wxSize(-1, 202));
	EXPECT_EQ(m_splitter->GetRootCell()->GetMaxSize(), wxSize(60, 255));
}

TEST_F(MultiSplitterTestVerticalLayout, ReAddChild)
{
	m_splitter->AddAbove(middle_panel, top_panel);
	m_splitter->AddBelow(top_panel, bottom_panel);
	
	top_cell = m_splitter->FindCellByWindow(top_panel);
	middle_cell = m_splitter->FindCellByWindow(middle_panel);
	bottom_cell = m_splitter->FindCellByWindow(bottom_panel);
	
	/* New layout:
	 *
	 * +------------------+
	 * |   middle_panel   |
	 * +------------------+
	 * | +--------------+ |
	 * | | bottom_panel | |
	 * | +--------------+ |
	 * | |   top_panel  | |
	 * | +--------------+ |
	 * +------------------+
	*/
	
	const Cell *root = m_splitter->GetRootCell();
	
	EXPECT_EQ(root->GetTopChild(), middle_cell);
	
	ASSERT_NE(root->GetBottomChild(), nullptr);
	EXPECT_EQ(root->GetBottomChild()->GetTopChild(), bottom_cell);
	EXPECT_EQ(root->GetBottomChild()->GetBottomChild(), top_cell);
}

TEST_F(MultiSplitterTestVerticalLayout, ResizeEqualWeights)
{
	m_splitter->SetClientSize(wxSize(1000, 618));
	
	EXPECT_EQ(top_cell->GetRect(), wxRect(0, 0, 1000, 142));
	EXPECT_EQ(top_panel->GetRect(), wxRect(0, 0, 1000, 140));
	
	EXPECT_EQ(middle_cell->GetRect(), wxRect(0, 142, 1000, 142));
	EXPECT_EQ(middle_panel->GetRect(), wxRect(0, 145, 1000, 137));
	
	EXPECT_EQ(bottom_cell->GetRect(), wxRect(0, 284, 1000, 334));
	EXPECT_EQ(bottom_panel->GetRect(), wxRect(0, 287, 1000, 331));
	
	m_splitter->SetClientSize(wxSize(1024, 768));
	
	EXPECT_EQ(top_cell->GetRect(), wxRect(0, 0, 1024, 192));
	EXPECT_EQ(top_panel->GetRect(), wxRect(0, 0, 1024, 190));
	
	EXPECT_EQ(middle_cell->GetRect(), wxRect(0, 192, 1024, 192));
	EXPECT_EQ(middle_panel->GetRect(), wxRect(0, 195, 1024, 187));
	
	EXPECT_EQ(bottom_cell->GetRect(), wxRect(0, 384, 1024, 384));
	EXPECT_EQ(bottom_panel->GetRect(), wxRect(0, 387, 1024, 381));
}

TEST_F(MultiSplitterTestVerticalLayout, ResizeDifferentWeights)
{
	m_splitter->SetWindowWeight(top_panel, 0.5f);
	m_splitter->SetWindowWeight(middle_panel, 0.5f);
	m_splitter->SetWindowWeight(bottom_panel, 1.0f);
	
	m_splitter->SetClientSize(wxSize(1000, 568));
	
	EXPECT_EQ(top_cell->GetRect(), wxRect(0, 0, 1000, 142));
	EXPECT_EQ(top_panel->GetRect(), wxRect(0, 0, 1000, 140));
	
	EXPECT_EQ(middle_cell->GetRect(), wxRect(0, 142, 1000, 142));
	EXPECT_EQ(middle_panel->GetRect(), wxRect(0, 145, 1000, 137));
	
	EXPECT_EQ(bottom_cell->GetRect(), wxRect(0, 284, 1000, 284));
	EXPECT_EQ(bottom_panel->GetRect(), wxRect(0, 287, 1000, 281));
	
	m_splitter->SetClientSize(wxSize(1024, 768));
	
	EXPECT_EQ(top_cell->GetRect(), wxRect(0, 0, 1024, 192));
	EXPECT_EQ(top_panel->GetRect(), wxRect(0, 0, 1024, 190));
	
	EXPECT_EQ(middle_cell->GetRect(), wxRect(0, 192, 1024, 192));
	EXPECT_EQ(middle_panel->GetRect(), wxRect(0, 195, 1024, 187));
	
	EXPECT_EQ(bottom_cell->GetRect(), wxRect(0, 384, 1024, 384));
	EXPECT_EQ(bottom_panel->GetRect(), wxRect(0, 387, 1024, 381));
}

TEST_F(MultiSplitterTestVerticalLayout, ResizeZeroWeights)
{
	m_splitter->SetWindowWeight(top_panel, 0.0f);
	m_splitter->SetWindowWeight(middle_panel, 1.0f);
	m_splitter->SetWindowWeight(bottom_panel, 1.0f);
	
	m_splitter->SetClientSize(wxSize(1000, 600));
	
	EXPECT_EQ(top_cell->GetRect(), wxRect(0, 0, 1000, 192));
	EXPECT_EQ(top_panel->GetRect(), wxRect(0, 0, 1000, 190));
	
	EXPECT_EQ(middle_cell->GetRect(), wxRect(0, 192, 1000, 108));
	EXPECT_EQ(middle_panel->GetRect(), wxRect(0, 195, 1000, 103));
	
	EXPECT_EQ(bottom_cell->GetRect(), wxRect(0, 300, 1000, 300));
	EXPECT_EQ(bottom_panel->GetRect(), wxRect(0, 303, 1000, 297));
	
	m_splitter->SetClientSize(wxSize(1024, 768));
	
	EXPECT_EQ(top_cell->GetRect(), wxRect(0, 0, 1024, 192));
	EXPECT_EQ(top_panel->GetRect(), wxRect(0, 0, 1024, 190));
	
	EXPECT_EQ(middle_cell->GetRect(), wxRect(0, 192, 1024, 192));
	EXPECT_EQ(middle_panel->GetRect(), wxRect(0, 195, 1024, 187));
	
	EXPECT_EQ(bottom_cell->GetRect(), wxRect(0, 384, 1024, 384));
	EXPECT_EQ(bottom_panel->GetRect(), wxRect(0, 387, 1024, 381));
}

TEST_F(MultiSplitterTestVerticalLayout, ApplySizeConstraintsNone)
{
	top_panel->SetMinSize(wxDefaultSize);
	top_panel->SetMaxSize(wxDefaultSize);
	
	middle_panel->SetMinSize(wxDefaultSize);
	middle_panel->SetMaxSize(wxDefaultSize);
	
	bottom_panel->SetMinSize(wxDefaultSize);
	bottom_panel->SetMaxSize(wxDefaultSize);
	
	m_splitter->ApplySizeConstraints();
	
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

TEST_F(MultiSplitterTestVerticalLayout, ApplySizeConstraintsMinHeight)
{
	top_panel->SetMinSize(wxSize(1000, 250));
	top_panel->SetMaxSize(wxDefaultSize);
	
	middle_panel->SetMinSize(wxDefaultSize);
	middle_panel->SetMaxSize(wxDefaultSize);
	
	bottom_panel->SetMinSize(wxSize(-1, 400));
	bottom_panel->SetMaxSize(wxDefaultSize);
	
	m_splitter->ApplySizeConstraints();
	
	wxRect top_panel_rect = top_panel->GetRect();
	wxRect middle_panel_rect = middle_panel->GetRect();
	wxRect bottom_panel_rect = bottom_panel->GetRect();
	
	EXPECT_EQ(top_panel_rect.x, 0);
	EXPECT_EQ(top_panel_rect.y, 0);
	EXPECT_EQ(top_panel_rect.width, 1024);
	EXPECT_EQ(top_panel_rect.height, 250);
	
	EXPECT_EQ(middle_panel_rect.x, 0);
	EXPECT_EQ(middle_panel_rect.y, 255);
	EXPECT_EQ(middle_panel_rect.width, 1024);
	EXPECT_EQ(middle_panel_rect.height, 108);
	
	EXPECT_EQ(bottom_panel_rect.x, 0);
	EXPECT_EQ(bottom_panel_rect.y, 368);
	EXPECT_EQ(bottom_panel_rect.width, 1024);
	EXPECT_EQ(bottom_panel_rect.height, 400);
}

TEST_F(MultiSplitterTestVerticalLayout, ApplySizeConstraintsMinHeightAlreadySatisfied)
{
	top_panel->SetMinSize(wxSize(1000, 180));
	top_panel->SetMaxSize(wxDefaultSize);
	
	middle_panel->SetMinSize(wxDefaultSize);
	middle_panel->SetMaxSize(wxDefaultSize);
	
	bottom_panel->SetMinSize(wxSize(-1, 200));
	bottom_panel->SetMaxSize(wxDefaultSize);
	
	m_splitter->ApplySizeConstraints();
	
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

TEST_F(MultiSplitterTestVerticalLayout, ApplySizeConstraintsMaxHeight)
{
	top_panel->SetMinSize(wxDefaultSize);
	top_panel->SetMaxSize(wxSize(1000, 170));
	
	middle_panel->SetMinSize(wxDefaultSize);
	middle_panel->SetMaxSize(wxDefaultSize);
	
	bottom_panel->SetMinSize(wxDefaultSize);
	bottom_panel->SetMaxSize(wxSize(-1, 350));
	
	m_splitter->ApplySizeConstraints();
	
	wxRect top_panel_rect = top_panel->GetRect();
	wxRect middle_panel_rect = middle_panel->GetRect();
	wxRect bottom_panel_rect = bottom_panel->GetRect();
	
	EXPECT_EQ(top_panel_rect.x, 0);
	EXPECT_EQ(top_panel_rect.y, 0);
	EXPECT_EQ(top_panel_rect.width, 1024);
	EXPECT_EQ(top_panel_rect.height, 170);
	
	EXPECT_EQ(middle_panel_rect.x, 0);
	EXPECT_EQ(middle_panel_rect.y, 175);
	EXPECT_EQ(middle_panel_rect.width, 1024);
	EXPECT_EQ(middle_panel_rect.height, 238);
	
	EXPECT_EQ(bottom_panel_rect.x, 0);
	EXPECT_EQ(bottom_panel_rect.y, 418);
	EXPECT_EQ(bottom_panel_rect.width, 1024);
	EXPECT_EQ(bottom_panel_rect.height, 350);
}

TEST_F(MultiSplitterTestVerticalLayout, ApplySizeConstraintsMaxHeightAlreadySatisfied)
{
	top_panel->SetMinSize(wxDefaultSize);
	top_panel->SetMaxSize(wxSize(1000, 200));
	
	middle_panel->SetMinSize(wxDefaultSize);
	middle_panel->SetMaxSize(wxDefaultSize);
	
	bottom_panel->SetMinSize(wxDefaultSize);
	bottom_panel->SetMaxSize(wxSize(-1, 400));
	
	m_splitter->ApplySizeConstraints();
	
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
