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

#include "platform.hpp"

#include <assert.h>
#include <functional>
#include <math.h>
#include <wx/dcclient.h>
#include <wx/debug.h>
#include <wx/renderer.h>
#include <wx/settings.h>

#include "MultiSplitter.hpp"

BEGIN_EVENT_TABLE(REHex::MultiSplitter, wxWindow)
	EVT_SIZE(REHex::MultiSplitter::OnSize)
	EVT_ENTER_WINDOW(REHex::MultiSplitter::OnMouseEnter)
	EVT_LEAVE_WINDOW(REHex::MultiSplitter::OnMouseLeave)
	EVT_MOTION(REHex::MultiSplitter::OnMouseMotion)
	EVT_LEFT_DOWN(REHex::MultiSplitter::OnMouseLeftDown)
	EVT_LEFT_UP(REHex::MultiSplitter::OnMouseLeftUp)
	EVT_MOUSE_CAPTURE_LOST(REHex::MultiSplitter::OnMouseCaptureLost)
END_EVENT_TABLE()

REHex::MultiSplitter::MultiSplitter(wxWindow *parent):
	wxWindow(parent, wxID_ANY),
	m_sash_size(GetDefaultSashSize()),
	m_resizing(false) {}

REHex::MultiSplitter::~MultiSplitter()
{
	RemoveAllChildren();
}

void REHex::MultiSplitter::AddFirst(wxWindow *window)
{
	wxASSERT_MSG((window->GetParent() == this), "Windows added to a MultiSplitter must be direct children");
	
	assert(!m_cells);
	m_cells.reset(new Cell(this, NULL, window));
	
	m_cells->Resize(GetClientSize());
	
	window->Bind(wxEVT_SHOW, &REHex::MultiSplitter::OnChildShowHide, this);
}

void REHex::MultiSplitter::AddLeftOf(wxWindow *window, wxWindow *base)
{
	wxASSERT_MSG((window->GetParent() == this), "Windows added to a MultiSplitter must be direct children");
	wxASSERT_MSG((window != base), "window and base passed to REHex::MultiSplitter::AddLeftOf() must be different windows");
	
	Cell *base_cell = FindCellByWindow(base);
	wxASSERT_MSG((base_cell != NULL), "Base window passed to REHex::MultiSplitter::AddLeftOf() has not been added to MultiSplitter");
	
	Cell *window_cell = FindCellByWindow(window);
	assert(window_cell == NULL || window_cell != base_cell);
	
	if(window_cell != NULL)
	{
		/* Window is already in the splitter, remove it from its previous position. */
		
		Cell *window_parent_cell = window_cell->GetParent();
		assert(window_parent_cell != NULL);
		
		window_parent_cell->RemoveChild(window);
		
		/* base_cell may be invalid now. */
		base_cell = FindCellByWindow(base);
		assert(base_cell != NULL);
	}
	
	base_cell->SplitVertically(window, base);
	
	if(window_cell == NULL)
	{
		window->Bind(wxEVT_SHOW, &REHex::MultiSplitter::OnChildShowHide, this);
	}
}

void REHex::MultiSplitter::AddRightOf(wxWindow *window, wxWindow *base)
{
	wxASSERT_MSG((window->GetParent() == this), "Windows added to a MultiSplitter must be direct children");
	wxASSERT_MSG((window != base), "window and base passed to REHex::MultiSplitter::AddRightOf() must be different windows");
	
	Cell *base_cell = FindCellByWindow(base);
	wxASSERT_MSG((base_cell != NULL), "Base window passed to REHex::MultiSplitter::AddRightOf() has not been added to MultiSplitter");
	
	Cell *window_cell = FindCellByWindow(window);
	assert(window_cell == NULL || window_cell != base_cell);
	
	if(window_cell != NULL)
	{
		/* Window is already in the splitter, remove it from its previous position. */
		
		Cell *window_parent_cell = window_cell->GetParent();
		assert(window_parent_cell != NULL);
		
		window_parent_cell->RemoveChild(window);
		
		/* base_cell may be invalid now. */
		base_cell = FindCellByWindow(base);
		assert(base_cell != NULL);
	}
	
	base_cell->SplitVertically(base, window);
	
	if(window_cell == NULL)
	{
		window->Bind(wxEVT_SHOW, &REHex::MultiSplitter::OnChildShowHide, this);
	}
}

void REHex::MultiSplitter::AddAbove(wxWindow *window, wxWindow *base)
{
	wxASSERT_MSG((window->GetParent() == this), "Windows added to a MultiSplitter must be direct children");
	wxASSERT_MSG((window != base), "window and base passed to REHex::MultiSplitter::AddAbove() must be different windows");
	
	Cell *base_cell = FindCellByWindow(base);
	wxASSERT_MSG((base_cell != NULL), "Base window passed to REHex::MultiSplitter::AddAbove() has not been added to MultiSplitter");
	
	Cell *window_cell = FindCellByWindow(window);
	assert(window_cell == NULL || window_cell != base_cell);
	
	if(window_cell != NULL)
	{
		/* Window is already in the splitter, remove it from its previous position. */
		
		Cell *window_parent_cell = window_cell->GetParent();
		assert(window_parent_cell != NULL);
		
		window_parent_cell->RemoveChild(window);
		
		/* base_cell may be invalid now. */
		base_cell = FindCellByWindow(base);
		assert(base_cell != NULL);
	}
	
	base_cell->SplitHorizontally(window, base);
	
	if(window_cell == NULL)
	{
		window->Bind(wxEVT_SHOW, &REHex::MultiSplitter::OnChildShowHide, this);
	}
}

void REHex::MultiSplitter::AddBelow(wxWindow *window, wxWindow *base)
{
	wxASSERT_MSG((window->GetParent() == this), "Windows added to a MultiSplitter must be direct children");
	wxASSERT_MSG((window != base), "window and base passed to REHex::MultiSplitter::AddBelow() must be different windows");
	
	Cell *base_cell = FindCellByWindow(base);
	wxASSERT_MSG((base_cell != NULL), "Base window passed to REHex::MultiSplitter::AddBelow() has not been added to MultiSplitter");
	
	Cell *window_cell = FindCellByWindow(window);
	assert(window_cell == NULL || window_cell != base_cell);
	
	if(window_cell != NULL)
	{
		/* Window is already in the splitter, remove it from its previous position. */
		
		Cell *window_parent_cell = window_cell->GetParent();
		assert(window_parent_cell != NULL);
		
		window_parent_cell->RemoveChild(window);
		
		/* base_cell may be invalid now. */
		base_cell = FindCellByWindow(base);
		assert(base_cell != NULL);
	}
	
	base_cell->SplitHorizontally(base, window);
	
	if(window_cell == NULL)
	{
		window->Bind(wxEVT_SHOW, &REHex::MultiSplitter::OnChildShowHide, this);
	}
}

void REHex::MultiSplitter::RemoveChild(wxWindow *window)
{
	Cell *cell = FindCellByWindow(window);
	wxASSERT_MSG((cell != NULL), "Unknown window passed to REHex::MultiSplitter::RemoveChild()");
	
	if(cell != NULL)
	{
		window->Unbind(wxEVT_SHOW, &REHex::MultiSplitter::OnChildShowHide, this);
		
		if(cell == m_cells.get())
		{
			m_cells.reset();
		}
		else{
			cell->GetParent()->RemoveChild(window);
		}
	}
}

void REHex::MultiSplitter::RemoveAllChildren()
{
	std::function<void(Cell*)> f;
	f = [&](Cell *cell)
	{
		if(cell != NULL)
		{
			if(cell->IsWindow())
			{
				cell->GetWindow()->Unbind(wxEVT_SHOW, &REHex::MultiSplitter::OnChildShowHide, this);
			}

			f(cell->GetLeftChild());
			f(cell->GetRightChild());
			f(cell->GetTopChild());
			f(cell->GetBottomChild());
		}
	};

	f(m_cells.get());
	m_cells.reset();
}

void REHex::MultiSplitter::DestroyChild(wxWindow *window)
{
	RemoveChild(window);
	window->Destroy();
}

wxWindow *REHex::MultiSplitter::FindChildByPoint(const wxPoint &point)
{
	Cell *cell = FindCellByPoint(point);
	return cell != NULL ? cell->GetWindow() : NULL;
}

void REHex::MultiSplitter::SetWindowWeight(wxWindow *window, float weight)
{
	Cell *cell = FindCellByWindow(window);
	assert(cell != NULL);
	
	cell->SetWeight(weight);
}

void REHex::MultiSplitter::SetWindowSize(wxWindow *window, const wxSize &size)
{
	Cell *cell = FindCellByWindow(window);
	assert(cell != NULL);
	
	int sash_size1 = m_sash_size / 2;
	int sash_size2 = (m_sash_size / 2) + (m_sash_size % 2);
	
	if(size.GetWidth() >= 0)
	{
		Cell *vsplit;
		bool child_is_right;
		
		std::tie(vsplit, child_is_right) = cell->FindVerticalSplitAncestor();
		
		if(vsplit != NULL)
		{
			wxRect vsplit_rect = vsplit->GetRect();
			int cell_width = size.GetWidth();

			if(cell->GetLeftNeighbor() != NULL)
			{
				cell_width += sash_size2;
			}

			if(cell->GetRightNeighbor() != NULL)
			{
				cell_width += sash_size1;
			}
			
			if(child_is_right)
			{
				vsplit->MoveSplitter(wxPoint((vsplit_rect.x + vsplit_rect.GetWidth() - cell_width), 0));
			}
			else{
				vsplit->MoveSplitter(wxPoint((vsplit_rect.x + cell_width), 0));
			}
		}
	}
	
	if(size.GetHeight() >= 0)
	{
		Cell *hsplit;
		bool child_is_bottom;
		
		std::tie(hsplit, child_is_bottom) = cell->FindHorizontalSplitAncestor();
		
		if(hsplit != NULL)
		{
			wxRect hsplit_rect = hsplit->GetRect();
			int cell_height = size.GetHeight();
			
			if(cell->GetTopNeighbor())
			{
				cell_height += sash_size2;
			}

			if(cell->GetBottomNeighbor() != NULL)
			{
				cell_height += sash_size1;
			}

			if(child_is_bottom)
			{
				hsplit->MoveSplitter(wxPoint(0, (hsplit_rect.y + hsplit_rect.GetHeight() - cell_height)));
			}
			else{
				hsplit->MoveSplitter(wxPoint(0, (hsplit_rect.y + cell_height)));
			}
		}
	}
}

int REHex::MultiSplitter::GetDefaultSashSize() const
{
	wxRendererNative &renderer = wxRendererNative::Get();
	return renderer.GetSplitterParams(this).widthSash;
}

int REHex::MultiSplitter::GetSashSize() const
{
	return m_sash_size;
}

void REHex::MultiSplitter::SetSashSize(int sash_size)
{
	m_sash_size = sash_size;

	if(m_cells)
	{
		wxSize client_size = GetClientSize();
		m_cells->Resize(wxRect(0, 0, client_size.GetWidth(), client_size.GetHeight()));
	}
}

REHex::MultiSplitter::Cell *REHex::MultiSplitter::FindCellByWindow(wxWindow *window)
{
	std::function<Cell*(Cell*)> f;
	f = [&](Cell *cell)
	{
		if(cell == NULL)
		{
			return (Cell*)(NULL);
		}
		
		if(cell->GetWindow() == window)
		{
			return cell;
		}
		
		Cell *c = f(cell->GetLeftChild());
		if(c != NULL) return c;
		
		c = f(cell->GetRightChild());
		if(c != NULL) return c;
		
		c = f(cell->GetTopChild());
		if(c != NULL) return c;
		
		c = f(cell->GetBottomChild());
		if(c != NULL) return c;
		
		return (Cell*)(NULL);
	};
	
	return f(m_cells.get());
}

REHex::MultiSplitter::Cell *REHex::MultiSplitter::FindCellByPoint(const wxPoint &point)
{
	std::function<Cell*(Cell*)> f;
	f = [&](Cell *cell)
	{
		if(cell == NULL)
		{
			return (Cell*)(NULL);
		}
		
		if(!cell->GetRect().Contains(point))
		{
			return (Cell*)(NULL);
		}
		
		if(cell->GetWindow() != NULL)
		{
			return cell;
		}
		
		Cell *c = f(cell->GetLeftChild());
		if(c != NULL) return c;
		
		c = f(cell->GetRightChild());
		if(c != NULL) return c;
		
		c = f(cell->GetTopChild());
		if(c != NULL) return c;
		
		c = f(cell->GetBottomChild());
		if(c != NULL) return c;
		
		return (Cell*)(NULL);
	};
	
	return f(m_cells.get());
}

void REHex::MultiSplitter::OnSize(wxSizeEvent &event)
{
	if(m_cells)
	{
		wxSize client_size = GetClientSize();
		m_cells->Resize(wxRect(0, 0, client_size.GetWidth(), client_size.GetHeight()));
	}
}

void REHex::MultiSplitter::OnMouseEnter(wxMouseEvent &event) {}

void REHex::MultiSplitter::OnMouseLeave(wxMouseEvent &event)
{
	SetCursor(wxNullCursor);
}

void REHex::MultiSplitter::OnMouseMotion(wxMouseEvent &event)
{
	if(m_resizing)
	{
		switch(m_resizing_edge)
		{
			case CellEdge::LEFT:
			case CellEdge::RIGHT:
			{
				Cell *common_ancestor = m_resizing_edge == CellEdge::LEFT
					? Cell::FindCommonAncestor(m_resizing_cell, m_resizing_cell->GetLeftNeighbor())
					: Cell::FindCommonAncestor(m_resizing_cell, m_resizing_cell->GetRightNeighbor());
				
				assert(common_ancestor != NULL);
				
				REHex::MultiSplitterResizeBias a(common_ancestor->GetLeftChild(), CellEdge::RIGHT);
				REHex::MultiSplitterResizeBias b(common_ancestor->GetRightChild(), CellEdge::LEFT);
				
				common_ancestor->MoveSplitter(event.GetPosition());
				
				break;
			}
			
			case CellEdge::TOP:
			case CellEdge::BOTTOM:
			{
				Cell *common_ancestor = m_resizing_edge == CellEdge::TOP
					? Cell::FindCommonAncestor(m_resizing_cell, m_resizing_cell->GetTopNeighbor())
					: Cell::FindCommonAncestor(m_resizing_cell, m_resizing_cell->GetBottomNeighbor());
				
				assert(common_ancestor != NULL);
				
				REHex::MultiSplitterResizeBias a(common_ancestor->GetTopChild(), CellEdge::BOTTOM);
				REHex::MultiSplitterResizeBias b(common_ancestor->GetBottomChild(), CellEdge::TOP);
				
				common_ancestor->MoveSplitter(event.GetPosition());
				
				break;
			}
			
			case CellEdge::NONE:
				abort(); /* Unreachable. */
		}
	}
	else{
		Cell *cell = FindCellByPoint(event.GetPosition());
		
		wxCursor cursor = wxNullCursor;
		
		if(cell != NULL)
		{
			auto e = cell->GetPointEdge(event.GetPosition());
			
			if((e.first == CellEdge::LEFT && cell->GetLeftNeighbor() != NULL)
				|| (e.first == CellEdge::RIGHT && cell->GetRightNeighbor() != NULL))
			{
				cursor = wxCursor(wxCURSOR_SIZEWE);
			}
			else if((e.first == CellEdge::TOP && cell->GetTopNeighbor() != NULL)
				|| (e.first == CellEdge::BOTTOM && cell->GetBottomNeighbor() != NULL))
			{
				cursor = wxCursor(wxCURSOR_SIZENS);
			}
		}
		
		SetCursor(cursor);
	}
}

void REHex::MultiSplitter::OnMouseLeftDown(wxMouseEvent &event)
{
	Cell *cell = FindCellByPoint(event.GetPosition());
	assert(cell != NULL);
	
	if(cell != NULL)
	{
		auto e = cell->GetPointEdge(event.GetPosition());
		
		if((e.first == CellEdge::LEFT && cell->GetLeftNeighbor() != NULL)
			|| (e.first == CellEdge::RIGHT && cell->GetRightNeighbor() != NULL)
			|| (e.first == CellEdge::TOP && cell->GetTopNeighbor() != NULL)
			|| (e.first == CellEdge::BOTTOM && cell->GetBottomNeighbor() != NULL))
		{
			m_resizing_cell = cell;
			m_resizing_edge = e.first;
			m_resizing = true;
			
			CaptureMouse();
		}
	}
	
	event.Skip();
}

void REHex::MultiSplitter::OnMouseLeftUp(wxMouseEvent &event)
{
	if(m_resizing)
	{
		ReleaseMouse();
		m_resizing = false;
	}
}

void REHex::MultiSplitter::OnMouseCaptureLost(wxMouseCaptureLostEvent &event)
{
	m_resizing = false;
}

void REHex::MultiSplitter::OnChildShowHide(wxShowEvent &event)
{
	m_cells->Resize(GetClientSize());
	event.Skip();
}

REHex::MultiSplitter::Cell::Cell(const MultiSplitter *splitter, Cell *parent, wxWindow *window):
	m_splitter(splitter),
	m_parent(parent),
	m_weight(1.0f),
	m_window(window) {}

void REHex::MultiSplitter::Cell::SetWeight(float weight)
{
	m_weight = weight;
}

float REHex::MultiSplitter::Cell::GetWeight() const
{
	return m_weight;
}

float REHex::MultiSplitter::Cell::GetHorizontalWeight() const
{
	if(IsVerticalSplit())
	{
		return m_left->GetHorizontalWeight() + m_right->GetHorizontalWeight();
	}
	else if(IsHorizontalSplit())
	{
		return std::max(m_top->GetHorizontalWeight(), m_bottom->GetHorizontalWeight());
	}
	else{
		return m_weight;
	}
}

float REHex::MultiSplitter::Cell::GetVerticalWeight() const
{
	if(IsVerticalSplit())
	{
		return std::max(m_left->GetVerticalWeight(), m_right->GetVerticalWeight());
	}
	else if(IsHorizontalSplit())
	{
		return m_top->GetVerticalWeight() + m_bottom->GetVerticalWeight();
	}
	else{
		return m_weight;
	}
}

void REHex::MultiSplitter::Cell::Resize(const wxRect &new_rect)
{
	wxRect old_rect = m_rect;
	m_rect = new_rect;
	
	if(IsVerticalSplit())
	{
		if(m_left->IsHidden())
		{
			m_right->Resize(m_rect);
			m_hidden_lt = true;
		}
		else if(m_right->IsHidden())
		{
			m_left->Resize(m_rect);
			m_hidden_rb = true;
		}
		else if(m_hidden_lt)
		{
			/* Window in left chid was hidden but has been shown, restore its previous
			 * width and give the rest of the space to the right cell.
			*/
			
			int l_width = m_left->GetRect().width;
			int r_width = m_rect.width - l_width;
			
			m_left->Resize(wxRect(m_rect.x, m_rect.y, l_width, m_rect.height));
			m_right->Resize(wxRect((m_rect.x + l_width), m_rect.y, r_width, m_rect.height));
			
			m_hidden_lt = false;
		}
		else if(m_hidden_rb)
		{
			/* Window in right child was hidden but has been shown, restore its
			 * previous width and give the rest of the space to the left cell.
			*/
			
			int r_width = m_right->GetRect().width;
			int l_width = m_rect.width - r_width;
			
			m_left->Resize(wxRect(m_rect.x, m_rect.y, l_width, m_rect.height));
			m_right->Resize(wxRect((m_rect.x + l_width), m_rect.y, r_width, m_rect.height));
			
			m_hidden_rb = false;
		}
		else{
			float l_weight = m_left->GetHorizontalWeight();
			float r_weight = m_right->GetHorizontalWeight();
			
			int delta = new_rect.width - old_rect.width;
			
			int l_width = m_left->GetRect().width;
			int r_width = m_right->GetRect().width;
			
			CalculateResize(&l_width, &r_width, l_weight, r_weight, delta, new_rect.width);
			
			m_left->Resize(wxRect(m_rect.x, m_rect.y, l_width, m_rect.height));
			m_right->Resize(wxRect((m_rect.x + l_width), m_rect.y, r_width, m_rect.height));
		}
	}
	else if(IsHorizontalSplit())
	{
		if(m_top->IsHidden())
		{
			m_bottom->Resize(m_rect);
			m_hidden_lt = true;
		}
		else if(m_bottom->IsHidden())
		{
			m_top->Resize(m_rect);
			m_hidden_rb = true;
		}
		else if(m_hidden_lt)
		{
			/* Window in top child was hidden but has been shown, restore its previous
			 * height and give the rest of the space to the bottom cell.
			*/
			
			int t_height = m_top->GetRect().height;
			int b_height = m_rect.height - t_height;
			
			m_top->Resize(wxRect(m_rect.x, m_rect.y, m_rect.width, t_height));
			m_bottom->Resize(wxRect(m_rect.x, (m_rect.y + t_height), m_rect.width, b_height));
			
			m_hidden_lt = false;
		}
		else if(m_hidden_rb)
		{
			/* Window in bottom child was hidden but has now been shown, restore its
			 * previous height and give the rest of the space to the top cell.
			*/
			
			int b_height = m_bottom->GetRect().height;
			int t_height = m_rect.height - b_height;
			
			m_top->Resize(wxRect(m_rect.x, m_rect.y, m_rect.width, t_height));
			m_bottom->Resize(wxRect(m_rect.x, (m_rect.y + t_height), m_rect.width, b_height));
			
			m_hidden_rb = false;
		}
		else{
			float t_weight = m_top->GetVerticalWeight();
			float b_weight = m_bottom->GetVerticalWeight();
			
			int delta = new_rect.height - old_rect.height;
			
			int t_height = m_top->GetRect().height;
			int b_height = m_bottom->GetRect().height;
			
			CalculateResize(&t_height, &b_height, t_weight, b_weight, delta, new_rect.height);
			
			m_top->Resize(wxRect(m_rect.x, m_rect.y, m_rect.width, t_height));
			m_bottom->Resize(wxRect(m_rect.x, (m_rect.y + t_height), m_rect.width, b_height));
		}
	}
	else{
		assert(m_window != NULL);
		
		ResizeWindow();
	}
}

void REHex::MultiSplitter::Cell::CalculateResize(int *size_lt, int *size_rb, float weight_lt, float weight_rb, int delta, int target)
{
	/* Avoid division by zero when both cells have a zero weight. */
	if(weight_lt == 0.0f && weight_rb == 0.0f)
	{
		weight_lt = 1.0f;
		weight_rb = 1.0f;
	}
	
	/* Calculate how much to grow/shrink each child by. */
	
	float lt_adj = ((float)(delta) / (weight_lt + weight_rb)) * weight_lt;
	float rb_adj = ((float)(delta) / (weight_lt + weight_rb)) * weight_rb;
	
	assert(!isnan(lt_adj));
	assert(!isnan(rb_adj));
	
	/* Subtract any growth previously applied to fill space. */
	
	*size_lt -= m_growth_bank_lt;
	m_growth_bank_lt = 0;
	
	*size_rb -= m_growth_bank_rb;
	m_growth_bank_rb = 0;
	
	/* Use up any banked adjustments from previous resizes first.
	 * This is to ensure that repeated small adjustments don't unfairly bias one side
	 * of the splitter.
	*/
	
	if((m_resize_bank_lt >= 1.0f && delta >= 1) || (m_resize_bank_lt <= -1.0f && delta <= -1))
	{
		float f = std::min(floorf(m_resize_bank_lt), lt_adj);
		
		*size_lt += f;
		lt_adj -= f;
		m_resize_bank_lt -= f;
	}
	
	if((m_resize_bank_rb >= 1.0f && delta >= 1) || (m_resize_bank_rb <= -1.0f && delta <= -1))
	{
		float f = std::min(floorf(m_resize_bank_rb), rb_adj);
		
		*size_rb += f;
		rb_adj -= f;
		m_resize_bank_rb -= f;
	}
	
	/* Now apply remaining integral portion of the delta to the child cells. */
	
	{
		float f = floorf(lt_adj);
		
		*size_lt += f;
		m_resize_bank_lt += (lt_adj - f);
	}
	
	{
		float f = floorf(rb_adj);
		
		*size_rb += f;
		m_resize_bank_rb += (rb_adj - f);
	}
	
	/* Clamp sizes in case of rounding error or grow to fill space. */
	
	if(weight_rb == 0.0f)
	{
		int grow = target - (*size_lt + *size_rb);
		
		if(grow < 0)
		{
			/* Overflow due to rounding error, discard the extra space. */
			*size_lt -= grow;
		}
		else{
			*size_lt += grow;
			m_growth_bank_lt = grow;
		}
	}
	else{
		int grow = target - (*size_lt + *size_rb);
		
		if(grow < 0)
		{
			/* Overflow due to rounding error, discard the extra space. */
			*size_rb -= grow;
		}
		else{
			*size_rb += grow;
			m_growth_bank_rb = grow;
		}
	}
}

void REHex::MultiSplitter::Cell::ResizeWindow()
{
	assert(m_window != NULL);

	int sash_size = m_splitter->GetSashSize();
	
	int sash_size1 = sash_size / 2;
	int sash_size2 = (sash_size / 2) + (sash_size % 2);
	
	int wx = m_rect.x;
	int wy = m_rect.y;
	int ww = m_rect.width;
	int wh = m_rect.height;
	
	if(GetLeftNeighbor() != NULL)
	{
		wx += sash_size2;
		ww -= sash_size2;
	}

	if(GetRightNeighbor() != NULL)
	{
		ww -= sash_size1;
	}

	if(GetTopNeighbor() != NULL)
	{
		wy += sash_size2;
		wh -= sash_size2;
	}

	if(GetBottomNeighbor() != NULL)
	{
		wh -= sash_size1;
	}

	m_window->SetPosition(wxPoint(wx, wy));
	m_window->SetSize(ww, wh);
}

template<typename T> T *REHex::MultiSplitter::Cell::_FindCommonAncestor(T *cell1, T *cell2)
{
	for(T *c1 = cell1; c1 != NULL; c1 = c1->GetParent())
	{
		for(T *c2 = cell2; c2 != NULL; c2 = c2->GetParent())
		{
			if(c2 == c1)
			{
				return c2;
			}
		}
	}
	
	return NULL;
}

REHex::MultiSplitter::Cell *REHex::MultiSplitter::Cell::FindCommonAncestor(Cell *cell1, Cell *cell2)
{
	return _FindCommonAncestor(cell1, cell2);
}

const REHex::MultiSplitter::Cell *REHex::MultiSplitter::Cell::FindCommonAncestor(const Cell *cell1, const Cell *cell2)
{
	return _FindCommonAncestor(cell1, cell2);
}

template<typename T> std::pair<T*, bool> REHex::MultiSplitter::Cell::_FindHorizontalSplitAncestor(T *cell)
{
	T *parent = cell->GetParent();
	T *child = cell;
	
	while(parent != NULL)
	{
		if(parent->IsHorizontalSplit())
		{
			return std::make_pair(parent, (parent->GetBottomChild() == child));
		}
		
		child = parent;
		parent = child->GetParent();
	}
	
	return std::make_pair<T*, bool>(NULL, false);
}

std::pair<REHex::MultiSplitter::Cell*, bool> REHex::MultiSplitter::Cell::FindHorizontalSplitAncestor()
{
	return _FindHorizontalSplitAncestor(this);
}

std::pair<const REHex::MultiSplitter::Cell*, bool> REHex::MultiSplitter::Cell::FindHorizontalSplitAncestor() const
{
	return _FindHorizontalSplitAncestor(this);
}

template<typename T> std::pair<T*, bool> REHex::MultiSplitter::Cell::_FindVerticalSplitAncestor(T *cell)
{
	T *parent = cell->GetParent();
	T *child = cell;
	
	while(parent != NULL)
	{
		if(parent->IsVerticalSplit())
		{
			return std::make_pair(parent, (parent->GetRightChild() == child));
		}
		
		child = parent;
		parent = child->GetParent();
	}
	
	return std::make_pair<T*, bool>(NULL, false);
}

std::pair<REHex::MultiSplitter::Cell*, bool> REHex::MultiSplitter::Cell::FindVerticalSplitAncestor()
{
	return _FindVerticalSplitAncestor(this);
}

std::pair<const REHex::MultiSplitter::Cell*, bool> REHex::MultiSplitter::Cell::FindVerticalSplitAncestor() const
{
	return _FindVerticalSplitAncestor(this);
}

bool REHex::MultiSplitter::Cell::IsHidden() const
{
	if(IsVerticalSplit())
	{
		return m_left->IsHidden() && m_right->IsHidden();
	}
	else if(IsHorizontalSplit())
	{
		return m_top->IsHidden() && m_bottom->IsHidden();
	}
	else{
		return !(m_window->IsShown());
	}
}

wxRect REHex::MultiSplitter::Cell::GetRect() const
{
	return m_rect;
}

void REHex::MultiSplitter::Cell::MoveSplitter(const wxPoint &point)
{
	if(IsHorizontalSplit())
	{
		int top_height = point.y - m_rect.y;
		int bottom_height = m_rect.GetHeight() - top_height;
		
		m_top->Resize(wxRect(m_rect.x, m_rect.y, m_rect.width, top_height));
		m_bottom->Resize(wxRect(m_rect.x, (m_rect.y + top_height), m_rect.width, bottom_height));
	}
	else if(IsVerticalSplit())
	{
		int left_width = point.x - m_rect.x;
		int right_width = m_rect.GetWidth() - left_width;
		
		m_left->Resize(wxRect(m_rect.x, m_rect.y, left_width, m_rect.height));
		m_right->Resize(wxRect((m_rect.x + left_width), m_rect.y, right_width, m_rect.height));
	}
}

void REHex::MultiSplitter::Cell::SplitHorizontally(wxWindow *window_top, wxWindow *window_bottom)
{
	assert(!m_left && !m_right && !m_top && !m_bottom);
	assert(m_window == window_top || m_window == window_bottom);
	
	std::unique_ptr<Cell> new_top(new Cell(m_splitter, this, window_top));
	std::unique_ptr<Cell> new_bottom(new Cell(m_splitter, this, window_bottom));
	
	m_top    = std::move(new_top);
	m_bottom = std::move(new_bottom);
	m_window = NULL;
	
	m_resize_bank_lt = 0.0f;
	m_resize_bank_rb = 0.0f;
	
	m_growth_bank_lt = 0;
	m_growth_bank_rb = 0;
	
	m_hidden_lt = false;
	m_hidden_rb = false;
	
	int t_height = m_rect.height / 2;
	int b_height = m_rect.height - t_height;
	
	m_top->Resize(wxRect(m_rect.x, m_rect.y, m_rect.width, t_height));
	m_bottom->Resize(wxRect(m_rect.x, (m_rect.y + t_height), m_rect.width, b_height));
}

void REHex::MultiSplitter::Cell::SplitVertically(wxWindow *window_left, wxWindow *window_right)
{
	assert(!m_left && !m_right && !m_top && !m_bottom);
	assert(m_window == window_left || m_window == window_right);
	
	std::unique_ptr<Cell> new_left(new Cell(m_splitter, this, window_left));
	std::unique_ptr<Cell> new_right(new Cell(m_splitter, this, window_right));
	
	m_left   = std::move(new_left);
	m_right  = std::move(new_right);
	m_window = NULL;
	
	m_resize_bank_lt = 0.0f;
	m_resize_bank_rb = 0.0f;
	
	m_growth_bank_lt = 0;
	m_growth_bank_rb = 0;
	
	m_hidden_lt = false;
	m_hidden_rb = false;
	
	int l_width = m_rect.width / 2;
	int r_width = m_rect.width - l_width;
	
	m_left->Resize(wxRect(m_rect.x, m_rect.y, l_width, m_rect.height));
	m_right->Resize(wxRect((m_rect.x + l_width), m_rect.y, r_width, m_rect.height));
}

void REHex::MultiSplitter::Cell::RemoveChild(wxWindow *window)
{
	assert((m_left && m_left->m_window == window) || (m_right && m_right->m_window == window) || (m_top && m_top->m_window == window) || (m_bottom && m_bottom->m_window == window));
	assert(!m_window);
	
	/* Save a copy of our rect so we can resize back up to it with proper scaling of any (new)
	 * child cells after adopting them from the remaining child.
	*/
	wxRect full_rect = m_rect;
	
	auto absorb_cell = [&](std::unique_ptr<Cell> cell)
	{
		m_rect = cell->m_rect;
		m_weight = cell->m_weight;
		
		m_left = std::move(cell->m_left);
		m_right = std::move(cell->m_right);
		m_top = std::move(cell->m_top);
		m_bottom = std::move(cell->m_bottom);
		
		m_window = cell->m_window;
		
		m_resize_bank_lt = 0.0f;
		m_resize_bank_rb = 0.0f;
		
		m_growth_bank_lt = 0;
		m_growth_bank_rb = 0;
		
		if(m_left) m_left->m_parent = this;
		if(m_right) m_right->m_parent = this;
		if(m_top) m_top->m_parent = this;
		if(m_bottom) m_bottom->m_parent = this;
	};
	
	if(m_left && m_left->m_window == window)
	{
		absorb_cell(std::move(m_right));
	}
	else if(m_right && m_right->m_window == window)
	{
		absorb_cell(std::move(m_left));
	}
	else if(m_top && m_top->m_window == window)
	{
		absorb_cell(std::move(m_bottom));
	}
	else if(m_bottom && m_bottom->m_window == window)
	{
		absorb_cell(std::move(m_top));
	}
	
	Resize(full_rect);
}

bool REHex::MultiSplitter::Cell::IsWindow() const
{
	if(m_window != NULL)
	{
		assert(!m_left && !m_right && !m_top && !m_bottom);
		return true;
	}
	else{
		return false;
	}
}

bool REHex::MultiSplitter::Cell::IsHorizontalSplit() const
{
	if(m_top)
	{
		assert(m_bottom && !m_left && !m_right && m_window == NULL);
		return true;
	}
	else{
		assert(!m_bottom);
		return false;
	}
}

bool REHex::MultiSplitter::Cell::IsVerticalSplit() const
{
	if(m_left)
	{
		assert(m_right && !m_top && !m_bottom && m_window == NULL);
		return true;
	}
	else{
		assert(!m_right);
		return false;
	}
}

bool REHex::MultiSplitter::Cell::IsLeftOf(const Cell *other) const
{
	const Cell *common_ancestor = FindCommonAncestor(this, other);
	assert(common_ancestor != NULL);
	
	const Cell *vsplit_ancestor;
	bool this_is_right;
	
	std::tie(vsplit_ancestor, this_is_right) = FindVerticalSplitAncestor();
	
	while(vsplit_ancestor != NULL)
	{
		if(vsplit_ancestor == common_ancestor)
		{
			return !this_is_right;
		}
		
		std::tie(vsplit_ancestor, this_is_right) = vsplit_ancestor->FindVerticalSplitAncestor();
	}
	
	return false;
}

bool REHex::MultiSplitter::Cell::IsRightOf(const Cell *other) const
{
	const Cell *common_ancestor = FindCommonAncestor(this, other);
	assert(common_ancestor != NULL);
	
	const Cell *vsplit_ancestor;
	bool this_is_right;
	
	std::tie(vsplit_ancestor, this_is_right) = FindVerticalSplitAncestor();
	
	while(vsplit_ancestor != NULL)
	{
		if(vsplit_ancestor == common_ancestor)
		{
			return this_is_right;
		}
		
		std::tie(vsplit_ancestor, this_is_right) = vsplit_ancestor->FindVerticalSplitAncestor();
	}
	
	return false;
}

bool REHex::MultiSplitter::Cell::IsAbove(const Cell *other) const
{
	const Cell *common_ancestor = FindCommonAncestor(this, other);
	assert(common_ancestor != NULL);
	
	const Cell *hsplit_ancestor;
	bool this_is_bottom;
	
	std::tie(hsplit_ancestor, this_is_bottom) = FindHorizontalSplitAncestor();
	
	while(hsplit_ancestor != NULL)
	{
		if(hsplit_ancestor == common_ancestor)
		{
			return !this_is_bottom;
		}
		
		std::tie(hsplit_ancestor, this_is_bottom) = hsplit_ancestor->FindHorizontalSplitAncestor();
	}
	
	return false;
}

bool REHex::MultiSplitter::Cell::IsBelow(const Cell *other) const
{
	const Cell *common_ancestor = FindCommonAncestor(this, other);
	assert(common_ancestor != NULL);
	
	const Cell *hsplit_ancestor;
	bool this_is_bottom;
	
	std::tie(hsplit_ancestor, this_is_bottom) = FindHorizontalSplitAncestor();
	
	while(hsplit_ancestor != NULL)
	{
		if(hsplit_ancestor == common_ancestor)
		{
			return this_is_bottom;
		}
		
		std::tie(hsplit_ancestor, this_is_bottom) = hsplit_ancestor->FindHorizontalSplitAncestor();
	}
	
	return false;
}

std::pair<REHex::MultiSplitter::CellEdge, float> REHex::MultiSplitter::Cell::GetPointEdge(const wxPoint &point) const
{
	if(!m_rect.Contains(point))
	{
		return std::make_pair(CellEdge::NONE, 0.0f);
	}
	
	float left_score = 1.0f - (float)(point.x - m_rect.GetLeft()) / (float)(m_rect.GetWidth());
	float right_score = 1.0f - (float)(m_rect.GetRight() - point.x) / (float)(m_rect.GetWidth());
	float top_score = 1.0f - (float)(point.y - m_rect.GetTop()) / (float)(m_rect.GetHeight());
	float bottom_score = 1.0f - (float)(m_rect.GetBottom() - point.y) / (float)(m_rect.GetBottom());
	
	if(left_score >= right_score && left_score >= top_score && left_score >= bottom_score)
	{
		return std::make_pair(CellEdge::LEFT, left_score);
	}
	else if(right_score >= left_score && right_score >= top_score && right_score >= bottom_score)
	{
		return std::make_pair(CellEdge::RIGHT, right_score);
	}
	else if(top_score >= left_score && top_score >= top_score && top_score >= bottom_score)
	{
		return std::make_pair(CellEdge::TOP, top_score);
	}
	else{
		return std::make_pair(CellEdge::BOTTOM, bottom_score);
	}
}

REHex::MultiSplitter::Cell *REHex::MultiSplitter::Cell::GetParent()
{
	return m_parent;
}

const REHex::MultiSplitter::Cell *REHex::MultiSplitter::Cell::GetParent() const
{
	return m_parent;
}

REHex::MultiSplitter::Cell *REHex::MultiSplitter::Cell::GetLeftChild()
{
	return m_left.get();
}

const REHex::MultiSplitter::Cell *REHex::MultiSplitter::Cell::GetLeftChild() const
{
	return m_left.get();
}

REHex::MultiSplitter::Cell *REHex::MultiSplitter::Cell::GetRightChild()
{
	return m_right.get();
}

const REHex::MultiSplitter::Cell *REHex::MultiSplitter::Cell::GetRightChild() const
{
	return m_right.get();
}

REHex::MultiSplitter::Cell *REHex::MultiSplitter::Cell::GetTopChild()
{
	return m_top.get();
}

const REHex::MultiSplitter::Cell *REHex::MultiSplitter::Cell::GetTopChild() const
{
	return m_top.get();
}

REHex::MultiSplitter::Cell *REHex::MultiSplitter::Cell::GetBottomChild()
{
	return m_bottom.get();
}

const REHex::MultiSplitter::Cell *REHex::MultiSplitter::Cell::GetBottomChild() const
{
	return m_bottom.get();
}

REHex::MultiSplitter::Cell *REHex::MultiSplitter::Cell::GetLeftNeighbor()
{
	const Cell *child = this;
	const Cell *parent = GetParent();

	while(parent != NULL)
	{
		if(parent->m_right.get() == child && !(parent->m_left->IsHidden()))
		{
			return parent->m_left.get();
		}

		child = parent;
		parent = child->GetParent();
	}
	
	return NULL;
}

REHex::MultiSplitter::Cell *REHex::MultiSplitter::Cell::GetRightNeighbor()
{
	const Cell *child = this;
	const Cell *parent = GetParent();

	while(parent != NULL)
	{
		if(parent->m_left.get() == child && !(parent->m_right->IsHidden()))
		{
			return parent->m_right.get();
		}

		child = parent;
		parent = child->GetParent();
	}
	
	return NULL;
}

REHex::MultiSplitter::Cell *REHex::MultiSplitter::Cell::GetTopNeighbor()
{
	const Cell *child = this;
	const Cell *parent = GetParent();

	while(parent != NULL)
	{
		if(parent->m_bottom.get() == child && !(parent->m_top->IsHidden()))
		{
			return parent->m_top.get();
		}

		child = parent;
		parent = child->GetParent();
	}
	
	return NULL;
}

REHex::MultiSplitter::Cell *REHex::MultiSplitter::Cell::GetBottomNeighbor()
{
	const Cell *child = this;
	const Cell *parent = GetParent();

	while(parent != NULL)
	{
		if(parent->m_top.get() == child && !(parent->m_bottom->IsHidden()))
		{
			return parent->m_bottom.get();
		}

		child = parent;
		parent = child->GetParent();
	}
	
	return NULL;
}

wxWindow *REHex::MultiSplitter::Cell::GetWindow() const
{
	return m_window;
}

REHex::MultiSplitterResizeBias::MultiSplitterResizeBias(REHex::MultiSplitter::Cell *root, REHex::MultiSplitter::CellEdge edge)
{
	walk_tree(root, edge, false);
}

REHex::MultiSplitterResizeBias::~MultiSplitterResizeBias()
{
	for(auto it = m_saved_weights.begin(); it != m_saved_weights.end(); ++it)
	{
		it->first->SetWeight(it->second);
	}
}

void REHex::MultiSplitterResizeBias::walk_tree(REHex::MultiSplitter::Cell *cell, REHex::MultiSplitter::CellEdge edge, bool force_zero)
{
	if(cell->IsVerticalSplit())
	{
		if(edge == REHex::MultiSplitter::CellEdge::LEFT)
		{
			walk_tree(cell->GetLeftChild(), edge, force_zero);
			walk_tree(cell->GetRightChild(), edge, true);
		}
		else if(edge == REHex::MultiSplitter::CellEdge::RIGHT)
		{
			walk_tree(cell->GetLeftChild(), edge, true);
			walk_tree(cell->GetRightChild(), edge, force_zero);
		}
		else{
			walk_tree(cell->GetLeftChild(), edge, force_zero);
			walk_tree(cell->GetRightChild(), edge, force_zero);
		}
	}
	else if(cell->IsHorizontalSplit())
	{
		if(edge == REHex::MultiSplitter::CellEdge::TOP)
		{
			walk_tree(cell->GetTopChild(), edge, force_zero);
			walk_tree(cell->GetBottomChild(), edge, true);
		}
		else if(edge == REHex::MultiSplitter::CellEdge::BOTTOM)
		{
			walk_tree(cell->GetTopChild(), edge, true);
			walk_tree(cell->GetBottomChild(), edge, force_zero);
		}
		else{
			walk_tree(cell->GetTopChild(), edge, force_zero);
			walk_tree(cell->GetBottomChild(), edge, force_zero);
		}
	}
	else if(cell->IsWindow())
	{
		m_saved_weights.emplace_back(cell, cell->GetWeight());
		cell->SetWeight(force_zero ? 0.0f : 1.0f);
	}
}
