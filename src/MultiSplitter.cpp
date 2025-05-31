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
#include "util.hpp"

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

void REHex::MultiSplitter::AddFirst(wxWindow *window, float weight)
{
	wxASSERT_MSG((window->GetParent() == this), "Windows added to a MultiSplitter must be direct children");
	
	assert(!m_cells);
	m_cells.reset(new Cell(this, NULL, window, weight));
	
	m_cells->Resize(GetClientSize());
	
	window->Bind(wxEVT_SHOW, &REHex::MultiSplitter::OnChildShowHide, this);
	window->Bind(wxEVT_MOTION, &REHex::MultiSplitter::OnChildMouseMotion, this);
	window->Bind(wxEVT_LEFT_DOWN, &REHex::MultiSplitter::OnChildMouseLeftDown, this);
}

void REHex::MultiSplitter::AddLeftOf(wxWindow *window, wxWindow *base, float weight)
{
	wxASSERT_MSG((window->GetParent() == this), "Windows added to a MultiSplitter must be direct children");
	wxASSERT_MSG((window != base), "window and base passed to REHex::MultiSplitter::AddLeftOf() must be different windows");
	
	Cell *base_cell = _FindCellByWindow(base);
	wxASSERT_MSG((base_cell != NULL), "Base window passed to REHex::MultiSplitter::AddLeftOf() has not been added to MultiSplitter");
	
	Cell *window_cell = _FindCellByWindow(window);
	assert(window_cell == NULL || window_cell != base_cell);
	
	if(window_cell != NULL)
	{
		/* Window is already in the splitter, remove it from its previous position. */
		
		Cell *window_parent_cell = window_cell->GetParent();
		assert(window_parent_cell != NULL);
		
		window_parent_cell->RemoveChild(window);
		
		/* base_cell may be invalid now. */
		base_cell = _FindCellByWindow(base);
		assert(base_cell != NULL);
	}
	
	base_cell->SplitVertically(window, base, weight);
	
	if(window_cell == NULL)
	{
		window->Bind(wxEVT_SHOW, &REHex::MultiSplitter::OnChildShowHide, this);
		window->Bind(wxEVT_MOTION, &REHex::MultiSplitter::OnChildMouseMotion, this);
		window->Bind(wxEVT_LEFT_DOWN, &REHex::MultiSplitter::OnChildMouseLeftDown, this);
	}
}

void REHex::MultiSplitter::AddRightOf(wxWindow *window, wxWindow *base, float weight)
{
	wxASSERT_MSG((window->GetParent() == this), "Windows added to a MultiSplitter must be direct children");
	wxASSERT_MSG((window != base), "window and base passed to REHex::MultiSplitter::AddRightOf() must be different windows");
	
	Cell *base_cell = _FindCellByWindow(base);
	wxASSERT_MSG((base_cell != NULL), "Base window passed to REHex::MultiSplitter::AddRightOf() has not been added to MultiSplitter");
	
	Cell *window_cell = _FindCellByWindow(window);
	assert(window_cell == NULL || window_cell != base_cell);
	
	if(window_cell != NULL)
	{
		/* Window is already in the splitter, remove it from its previous position. */
		
		Cell *window_parent_cell = window_cell->GetParent();
		assert(window_parent_cell != NULL);
		
		window_parent_cell->RemoveChild(window);
		
		/* base_cell may be invalid now. */
		base_cell = _FindCellByWindow(base);
		assert(base_cell != NULL);
	}
	
	base_cell->SplitVertically(base, window, weight);
	
	if(window_cell == NULL)
	{
		window->Bind(wxEVT_SHOW, &REHex::MultiSplitter::OnChildShowHide, this);
		window->Bind(wxEVT_MOTION, &REHex::MultiSplitter::OnChildMouseMotion, this);
		window->Bind(wxEVT_LEFT_DOWN, &REHex::MultiSplitter::OnChildMouseLeftDown, this);
	}
}

void REHex::MultiSplitter::AddAbove(wxWindow *window, wxWindow *base, float weight)
{
	wxASSERT_MSG((window->GetParent() == this), "Windows added to a MultiSplitter must be direct children");
	wxASSERT_MSG((window != base), "window and base passed to REHex::MultiSplitter::AddAbove() must be different windows");
	
	Cell *base_cell = _FindCellByWindow(base);
	wxASSERT_MSG((base_cell != NULL), "Base window passed to REHex::MultiSplitter::AddAbove() has not been added to MultiSplitter");
	
	Cell *window_cell = _FindCellByWindow(window);
	assert(window_cell == NULL || window_cell != base_cell);
	
	if(window_cell != NULL)
	{
		/* Window is already in the splitter, remove it from its previous position. */
		
		Cell *window_parent_cell = window_cell->GetParent();
		assert(window_parent_cell != NULL);
		
		window_parent_cell->RemoveChild(window);
		
		/* base_cell may be invalid now. */
		base_cell = _FindCellByWindow(base);
		assert(base_cell != NULL);
	}
	
	base_cell->SplitHorizontally(window, base, weight);
	
	if(window_cell == NULL)
	{
		window->Bind(wxEVT_SHOW, &REHex::MultiSplitter::OnChildShowHide, this);
		window->Bind(wxEVT_MOTION, &REHex::MultiSplitter::OnChildMouseMotion, this);
		window->Bind(wxEVT_LEFT_DOWN, &REHex::MultiSplitter::OnChildMouseLeftDown, this);
	}
}

void REHex::MultiSplitter::AddBelow(wxWindow *window, wxWindow *base, float weight)
{
	wxASSERT_MSG((window->GetParent() == this), "Windows added to a MultiSplitter must be direct children");
	wxASSERT_MSG((window != base), "window and base passed to REHex::MultiSplitter::AddBelow() must be different windows");
	
	Cell *base_cell = _FindCellByWindow(base);
	wxASSERT_MSG((base_cell != NULL), "Base window passed to REHex::MultiSplitter::AddBelow() has not been added to MultiSplitter");
	
	Cell *window_cell = _FindCellByWindow(window);
	assert(window_cell == NULL || window_cell != base_cell);
	
	if(window_cell != NULL)
	{
		/* Window is already in the splitter, remove it from its previous position. */
		
		Cell *window_parent_cell = window_cell->GetParent();
		assert(window_parent_cell != NULL);
		
		window_parent_cell->RemoveChild(window);
		
		/* base_cell may be invalid now. */
		base_cell = _FindCellByWindow(base);
		assert(base_cell != NULL);
	}
	
	base_cell->SplitHorizontally(base, window, weight);
	
	if(window_cell == NULL)
	{
		window->Bind(wxEVT_SHOW, &REHex::MultiSplitter::OnChildShowHide, this);
		window->Bind(wxEVT_MOTION, &REHex::MultiSplitter::OnChildMouseMotion, this);
		window->Bind(wxEVT_LEFT_DOWN, &REHex::MultiSplitter::OnChildMouseLeftDown, this);
	}
}

#if 0
void REHex::MultiSplitter::RemoveChild(wxWindow *window)
{
	Cell *cell = _FindCellByWindow(window);
	wxASSERT_MSG((cell != NULL), "Unknown window passed to REHex::MultiSplitter::RemoveChild()");
	
	if(cell != NULL)
	{
		window->Unbind(wxEVT_LEFT_DOWN, &REHex::MultiSplitter::OnChildMouseLeftDown, this);
		window->Unbind(wxEVT_MOTION, &REHex::MultiSplitter::OnChildMouseMotion, this);
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
#endif

void REHex::MultiSplitter::RemoveAllChildren()
{
	std::function<void(Cell*)> f;
	f = [&](Cell *cell)
	{
		if(cell != NULL)
		{
			if(cell->IsWindow())
			{
				cell->GetWindow()->Unbind(wxEVT_LEFT_DOWN, &REHex::MultiSplitter::OnChildMouseLeftDown, this);
				cell->GetWindow()->Unbind(wxEVT_MOTION, &REHex::MultiSplitter::OnChildMouseMotion, this);
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
	Cell *cell = _FindCellByPoint(point);
	return cell != NULL ? cell->GetWindow() : NULL;
}

void REHex::MultiSplitter::SetWindowWeight(wxWindow *window, float weight)
{
	Cell *cell = _FindCellByWindow(window);
	assert(cell != NULL);
	
	cell->SetWeight(weight);
}

void REHex::MultiSplitter::SetWindowDragBorder(wxWindow *window, int drag_border_all)
{
	Cell *cell = _FindCellByWindow(window);
	assert(cell != NULL);
	
	cell->SetDragBorder(drag_border_all, drag_border_all, drag_border_all, drag_border_all);
}

void REHex::MultiSplitter::SetWindowDragBorder(wxWindow *window, int drag_border_left, int drag_border_right, int drag_border_top, int drag_border_bottom)
{
	Cell *cell = _FindCellByWindow(window);
	assert(cell != NULL);
	
	cell->SetDragBorder(drag_border_left, drag_border_right, drag_border_top, drag_border_bottom);
}

void REHex::MultiSplitter::SetWindowSize(wxWindow *window, const wxSize &size)
{
	Cell *cell = _FindCellByWindow(window);
	assert(cell != NULL);
	
	int sash_size1, sash_size2;
	std::tie(sash_size1, sash_size2) = GetDividedSashSize();
	
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
				vsplit->MoveSplitter(wxPoint((vsplit_rect.x + vsplit_rect.GetWidth() - cell_width), 0), true);
			}
			else{
				vsplit->MoveSplitter(wxPoint((vsplit_rect.x + cell_width), 0), true);
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
				hsplit->MoveSplitter(wxPoint(0, (hsplit_rect.y + hsplit_rect.GetHeight() - cell_height)), true);
			}
			else{
				hsplit->MoveSplitter(wxPoint(0, (hsplit_rect.y + cell_height)), true);
			}
		}
	}
}

void REHex::MultiSplitter::ApplySizeConstraints()
{
	if(m_cells)
	{
		m_cells->ApplySizeConstraints();
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

std::pair<int, int> REHex::MultiSplitter::GetDividedSashSize() const
{
	int sash_size1 = m_sash_size / 2;
	int sash_size2 = (m_sash_size / 2) + (m_sash_size % 2);
	
	return std::make_pair(sash_size1, sash_size2);
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

const REHex::MultiSplitter::Cell *REHex::MultiSplitter::GetRootCell() const
{
	return m_cells.get();
}

REHex::MultiSplitter::Cell *REHex::MultiSplitter::_FindCellByWindow(wxWindow *window)
{
	return _FindCellByWindow(m_cells.get(), window);
}

const REHex::MultiSplitter::Cell *REHex::MultiSplitter::FindCellByWindow(wxWindow *window) const
{
	return _FindCellByWindow(m_cells.get(), window);
}

template<typename T> T *REHex::MultiSplitter::_FindCellByWindow(T *cell, wxWindow *window)
{
	if(cell == NULL)
	{
		return NULL;
	}
	
	if(cell->IsWindow() && cell->GetWindow() == window)
	{
		return cell;
	}
	
	Cell *c = _FindCellByWindow(cell->GetLeftChild(), window);
	if(c != NULL) return c;
	
	c = _FindCellByWindow(cell->GetRightChild(), window);
	if(c != NULL) return c;
	
	c = _FindCellByWindow(cell->GetTopChild(), window);
	if(c != NULL) return c;
	
	c = _FindCellByWindow(cell->GetBottomChild(), window);
	if(c != NULL) return c;
	
	return NULL;
}

REHex::MultiSplitter::Cell *REHex::MultiSplitter::_FindCellByPoint(const wxPoint &point)
{
	return _FindCellByPoint(m_cells.get(), point);
}

const REHex::MultiSplitter::Cell *REHex::MultiSplitter::FindCellByPoint(const wxPoint &point) const
{
	return _FindCellByPoint(m_cells.get(), point);
}

template<typename T> T *REHex::MultiSplitter::_FindCellByPoint(T *cell, const wxPoint &point)
{
	if(cell == NULL)
	{
		return NULL;
	}
	
	if(!cell->GetRect().Contains(point))
	{
		return NULL;
	}
	
	if(cell->IsWindow())
	{
		if(cell->GetWindow()->IsShown())
		{
			return cell;
		}
		else{
			return NULL;
		}
	}
	
	Cell *c = _FindCellByPoint(cell->GetLeftChild(), point);
	if(c != NULL) return c;
	
	c = _FindCellByPoint(cell->GetRightChild(), point);
	if(c != NULL) return c;
	
	c = _FindCellByPoint(cell->GetTopChild(), point);
	if(c != NULL) return c;
	
	c = _FindCellByPoint(cell->GetBottomChild(), point);
	if(c != NULL) return c;
	
	return NULL;
}

void REHex::MultiSplitter::BeginResize(Cell *cell, Edge edge)
{
	assert(!m_resizing);
	
	m_resizing_cell = cell;
	m_resizing_edge = edge;
	m_resizing = true;
	
	CaptureMouse();
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
			case Edge::LEFT:
			case Edge::RIGHT:
			{
				Cell *common_ancestor = m_resizing_edge == Edge::LEFT
					? Cell::FindCommonAncestor(m_resizing_cell, m_resizing_cell->GetLeftNeighbor())
					: Cell::FindCommonAncestor(m_resizing_cell, m_resizing_cell->GetRightNeighbor());
				
				assert(common_ancestor != NULL);
				
				REHex::MultiSplitterResizeBias a(common_ancestor->GetLeftChild(), Edge::RIGHT);
				REHex::MultiSplitterResizeBias b(common_ancestor->GetRightChild(), Edge::LEFT);
				
				common_ancestor->MoveSplitter(event.GetPosition(), false);
				
				break;
			}
			
			case Edge::TOP:
			case Edge::BOTTOM:
			{
				Cell *common_ancestor = m_resizing_edge == Edge::TOP
					? Cell::FindCommonAncestor(m_resizing_cell, m_resizing_cell->GetTopNeighbor())
					: Cell::FindCommonAncestor(m_resizing_cell, m_resizing_cell->GetBottomNeighbor());
				
				assert(common_ancestor != NULL);
				
				REHex::MultiSplitterResizeBias a(common_ancestor->GetTopChild(), Edge::BOTTOM);
				REHex::MultiSplitterResizeBias b(common_ancestor->GetBottomChild(), Edge::TOP);
				
				common_ancestor->MoveSplitter(event.GetPosition(), false);
				
				break;
			}
		}
	}
	else{
		Cell *cell = _FindCellByPoint(event.GetPosition());
		
		wxCursor cursor = wxNullCursor;
		
		if(cell != NULL)
		{
			wxRect cell_rect = cell->GetRect();
			
			if(cell_rect.Contains(event.GetPosition()))
			{
				Edge edge = find_nearest_edge(event.GetPosition(), cell_rect);
				
				if((edge == Edge::LEFT && cell->GetLeftNeighbor() != NULL)
					|| (edge == Edge::RIGHT && cell->GetRightNeighbor() != NULL))
				{
					cursor = wxCursor(wxCURSOR_SIZEWE);
				}
				else if((edge == Edge::TOP && cell->GetTopNeighbor() != NULL)
					|| (edge == Edge::BOTTOM && cell->GetBottomNeighbor() != NULL))
				{
					cursor = wxCursor(wxCURSOR_SIZENS);
				}
			}
		}
		
		SetCursor(cursor);
	}
}

void REHex::MultiSplitter::OnMouseLeftDown(wxMouseEvent &event)
{
	Cell *cell = _FindCellByPoint(event.GetPosition());
	assert(cell != NULL);
	
	if(cell != NULL)
	{
		wxRect cell_rect = cell->GetRect();
		
		if(cell_rect.Contains(event.GetPosition()))
		{
			Edge edge = find_nearest_edge(event.GetPosition(), cell_rect);
			
			if((edge == Edge::LEFT && cell->GetLeftNeighbor() != NULL)
				|| (edge == Edge::RIGHT && cell->GetRightNeighbor() != NULL)
				|| (edge == Edge::TOP && cell->GetTopNeighbor() != NULL)
				|| (edge == Edge::BOTTOM && cell->GetBottomNeighbor() != NULL))
			{
				BeginResize(cell, edge);
				return;
			}
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

void REHex::MultiSplitter::OnChildMouseMotion(wxMouseEvent &event)
{
	wxWindow *child_window = (wxWindow*)(event.GetEventObject());
	
	Cell *cell = _FindCellByWindow(child_window);
	assert(cell != NULL);
	
	if(cell != NULL)
	{
		wxSize child_window_size = child_window->GetSize();
		wxPoint child_mouse_pos = event.GetPosition();
		
		bool in_drag_border = child_mouse_pos.x < cell->GetDragBorderLeft()
			|| child_mouse_pos.x >= (child_window_size.GetWidth() - cell->GetDragBorderRight())
			|| child_mouse_pos.y < cell->GetDragBorderTop()
			|| child_mouse_pos.y >= (child_window_size.GetHeight() - cell->GetDragBorderBottom());
		
		// fprintf(stderr, "%sin drag border x = %d y = %d\n", (in_drag_border ? "" : "not "), child_mouse_pos.x, child_mouse_pos.y);
		
		/* TODO: Save/restore existing cursor on child window. */
		
		if(in_drag_border)
		{
			wxPoint mouse_pos = ScreenToClient(child_window->ClientToScreen(child_mouse_pos));
			
			Edge nearest_cell_edge = find_nearest_edge(mouse_pos, cell->GetRect());
			
			switch(nearest_cell_edge)
			{
				case Edge::LEFT:
					if(cell->GetLeftNeighbor() != NULL)
					{
						child_window->SetCursor(wxCursor(wxCURSOR_SIZEWE));
					}
					
					break;
					
				case Edge::RIGHT:
					if(cell->GetRightNeighbor() != NULL)
					{
						child_window->SetCursor(wxCursor(wxCURSOR_SIZEWE));
					}
					
					break;
					
				case Edge::TOP:
					if(cell->GetTopNeighbor() != NULL)
					{
						child_window->SetCursor(wxCursor(wxCURSOR_SIZENS));
					}
					
					break;
					
				case Edge::BOTTOM:
					if(cell->GetBottomNeighbor() != NULL)
					{
						child_window->SetCursor(wxCursor(wxCURSOR_SIZENS));
					}
					
					break;
			}
		}
		else{
			child_window->SetCursor(wxNullCursor);
		}
	}
	
	event.Skip();
}

void REHex::MultiSplitter::OnChildMouseLeftDown(wxMouseEvent &event)
{
	wxWindow *child_window = (wxWindow*)(event.GetEventObject());
	
	Cell *cell = _FindCellByWindow(child_window);
	assert(cell != NULL);
	
	if(cell != NULL)
	{
		wxSize child_window_size = child_window->GetSize();
		wxPoint child_mouse_pos = event.GetPosition();
		
		bool in_drag_border = child_mouse_pos.x < cell->GetDragBorderLeft()
			|| child_mouse_pos.x >= (child_window_size.GetWidth() - cell->GetDragBorderRight())
			|| child_mouse_pos.y < cell->GetDragBorderTop()
			|| child_mouse_pos.y >= (child_window_size.GetHeight() - cell->GetDragBorderBottom());
		
		if(in_drag_border)
		{
			wxPoint mouse_pos = ScreenToClient(child_window->ClientToScreen(child_mouse_pos));
			
			Edge nearest_cell_edge = find_nearest_edge(mouse_pos, cell->GetRect());
			
			switch(nearest_cell_edge)
			{
				case Edge::LEFT:
					if(cell->GetLeftNeighbor() != NULL)
					{
						BeginResize(cell, nearest_cell_edge);
						return;
					}
					
					break;
					
				case Edge::RIGHT:
					if(cell->GetRightNeighbor() != NULL)
					{
						BeginResize(cell, nearest_cell_edge);
						return;
					}
					
					break;
					
				case Edge::TOP:
					if(cell->GetTopNeighbor() != NULL)
					{
						BeginResize(cell, nearest_cell_edge);
						return;
					}
					
					break;
					
				case Edge::BOTTOM:
					if(cell->GetBottomNeighbor() != NULL)
					{
						BeginResize(cell, nearest_cell_edge);
						return;
					}
					
					break;
			}
		}
	}
	
	event.Skip();
}

REHex::MultiSplitter::Cell::Cell(const MultiSplitter *splitter, Cell *parent, wxWindow *window, float weight):
	m_splitter(splitter),
	m_parent(parent),
	m_weight(weight),
	m_drag_border_left(0),
	m_drag_border_right(0),
	m_drag_border_top(0),
	m_drag_border_bottom(0),
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

void REHex::MultiSplitter::Cell::SetDragBorder(int drag_border_left, int drag_border_right, int drag_border_top, int drag_border_bottom)
{
	assert(IsWindow());
	
	assert(drag_border_left >= 0);
	assert(drag_border_right >= 0);
	assert(drag_border_top >= 0);
	assert(drag_border_bottom >= 0);
	
	m_drag_border_left = drag_border_left;
	m_drag_border_right = drag_border_right;
	m_drag_border_top = drag_border_top;
	m_drag_border_bottom = drag_border_bottom;
}

int REHex::MultiSplitter::Cell::GetDragBorderLeft() const
{
	assert(IsWindow());
	return m_drag_border_left;
}

int REHex::MultiSplitter::Cell::GetDragBorderRight() const
{
	assert(IsWindow());
	return m_drag_border_right;
}

int REHex::MultiSplitter::Cell::GetDragBorderTop() const
{
	assert(IsWindow());
	return m_drag_border_top;
}

int REHex::MultiSplitter::Cell::GetDragBorderBottom() const
{
	assert(IsWindow());
	return m_drag_border_bottom;
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

	int sash_size1, sash_size2;
	std::tie(sash_size1, sash_size2) = m_splitter->GetDividedSashSize();
	
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
	
	// fprintf(stderr, "x = %d, y = %d, w = %d, h = %d (r = %d, b = %d)\n", wx, wy, ww, wh, (wx + ww - 1), (wy + wh - 1));

	m_window->SetPosition(wxPoint(wx, wy));
	m_window->SetSize(ww, wh);
	
	// wxRect ca = m_window->GetClientRect();
	// fprintf(stderr, "client x = %d, y = %d, w = %d, h = %d (r = %d, b = %d)\n", ca.GetLeft(), ca.GetTop(), ca.GetWidth(), ca.GetHeight(), ca.GetRight(), ca.GetBottom());
}

int REHex::MultiSplitter::Cell::GetLeftSashWidth() const
{
	if(GetLeftNeighbor() != NULL)
	{
		return m_splitter->GetDividedSashSize().second;
	}
	else{
		return 0;
	}
}

int REHex::MultiSplitter::Cell::GetRightSashWidth() const
{
	if(GetRightNeighbor() != NULL)
	{
		return m_splitter->GetDividedSashSize().first;
	}
	else{
		return 0;
	}
}

int REHex::MultiSplitter::Cell::GetTopSashHeight() const
{
	if(GetTopNeighbor() != NULL)
	{
		return m_splitter->GetDividedSashSize().second;
	}
	else{
		return 0;
	}
}

int REHex::MultiSplitter::Cell::GetBottomSashHeight() const
{
	if(GetBottomNeighbor() != NULL)
	{
		return m_splitter->GetDividedSashSize().first;
	}
	else{
		return 0;
	}
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

static int ConstraintAdd(int size1, int size2)
{
	if(size1 >= 0 && size2 >= 0)
	{
		return size1 + size2;
	}
	else if(size1 >= 0)
	{
		return size1;
	}
	else if(size2 >= 0)
	{
		return size2;
	}
	else{
		return -1;
	}
}

static int ConstraintMin(int size1, int size2)
{
	if(size1 >= 0 && size2 >= 0)
	{
		return std::min(size1, size2);
	}
	else if(size1 >= 0)
	{
		return size1;
	}
	else if(size2 >= 0)
	{
		return size2;
	}
	else{
		return -1;
	}
}

static int ConstraintMax(int size1, int size2)
{
	if(size1 >= 0 && size2 >= 0)
	{
		return std::max(size1, size2);
	}
	else if(size1 >= 0)
	{
		return size1;
	}
	else if(size2 >= 0)
	{
		return size2;
	}
	else{
		return -1;
	}
}

wxSize REHex::MultiSplitter::Cell::GetMinSize() const
{
	if(IsVerticalSplit())
	{
		wxSize left_size = m_left->GetMinSize();
		wxSize right_size = m_right->GetMinSize();
		
		return wxSize(
			ConstraintAdd(left_size.GetWidth(), right_size.GetWidth()),
			ConstraintMax(left_size.GetHeight(), right_size.GetHeight()));
	}
	else if(IsHorizontalSplit())
	{
		wxSize top_size = m_top->GetMinSize();
		wxSize bottom_size = m_bottom->GetMinSize();
		
		return wxSize(
			ConstraintMax(top_size.GetWidth(), bottom_size.GetWidth()),
			ConstraintAdd(top_size.GetHeight(), bottom_size.GetHeight()));
	}
	else{
		if(m_window->IsShown())
		{
			wxSize window_min_size = m_window->GetMinSize();
			
			return wxSize(
				ConstraintAdd(window_min_size.GetWidth(), (GetLeftSashWidth() + GetRightSashWidth())),
				ConstraintAdd(window_min_size.GetHeight(), (GetTopSashHeight() + GetBottomSashHeight())));
		}
		else{
			/* Window is hidden, no space required. */
			return wxSize(0, 0);
		}
	}
}

wxSize REHex::MultiSplitter::Cell::GetMaxSize() const
{
	if(IsVerticalSplit())
	{
		if(m_left->IsHidden())
		{
			return m_right->GetMaxSize();
		}
		else if(m_right->IsHidden())
		{
			return m_left->GetMaxSize();
		}
		
		wxSize left_size = m_left->GetMaxSize();
		wxSize right_size = m_right->GetMaxSize();
		
		int max_width = left_size.GetWidth() >= 0 && right_size.GetWidth() >= 0
			? left_size.GetWidth() + right_size.GetWidth()
			: -1;
		
		int max_height = ConstraintMin(left_size.GetHeight(), right_size.GetHeight());
		
		return wxSize(max_width, max_height);
	}
	else if(IsHorizontalSplit())
	{
		if(m_top->IsHidden())
		{
			return m_bottom->GetMaxSize();
		}
		else if(m_bottom->IsHidden())
		{
			return m_top->GetMaxSize();
		}
		
		wxSize top_size = m_top->GetMaxSize();
		wxSize bottom_size = m_bottom->GetMaxSize();
		
		int max_width = ConstraintMin(top_size.GetWidth(), bottom_size.GetWidth());
		
		int max_height = top_size.GetHeight() >= 0 && bottom_size.GetHeight() >= 0
			? top_size.GetHeight() + bottom_size.GetHeight()
			: -1;
		
		return wxSize(max_width, max_height);
	}
	else{
		if(m_window->IsShown())
		{
			wxSize window_max_size = m_window->GetMaxSize();
			
			if(window_max_size.GetWidth() >= 0)
			{
				window_max_size.SetWidth(window_max_size.GetWidth() + GetLeftSashWidth() + GetRightSashWidth());
			}
			
			if(window_max_size.GetHeight() >= 0)
			{
				window_max_size.SetHeight(window_max_size.GetHeight() + GetTopSashHeight() + GetBottomSashHeight());
			}
			
			return window_max_size;
		}
		else{
			/* Window is hidden, no space required. */
			return wxDefaultSize;
		}
	}
}

wxRect REHex::MultiSplitter::Cell::GetRect() const
{
	return m_rect;
}

void REHex::MultiSplitter::Cell::MoveSplitter(const wxPoint &point, bool force)
{
	if(IsHorizontalSplit())
	{
		int top_height = point.y - m_rect.y;
		int bottom_height = m_rect.GetHeight() - top_height;
		
		if(!force)
		{
			wxSize top_min_size = m_top->GetMinSize();
			wxSize bottom_min_size = m_bottom->GetMinSize();
			
			wxSize top_max_size = m_top->GetMaxSize();
			wxSize bottom_max_size = m_bottom->GetMaxSize();
			
			if((top_min_size.GetHeight() >= 0 && top_height < top_min_size.GetHeight())
				|| (bottom_min_size.GetHeight() >= 0 && bottom_height < bottom_min_size.GetHeight())
				|| (top_max_size.GetHeight() >= 0 && top_height > top_max_size.GetHeight())
				|| (bottom_max_size.GetHeight() >= 0 && bottom_height > bottom_max_size.GetHeight()))
			{
				return;
			}
		}
		
		m_top->Resize(wxRect(m_rect.x, m_rect.y, m_rect.width, top_height));
		m_bottom->Resize(wxRect(m_rect.x, (m_rect.y + top_height), m_rect.width, bottom_height));
	}
	else if(IsVerticalSplit())
	{
		int left_width = point.x - m_rect.x;
		int right_width = m_rect.GetWidth() - left_width;
		
		if(!force)
		{
			wxSize left_min_size = m_left->GetMinSize();
			wxSize right_min_size = m_right->GetMinSize();
			
			wxSize left_max_size = m_left->GetMaxSize();
			wxSize right_max_size = m_right->GetMaxSize();
			
			if((left_min_size.GetWidth() >= 0 && left_width < left_min_size.GetWidth())
				|| (right_min_size.GetWidth() >= 0 && right_width < right_min_size.GetWidth())
				|| (left_max_size.GetWidth() >= 0 && left_width > left_max_size.GetWidth())
				|| (right_max_size.GetWidth() >= 0 && right_width > right_max_size.GetWidth()))
			{
				return;
			}
		}
		
		m_left->Resize(wxRect(m_rect.x, m_rect.y, left_width, m_rect.height));
		m_right->Resize(wxRect((m_rect.x + left_width), m_rect.y, right_width, m_rect.height));
	}
}

void REHex::MultiSplitter::Cell::ApplySizeConstraints()
{
	if(IsHorizontalSplit())
	{
		if(!(m_top->IsHidden() || m_bottom->IsHidden()))
		{
			int top_height = m_bottom->GetRect().y - m_rect.y;
			
			int top_min_height = m_top->GetMinSize().GetHeight();
			int bottom_min_height = m_bottom->GetMinSize().GetHeight();
			
			if(top_min_height > 0 && top_height < top_min_height)
			{
				top_height = top_min_height;
			}
			else if(bottom_min_height > 0 && (m_rect.height - top_height) < bottom_min_height)
			{
				top_height = m_rect.height - bottom_min_height;
			}
			
			int top_max_height = m_top->GetMaxSize().GetHeight();
			int bottom_max_height = m_bottom->GetMaxSize().GetHeight();
			
			if(top_max_height > 0 && top_height > top_max_height)
			{
				top_height = top_max_height;
			}
			else if(bottom_max_height > 0 && (m_rect.height - top_height) > bottom_max_height)
			{
				top_height = m_rect.height - bottom_max_height;
			}
			
			m_top->Resize(wxRect(m_rect.x, m_rect.y, m_rect.width, top_height));
			m_bottom->Resize(wxRect(m_rect.x, (m_rect.y + top_height), m_rect.width, (m_rect.height - top_height)));
		}
		
		m_top->ApplySizeConstraints();
		m_bottom->ApplySizeConstraints();
	}
	else if(IsVerticalSplit())
	{
		if(!(m_left->IsHidden() || m_right->IsHidden()))
		{
			int left_width = m_right->GetRect().x - m_rect.x;
			
			int left_min_width = m_left->GetMinSize().GetWidth();
			int right_min_width = m_right->GetMinSize().GetWidth();
			
			if(left_min_width > 0 && left_width < left_min_width)
			{
				left_width = left_min_width;
			}
			else if(right_min_width > 0 && (m_rect.width - left_width) < right_min_width)
			{
				left_width = m_rect.width - right_min_width;
			}
			
			int left_max_width = m_left->GetMaxSize().GetWidth();
			int right_max_width = m_right->GetMaxSize().GetWidth();
			
			if(left_max_width > 0 && left_width > left_max_width)
			{
				left_width = left_max_width;
			}
			else if(right_max_width > 0 && (m_rect.width - left_width) > right_max_width)
			{
				left_width = m_rect.width - right_max_width;
			}
			
			m_left->Resize(wxRect(m_rect.x, m_rect.y, left_width, m_rect.height));
			m_right->Resize(wxRect((m_rect.x + left_width), m_rect.y, (m_rect.width - left_width), m_rect.height));
		}
		
		m_left->ApplySizeConstraints();
		m_right->ApplySizeConstraints();
	}
}

void REHex::MultiSplitter::Cell::SplitHorizontally(wxWindow *window_top, wxWindow *window_bottom, float new_window_weight)
{
	assert(!m_left && !m_right && !m_top && !m_bottom);
	assert(m_window == window_top || m_window == window_bottom);
	
	std::unique_ptr<Cell> new_top(new Cell(m_splitter, this, window_top, new_window_weight));
	std::unique_ptr<Cell> new_bottom(new Cell(m_splitter, this, window_bottom, new_window_weight));
	
	m_top    = std::move(new_top);
	m_bottom = std::move(new_bottom);
	m_window = NULL;
	
	m_resize_bank_lt = 0.0f;
	m_resize_bank_rb = 0.0f;
	
	m_growth_bank_lt = 0;
	m_growth_bank_rb = 0;
	
	m_hidden_lt = false;
	m_hidden_rb = false;
	
	/* Avoid division by zero if both weights are zero. */
	int t_height = m_top->m_weight == m_bottom->m_weight
		? m_rect.height / 2
		: ((float)(m_rect.height) / (m_top->m_weight + m_bottom->m_weight)) * m_top->m_weight;
	
	int b_height = m_rect.height - t_height;
	
	m_top->Resize(wxRect(m_rect.x, m_rect.y, m_rect.width, t_height));
	m_bottom->Resize(wxRect(m_rect.x, (m_rect.y + t_height), m_rect.width, b_height));
}

void REHex::MultiSplitter::Cell::SplitVertically(wxWindow *window_left, wxWindow *window_right, float new_window_weight)
{
	assert(!m_left && !m_right && !m_top && !m_bottom);
	assert(m_window == window_left || m_window == window_right);
	
	std::unique_ptr<Cell> new_left(new Cell(m_splitter, this, window_left, new_window_weight));
	std::unique_ptr<Cell> new_right(new Cell(m_splitter, this, window_right, new_window_weight));
	
	/* The cell which inherits our window should also inherit the existing weight/etc. */
	
	Cell *inheritor = m_window == window_left ? new_left.get() : new_right.get();
	
	inheritor->m_weight = m_weight;
	inheritor->m_drag_border_left = m_drag_border_left;
	inheritor->m_drag_border_right = m_drag_border_right;
	inheritor->m_drag_border_top = m_drag_border_top;
	inheritor->m_drag_border_bottom = m_drag_border_bottom;
	
	m_left   = std::move(new_left);
	m_right  = std::move(new_right);
	m_window = NULL;
	
	m_resize_bank_lt = 0.0f;
	m_resize_bank_rb = 0.0f;
	
	m_growth_bank_lt = 0;
	m_growth_bank_rb = 0;
	
	m_hidden_lt = false;
	m_hidden_rb = false;
	
	/* Avoid division by zero if both weights are zero. */
	int l_width = m_left->m_weight == m_right->m_weight
		? m_rect.width / 2
		: ((float)(m_rect.width) / (m_left->m_weight + m_right->m_weight)) * m_left->m_weight;
	
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
		
		m_drag_border_left = cell->m_drag_border_left;
		m_drag_border_right = cell->m_drag_border_right;
		m_drag_border_top = cell->m_drag_border_top;
		m_drag_border_bottom = cell->m_drag_border_bottom;
		
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
	return _GetLeftNeighbor(this);
}

const REHex::MultiSplitter::Cell *REHex::MultiSplitter::Cell::GetLeftNeighbor() const
{
	return _GetLeftNeighbor(this);
}

template<typename T> T *REHex::MultiSplitter::Cell::_GetLeftNeighbor(T *cell)
{
	T *child = cell;
	T *parent = cell->GetParent();

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
	return _GetRightNeighbor(this);
}

const REHex::MultiSplitter::Cell *REHex::MultiSplitter::Cell::GetRightNeighbor() const
{
	return _GetRightNeighbor(this);
}

template<typename T> T *REHex::MultiSplitter::Cell::_GetRightNeighbor(T *cell)
{
	T *child = cell;
	T *parent = cell->GetParent();

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
	return _GetTopNeighbor(this);
}

const REHex::MultiSplitter::Cell *REHex::MultiSplitter::Cell::GetTopNeighbor() const
{
	return _GetTopNeighbor(this);
}

template<typename T> T *REHex::MultiSplitter::Cell::_GetTopNeighbor(T *cell)
{
	T *child = cell;
	T *parent = cell->GetParent();

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
	return _GetBottomNeighbor(this);
}

const REHex::MultiSplitter::Cell *REHex::MultiSplitter::Cell::GetBottomNeighbor() const
{
	return _GetBottomNeighbor(this);
}

template<typename T> T *REHex::MultiSplitter::Cell::_GetBottomNeighbor(T *cell)
{
	T *child = cell;
	T *parent = cell->GetParent();

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

REHex::MultiSplitterResizeBias::MultiSplitterResizeBias(REHex::MultiSplitter::Cell *root, Edge edge)
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

void REHex::MultiSplitterResizeBias::walk_tree(REHex::MultiSplitter::Cell *cell, Edge edge, bool force_zero)
{
	if(cell->IsVerticalSplit())
	{
		if(edge == Edge::LEFT)
		{
			walk_tree(cell->GetLeftChild(), edge, force_zero);
			walk_tree(cell->GetRightChild(), edge, true);
		}
		else if(edge == Edge::RIGHT)
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
		if(edge == Edge::TOP)
		{
			walk_tree(cell->GetTopChild(), edge, force_zero);
			walk_tree(cell->GetBottomChild(), edge, true);
		}
		else if(edge == Edge::BOTTOM)
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
