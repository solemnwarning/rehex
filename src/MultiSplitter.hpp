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

#ifndef REHEX_MULTISPLITTER_HPP
#define REHEX_MULTISPLITTER_HPP

#include <memory>
#include <vector>
#include <wx/window.h>

#include "util.hpp"

class MultiSplitterTest;

namespace REHex
{
	/**
	* @brief A splitter window, like wxSplitterWindow with more features.
	*/
	class MultiSplitter: public wxWindow
	{
		public:
			/**
			 * @brief A cell in the wxExSplitter hierarchy.
			 *
			 * A cell occupies a region of the screen in a wxExSplitter window and can be in any
			 * of three states:
			 *
			 * - Holding a single window.
			 * - Holding a left and right child (vertically split)
			 * - Holding a top and bottom child (horizontally split)
			 *
			 * In the split case, either or both child cells may be further splits with their
			 * own children to build arbitrarily complex layouts.
			*/
			class Cell
			{
			private:
				const MultiSplitter *m_splitter;
				Cell *m_parent;
			
				wxRect m_rect;
				float m_weight;
				
				int m_drag_border_left;
				int m_drag_border_right;
				int m_drag_border_top;
				int m_drag_border_bottom;
			
				std::unique_ptr<Cell> m_left;
				std::unique_ptr<Cell> m_right;
				std::unique_ptr<Cell> m_top;
				std::unique_ptr<Cell> m_bottom;
			
				wxWindow *m_window;
			
				float m_resize_bank_lt;
				float m_resize_bank_rb;
			
				int m_growth_bank_lt;
				int m_growth_bank_rb;
				
				bool m_hidden_lt;
				bool m_hidden_rb;
			
			public:
				Cell(const MultiSplitter *splitter, Cell *parent, wxWindow *window, float weight);
				
				/**
				 * @brief Set the "weight" of the cell.
				 *
				 * The weight of the cell is used to proportionally grow and shrink
				 * cells when their parent cell is resized.
				 *
				 * In the case of split cells, their weight is ignored and the
				 * weights of their child cells are used instead.
				 *
				 * If a cell has a weight of zero, its size will be preserved and
				 * other cells will grow/shrink as necessary.
				*/
				void SetWeight(float weight);
				
				/**
				 * @brief Get the weight of the cell.
				*/
				float GetWeight() const;
				
				/**
				 * @brief Get the effective horizontal weight of the cell.
				 *
				 * The effective weight of the cell is the weight used by its
				 * parent when proportionally allocating screen area.
				 *
				 * In the case of a horizontal split, the effective horizontal
				 * weight is the sum of the effective horizontal weights of its
				 * children.
				 *
				 * In the case of a vertical split, the effective horizontal
				 * weight is the highest effective horizontal weight of its
				 * children.
				*/
				float GetHorizontalWeight() const;
			
				/**
				 * @brief Get the effective vertical weight of the cell.
				 *
				 * The effective weight of the cell is the weight used by its
				 * parent when proportionally allocating screen area.
				 *
				 * In the case of a horizontal split, the effective vertical
				 * weight is the highest effective vertical weight of its children.
				 *
				 * In the case of a vertical split, the effective vertical
				 * weight is the sum of the effective vertical weights of its
				 * children.
				*/
				float GetVerticalWeight() const;
				
				/**
				 * @brief Set the "drag border" of the cell.
				 * @see REHex::MultiSplitter::SetWindowDragBorder.
				*/
				void SetDragBorder(int drag_border_left, int drag_border_right, int drag_border_top, int drag_border_bottom);
				
				/**
				 * @brief Get the size of the "drag border" on the left edge of this cell's window.
				 * @see REHex::MultiSplitter::SetWindowDragBorder.
				*/
				int GetDragBorderLeft() const;
				
				/**
				 * @brief Get the size of the "drag border" on the right edge of this cell's window.
				 * @see REHex::MultiSplitter::SetWindowDragBorder.
				*/
				int GetDragBorderRight() const;
				
				/**
				 * @brief Get the size of the "drag border" on the top edge of this cell's window.
				 * @see REHex::MultiSplitter::SetWindowDragBorder.
				*/
				int GetDragBorderTop() const;
				
				/**
				 * @brief Get the size of the "drag border" on the bottom edge of this cell's window.
				 * @see REHex::MultiSplitter::SetWindowDragBorder.
				*/
				int GetDragBorderBottom() const;
				
				/**
				 * @brief Reposition and resize the cell.
				 *
				 * @param rect New screen area within the wxExSplitter
				*/
				void Resize(const wxRect &rect);
				
				/**
				 * @brief Get the screen area of the cell.
				 *
				 * @return Screen area of the cell relative to the wxExSplitter window.
				*/
				wxRect GetRect() const;
				
				/**
				 * @brief Move the splitter of a split cell.
				 *
				 * @brief point  Point within the wxExSplitter window.
				 * @brief force  Override window size constraints.
				 *
				 * Moves the splitter of a split cell by repositioning and resizing
				 * the cells on each side of the split.
				*/
				void MoveSplitter(const wxPoint &point, bool force);
				
				/**
				 * @brief Apply size constraints of child cells.
				 *
				 * Moves the splitter of a split cell as required to honor the
				 * current size constraints of any children.
				*/
				void ApplySizeConstraints();
				
				/**
				 * @brief Split the cell horizontally.
				 *
				 * Splits a cell which is not split into a top and bottom window.
				 *
				 * One of the given windows must be the window currently managed by
				 * this cell and the other one should not be in the wxExSplitter cell
				 * hierarchy.
				*/
				void SplitHorizontally(wxWindow *window_top, wxWindow *window_bottom, float new_window_weight);
				
				/**
				 * @brief Split the cell vertically.
				 *
				 * Splits a cell which is not split into a left and right window.
				 *
				 * One of the given windows must be the window currently managed by
				 * this cell and the other one should not be in the wxExSplitter cell
				 * hierarchy.
				*/
				void SplitVertically(wxWindow *window_left, wxWindow *window_right, float new_window_weight);
				
				/**
				 * @brief Remove one of the immediate child cells from a split cell.
				 *
				 * Destroys the cells under this one, removing the given window
				 * from the wxExSplitter hierarchy and taking ownership of the one
				 * managed by the other cell.
				*/
				void RemoveChild(wxWindow *window);
			
				/**
				 * @brief Check if this cell contains a child window.
				*/
				bool IsWindow() const;
			
				/**
				 * @brief Check if this cell contains top and bottom child cells.
				*/
				bool IsHorizontalSplit() const;
			
				/**
				 * @brief Check if this cell contains left and right child cells.
				*/
				bool IsVerticalSplit() const;
				
				/**
				 * @brief Check if this cell is left of another cell.
				 *
				 * This method returns true if the two cells have a common ancestor
				 * which is vertically split, this cell is under the left leg of it
				 * and the other cell is under the right leg.
				*/
				bool IsLeftOf(const Cell *other) const;
				
				/**
				 * @brief Check if this cell is right of another cell.
				 *
				 * This method returns true if the two cells have a common ancestor
				 * which is vertically split, this cell is under the right leg of it
				 * and the other cell is under the left leg.
				*/
				bool IsRightOf(const Cell *other) const;
				
				/**
				 * @brief Check if this cell is above another cell.
				 *
				 * This method returns true if the two cells have a common ancestor
				 * which is horizontally split, this cell is under the top leg of it
				 * and the other cell is under the bottom leg.
				*/
				bool IsAbove(const Cell *other) const;
				
				/**
				 * @brief Check if this cell is below another cell.
				 *
				 * This method returns true if the two cells have a common ancestor
				 * which is horizontally split, this cell is under the left bottom
				 * left of it and the other cell is under the top leg.
				*/
				bool IsBelow(const Cell *other) const;
				
				/**
				 * @brief Get the parent of this cell in the hierarchy.
				*/
				Cell *GetParent();
				
				/**
				 * @brief Get the parent of this cell in the hierarchy.
				*/
				const Cell *GetParent() const;
			
				/**
				 * @brief Get the left child of this cell in the hierarchy.
				*/
				Cell *GetLeftChild();
				
				/**
				 * @brief Get the left child of this cell in the hierarchy.
				*/
				const Cell *GetLeftChild() const;
			
				/**
				 * @brief Get the right child of this cell in the hierarchy.
				*/
				Cell *GetRightChild();
				
				/**
				 * @brief Get the right child of this cell in the hierarchy.
				*/
				const Cell *GetRightChild() const;
			
				/**
				 * @brief Get the top child of this cell in the hierarchy.
				*/
				Cell *GetTopChild();
				
				/**
				 * @brief Get the top child of this cell in the hierarchy.
				*/
				const Cell *GetTopChild() const;
			
				/**
				 * @brief Get the bottom child of this cell in the hierarchy.
				*/
				Cell *GetBottomChild();
				
				/**
				 * @brief Get the bottom child of this cell in the hierarchy.
				*/
				const Cell *GetBottomChild() const;
			
				/**
				 * @brief Get the cell *visibly* to the left of this one in the hierarchy.
				*/
				Cell *GetLeftNeighbor();
				
				/**
				 * @brief Get the cell *visibly* to the left of this one in the hierarchy.
				*/
				const Cell *GetLeftNeighbor() const;
			
				/**
				 * @brief Get the cell *visibly* to the right of this one in the hierarchy.
				*/
				Cell *GetRightNeighbor();
				
				/**
				 * @brief Get the cell *visibly* to the right of this one in the hierarchy.
				*/
				const Cell *GetRightNeighbor() const;
			
				/**
				 * @brief Get the cell *visibly* above this one in the hierarchy.
				*/
				Cell *GetTopNeighbor();
				
				/**
				 * @brief Get the cell *visibly* above this one in the hierarchy.
				*/
				const Cell *GetTopNeighbor() const;
			
				/**
				 * @brief Get the cell *visibly* below this one in the hierarchy.
				*/
				Cell *GetBottomNeighbor();
				
				/**
				 * @brief Get the cell *visibly* below this one in the hierarchy.
				*/
				const Cell *GetBottomNeighbor() const;
			
				/**
				 * @brief Get the wxWindow occupying this cell in the hierarchy.
				*/
				wxWindow *GetWindow() const;
			
				/**
				 * @brief Find the nearest common ancestor of two cells.
				*/
				static Cell *FindCommonAncestor(Cell *cell1, Cell *cell2);
				
				/**
				 * @brief Find the nearest common ancestor of two cells.
				*/
				static const Cell *FindCommonAncestor(const Cell *cell1, const Cell *cell2);
			
				/**
				 * @brief Find the nearest horizontally split ancestor.
				 * @return Pointer to the cell, and whether we are the bottom child.
				*/
				std::pair<Cell*, bool> FindHorizontalSplitAncestor();
				
				/**
				 * @brief Find the nearest horizontally split ancestor.
				 * @return Pointer to the cell, and whether we are the bottom child.
				*/
				std::pair<const Cell*, bool> FindHorizontalSplitAncestor() const;
			
				/**
				 * @brief Find the nearest vertically split ancestor.
				 * @return Pointer to the cell, and whether we are the right child.
				*/
				std::pair<Cell*, bool> FindVerticalSplitAncestor();
				
				/**
				 * @brief Find the nearest vertically split ancestor.
				 * @return Pointer to the cell, and whether we are the right child.
				*/
				std::pair<const Cell*, bool> FindVerticalSplitAncestor() const;
				
				/**
				 * @brief Check if all windows under this cell are hidden.
				*/
				bool IsHidden() const;
				
				/**
				 * @brief Get the minimum screen size for this cell and any children.
				*/
				wxSize GetMinSize() const;
				
				/**
				 * @brief Get the maximum screen size for this cell and any children.
				*/
				wxSize GetMaxSize() const;
				
			private:
				/**
				 * @brief const-agnostic implementation of GetLeftNeighbor().
				*/
				template<typename T> static T *_GetLeftNeighbor(T *cell);
				
				/**
				 * @brief const-agnostic implementation of GetRightNeighbor().
				*/
				template<typename T> static T *_GetRightNeighbor(T *cell);
				
				/**
				 * @brief const-agnostic implementation of GetTopNeighbor().
				*/
				template<typename T> static T *_GetTopNeighbor(T *cell);
				
				/**
				 * @brief const-agnostic implementation of GetBottomNeighbor().
				*/
				template<typename T> static T *_GetBottomNeighbor(T *cell);
				
				/**
				 * @brief const-agnostic implementation of FindCommonAncestor().
				*/
				template<typename T> static T *_FindCommonAncestor(T *cell1, T *cell2);
				
				/**
				 * @brief const-agnostic implementation of FindHorizontalSplitAncestor().
				*/
				template<typename T> static std::pair<T*, bool> _FindHorizontalSplitAncestor(T *cell);
				
				/**
				 * @brief const-agnostic implementation of FindVerticalSplitAncestor().
				*/
				template<typename T> static std::pair<T*, bool> _FindVerticalSplitAncestor(T *cell);
				
				void CalculateResize(int *size_lt, int *size_rb, float weight_lt, float weight_rb, int delta, int target);
				void ResizeWindow();
				
				/**
				 * @brief Get the space inside the left edge of this cell for the sash.
				*/
				int GetLeftSashWidth() const;
				
				/**
				 * @brief Get the space inside the right edge of this cell for the sash.
				*/
				int GetRightSashWidth() const;
				
				/**
				 * @brief Get the space inside the top edge of this cell for the sash.
				*/
				int GetTopSashHeight() const;
				
				/**
				 * @brief Get the space inside the bottom edge of this cell for the sash.
				*/
				int GetBottomSashHeight() const;
			};
			
		private:
			int m_sash_size;
			
			std::unique_ptr<Cell> m_cells;
			
			bool m_resizing;
			Cell *m_resizing_cell;
			Edge m_resizing_edge;
			
		public:
			MultiSplitter(wxWindow *parent);
			virtual ~MultiSplitter();
			
			/**
			 * @brief Add the first window to the splitter.
			*/
			void AddFirst(wxWindow *window, float weight = 1.0f);
			
			/**
			 * @brief Split an existing cell, inserting a new window to the left.
			 *
			 * @param window  New window to be added to the splitter.
			 * @param base    Existing window in the splitter.
			 * @param weight  Weight of the new window.
			 *
			 * The width of the existing cell will be proportionally split between the
			 * new and existing windows based on their weight.
			*/
			void AddLeftOf(wxWindow *window, wxWindow *base, float weight = 1.0f);
			
			/**
			 * @brief Split an existing cell, inserting a new window to the right.
			 *
			 * @param window  New window to be added to the splitter.
			 * @param base    Existing window in the splitter.
			 * @param weight  Weight of the new window.
			 *
			 * The width of the existing cell will be proportionally split between the
			 * new and existing windows based on their weight.
			*/
			void AddRightOf(wxWindow *window, wxWindow *base, float weight = 1.0f);
			
			/**
			 * @brief Split an existing cell, inserting a new window above.
			 *
			 * @param window  New window to be added to the splitter.
			 * @param base    Existing window in the splitter.
			 * @param weight  Weight of the new window.
			 *
			 * The height of the existing cell will be proportionally split between the
			 * new and existing windows based on their weight.
			*/
			void AddAbove(wxWindow *window, wxWindow *base, float weight = 1.0f);
			
			/**
			 * @brief Split an existing cell, inserting a new window below.
			 *
			 * @param window  New window to be added to the splitter.
			 * @param base    Existing window in the splitter.
			 * @param weight  Weight of the new window.
			 *
			 * The height of the existing cell will be proportionally split between the
			 * new and existing windows based on their weight.
			*/
			void AddBelow(wxWindow *window, wxWindow *base, float weight = 1.0f);
			
#if 0 /* NOTE: Disabled due to collision with wxWindow::RemoveChild(), and not used. */
			/**
			 * @brief Remove a child window from the splitter without destroying it.
			*/
			void RemoveChild(wxWindow *window);
#endif
			
			/**
			 * @brief Remove all child windows from the splitter without destroying them.
			*/
			void RemoveAllChildren();
			
			/**
			 * @brief Remove a child window from the splitter and destroy it.
			*/
			void DestroyChild(wxWindow *window);
			
			wxWindow *FindChildByPoint(const wxPoint &point);
			
			/**
			 * @brief Set the "weight" of a window managed by this splitter.
			 *
			 * The weight of the window is used to proportionally grow and shrink windows when
			 * their parent cell is resized.
			 *
			 * If a window has a weight of zero, its size will be preserved and other windows
			 * will grow/shrink as necessary.
			*/
			void SetWindowWeight(wxWindow *window, float weight);
			
			/**
			 * @brief Set the "drag border" area of a window managed by this splitter.
			 *
			 * The drag border of a window is additional area outside of the drag sash but inside
			 * the area of a child window which the user can also click and drag to resize. This is
			 * intended to be used with child controls which have a visible border where the user
			 * may expect to be able to drag to resize the window.
			 *
			 * This functionality will only work for area which is occupied by the direct child of
			 * the splitter, not any of its descendants.
			*/
			void SetWindowDragBorder(wxWindow *window, int drag_border_all);
			
			/**
			 * @brief Set the "drag border" area of a window managed by this splitter.
			 *
			 * The drag border of a window is additional area outside of the drag sash but inside
			 * the area of a child window which the user can also click and drag to resize. This is
			 * intended to be used with child controls which have a visible border where the user
			 * may expect to be able to drag to resize the window.
			 *
			 * This functionality will only work for area which is occupied by the direct child of
			 * the splitter, not any of its descendants.
			*/
			void SetWindowDragBorder(wxWindow *window, int drag_border_left, int drag_border_right, int drag_border_top, int drag_border_bottom);
			
			/**
			 * @brief Set the size of a window managed by this splitter.
			 *
			 * This method will move the splitter(s) around to set the window to the requested
			 * size.
			 *
			 * If there is no vertical split, then the width of the window will not be changed
			 * and if there is no horizontal split, then the height of the window will not be
			 * changed.
			 *
			 * If either the width or height is negative, it will not be changed.
			*/
			void SetWindowSize(wxWindow *window, const wxSize &size);
			
			/**
			 * @brief Apply size constraints of child windows.
			 *
			 * Moves the splitters as required to honor the current size constraints of
			 * any child windows.
			*/
			void ApplySizeConstraints();
			
			/**
			 * @brief Returns the default sash size in pixels.
			 * @see wxSplitterWindow::GetDefaultSashSize().
			*/
			int GetDefaultSashSize() const;
	
			/**
			 * @brief Get the configured sash size in pixels.
			*/
			int GetSashSize() const;
			
			/**
			 * @brief Get the sash size in two halves.
			 *
			 * This method returns the sash size divided into two not necessarily
			 * equal halves to account for truncation.
			*/
			std::pair<int, int> GetDividedSashSize() const;
	
			/**
			 * @brief Set the configured sash size in pixels.
			*/
			void SetSashSize(int sash_size);
			
			/**
			 * @brief Get the Cell at the root of the splitter hierarchy.
			*/
			const Cell *GetRootCell() const;
			
			/**
			 * @brief Find the Cell object for a child of the splitter.
			*/
			const Cell *FindCellByWindow(wxWindow *window) const;
			
			/**
			 * @brief Find the deepest cell covering a point in the splitter's client area.
			*/
			const Cell *FindCellByPoint(const wxPoint &point) const;
			
		private:
			/**
			 * @brief Find the Cell object for a child of the splitter.
			*/
			Cell *_FindCellByWindow(wxWindow *window);
			
			/**
			 * @brief const-agnostic implementation of FindCellByWindow().
			*/
			template<typename T> static T *_FindCellByWindow(T *cell, wxWindow *window);
			
			/**
			 * @brief Find the deepest cell covering a point in the splitter's client area.
			*/
			Cell *_FindCellByPoint(const wxPoint &point);
			
			/**
			 * @brief const-agnostic implementation of FindCellByPoint().
			*/
			template<typename T> static T *_FindCellByPoint(T *cell, const wxPoint &point);
			
			/**
			 * @brief Begin resizing a cell by dragging the edge in response to the left mouse button being pressed.
			*/
			void BeginResize(Cell *cell, Edge edge);
			
			void OnPaint(wxPaintEvent &event);
			void OnSize(wxSizeEvent &event);
			void OnMouseEnter(wxMouseEvent &event);
			void OnMouseLeave(wxMouseEvent &event);
			void OnMouseMotion(wxMouseEvent &event);
			void OnMouseLeftDown(wxMouseEvent &event);
			void OnMouseLeftUp(wxMouseEvent &event);
			void OnMouseCaptureLost(wxMouseCaptureLostEvent &event);
			
			void OnChildShowHide(wxShowEvent &event);
			void OnChildMouseMotion(wxMouseEvent &event);
			void OnChildMouseLeftDown(wxMouseEvent &event);
			
		DECLARE_EVENT_TABLE()
		
		friend MultiSplitterTest;
	};
	
	/**
	 * @brief Temporarily set all the weight in a cell hierarchy to one edge.
	 *
	 * Constructing this object (for example) with Edge::LEFT will set the weight of all windows
	 * against the left edge of the hierarchy under root to 1.0f and all others to 0.0f. Their original
	 * weights will be restored when the object is destroyed.
	*/
	class MultiSplitterResizeBias
	{
		private:
			std::vector<std::pair<MultiSplitter::Cell*,float>> m_saved_weights;
			
		public:
			MultiSplitterResizeBias(MultiSplitter::Cell *root, Edge edge);
			~MultiSplitterResizeBias();
			
		private:
			void walk_tree(MultiSplitter::Cell *cell, Edge edge, bool force_zero);
	};
}

#endif /* !REHEX_MULTISPLITTER_HPP */
