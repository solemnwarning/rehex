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

#ifndef REHEX_FASTRECTANGLEFILLER_HPP
#define REHEX_FASTRECTANGLEFILLER_HPP

#include <wx/colour.h>
#include <wx/dc.h>
#include <wx/gdicmn.h>

namespace REHex
{
	/**
	 * @brief Helper class for more efficient filling of adjacent rectangles.
	 *
	 * This is a wrapper for wxDC::DrawRectangle() that will merge successive adjacent
	 * rectangles for efficiency.
	*/
	template<typename T> class FastRectangleFillerImpl
	{
		public:
			FastRectangleFillerImpl(T &dc);
			
			/**
			 * @brief Flush any pending wxDC::DrawRectangle() operation.
			*/
			~FastRectangleFillerImpl();
			
			/**
			 * @brief Prepare a rectangle to be drawn to the DC.
			 *
			 * Merges the rectangle with any previous ones to be drawn as a single
			 * wxDC::DrawRectangle() operation.
			 *
			 * If the current pending rectangle cannot be merged with the new one, it
			 * will be flushed and the new one stored.
			*/
			void fill_rectangle(const wxRect &rect, const wxColour &colour);
			void fill_rectangle(int x, int y, int width, int height, const wxColour &colour);
			
			/**
			 * @brief Flush any pending wxDC::DrawRectangle() operation.
			*/
			void flush();
			
		private:
			T &dc;
			
			wxRect pending_rect;
			wxColour pending_colour;
	};
	
	typedef FastRectangleFillerImpl<wxDC> FastRectangleFiller;
}

template<typename T> REHex::FastRectangleFillerImpl<T>::FastRectangleFillerImpl(T &dc):
	dc(dc) {}

template<typename T> REHex::FastRectangleFillerImpl<T>::~FastRectangleFillerImpl()
{
	flush();
}

template<typename T> void REHex::FastRectangleFillerImpl<T>::fill_rectangle(const wxRect &rect, const wxColour &colour)
{
	if(rect.IsEmpty())
	{
		return;
	}
	
	if(!pending_rect.IsEmpty() && colour == pending_colour)
	{
		wxRect pending_rect2(
			pending_rect.x, pending_rect.y,
			pending_rect.width + 1, pending_rect.height + 1);
		
		wxRect rect2(
			rect.x, rect.y,
			rect.width + 1, rect.height + 1);
		
		if(pending_rect.Contains(rect))
		{
			/* New rect is inside pending rect - nothing to do. */
			return;
		}
		else if(rect.Contains(pending_rect))
		{
			/* Pending rect is inside new rect - expand it. */
			pending_rect = rect;
			return;
		}
		else if(rect2.Intersects(pending_rect2) && (
			(rect.GetTop() == pending_rect.GetTop() && rect.GetBottom() == pending_rect.GetBottom())
			|| (rect.GetLeft() == pending_rect.GetLeft() && rect.GetRight() == pending_rect.GetRight())))
		{
			/* Adjacent or overlapping rectangles of same height/width. */
			pending_rect.Union(rect);
			return;
		}
	}
	
	/* Cannot merge with pending_rect - replace it. */
	
	flush();
	
	pending_rect = rect;
	pending_colour = colour;
}

template<typename T> void REHex::FastRectangleFillerImpl<T>::fill_rectangle(int x, int y, int width, int height, const wxColour &colour)
{
	fill_rectangle(wxRect(x, y, width, height), colour);
}

template<typename T> void REHex::FastRectangleFillerImpl<T>::flush()
{
	if(pending_rect.IsEmpty())
	{
		return;
	}
	
	/* wxDC::SetBrush() is slow on macOS, even if you're using the same one over and over, so
	 * avoid it if we can.
	*/
	const wxBrush &dc_brush = dc.GetBrush();
	if(!dc_brush.IsOk() || dc_brush.GetColour() != pending_colour || dc_brush.GetStyle() != wxBRUSHSTYLE_SOLID)
	{
		dc.SetBrush(wxBrush(pending_colour));
	}
	
	if(dc.GetPen() != *wxTRANSPARENT_PEN)
	{
		dc.SetPen(*wxTRANSPARENT_PEN);
	}
	
	dc.DrawRectangle(pending_rect);
	
	pending_rect.width = 0;
	pending_rect.height = 0;
}

#endif /* !REHEX_FASTRECTANGLEFILLER_HPP */
