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

#ifndef REHEX_PROCEDURALBITMAP_HPP
#define REHEX_PROCEDURALBITMAP_HPP

#include <wx/control.h>

namespace REHex
{
	/**
	 * @brief Control for displaying dynamically generated bitmaps.
	 *
	 * This control displays a bitmap which is rendered in chunks on demand rather than kept in
	 * memory in its entirety, allowing for displaying portions of a very large image efficiently.
	 *
	 * Users of this control must subclass it and implement the render_rect() method to render the
	 * bitmap on demand. If the content of the backing image is changed, call Refresh() to force it
	 * to be updated.
	*/
	class ProceduralBitmap: public wxControl
	{
		public:
			/**
			 * @brief Construct a new ProceduralBitmap control.
			 *
			 * @param parent  Parent window.
			 * @param id      Window ID.
			 * @param size    Size of the bitmap to display.
			 * @param pos     Position of control.
			 * @param style   Style flags for control.
			*/
			ProceduralBitmap(wxWindow *parent, wxWindowID id, const wxSize &size, const wxPoint &pos = wxDefaultPosition, long style = 0);
			
			virtual ~ProceduralBitmap() override = default;
			
			/**
			 * @brief Update the virtual bitmap size and redraw.
			*/
			void set_bitmap_size(const wxSize &size);
			
			/**
			 * @brief Get the size of the virtual bitmap.
			*/
			wxSize get_bitmap_size() const;
			
		protected:
			/**
			 * @brief Render a rectangle of the backing image.
			 *
			 * This method is called by the base class to render portions of the image on demand
			 * when the control needs to be painted.
			*/
			virtual wxBitmap render_rect(const wxRect &rect) = 0;
			
		private:
			wxSize m_bitmap_size;
			
			int m_scroll_x;
			int m_scroll_x_max;
			int m_scroll_y;
			int m_scroll_y_max;
			
			int m_wheel_x_accum;
			int m_wheel_y_accum;
			
			wxSize m_client_size;
			
			void update_scroll_ranges();
			
			void OnPaint(wxPaintEvent &event);
			void OnSize(wxSizeEvent &event);
			void OnScroll(wxScrollWinEvent &event);
			void OnWheel(wxMouseEvent &event);
			
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_PROCEDURALBITMAP_HPP */
