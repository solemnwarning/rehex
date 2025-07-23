/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_BITMAPTOOL_HPP
#define REHEX_BITMAPTOOL_HPP

#include <wx/checkbox.h>
#include <wx/choice.h>
#include <wx/sizer.h>
#include <wx/spinctrl.h>
#include <wx/toolbar.h>

#include "BitOffset.hpp"
#include "document.hpp"
#include "NumericTextCtrl.hpp"
#include "ProceduralBitmap.hpp"
#include "SafeWindowPointer.hpp"
#include "SharedDocumentPointer.hpp"
#include "ToolPanel.hpp"

namespace REHex {
	class BitmapTool: public ToolPanel
	{
		public:
			enum PixelFormat {
				PIXEL_FMT_1BPP,
				PIXEL_FMT_2BPP,
				PIXEL_FMT_4BPP,
				
				PIXEL_FMT_8BPP_GREYSCALE,
				PIXEL_FMT_8BPP_RGB332,
				
				PIXEL_FMT_16BPP_RGB565,
				PIXEL_FMT_16BPP_RGB555,
				PIXEL_FMT_16BPP_RGB444,
				PIXEL_FMT_16BPP_ARGB1555,
				PIXEL_FMT_16BPP_BGR565,
				PIXEL_FMT_16BPP_BGR555,
				PIXEL_FMT_16BPP_BGR444,
				
				PIXEL_FMT_24BPP_RGB888,
				
				PIXEL_FMT_32BPP_RGBA8888,
			};
			
			BitmapTool(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			
			virtual std::string name() const override;
			virtual std::string label() const override;
			virtual Shape shape() const override;
			
			virtual void save_state(wxConfig *config) const override;
			virtual void load_state(wxConfig *config) override;
			
			virtual wxSize DoGetBestClientSize() const override;
			
			void set_image_offset(BitOffset offset);
			
			void set_image_size(int width, int height);
			wxSize get_image_size() const;
			
			void set_pixel_format(PixelFormat format);
			void set_flip_x(bool flip_x);
			void set_flip_y(bool flip_y);
			void set_row_length(int row_length);
			
			/**
			 * @brief Render a portion of the image to a wxBitmap.
			 *
			 * @param bitmap      wxBitmap to render into.
			 * @param image_rect  Rectangle from the image to render.
			 * @param blend_bg    Blend pixels over existing bitmap.
			 *
			 * This method renders a rectangle of the selected image into a wxBitmap, scaling it if
			 * the size of the bitmap doesn't match the rectangle size.
			*/
			template<typename PDT> void render_rect(wxBitmap *bitmap, const wxRect &image_rect, bool blend_bg);
			
		private:
			SharedDocumentPointer document;
			SafeWindowPointer<DocumentCtrl> document_ctrl;
			
			NumericTextCtrl *offset_textctrl;
			wxCheckBox *offset_follow_cb;
			wxSpinCtrl *width_textctrl;
			wxSpinCtrl *height_textctrl;
			wxChoice *pixel_fmt_choice;
			wxChoice *colour_fmt_choice;
			wxCheckBox *row_packed_cb;
			wxSpinCtrl *row_length_spinner;
			wxToolBar *toolbar;
			
			class Preview: public ProceduralBitmap
			{
				private:
					BitmapTool *m_parent;
					wxColour m_bg;
					
				public:
					Preview(BitmapTool *parent, const wxSize &size);
					
					void set_bg(const wxColour &bg);
				
				protected:
					virtual wxBitmap render_rect(const wxRect &rect) override;
					
				private:
					void fill_bg(wxBitmap *bitmap, int base_x, int base_y);
			};
			
			Preview *m_preview;
			wxBoxSizer *m_preview_sizer;
			
			BitOffset image_offset;
			int image_width, image_height;
			int row_length;
			
			int pixel_fmt_div;      /* Number of (possibly partial) pixels per byte */
			int pixel_fmt_multi;    /* Number of bytes to consume per pixel */
			int pixel_fmt_bits;     /* Mask of bits to consume for first pixel in byte */
			
			std::function<wxColour(uint32_t)> colour_fmt_conv;
			
			bool fit_to_screen;
			bool actual_size;
			int zoom;
			
			int bitmap_width, bitmap_height;
			
			void document_unbind();
			
			void update_colour_format_choices();
			void update_pixel_fmt();
			void reset_row_length_spinner();
			
			void update();
			
			void OnDocumentDestroy(wxWindowDestroyEvent &event);
			void OnCursorUpdate(CursorUpdateEvent &event);
			void OnDepth(wxCommandEvent &event);
			void OnFormat(wxCommandEvent &event);
			void OnFollowCursor(wxCommandEvent &event);
			void OnImageWidth(wxSpinEvent &event);
			void OnImageHeight(wxSpinEvent &event);
			void OnRowsPacked(wxCommandEvent &event);
			void OnRowLength(wxSpinEvent &event);
			void OnFit(wxCommandEvent &event);
			void OnActualSize(wxCommandEvent &event);
			void OnZoomIn(wxCommandEvent &event);
			void OnZoomOut(wxCommandEvent &event);
			void OnBackground(wxCommandEvent &event);
			void OnXXX(wxCommandEvent &event);
			void OnSize(wxSizeEvent &event);
			void OnBitmapRightDown(wxMouseEvent &event);
			
			/* Stays at the bottom because it changes the protection... */
			DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_BITMAPTOOL_HPP */
