/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_FIXEDSIZEVALUEREGION_HPP
#define REHEX_FIXEDSIZEVALUEREGION_HPP

#include <assert.h>
#include <exception>
#include <inttypes.h>
#include <stdint.h>
#include <wx/clipbrd.h>
#include <wx/dataobj.h>
#include <wx/utils.h>

#include "DataType.hpp"
#include "document.hpp"
#include "DocumentCtrl.hpp"
#include "SharedDocumentPointer.hpp"

namespace REHex
{
	/**
	 * @brief Region class for displaying a single fixed-size value.
	 *
	 * This (base) class can be used for displaying a single value of a
	 * known size (e.g. an integer).
	 *
	 * This class must be subclassed and the load_value() and store_value()
	 * methods implemented in the chlid class to handle loading and storing
	 * the value as a string.
	 *
	 * The value must occupy one line of text and screen space will be
	 * reserved as such.
	*/
	class FixedSizeValueRegion: public DocumentCtrl::GenericDataRegion
	{
		protected:
			SharedDocumentPointer doc;
			
		private:
			std::string type_label;
			
			static const int MAX_INPUT_LEN = 20;               /* Wide enough for any decimal 64-bit value. */
			static const int TYPE_X_CHAR = MAX_INPUT_LEN + 2;  /**< X position to display type relative to left edge of data, in characters. */
			static const int TYPE_MAX_LEN = 5;                 /**< Maximum length of type_label. */
			
			int offset_text_x;  /**< Virtual X coord of left edge of offsets, in pixels. */
			int data_text_x;    /**< Virtual X coord of left edge of data, in pixels. */
			
			bool input_active;      /**< Is the user typing a new value for this range in? */
			std::string input_buf;  /**< Input text buffer, empty when input_active is false. */
			size_t input_pos;       /**< Insert cursor position in input_buf, zero when input_active is false. */
			
			void activate();
			void commit();
			bool partially_selected(DocumentCtrl *doc_ctrl);
			
		protected:
			FixedSizeValueRegion(SharedDocumentPointer &doc, BitOffset offset, BitOffset length, BitOffset virt_offset, const std::string &type_label);
			
			/**
			 * @brief Load the value from the file for display.
			 *
			 * Loads the value from the file (at d_offset) and
			 * formats it as a string suitable for display/editing
			 * by the user.
			*/
			virtual std::string load_value() const = 0;
			
			/**
			 * @brief Store the value into the file.
			 *
			 * Parses the value as modified by the user and stores
			 * it into the file (at d_offset).
			 *
			 * Returns true if the value was accepted, false if it
			 * was improperly formatted or otherwise invalid.
			*/
			virtual bool store_value(const std::string &value) = 0;
			
			virtual int calc_width(DocumentCtrl &doc_ctrl) override;
			virtual void calc_height(DocumentCtrl &doc_ctrl) override;
			virtual void draw(DocumentCtrl &doc_ctrl, wxDC &dc, int x, int64_t y) override;
			virtual std::pair<BitOffset, ScreenArea> offset_at_xy(DocumentCtrl &doc_ctrl, int mouse_x_px, int64_t mouse_y_lines) override;
			virtual std::pair<BitOffset, ScreenArea> offset_near_xy(DocumentCtrl &doc_ctrl, int mouse_x_px, int64_t mouse_y_lines, ScreenArea type_hint) override;
			
			virtual BitOffset cursor_left_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl) override;
			virtual BitOffset cursor_right_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl) override;
			virtual BitOffset cursor_up_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl) override;
			virtual BitOffset cursor_down_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl) override;
			virtual BitOffset cursor_home_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl) override;
			virtual BitOffset cursor_end_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl) override;
			
			virtual int cursor_column(BitOffset pos) override;
			virtual BitOffset first_row_nearest_column(int column) override;
			virtual BitOffset last_row_nearest_column(int column) override;
			virtual BitOffset nth_row_nearest_column(int64_t row, int column) override;
			
			virtual DocumentCtrl::Rect calc_offset_bounds(BitOffset offset, DocumentCtrl *doc_ctrl) override;
			virtual ScreenArea screen_areas_at_offset(BitOffset offset, DocumentCtrl *doc_ctrl) override;
			
			virtual bool OnChar(DocumentCtrl *doc_ctrl, wxKeyEvent &event) override;
			virtual wxDataObject *OnCopy(DocumentCtrl &doc_ctrl) override;
			virtual bool OnPaste(DocumentCtrl *doc_ctrl) override;
	};
}

#endif /* !REHEX_FIXEDSIZEVALUEREGION_HPP */
