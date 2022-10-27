/* Reverse Engineer's Hex Editor
 * Copyright (C) 2019-2022 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_RANGEDIALOG_HPP
#define REHEX_RANGEDIALOG_HPP

#include <wx/dialog.h>
#include <wx/radiobut.h>
#include <utility>

#include "DocumentCtrl.hpp"
#include "NumericTextCtrl.hpp"

namespace REHex {
	/**
	 * @brief Dialog for entering a range.
	 *
	 * This allows entering a range by start and end offset, or start offset and length.
	 *
	 * If virtual mappings are being displayed, then all offsets and lengths are shown and read
	 * are in the virtual address space.
	 *
	 * The document size/mappings/etc MUST NOT change after this dialog is set up - the typical
	 * pattern is to create a RangeDialog, optionally initialise the range, use ShowModal() and
	 * then dispose of it before performing other operations.
	*/
	class RangeDialog: public wxDialog
	{
		public:
			/**
			 * @brief Create a RangeDialog object.
			 *
			 * @param parent           Parent wxWindow object.
			 * @param document_ctrl    DocumentCtrl to use the file address space from.
			 * @param title            Title for the dialog.
			 * @param allow_nonlinear  If true, nonlinear ranges may be entered.
			*/
			RangeDialog(wxWindow *parent, DocumentCtrl *document_ctrl, const wxString &title, bool allow_nonlinear);
			
			virtual ~RangeDialog();
			
			/**
			 * @brief Checks if a valid range has been set.
			*/
			bool range_valid() const;
			
			/**
			 * @brief Sets a range using a pair of (real) offsets.
			 *
			 * @param first First offset in the range.
			 * @param last  Last offset in the range.
			*/
			void set_range_raw(off_t first, off_t last);
			
			/**
			 * @brief Returns the first/last real offsets in the range.
			 *
			 * The range is valid if both fields are >= 0.
			*/
			std::pair<off_t, off_t> get_range_raw() const;
			
			/**
			 * @brief Set a range from a real offset and (linear) length.
			*/
			void set_range_linear(off_t offset, off_t length);
			
			/**
			 * @brief Get the chosen linear range.
			 *
			 * If no (or a nonlinear) range has been entered, a range of length zero
			 * will be returned.
			*/
			std::pair<off_t, off_t> get_range_linear() const;
			
			/**
			 * @brief Fill in the offset input in the dialog.
			 *
			 * Intended for suggesting a start point (e.g. the cursor position) when
			 * there is no existing range to base the range on.
			*/
			void set_offset_hint(off_t offset);
			
		private:
			DocumentCtrl *document_ctrl;
			bool allow_nonlinear;
			
			NumericTextCtrl *range_from;
			
			wxRadioButton *range_to_enable;
			NumericTextCtrl *range_to;
			
			wxRadioButton *range_len_enable;
			NumericTextCtrl *range_len;
			
			off_t range_first;
			off_t range_last;
			
			void enable_inputs();
			
			void OnOK(wxCommandEvent &event);
			void OnRadio(wxCommandEvent &event);
			
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_RANGEDIALOG_HPP */
