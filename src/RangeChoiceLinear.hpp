/* Reverse Engineer's Hex Editor
 * Copyright (C) 2022-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_RANGECHOICELINEAR_HPP
#define REHEX_RANGECHOICELINEAR_HPP

#include <wx/choice.h>
#include <utility>

#include "BitOffset.hpp"
#include "DocumentCtrl.hpp"
#include "Events.hpp"
#include "SafeWindowPointer.hpp"
#include "SharedDocumentPointer.hpp"

namespace REHex
{
	/**
	 * @brief A wxChoice-derived control for selecting a LINEAR range in a file.
	 *
	 * This is intended to be used as a persistent control for selecting a range of data in a
	 * file to be processed/analysed.
	 *
	 * Raises an EV_SELECTION_CHANGED event whenever the byte range changes either directly
	 * because the user changed the range control or indirectly because a dynamic choice like
	 * "the whole file" was selected and the file size changed.
	*/
	class RangeChoiceLinear: public wxChoice
	{
		public:
			RangeChoiceLinear(wxWindow *parent, wxWindowID id, SharedDocumentPointer &document, DocumentCtrl *doc_ctrl);
			virtual ~RangeChoiceLinear();
			
			/**
			 * @brief Get the current range.
			 *
			 * Returns the offset and length of the chosen range. Length will be zero
			 * if no data is selected.
			*/
			std::pair<BitOffset, BitOffset> get_range() const;
			
			/**
			 * @brief Check if "Whole file" is selected.
			*/
			bool is_whole_file() const;
			
			void set_whole_file();
			void set_follow_selection();
			
			/**
			 * @brief Set whether bit-aligned offsets are allowed.
			 *
			 * If this is enabled, then ranges with bit-aligned offsets will be
			 * permitted. Disabled by default.
			*/
			void set_allow_bit_aligned_offset(bool allow_bit_aligned_offset);
			
			/**
			 * @brief Set whether bit-aligned lengths are allowed.
			 *
			 * If this is enabled, then ranges which are not a whole number of bytes
			 * in length are permitted. Disabled by default.
			*/
			void set_allow_bit_aligned_length(bool allow_bit_aligned_length);
			
		private:
			SharedDocumentPointer document;
			SafeWindowPointer<DocumentCtrl> doc_ctrl;
			
			bool allow_bit_aligned_offset;
			bool allow_bit_aligned_length;
			
			int current_selection;
			BitOffset current_offset, current_length;
			
			BitOffset fixed_offset, fixed_length;
			
			void update_range();
			void set_fixed_range(BitOffset offset, BitOffset length);
			void clear_fixed_range();
			
			void OnChoice(wxCommandEvent &event);
			
			void OnDocumentDataErase(OffsetLengthEvent &event);
			void OnDocumentDataInsert(OffsetLengthEvent &event);
			void OnSelectionChanged(wxCommandEvent &event);
	};
}

#endif /* !REHEX_RANGECHOICELINEAR_HPP */
