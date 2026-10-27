/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2026 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_DISASSEMBLYREGION_HPP
#define REHEX_DISASSEMBLYREGION_HPP

#include <stddef.h>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>
#include <wx/wx.h>

#include "AppSettings.hpp"
#include "ByteRangeSet.hpp"
#include "CodeAnalyser.hpp"
#include "DocumentCtrl.hpp"
#include "Events.hpp"
#include "SharedDocumentPointer.hpp"

namespace REHex
{
	class DisassemblyRegion: public DocumentCtrl::GenericDataRegion
	{
		private:
			SharedDocumentPointer doc;
			RangeTextColourFunction text_colour_func;
			
			int offset_text_x;  /**< X co-ordinate of left edge of offsets. */
			int hex_text_x;     /**< X co-ordinate of left edge of hex data. */
			int code_text_x;    /**< X co-ordinate of left edge of disassembly. */
			int ascii_text_x;
			
			off_t longest_instruction;
			size_t longest_disasm;
			
			AsmSyntax preferred_asm_syntax;
			
			CodeAnalyser *get_analyser();
			
			struct AnalysisPosition
			{
				BitOffset offset;
				int64_t line;
			};
			
			AnalysisPosition get_analysis_position(CodeAnalyser *analyser) const;
			
		public:
			off_t max_bytes_per_line() const;
			
			DisassemblyRegion(SharedDocumentPointer &doc, BitOffset offset, BitOffset length, BitOffset virt_offset, const GenericDataRegion::RangeTextColourFunction &text_colour_func);
			virtual ~DisassemblyRegion() override = default;
			
			virtual int calc_width(DocumentCtrl &doc_ctrl) override;
			virtual void calc_height(DocumentCtrl &doc_ctrl) override;
			
			virtual void draw(DocumentCtrl &doc_ctrl, wxDC &dc, int x, int64_t y) override;
			
			virtual unsigned int check() override;
			
			virtual std::pair<BitOffset, ScreenArea> offset_at_xy(DocumentCtrl &doc_ctrl, int mouse_x_px, int64_t mouse_y_lines) override;
			virtual std::pair<BitOffset, ScreenArea> offset_near_xy(DocumentCtrl &doc_ctrl, int mouse_x_px, int64_t mouse_y_lines, ScreenArea type_hint) override;
			
			virtual BitOffset cursor_left_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl) override;
			virtual BitOffset cursor_right_from(BitOffset pos, ScreenArea active_area, DocumentCtrl *doc_ctrl) override;
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
			
			virtual wxDataObject *OnCopy(DocumentCtrl &doc_ctrl) override;
	};
}

#endif /* !REHEX_DISASSEMBLYREGION_HPP */
