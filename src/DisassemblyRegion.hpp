/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2022 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <capstone/capstone.h>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>
#include <wx/wx.h>

#include "AppSettings.hpp"
#include "ByteRangeSet.hpp"
#include "DocumentCtrl.hpp"
#include "Events.hpp"
#include "SharedDocumentPointer.hpp"

namespace REHex
{
	class DisassemblyRegion: public DocumentCtrl::GenericDataRegion
	{
		public:
			struct Instruction {
				off_t offset, length;
				std::vector<unsigned char> data;
				std::string disasm;
				int64_t rel_y_offset;
			};
			
			/**
			 * @brief A range of whole instructions in the file.
			*/
			struct InstructionRange
			{
				off_t offset;  /**< Offset to range within file. */
				off_t length;  /**< Length of range within file. */
				
				off_t longest_instruction;  /**< Longest instruction in the range, in bytes. */
				size_t longest_disasm;      /**< Longest disassembled instruction, in characters. */
				
				int64_t rel_y_offset;  /**< Y position where this range's disassembly starts in the DisassemblyRegion. */
				int64_t y_lines;       /**< Length of this range's disassembly, in lines. */
			};
			
		private:
			SharedDocumentPointer doc;
			off_t virt_offset;
			
			cs_arch arch;
			size_t disassembler;
			
			int offset_text_x;  /**< X co-ordinate of left edge of offsets. */
			int hex_text_x;     /**< X co-ordinate of left edge of hex data. */
			int code_text_x;    /**< X co-ordinate of left edge of disassembly. */
			int ascii_text_x;
			
			ByteRangeSet dirty;                       /**< Bytes which are waiting to be analysed. */
			std::vector<InstructionRange> processed;  /**< Ranges of up-to-date analysed code. */
			std::vector<Instruction> instructions;    /**< Cached disassembled instructions. */
			
			off_t longest_instruction;
			size_t longest_disasm;
			
			AsmSyntax preferred_asm_syntax;
			
			void disasm_instruction(const uint8_t **code, size_t *size, uint64_t *address, cs_insn *insn);
			
			void OnDataOverwrite(OffsetLengthEvent &event);
			
		public:
			off_t unprocessed_offset() const;
			off_t unprocessed_bytes() const;
			int64_t processed_lines() const;
			
			off_t max_bytes_per_line() const;
			
			/**
			 * @brief Find the element in processed which encompasses an offset.
			 * @returns Iterator to matching element, or end iterator if none match.
			*/
			std::vector<InstructionRange>::const_iterator processed_by_offset(off_t abs_offset);
			
			/**
			 * @brief Find the element in processed which encompasses a line.
			 * @returns Iterator to matching element, or end iterator if none match.
			*/
			std::vector<InstructionRange>::const_iterator processed_by_line(int64_t rel_line);
			
			/**
			 * @brief Find the Instruction which encompasses an offset.
			 * @returns Reference to vector and iterator to element, or end iterator on error.
			 *
			 * NOTE: This method may disassemble an InstructionRange if the requested
			 * Instruction hasn't been cached, and may invalidate references/iterators
			 * returned by previous calls.
			*/
			std::pair<const std::vector<Instruction>&, std::vector<Instruction>::const_iterator> instruction_by_offset(off_t abs_offset);
			
			/**
			 * @brief Find the Instruction on the given line.
			 * @returns Reference to vector and iterator to element, or end iterator on error.
			 *
			 * NOTE: This method may disassemble an InstructionRange if the requested
			 * Instruction hasn't been cached, and may invalidate references/iterators
			 * returned by previous calls.
			*/
			std::pair<const std::vector<Instruction>&, std::vector<Instruction>::const_iterator> instruction_by_line(int64_t rel_line);
			
			DisassemblyRegion(SharedDocumentPointer &doc, off_t offset, off_t length, off_t virt_offset, cs_arch arch, cs_mode mode);
			~DisassemblyRegion();
			
			/* For unit testing. */
			const ByteRangeSet &get_dirty() const { return dirty; }
			const std::vector<InstructionRange> &get_processed() const { return processed; }
			
			virtual int calc_width(DocumentCtrl &doc_ctrl) override;
			virtual void calc_height(DocumentCtrl &doc_ctrl, wxDC &dc) override;
			
			virtual void draw(DocumentCtrl &doc_ctrl, wxDC &dc, int x, int64_t y) override;
			
			virtual unsigned int check() override;
			
			virtual std::pair<off_t, ScreenArea> offset_at_xy(DocumentCtrl &doc_ctrl, int mouse_x_px, int64_t mouse_y_lines) override;
			virtual std::pair<off_t, ScreenArea> offset_near_xy(DocumentCtrl &doc_ctrl, int mouse_x_px, int64_t mouse_y_lines, ScreenArea type_hint) override;
			
			virtual off_t cursor_left_from(off_t pos) override;
			virtual off_t cursor_right_from(off_t pos) override;
			virtual off_t cursor_up_from(off_t pos) override;
			virtual off_t cursor_down_from(off_t pos) override;
			virtual off_t cursor_home_from(off_t pos) override;
			virtual off_t cursor_end_from(off_t pos) override;
			
			virtual int cursor_column(off_t pos) override;
			virtual off_t first_row_nearest_column(int column) override;
			virtual off_t last_row_nearest_column(int column) override;
			virtual off_t nth_row_nearest_column(int64_t row, int column) override;
			
			virtual DocumentCtrl::Rect calc_offset_bounds(off_t offset, DocumentCtrl *doc_ctrl) override;
			virtual ScreenArea screen_areas_at_offset(off_t offset, DocumentCtrl *doc_ctrl) override;
			
			virtual wxDataObject *OnCopy(DocumentCtrl &doc_ctrl) override;
	};
}

#endif /* !REHEX_DISASSEMBLYREGION_HPP */
