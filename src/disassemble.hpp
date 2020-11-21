/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_DISASSEMBLE_HPP
#define REHEX_DISASSEMBLE_HPP

#include <capstone/capstone.h>
#include <map>
#include <string>
#include <utility>
#include <wx/choice.h>
#include <wx/panel.h>
#include <wx/wx.h>

#include "ByteRangeSet.hpp"
#include "CodeCtrl.hpp"
#include "document.hpp"
#include "Events.hpp"
#include "SafeWindowPointer.hpp"
#include "SharedDocumentPointer.hpp"
#include "ToolPanel.hpp"

namespace REHex {
	class Disassemble: public ToolPanel
	{
		public:
			Disassemble(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			virtual ~Disassemble();
			
			virtual std::string name() const override;
// 			virtual std::string label() const override;
// 			virtual Shape shape() const override;
			
			virtual void save_state(wxConfig *config) const override;
			virtual void load_state(wxConfig *config) override;
			virtual void update() override;
			
			virtual wxSize DoGetBestClientSize() const override;
			
		private:
			struct Instruction {
				off_t length;
				std::string disasm;
			};
			
			SharedDocumentPointer document;
			SafeWindowPointer<DocumentCtrl> document_ctrl;
			
			size_t disassembler;
			
			wxChoice *arch;
			CodeCtrl *assembly;
			
			void reinit_disassembler();
			std::map<off_t, Instruction> disassemble(off_t offset, const void *code, size_t size);
			
			void OnCursorUpdate(CursorUpdateEvent &event);
			void OnArch(wxCommandEvent &event);
			void OnDataModified(OffsetLengthEvent &event);
			void OnBaseChanged(wxCommandEvent &event);
			
			/* Stays at the bottom because it changes the protection... */
			DECLARE_EVENT_TABLE()
	};
	
	class DisassemblyRegion: public DocumentCtrl::GenericDataRegion
	{
		private:
			SharedDocumentPointer doc;
			
			size_t disassembler;
			
			int offset_text_x;
			int hex_text_x;
			int code_text_x;
			
			struct Instruction {
				off_t offset, length;
				std::vector<unsigned char> data;
				std::string disasm;
			};
			
			struct InstructionRange
			{
				off_t offset, length;
				
				off_t longest_instruction;
				size_t longest_disasm;
				
				int64_t rel_y_offset;
				int64_t y_lines;
			};
			
			ByteRangeSet dirty;                       /**< Bytes which are waiting to be analysed. */
			std::vector<InstructionRange> processed;  /**< Ranges of up-to-date analysed code. */
			std::vector<Instruction> instructions;    /**< Recently disassembled instructions. */
			
			off_t longest_instruction;
			size_t longest_disasm;
			
			off_t unprocessed_offset() const;
			off_t unprocessed_bytes() const;
			
			/**
			 * @brief Find the element in processed which encompasses an offset.
			 * @returns Iterator to matching element, or end iterator if none match.
			*/
			std::vector<InstructionRange>::iterator processed_by_offset(off_t abs_offset);
			
			/**
			 * @brief Find the element in processed which encompasses a line.
			 * @returns Iterator to matching element, or end iterator if none match.
			*/
			std::vector<InstructionRange>::iterator processed_by_line(int64_t rel_line);
			
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
			
		public:
			DisassemblyRegion(SharedDocumentPointer &doc, off_t offset, off_t length, cs_arch arch, cs_mode mode);
			~DisassemblyRegion();
			
		protected:
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
	};
}

#endif /* !REHEX_DISASSEMBLE_HPP */
