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

#ifndef REHEX_CODEANALYSER_HPP
#define REHEX_CODEANALYSER_HPP

#include <capstone/capstone.h>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>
#include <wx/wx.h>

#include "AppSettings.hpp"
#include "ByteRangeSet.hpp"
#include "DataType.hpp"
#include "ThreadPool.hpp"

namespace REHex
{
	/**
	 * @brief DataAnalyser class for disassembling and analysing machine code.
	*/
	class CodeAnalyser: public DataAnalyser
	{
		private:
			static constexpr uint8_t MAX_INSTRUCTION_LENGTH = 24;
			
			struct CachedInstruction {
				off_t rel_offset;  /**< Offset of instruction, relative to m_base_offset. */
				int64_t rel_line;  /**< Line (number) of instruction relative to m_base_offset. */
				
				char instruction[MAX_INSTRUCTION_LENGTH];
				uint8_t length;
				
				std::string disasm;
			};
			
			/**
			 * @brief A range of whole instructions in the file.
			*/
			struct InstructionRange
			{
				off_t offset;  /**< Offset to range within file, relative to m_base_offset. */
				off_t length;  /**< Length of range within file. */
				
				off_t longest_instruction;  /**< Longest instruction in the range, in bytes. */
				size_t longest_disasm;      /**< Longest disassembled instruction, in characters. */
				
				int64_t rel_y_offset;  /**< Y position where this range's disassembly starts in the CodeAnalyser. */
				int64_t y_lines;       /**< Length of this range's disassembly, in lines. */
			};
			
		public:
			/**
			 * @brief A single disassembled instruction.
			*/
			class Instruction
			{
				private:
					BitOffset m_offset;
					int64_t m_line;
					
					char m_instruction[24];
					uint8_t m_length;
					
					std::string m_assembly;
					
				public:
					Instruction(BitOffset offset, int64_t line, const void *instruction, uint8_t length, const std::string &assembly):
						m_offset(offset),
						m_line(line),
						m_length(length),
						m_assembly(assembly)
					{
						assert(length <= sizeof(m_instruction));
						memcpy(m_instruction, instruction, length);
					}
					
					Instruction(): m_offset(BitOffset::INVALID) {}
					
					/**
					 * @brief Get offset of instruction within file.
					*/
					BitOffset offset() const
					{
						assert(m_offset != BitOffset::INVALID);
						return m_offset;
					}
					
					/**
					 * @brief Get the line (instruction) number within the CodeAnalyser range.
					*/
					int64_t line() const
					{
						assert(m_offset != BitOffset::INVALID);
						return m_line;
					}
					
					/**
					 * @brief Get pointer to encoded instruction.
					*/
					const void *instruction() const
					{
						assert(m_offset != BitOffset::INVALID);
						return m_instruction;
					}
					
					/**
					 * @brief Get length of encoded instruction.
					*/
					uint8_t length() const
					{
						assert(m_offset != BitOffset::INVALID);
						return m_length;
					}
					
					/**
					 * @brief Get human-readable disassembly of instruction.
					*/
					const std::string &assembly() const
					{
						assert(m_offset != BitOffset::INVALID);
						return m_assembly;
					}
					
					/**
					 * @brief Check if this object contains a valid instruction.
					*/
					explicit operator bool() const
					{
						return m_offset != BitOffset::INVALID;
					}
			};
			
		private:
			Document *doc;
			
			BitOffset m_base_offset;
			off_t m_data_length;
			
			cs_arch arch;
			size_t disassembler;
			
			ByteRangeSet dirty;                       /**< Bytes which are waiting to be analysed, relative to d_offset */
			std::vector<InstructionRange> processed;  /**< Ranges of up-to-date analysed code. */
			std::vector<CachedInstruction> instructions;    /**< Cached disassembled instructions. */
			
			off_t m_longest_instruction;
			size_t m_longest_disasm;
			
			AsmSyntax preferred_asm_syntax; // TODO
			
			ThreadPool::TaskHandle m_task;
			
			bool analyse_chunk();
			void disasm_instruction(const uint8_t **code, size_t *size, uint64_t *address, cs_insn *insn);
			
		public:
			/**
			 * @brief Find the Instruction which encompasses an offset.
			 *
			 * @param offset  Absolute offset in file.
			 *
			 * NOTE: This method may return an invalid Instruction object if the requested offset
			 * hasn't been analysed yet - check the returned object is true before trying to call
			 * any of the accessor methods.
			*/
			Instruction instruction_by_abs_offset(BitOffset offset);
			
			/**
			 * @brief Find the Instruction on the given line.
			 *
			 * @param base_offset  Absolute position of instruction to offset from.
			 * @param rel_line     Number of lines past base_offset to advance.
			 *
			 * NOTE: This method may return an invalid Instruction object if the requested offset
			 * hasn't been analysed yet - check the returned object is true before trying to call
			 * any of the accessor methods.
			*/
			Instruction instruction_by_line(BitOffset base_offset, int64_t rel_line);
			
			/**
			 * @brief Get the length of the longest processed instruction in bytes.
			*/
			uint8_t longest_instruction() const { return m_longest_instruction; }
			
			/**
			 * @brief Get the length of the longest disassembled instruction in characters.
			*/
			size_t longest_disasm() const { return m_longest_disasm; }
			
			struct AnalysisPosition
			{
				BitOffset offset;
				int64_t line;
			};
			
			AnalysisPosition get_analysis_position() const;
			
			CodeAnalyser(Document *doc, BitOffset offset, BitOffset length, cs_arch arch, cs_mode mode);
			virtual ~CodeAnalyser() override;
			
			/* For unit testing. */
			const ByteRangeSet &get_dirty() const { return dirty; }
			const std::vector<InstructionRange> &get_processed() const { return processed; }
			
			virtual void pause() override;
			virtual void resume() override;
			virtual void refresh(BitOffset offset, BitOffset length) override;
			virtual void rebase(BitOffset offset) override;
			
		private:
			/**
			 * @brief Find the element in processed which encompasses an offset.
			 * @returns Iterator to matching element, or end iterator if none match.
			*/
			std::vector<InstructionRange>::const_iterator processed_by_rel_offset(off_t rel_offset);
			
			/**
			 * @brief Find the element in processed which encompasses a line.
			 * @returns Iterator to matching element, or end iterator if none match.
			*/
			std::vector<InstructionRange>::const_iterator processed_by_line(int64_t rel_line);
			
			/**
			 * @brief Find the Instruction which encompasses an offset.
			 * @returns Reference an interator into CodeAnalyser::instructions, the end if not (yet) available.
			 *
			 * NOTE: This method may disassemble an InstructionRange if the requested Instruction
			 * hasn't been cached, and will invalidate iterators returned by previous calls.
			*/
			std::vector<CachedInstruction>::const_iterator cached_instruction_by_rel_offset(off_t rel_offset);
	};
}

#endif /* !REHEX_CODEANALYSER_HPP */
