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

#include "platform.hpp"

#include <algorithm>
#include <capstone/capstone.h>
#include <iterator>
#include <numeric>
#include <string.h>
#include <tuple>
#include <vector>

#include "App.hpp"
#include "CodeAnalyser.hpp"
#include "util.hpp"

static const off_t SOFT_IR_LIMIT = 10240; /* 100KiB */
static const size_t INSTRUCTION_CACHE_LIMIT = 250000;

// TODO: Synchronisation!

REHex::CodeAnalyser::CodeAnalyser(Document *doc, BitOffset offset, BitOffset length, cs_arch arch, cs_mode mode):
	doc(doc),
	m_base_offset(offset),
	m_data_length(length.byte()),
	arch(arch),
	preferred_asm_syntax(AsmSyntax::INTEL)
{
	cs_err error = cs_open(arch, mode, &disassembler);
	if(error != CS_ERR_OK)
	{
		/* TODO: Report error */
		abort();
	}
	
	cs_option(disassembler, CS_OPT_SKIPDATA, CS_OPT_ON);
	
	m_longest_instruction = 0;
	m_longest_disasm = 0;
	
	dirty.set_range(0, m_data_length);
	
	m_task = wxGetApp().thread_pool->queue_task([this]() { return analyse_chunk(); }, 1);
}

REHex::CodeAnalyser::~CodeAnalyser()
{
	m_task.finish();
	m_task.join();
	
	cs_close(&disassembler);
}

void REHex::CodeAnalyser::pause()
{
	assert(!m_task.paused());
	m_task.pause();
}

void REHex::CodeAnalyser::resume()
{
	assert(m_task.paused());
	m_task.resume();
}

void REHex::CodeAnalyser::refresh(BitOffset rel_offset, BitOffset length)
{
	assert(m_task.paused());
	
	/* Workaround for older GCC/libstd++ which don't support passing a const_iterator
	 * to std::vector::erase() despite claiming to be C++11.
	*/
	#if !defined(__clang__) && defined(__GNUC__) && (__GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 9))
	auto p_erase_begin_c = processed_by_rel_offset(rel_offset.byte());
	auto p_erase_begin = const_iterator_to_iterator(p_erase_begin_c, processed);
	#else
	auto p_erase_begin = processed_by_rel_offset(rel_offset.byte());
	#endif
	
	if(p_erase_begin != processed.end())
	{
		assert(p_erase_begin->offset <= rel_offset.byte());
		
		dirty.set_range(p_erase_begin->offset, (m_data_length - p_erase_begin->offset));
		m_task.restart();
		
		processed.erase(p_erase_begin, processed.end());
		instructions.clear();
	}
	
	assert(dirty.isset(rel_offset.byte(), (m_data_length - rel_offset.byte())));
}

void REHex::CodeAnalyser::rebase(BitOffset offset)
{
	assert(m_task.paused());
	m_base_offset = offset;
}

bool REHex::CodeAnalyser::analyse_chunk()
{
	if(dirty.empty())
	{
		/* Range is fully analysed. */
		return true;
	}
	
	ByteRangeSet::Range first_dirty_range = dirty[0];
	
	off_t process_base = first_dirty_range.offset;
	off_t process_len  = std::min(first_dirty_range.length, SOFT_IR_LIMIT);
	
	/* Read in some extra data after the range to be processed (if available), but NOT beyond
	 * the end of the region, so we can correctly disassemble an instruction spanning the end
	 * of the range and expand the InstructionRange to encompass it.
	*/
	
	off_t remain_after = m_data_length - (process_base + process_len);
	assert(remain_after >= 0);
	
	off_t process_extra = std::min<off_t>(128, remain_after);
	
	std::vector<unsigned char> data;
	try {
		data = doc->read_data((m_base_offset + BitOffset(process_base, 0)), process_len + process_extra);
	}
	catch(const std::exception &e)
	{
		wxGetApp().printf_error("Exception in REHex::CodeAnalyser::analyse_chunk: %s\n", e.what());
		return true; /* Will make us spin so long as the read error persists. ugh. */
	}
	
	const uint8_t* code_ = static_cast<const uint8_t*>(data.data());
	size_t code_size = data.size();
	// uint64_t address = process_base;
	uint64_t address = m_base_offset.byte() + process_base;
	cs_insn* insn = cs_malloc(disassembler);
	
	InstructionRange new_ir;
	new_ir.offset               = process_base;
	new_ir.length               = 0;
	new_ir.longest_instruction  = 0;
	new_ir.longest_disasm       = 0;
	new_ir.rel_y_offset         = processed.empty() ? 0 : (processed.back().rel_y_offset + processed.back().y_lines);
	new_ir.y_lines              = 0;
	
	/* NOTE: @code, @code_size & @address variables are all updated! */
	while(code_ < (data.data() + process_len))
	{
		disasm_instruction(&code_, &code_size, &address, insn);
		
		/* Instruction operands are aligned to tab boundaries using spaces. */
		
		const size_t OP_ALIGN = 8;
		
		size_t mnemonic_len = strlen(insn->mnemonic);
		size_t space_count = (OP_ALIGN - (mnemonic_len % OP_ALIGN));
		
		size_t disasm_length = mnemonic_len + space_count + strlen(insn->op_str);
		
		new_ir.length += insn->size;
		
		new_ir.longest_instruction = std::max<off_t>(new_ir.longest_instruction, insn->size);
		new_ir.longest_disasm = std::max(new_ir.longest_disasm, disasm_length);
		
		++(new_ir.y_lines);
	}
	
	cs_free(insn, 1);
	
	assert(processed.empty() || (processed.back().offset + processed.back().length) == new_ir.offset);
	processed.push_back(new_ir);
	
	if(new_ir.longest_instruction > m_longest_instruction)
	{
		m_longest_instruction = new_ir.longest_instruction;
	}
	
	if(new_ir.longest_disasm > m_longest_disasm)
	{
		m_longest_disasm = new_ir.longest_disasm;
	}
	
	dirty.clear_range(new_ir.offset, new_ir.length);
	
	return dirty.empty();
}

REHex::CodeAnalyser::AnalysisPosition REHex::CodeAnalyser::get_analysis_position() const
{
	AnalysisPosition ap;
	
	ap.offset = dirty.empty()
		? m_base_offset + m_data_length
		: m_base_offset + BitOffset(dirty.first().offset, 0);
	
	ap.line = processed.empty()
		? 0
		: processed.back().rel_y_offset + processed.back().y_lines;
	
	return ap;
}

std::vector<REHex::CodeAnalyser::InstructionRange>::const_iterator REHex::CodeAnalyser::processed_by_rel_offset(off_t rel_offset)
{
	InstructionRange ir_v;
	ir_v.offset = rel_offset;
	
	auto next_ir = std::upper_bound(processed.begin(), processed.end(), ir_v,
		[](const InstructionRange &lhs, const InstructionRange &rhs)
		{
			return lhs.offset < rhs.offset;
		});
	
	if(next_ir == processed.begin())
	{
		return processed.end();
	}
	
	auto ir = std::prev(next_ir);
	
	if(ir->offset <= rel_offset && (ir->offset + ir->length) > rel_offset)
	{
		return ir;
	}
	else{
		return processed.end();
	}
}

std::vector<REHex::CodeAnalyser::InstructionRange>::const_iterator REHex::CodeAnalyser::processed_by_line(int64_t rel_line)
{
	InstructionRange ir_v;
	ir_v.rel_y_offset = rel_line;
	
	auto next_ir = std::upper_bound(processed.begin(), processed.end(), ir_v,
		[](const InstructionRange &lhs, const InstructionRange &rhs)
		{
			return lhs.rel_y_offset < rhs.rel_y_offset;
		});
	
	if(next_ir == processed.begin())
	{
		return processed.end();
	}
	
	auto ir = std::prev(next_ir);
	
	if(ir->rel_y_offset <= rel_line && (ir->rel_y_offset + ir->y_lines) > rel_line)
	{
		return ir;
	}
	else{
		return processed.end();
	}
}

std::vector<REHex::CodeAnalyser::CachedInstruction>::const_iterator REHex::CodeAnalyser::cached_instruction_by_rel_offset(off_t rel_offset)
{
	CachedInstruction i_v;
	i_v.rel_offset = rel_offset;
	
	auto next_i = std::upper_bound(instructions.begin(), instructions.end(), i_v,
		[](const CachedInstruction &lhs, const CachedInstruction &rhs)
		{
			return lhs.rel_offset < rhs.rel_offset;
		});
	
	if(next_i != instructions.begin())
	{
		auto i = std::prev(next_i);
		
		if(i->rel_offset <= rel_offset && (i->rel_offset + i->length) > rel_offset)
		{
			return i;
		}
	}
	
	auto ir = processed_by_rel_offset(rel_offset);
	if(ir == processed.end())
	{
		return instructions.end();
	}
	
	std::vector<unsigned char> ir_data;
	try {
		ir_data = doc->read_data((m_base_offset + BitOffset(ir->offset, 0)), ir->length);
	}
	catch(const std::exception &e)
	{
		wxGetApp().printf_error("Exception in REHex::CodeAnalyser::instruction_by_offset: %s\n", e.what());
		return instructions.end();
	}
	
	std::vector<CachedInstruction> new_instructions;
	
	/* I don't know if this is a bug in Capstone, or some horribleness in x86 instruction
	 * encoding, but some instructions in my testing disassemble (slightly) differently if I
	 * give the disassembler the address where the instruction was in the original executable
	 * vs. relative to the start of the region, so we try to give it a file-relative address.
	*/
	off_t disasm_base_addr = m_base_offset.byte();
	
	const uint8_t* code_ = static_cast<const uint8_t*>(ir_data.data());
	size_t code_size = ir_data.size();
	uint64_t address = disasm_base_addr + ir->offset;
	cs_insn* insn = cs_malloc(disassembler);
	
	/* NOTE: @code, @code_size & @address variables are all updated! */
	while(code_ < (ir_data.data() + ir_data.size()))
	{
		disasm_instruction(&code_, &code_size, &address, insn);
		
		CachedInstruction inst;
		
		/* Align instruction operands to tab boundaries using spaces. */
		
		const size_t OP_ALIGN = 8;
		
		size_t mnemonic_len = strlen(insn->mnemonic);
		size_t space_count = (OP_ALIGN - (mnemonic_len % OP_ALIGN));
		
		std::string disasm_buf = std::string(insn->mnemonic) + std::string(space_count, ' ') + insn->op_str;
		
		inst.rel_offset   = insn->address - disasm_base_addr;
		inst.length       = insn->size;
		inst.disasm       = disasm_buf;
		inst.rel_line     = ir->rel_y_offset + new_instructions.size();
		
		memcpy(inst.instruction, (code_ - insn->size), insn->size);
		
		new_instructions.push_back(inst);
	}
	
	cs_free(insn, 1);
	
	assert(next_i == instructions.begin() || (std::prev(next_i)->rel_offset + std::prev(next_i)->length) <= new_instructions.front().rel_offset);
	assert(next_i == instructions.end() || next_i->rel_offset >= new_instructions.back().rel_offset + new_instructions.back().length);
	
	/* If we're about to exceed the disassembly cache size, clear it and start again with only
	 * the range we just disassembled. A bit of a dumb approach, but disassembly *should* be
	 * fast enough to quickly repopulate the cache on demand, or else responsiveness would suck
	 * with the current design anyway.
	*/
	
	if((instructions.size() + new_instructions.size()) > INSTRUCTION_CACHE_LIMIT)
	{
		instructions.clear();
		next_i = instructions.end();
	}
	
	instructions.insert(next_i, new_instructions.begin(), new_instructions.end());
	
	return cached_instruction_by_rel_offset(rel_offset);
}

REHex::CodeAnalyser::Instruction REHex::CodeAnalyser::instruction_by_abs_offset(BitOffset offset)
{
	assert(offset >= m_base_offset);
	assert(offset < (m_base_offset + BitOffset(m_data_length)));
	
	BitOffset rel_offset = offset - m_base_offset;
	
	auto ir_first_i = cached_instruction_by_rel_offset(rel_offset.byte());
	if(ir_first_i == instructions.end())
	{
		return Instruction();
	}
	else{
		return Instruction(
			(m_base_offset + ir_first_i->rel_offset),
			ir_first_i->rel_line,
			ir_first_i->instruction,
			ir_first_i->length,
			ir_first_i->disasm);
	}
}

REHex::CodeAnalyser::Instruction REHex::CodeAnalyser::instruction_by_line(BitOffset base_offset, int64_t rel_line)
{
	assert(base_offset >= m_base_offset);
	assert(base_offset < (m_base_offset + BitOffset(m_data_length)));
	
	BitOffset rel_offset = base_offset - m_base_offset;
	
	auto base_instr = cached_instruction_by_rel_offset(rel_offset.byte());
	if(base_instr == instructions.end())
	{
		return Instruction();
	}
	
	rel_line += base_instr->rel_line;
	
	auto ir = processed_by_line(rel_line);
	if(ir == processed.end())
	{
		return Instruction();
	}
	
	int64_t line_within_ir = rel_line - ir->rel_y_offset;
	assert(line_within_ir >= 0);
	assert(line_within_ir < (ir->rel_y_offset + ir->y_lines));
	
	auto ir_first_i = cached_instruction_by_rel_offset(ir->offset);
	if(ir_first_i == instructions.end())
	{
		return Instruction();
	}
	
	assert(std::distance(ir_first_i, instructions.cend()) > line_within_ir);
	
	auto ci_it = std::next(ir_first_i, line_within_ir);
	
	return Instruction(
		(m_base_offset + ci_it->rel_offset),
		ci_it->rel_line,
		ci_it->instruction,
		ci_it->length,
		ci_it->disasm);
}

void REHex::CodeAnalyser::disasm_instruction(const uint8_t **code, size_t *size, uint64_t *address, cs_insn *insn)
{
	assert(*size > 0);
	
	/* Setting the CS_OPT_SKIPDATA option makes Capstone insert .byte "instructions" into the
	 * disassembly where an invalid instruction is encountered, but under some situations it
	 * won't do that (e.g. sequences of trailing bytes that are shorter than the fixed
	 * instruction length on ARM), in which case we never finish disassembly. So we generate
	 * our own .byte instructions where Capstone chooses not to.
	*/
	
	bool valid_instr = cs_disasm_iter(disassembler, code, size, address, insn);
	if(!valid_instr)
	{
		insn->id      = 0;
		insn->address = *address;
		insn->size    = 1;
		insn->detail  = NULL;
		
		assert(sizeof(insn->bytes) >= insn->size);
		memcpy(insn->bytes, *code, insn->size);
		
		snprintf(insn->mnemonic, sizeof(insn->mnemonic), ".byte");
		snprintf(insn->op_str,   sizeof(insn->op_str),   "0x%02x", (unsigned)(**code));
		
		*code    += insn->size;
		*size    -= insn->size;
		*address += insn->size;
	}
}
