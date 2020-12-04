/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "DisassemblyRegion.hpp"
#include "Events.hpp"
#include "util.hpp"

static const off_t SOFT_IR_LIMIT = 10240; /* 100KiB */
static const size_t INSTRUCTION_CACHE_LIMIT = 250000;

REHex::DisassemblyRegion::DisassemblyRegion(SharedDocumentPointer &doc, off_t offset, off_t length, cs_arch arch, cs_mode mode):
	GenericDataRegion(offset, length),
	doc(doc)
{
	cs_err error = cs_open(arch, mode, &disassembler);
	if(error != CS_ERR_OK)
	{
		/* TODO: Report error */
		abort();
	}
	
	cs_option(disassembler, CS_OPT_SKIPDATA, CS_OPT_ON);
	
	longest_instruction = 0;
	longest_disasm = 0;
	
	this->doc.auto_cleanup_bind(DATA_OVERWRITE, &REHex::DisassemblyRegion::OnDataOverwrite, this);
	
	dirty.set_range(d_offset, d_length);
}

REHex::DisassemblyRegion::~DisassemblyRegion()
{
	cs_close(&disassembler);
}

void REHex::DisassemblyRegion::OnDataOverwrite(OffsetLengthEvent &event)
{
	off_t d_end = d_offset + d_length;
	off_t event_end = event.offset + event.length;
	
	if(event.offset < d_end && event_end > d_offset)
	{
		off_t intersection_offset = std::max(d_offset, event.offset);
		
		/* Workaround for older GCC/libstd++ which don't support passing a const_iterator
		 * to std::vector::erase() despite claiming to be C++11.
		*/
		#if !defined(__clang__) && defined(__GNUC__) && (__GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 9))
		auto p_erase_begin_c = processed_by_offset(intersection_offset);
		auto p_erase_begin = const_iterator_to_iterator(p_erase_begin_c, processed);
		#else
		auto p_erase_begin = processed_by_offset(intersection_offset);
		#endif
		
		dirty.set_range(p_erase_begin->offset, (d_length - (intersection_offset - d_offset)));
		
		processed.erase(p_erase_begin, processed.end());
		instructions.clear();
	}
	
	event.Skip();
}

int REHex::DisassemblyRegion::calc_width(DocumentCtrl &doc_ctrl)
{
	int indent_width = doc_ctrl.indent_width(indent_depth);
	
	int offset_column_width = doc_ctrl.get_show_offsets()
		? doc_ctrl.get_offset_column_width()
		: 0;
	
	unsigned int bytes_per_group = doc_ctrl.get_bytes_per_group();
	
	off_t bytes_per_line = max_bytes_per_line();
	
	offset_text_x = indent_width;
	hex_text_x    = offset_text_x + offset_column_width;
	code_text_x   = hex_text_x
		+ doc_ctrl.hf_string_width(
			(bytes_per_line * 2)
			+ ((bytes_per_line - 1) / bytes_per_group)
			+ 1);
	
	return code_text_x + doc_ctrl.hf_string_width(longest_disasm) + indent_width;
}

void REHex::DisassemblyRegion::calc_height(DocumentCtrl &doc_ctrl, wxDC &dc)
{
	int64_t total_lines = std::accumulate(processed.begin(), processed.end(),
		(int64_t)(0), [](int64_t sum, const InstructionRange &ir) { return sum + ir.y_lines; });
	
	off_t up_bytes_per_line = max_bytes_per_line();
	
	off_t up_total = unprocessed_bytes();
	int64_t up_lines = (up_total + (up_bytes_per_line - 1)) / up_bytes_per_line;
	
	y_lines = total_lines + up_lines + indent_final;
}

void REHex::DisassemblyRegion::draw(DocumentCtrl &doc_ctrl, wxDC &dc, int x, int64_t y)
{
	draw_container(doc_ctrl, dc, x, y);
	
	int hf_char_height = doc_ctrl.hf_char_height();
	
	int64_t line_num = (y < 0 ? (-y / hf_char_height) : 0);
	y += line_num * hf_char_height;
	
	wxSize client_size = doc_ctrl.GetClientSize();
	
	bool alternate = ((y_offset + line_num) % 2) != 0;
	
	auto highlight_func = [&](off_t offset)
	{
		/* TODO: Support secondary selection. */
		
		off_t selection_off, selection_len;
		std::tie(selection_off, selection_len) = doc_ctrl.get_selection();
		
		if(selection_len > 0 && offset >= selection_off && offset < (selection_off + selection_len))
		{
			return Highlight(Palette::PAL_SELECTED_TEXT_FG, Palette::PAL_SELECTED_TEXT_BG, doc_ctrl.hex_view_active());
		}
		else{
			const NestedOffsetLengthMap<int> &highlights = doc->get_highlights();
			
			auto highlight = NestedOffsetLengthMap_get(highlights, offset);
			if(highlight != highlights.end())
			{
				return Highlight(
					active_palette->get_highlight_fg_idx(highlight->second),
					active_palette->get_highlight_bg_idx(highlight->second),
					true);
			}
			else if(doc->is_byte_dirty(offset))
			{
				return Highlight(
					Palette::PAL_DIRTY_TEXT_FG,
					Palette::PAL_DIRTY_TEXT_BG,
					true);
			}
			else{
				return (Highlight)(NoHighlight());
			}
		}
	};
	
	auto set_text_attribs = [&](bool selected)
	{
		dc.SetFont(doc_ctrl.get_font());
		dc.SetBackgroundMode(wxSOLID);
		
		if(selected)
		{
			wxColour selected_bg_colour = doc_ctrl.special_view_active()
				? (*active_palette)[Palette::PAL_SELECTED_TEXT_BG]
				: active_palette->get_average_colour(Palette::PAL_SELECTED_TEXT_BG, Palette::PAL_NORMAL_TEXT_BG);
			
			dc.SetTextForeground((*active_palette)[Palette::PAL_SELECTED_TEXT_FG]);
			dc.SetTextBackground(selected_bg_colour);
		}
		else{
			dc.SetTextForeground((*active_palette)[alternate ? Palette::PAL_ALTERNATE_TEXT_FG : Palette::PAL_NORMAL_TEXT_FG]);
			dc.SetTextBackground((*active_palette)[Palette::PAL_NORMAL_TEXT_BG]);
		}
	};
	
	/* Draw disassembled instructions within the visible rows. */
	
	auto instr_first = instruction_by_line(line_num);
	
	const std::vector<Instruction> *instr_vec = &(instr_first.first);
	std::vector<Instruction>::const_iterator instr = instr_first.second;
	
	off_t selection_off, selection_len;
	std::tie(selection_off, selection_len) = doc_ctrl.get_selection();
	
	while(instr != instr_vec->end() && y < client_size.GetHeight() && line_num < (y_lines - indent_final))
	{
		if(doc_ctrl.get_show_offsets())
		{
			/* Draw the offsets to the left */
			
			std::string offset_str = format_offset(instr->offset, doc_ctrl.get_offset_display_base(), doc->buffer_length());
			
			set_text_attribs(false);
			dc.DrawText(offset_str, x + offset_text_x, y);
			
			int offset_vl_x = x + hex_text_x - (doc_ctrl.hf_char_width() / 2);
			
			wxPen norm_fg_1px((*active_palette)[Palette::PAL_NORMAL_TEXT_FG], 1);
			
			dc.SetPen(norm_fg_1px);
			dc.DrawLine(offset_vl_x, y, offset_vl_x, y + hf_char_height);
		}
		
		draw_hex_line(&doc_ctrl, dc, x + hex_text_x, y, instr->data.data(), instr->length, 0, instr->offset, alternate, highlight_func);
		
		bool selected = selection_len > 0 && selection_off <= instr->offset && (selection_off + selection_len) >= (instr->offset + instr->length);
		
		set_text_attribs(selected);
		dc.DrawText(instr->disasm, x + code_text_x, y);
		
		y += hf_char_height;
		++line_num;
		
		/* Advancing instr to the end means we've either reached unprocessed data and will
		 * have to stop, or have run out of cached instructions and need to cache more.
		*/
		
		++instr;
		
		if(instr == instr_vec->end())
		{
			auto next_instr = instruction_by_line(line_num);
			
			instr_vec = &(next_instr.first);
			instr = next_instr.second;
		}
		
		alternate = !alternate;
	}
	
	/* Draw bytes not yet disassembled within the visible rows. */
	
	off_t up_bytes_per_line = max_bytes_per_line();
	
	int64_t up_first_line = processed.empty() ? 0 : (processed.back().rel_y_offset + processed.back().y_lines);
	off_t up_skip_bytes = (line_num - up_first_line) * up_bytes_per_line;
	
	off_t up_off    = unprocessed_offset() + up_skip_bytes;
	off_t up_remain = unprocessed_bytes() - up_skip_bytes;
	
	while(up_remain > 0 && y < client_size.GetHeight() && line_num < (y_lines - indent_final))
	{
		if(doc_ctrl.get_show_offsets())
		{
			/* Draw the offsets to the left */
			
			std::string offset_str = format_offset(up_off, doc_ctrl.get_offset_display_base(), doc->buffer_length());
			
			set_text_attribs(false);
			dc.DrawText(offset_str, x + offset_text_x, y);
			
			int offset_vl_x = x + hex_text_x - (doc_ctrl.hf_char_width() / 2);
			
			wxPen norm_fg_1px((*active_palette)[Palette::PAL_NORMAL_TEXT_FG], 1);
			
			dc.SetPen(norm_fg_1px);
			dc.DrawLine(offset_vl_x, y, offset_vl_x, y + hf_char_height);
		}
		
		off_t line_len = std::min(up_remain, up_bytes_per_line);
		
		bool data_err = false;
		std::vector<unsigned char> line_data;
		try {
			line_data = doc->read_data(up_off, line_len);
			assert(line_data.size() == (size_t)(line_len));
		}
		catch(const std::exception &e)
		{
			fprintf(stderr, "Exception in REHex::DisassemblyRegion::draw: %s\n", e.what());
			data_err = true;
		}
		
		const unsigned char *ldp = data_err ? NULL : line_data.data();
		size_t ldl = data_err ? line_len : line_data.size();
		
		draw_hex_line(&doc_ctrl, dc, x + hex_text_x, y, ldp, ldl, 0, up_off, alternate, highlight_func);
		
		set_text_attribs(false);
		dc.DrawText("<< PROCESSING >>", x + code_text_x, y);
		
		y += hf_char_height;
		++line_num;
		
		up_off    += line_len;
		up_remain -= line_len;
		
		alternate = !alternate;
	}
}

unsigned int REHex::DisassemblyRegion::check()
{
	if(dirty.empty())
	{
		/* Range is fully analysed. */
		return Region::IDLE;
	}
	
	unsigned int state = Region::IDLE;
	
	ByteRangeSet::Range first_dirty_range = dirty[0];
	
	off_t process_base = first_dirty_range.offset;
	off_t process_len  = std::min(first_dirty_range.length, SOFT_IR_LIMIT);
	
	std::vector<unsigned char> data;
	try {
		data = doc->read_data(process_base, process_len + 128);
	}
	catch(const std::exception &e)
	{
		fprintf(stderr, "Exception in REHex::DisassemblyRegion::check: %s\n", e.what());
		return Region::PROCESSING; /* Will make us spin so long as the read error persists. ugh. */
	}
	
	const uint8_t* code_ = static_cast<const uint8_t*>(data.data());
	size_t code_size = data.size();
	uint64_t address = process_base;
	cs_insn* insn = cs_malloc(disassembler);
	
	InstructionRange new_ir;
	new_ir.offset               = process_base;
	new_ir.length               = 0;
	new_ir.longest_instruction  = 0;
	new_ir.longest_disasm       = 0;
	new_ir.rel_y_offset         = processed.empty() ? 0 : (processed.back().rel_y_offset + processed.back().y_lines);
	new_ir.y_lines              = 0;
	
	/* NOTE: @code, @code_size & @address variables are all updated! */
	while(code_ < (data.data() + process_len) && cs_disasm_iter(disassembler, &code_, &code_size, &address, insn))
	{
		size_t disasm_length = strlen(insn->mnemonic) + 1 + strlen(insn->op_str);
		
		new_ir.length += insn->size;
		
		new_ir.longest_instruction = std::max<off_t>(new_ir.longest_instruction, insn->size);
		new_ir.longest_disasm = std::max(new_ir.longest_disasm, disasm_length);
		
		++(new_ir.y_lines);
		
		state |= (StateFlag)Region::HEIGHT_CHANGE;
	}
	
	cs_free(insn, 1);
	
	assert(processed.empty() || (processed.back().offset + processed.back().length) == new_ir.offset);
	processed.push_back(new_ir);
	
	if(new_ir.longest_instruction > longest_instruction)
	{
		longest_instruction = new_ir.longest_instruction;
		state |= (StateFlag)Region::WIDTH_CHANGE;
	}
	
	if(new_ir.longest_disasm > longest_disasm)
	{
		longest_disasm = new_ir.longest_disasm;
		state |= (StateFlag)Region::WIDTH_CHANGE;
	}
	
	dirty.clear_range(new_ir.offset, new_ir.length);
	
	if(!dirty.empty())
	{
		state |= (StateFlag)Region::PROCESSING;
	}
	
	return state;
}

std::pair<off_t, REHex::DocumentCtrl::GenericDataRegion::ScreenArea> REHex::DisassemblyRegion::offset_at_xy(DocumentCtrl &doc_ctrl, int mouse_x_px, int64_t mouse_y_lines)
{
	int64_t processed_lines = this->processed_lines();
	
	if(mouse_y_lines < processed_lines)
	{
		/* Line has been processed. */
		
		auto instr = instruction_by_line(mouse_y_lines);
		if(instr.second == instr.first.end())
		{
			/* Couldn't get instruction. Don't know how long the line is. */
			return std::make_pair<off_t, ScreenArea>(-1, SA_NONE);
		}
		
		if(mouse_x_px >= code_text_x)
		{
			/* Mouse in code area. */
			
			unsigned int char_offset = doc_ctrl.hf_char_at_x(mouse_x_px - code_text_x);
			if(char_offset < instr.second->disasm.length())
			{
				return std::make_pair(instr.second->offset, SA_SPECIAL);
			}
		}
		else if(mouse_x_px >= hex_text_x)
		{
			/* Mouse in hex area. */
			int line_offset = offset_at_x_hex(&doc_ctrl, (mouse_x_px - hex_text_x));
			if(line_offset < 0 || line_offset >= instr.second->length)
			{
				return std::make_pair<off_t, ScreenArea>(-1, SA_NONE);
			}
			
			return std::make_pair<off_t, ScreenArea>((instr.second->offset + line_offset), SA_HEX);
		}
		else{
			/* Mouse in offset area. */
			return std::make_pair<off_t, ScreenArea>(-1, SA_NONE);
		}
	}
	else{
		/* Line isn't processed yet. */
		
		off_t up_base = unprocessed_offset();
		off_t up_bytes_per_line = max_bytes_per_line();
		
		int64_t up_row = mouse_y_lines - processed_lines;
		
		off_t line_base = up_base + (up_row * up_bytes_per_line);
		off_t line_end  = std::min((line_base + up_bytes_per_line), (d_offset + d_length - 1));
		off_t line_len  = line_end - line_base;
		
		if(mouse_x_px >= hex_text_x)
		{
			/* Mouse in hex area. */
			int line_offset = offset_at_x_hex(&doc_ctrl, (mouse_x_px - hex_text_x));
			if(line_offset < 0 || line_offset >= line_len)
			{
				return std::make_pair<off_t, ScreenArea>(-1, SA_NONE);
			}
			
			return std::make_pair<off_t, ScreenArea>((line_base + line_offset), SA_HEX);
		}
		else{
			/* Mouse in offset area. */
			return std::make_pair<off_t, ScreenArea>(-1, SA_NONE);
		}
	}
	
	return std::make_pair<off_t, ScreenArea>(-1, SA_NONE);
}

std::pair<off_t, REHex::DocumentCtrl::GenericDataRegion::ScreenArea> REHex::DisassemblyRegion::offset_near_xy(DocumentCtrl &doc_ctrl, int mouse_x_px, int64_t mouse_y_lines, ScreenArea type_hint)
{
	int64_t processed_lines = this->processed_lines();
	
	if(mouse_y_lines < processed_lines)
	{
		/* Line has been processed. */
		
		auto instr = instruction_by_line(mouse_y_lines);
		if(instr.second == instr.first.end())
		{
			/* Couldn't get instruction. Don't know how long the line is. */
			return std::make_pair<off_t, ScreenArea>(-1, SA_NONE);
		}
		
		off_t instr_base = instr.second->offset;
		off_t instr_end  = instr.second->offset + instr.second->length;
		
		if((mouse_x_px >= code_text_x && type_hint == SA_NONE) || type_hint == SA_SPECIAL)
		{
			/* Mouse in code area. */
			
			if(mouse_x_px < code_text_x)
			{
				return std::make_pair(std::max<off_t>((instr.second->offset - 1), 0), SA_SPECIAL);
			}
			
			unsigned int char_offset = doc_ctrl.hf_char_at_x(mouse_x_px - code_text_x);
			if(char_offset < instr.second->disasm.length())
			{
				return std::make_pair(instr.second->offset, SA_SPECIAL);
			}
			else{
				return std::make_pair((instr.second->offset + instr.second->length - 1), SA_SPECIAL);
			}
		}
		else if((mouse_x_px >= hex_text_x && type_hint == SA_NONE) || type_hint == SA_HEX)
		{
			/* Mouse in hex area. */
			int line_offset = offset_near_x_hex(&doc_ctrl, (mouse_x_px - hex_text_x));
			
			off_t real_offset;
			
			if(line_offset < 0)
			{
				real_offset = std::max<off_t>((instr_base - 1), 0);
			}
			else{
				real_offset = std::min(
					(instr_base + line_offset),
					(instr_end - 1));
			}
			
			return std::make_pair(real_offset, SA_HEX);
		}
		else{
			/* Mouse in offset area. */
			return std::make_pair<off_t, ScreenArea>(-1, SA_NONE);
		}
	}
	else{
		/* Line isn't processed yet. */
		
		off_t up_base = unprocessed_offset();
		off_t up_bytes_per_line = max_bytes_per_line();
		
		int64_t up_row = mouse_y_lines - processed_lines;
		
		off_t line_base = up_base + (up_row * up_bytes_per_line);
		off_t line_end  = std::min((line_base + up_bytes_per_line), (d_offset + d_length - 1));
		
		if(mouse_x_px >= hex_text_x || type_hint == SA_HEX)
		{
			/* Mouse in hex area. */
			int line_offset = offset_near_x_hex(&doc_ctrl, (mouse_x_px - hex_text_x));
			
			off_t real_offset;
			
			if(line_offset < 0)
			{
				real_offset = std::max<off_t>((line_base - 1), 0);
			}
			else{
				real_offset = std::min(
					(line_base + line_offset),
					(line_end - 1));
			}
			
			return std::make_pair(real_offset, SA_HEX);
		}
		else{
			/* Mouse in offset area. */
			return std::make_pair<off_t, ScreenArea>(-1, SA_NONE);
		}
	}
	
	return std::make_pair<off_t, ScreenArea>(-1, SA_NONE);
}

off_t REHex::DisassemblyRegion::cursor_left_from(off_t pos)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	if(pos > d_offset)
	{
		return pos - 1;
	}
	else{
		return CURSOR_PREV_REGION;
	}
}

off_t REHex::DisassemblyRegion::cursor_right_from(off_t pos)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	if((pos + 1) < (d_offset + d_length))
	{
		return pos + 1;
	}
	else{
		return CURSOR_NEXT_REGION;
	}
}

off_t REHex::DisassemblyRegion::cursor_up_from(off_t pos)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	off_t up_off = unprocessed_offset();
	
	off_t up_bytes_per_line = max_bytes_per_line();
	
	if(pos < up_off)
	{
		auto instr = instruction_by_offset(pos);
		if(instr.second == instr.first.end())
		{
			/* Couldn't get instruction. */
			return pos;
		}
		
		off_t this_instr_off = instr.second->offset;
		
		if(this_instr_off == d_offset)
		{
			/* Already on first line in region. */
			return CURSOR_PREV_REGION;
		}
		
		auto prev_instr = instruction_by_offset(this_instr_off - 1);
		if(prev_instr.second == prev_instr.first.end())
		{
			/* Couldn't get instruction. */
			return pos;
		}
		
		off_t prev_instr_off = prev_instr.second->offset;
		off_t prev_instr_len = prev_instr.second->length;
		
		return std::min(
			(prev_instr_off + (pos - this_instr_off)),
			(prev_instr_off + prev_instr_len - 1));
	}
	else if(pos < (up_off + up_bytes_per_line))
	{
		/* Move from top of unprocessed data to last line of disassembly. */
		
		if(up_off == d_offset)
		{
			return CURSOR_PREV_REGION;
		}
		else{
			auto instr = instruction_by_offset(up_off - 1);
			if(instr.second == instr.first.end())
			{
				/* Couldn't get instruction. */
				return pos;
			}
			
			return std::min(
				(instr.second->offset + (pos - up_off)),
				(instr.second->offset + instr.second->length - 1));
		}
	}
	else{
		/* Move between unprocessed lines. */
		return pos - up_bytes_per_line;
	}
}

off_t REHex::DisassemblyRegion::cursor_down_from(off_t pos)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	off_t up_off = unprocessed_offset();
	
	off_t up_bytes_per_line = max_bytes_per_line();
	
	if(pos < up_off)
	{
		/* Move down a line from within disassembly. */
		
		auto instr = instruction_by_offset(pos);
		if(instr.second == instr.first.end())
		{
			/* Couldn't get instruction. */
			return pos;
		}
		
		off_t this_instr_off = instr.second->offset;
		off_t this_instr_len = instr.second->length;
		
		off_t up_off = unprocessed_offset();
		
		if((this_instr_off + this_instr_len) == (d_offset + d_length))
		{
			/* Already on last line in region. */
			return CURSOR_NEXT_REGION;
		}
		else if((this_instr_off + this_instr_len) == up_off)
		{
			/* On last line in disassembly. */
			
			return std::min(
				(up_off + (pos - this_instr_off)),
				(d_offset + d_length - 1));
		}
		
		auto next_instr = instruction_by_offset(this_instr_off + this_instr_len);
		if(next_instr.second == next_instr.first.end())
		{
			/* Couldn't get instruction. */
			return pos;
		}
		
		off_t next_instr_off = next_instr.second->offset;
		off_t next_instr_len = next_instr.second->length;
		
		return std::min(
			(next_instr_off + (pos - this_instr_off)),
			(next_instr_off + next_instr_len - 1));
	}
	else{
		/* Move down a line from within unprocessed data. */
		off_t line_pos = (pos - up_off) % up_bytes_per_line;
		off_t next_line_begin = (pos - line_pos) + up_bytes_per_line;
		off_t next_line_pos = pos + up_bytes_per_line;
		
		if(next_line_pos < (d_offset + d_length))
		{
			/* Move to same position in next line. */
			return next_line_pos;
		}
		else if(next_line_begin < (d_offset + d_length))
		{
			/* Move to end of next (last) line. */
			return (d_offset + d_length - 1);
		}
		else{
			/* Move to next region. */
			return CURSOR_NEXT_REGION;
		}
	}
}

off_t REHex::DisassemblyRegion::cursor_home_from(off_t pos)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	off_t up_off = unprocessed_offset();
	
	off_t up_bytes_per_line = max_bytes_per_line();
	
	if(pos < up_off)
	{
		/* Move to start of line in disassembly. */
		
		auto instr = instruction_by_offset(pos);
		if(instr.second == instr.first.end())
		{
			/* Couldn't get Instruction. */
			return pos;
		}
		
		return instr.second->offset;
	}
	else{
		/* Move to start of unprocessed line. */
		off_t line_pos = (pos - up_off) % up_bytes_per_line;
		return pos - line_pos;
	}
}

off_t REHex::DisassemblyRegion::cursor_end_from(off_t pos)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	off_t up_off = unprocessed_offset();
	
	off_t up_bytes_per_line = max_bytes_per_line();
	
	if(pos < up_off)
	{
		/* Move to end of line in disassembly. */
		
		auto instr = instruction_by_offset(pos);
		if(instr.second == instr.first.end())
		{
			/* Couldn't get Instruction. */
			return pos;
		}
		
		return instr.second->offset + instr.second->length - 1;
	}
	else{
		/* Move to end of unprocessed line. */
		off_t line_pos = (pos - up_off) % up_bytes_per_line;
		return std::min(
			((pos - line_pos) + (up_bytes_per_line - 1)),
			(d_offset + d_length - 1));
	}
}

int REHex::DisassemblyRegion::cursor_column(off_t pos)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	off_t up_off = unprocessed_offset();
	
	if(pos < up_off)
	{
		/* Offset is within disassembled area. */
		
		auto instr = instruction_by_offset(pos);
		if(instr.second == instr.first.end())
		{
			/* Couldn't get instruction. Fallback. */
			return 0;
		}
		
		assert(instr.second->offset <= pos);
		assert((instr.second->offset + instr.second->length) > pos);
		
		return pos - instr.second->offset;
	}
	else{
		/* Offset is within not-yet-processed data. */
		
		return (pos - up_off) % max_bytes_per_line();
	}
}

off_t REHex::DisassemblyRegion::first_row_nearest_column(int column)
{
	return nth_row_nearest_column(0, column);
}

off_t REHex::DisassemblyRegion::last_row_nearest_column(int column)
{
	return nth_row_nearest_column(y_lines, column);
}

off_t REHex::DisassemblyRegion::nth_row_nearest_column(int64_t row, int column)
{
	int64_t processed_lines = processed.empty() ? 0 : (processed.back().rel_y_offset + processed.back().y_lines);
	
	if(row < processed_lines)
	{
		/* Line has been processed. */
		
		auto instr = instruction_by_line(row);
		if(instr.second == instr.first.end())
		{
			/* Couldn't get instruction. Fallback. */
			return d_offset;
		}
		
		return std::min(
			(instr.second->offset + column),
			(instr.second->offset + instr.second->length - 1));
	}
	else{
		/* Line isn't processed yet. */
		
		off_t up_base = unprocessed_offset();
		int64_t up_row = row - processed_lines;
		
		return std::min(
			(up_base + (up_row * max_bytes_per_line()) + column),
			(d_offset + d_length - 1));
	}
}

REHex::DocumentCtrl::Rect REHex::DisassemblyRegion::calc_offset_bounds(off_t offset, DocumentCtrl *doc_ctrl)
{
	off_t up_off = unprocessed_offset();
	
	unsigned int bytes_per_group = doc_ctrl->get_bytes_per_group();
	
	if(offset < up_off)
	{
		/* Offset is within disassembly. */
		
		auto instr = instruction_by_offset(offset);
		if(instr.second == instr.first.end())
		{
			/* Couldn't get instruction. Fallback. */
			return DocumentCtrl::Rect(y_offset, y_lines, 1, 1);
		}
		
		assert(instr.second->offset <= offset);
		assert((instr.second->offset + instr.second->length) > offset);
		
		off_t line_off = offset - instr.second->offset;
		
		return DocumentCtrl::Rect(
			/* Left X co-ordinate of hex byte. */
			hex_text_x + doc_ctrl->hf_string_width((line_off * 2) + (line_off / bytes_per_group)),
			
			/* Line number. */
			(y_offset + instr.second->rel_y_offset),
			
			/* Width of hex byte. */
			doc_ctrl->hf_string_width(2),
			
			/* Height of instruction (in lines). */
			1);
	}
	else{
		/* Offset hasn't been processed yet. */
		
		off_t up_bytes_per_line = max_bytes_per_line();
		
		off_t offset_within_up = offset - up_off;
		off_t line_off = offset_within_up % up_bytes_per_line;
		
		int64_t processed_lines = processed.empty() ? 0 : (processed.back().rel_y_offset + processed.back().y_lines);
		int64_t up_line = offset_within_up / up_bytes_per_line;
		
		return DocumentCtrl::Rect(
			/* Left X co-ordinate of hex byte. */
			hex_text_x + doc_ctrl->hf_string_width((line_off * 2) + (line_off / bytes_per_group)),
			
			/* Line number. */
			(y_offset + processed_lines + up_line),
			
			/* Width of hex byte. */
			doc_ctrl->hf_string_width(2),
			
			/* Height (in lines). */
			1);
	}
}

off_t REHex::DisassemblyRegion::unprocessed_offset() const
{
	if(processed.empty())
	{
		return d_offset;
	}
	else{
		return processed.back().offset + processed.back().length;
	}
}

off_t REHex::DisassemblyRegion::unprocessed_bytes() const
{
	return d_length - (unprocessed_offset() - d_offset);
}

int64_t REHex::DisassemblyRegion::processed_lines() const
{
	if(processed.empty())
	{
		return 0;
	}
	else{
		return processed.back().rel_y_offset + processed.back().y_lines;
	}
}

off_t REHex::DisassemblyRegion::max_bytes_per_line() const
{
	return (longest_instruction > 0)
		? longest_instruction
		: 8;
}

std::vector<REHex::DisassemblyRegion::InstructionRange>::const_iterator REHex::DisassemblyRegion::processed_by_offset(off_t abs_offset)
{
	InstructionRange ir_v;
	ir_v.offset = abs_offset;
	
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
	
	if(ir->offset <= abs_offset && (ir->offset + ir->length) > abs_offset)
	{
		return ir;
	}
	else{
		return processed.end();
	}
}

std::vector<REHex::DisassemblyRegion::InstructionRange>::const_iterator REHex::DisassemblyRegion::processed_by_line(int64_t rel_line)
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

std::pair<const std::vector<REHex::DisassemblyRegion::Instruction>&, std::vector<REHex::DisassemblyRegion::Instruction>::const_iterator> REHex::DisassemblyRegion::instruction_by_offset(off_t abs_offset)
{
	static const std::vector<Instruction> EMPTY;
	static const std::pair<const std::vector<Instruction>&, std::vector<Instruction>::const_iterator> EMPTY_END(EMPTY, EMPTY.end());
	
	Instruction i_v;
	i_v.offset = abs_offset;
	
	auto next_i = std::upper_bound(instructions.begin(), instructions.end(), i_v,
		[](const Instruction &lhs, const Instruction &rhs)
		{
			return lhs.offset < rhs.offset;
		});
	
	if(next_i != instructions.begin())
	{
		auto i = std::prev(next_i);
		
		if(i->offset <= abs_offset && (i->offset + i->length) > abs_offset)
		{
			return std::pair<const std::vector<Instruction>&, std::vector<Instruction>::const_iterator>(
				instructions,
				i);
		}
	}
	
	auto ir = processed_by_offset(abs_offset);
	if(ir == processed.end())
	{
		return EMPTY_END;
	}
	
	std::vector<unsigned char> ir_data;
	try {
		ir_data = doc->read_data(ir->offset, ir->length);
	}
	catch(const std::exception &e)
	{
		fprintf(stderr, "Exception in REHex::DisassemblyRegion::instruction_by_offset: %s\n", e.what());
		return EMPTY_END;
	}
	
	std::vector<Instruction> new_instructions;
	
	const uint8_t* code_ = static_cast<const uint8_t*>(ir_data.data());
	size_t code_size = ir_data.size();
	uint64_t address = ir->offset;
	cs_insn* insn = cs_malloc(disassembler);
	
	/* NOTE: @code, @code_size & @address variables are all updated! */
	while(cs_disasm_iter(disassembler, &code_, &code_size, &address, insn))
	{
		Instruction inst;
		
		/* Align instruction operands to tab boundaries using spaces. */
		
		const size_t OP_ALIGN = 8;
		
		size_t mnemonic_len = strlen(insn->mnemonic);
		size_t space_count = (OP_ALIGN - (mnemonic_len % OP_ALIGN));
		
		std::string disasm_buf = std::string(insn->mnemonic) + std::string(space_count, ' ') + insn->op_str;
		
		inst.offset       = insn->address;
		inst.length       = insn->size;
		inst.data         = std::vector<unsigned char>((unsigned char*)(code_ - insn->size), (unsigned char*)(code_));
		inst.disasm       = disasm_buf;
		inst.rel_y_offset = ir->rel_y_offset + new_instructions.size();
		
		new_instructions.push_back(inst);
	}
	
	cs_free(insn, 1);
	
	assert(next_i == instructions.begin() || (std::prev(next_i)->offset + std::prev(next_i)->length) <= new_instructions.front().offset);
	assert(next_i == instructions.end() || next_i->offset >= new_instructions.back().offset + new_instructions.back().length);
	
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
	
	return instruction_by_offset(abs_offset);
}

std::pair<const std::vector<REHex::DisassemblyRegion::Instruction>&, std::vector<REHex::DisassemblyRegion::Instruction>::const_iterator> REHex::DisassemblyRegion::instruction_by_line(int64_t rel_line)
{
	static const std::vector<Instruction> EMPTY;
	static const std::pair<const std::vector<Instruction>&, std::vector<Instruction>::const_iterator> EMPTY_END(EMPTY, EMPTY.end());
	
	auto ir = processed_by_line(rel_line);
	if(ir == processed.end())
	{
		return EMPTY_END;
	}
	
	int64_t line_within_ir = rel_line - ir->rel_y_offset;
	assert(line_within_ir >= 0);
	assert(line_within_ir < (ir->rel_y_offset + ir->y_lines));
	
	auto ir_first_i = instruction_by_offset(ir->offset);
	if(ir_first_i.second == ir_first_i.first.end())
	{
		return EMPTY_END;
	}
	
	assert(std::distance(ir_first_i.second, ir_first_i.first.end()) > line_within_ir);
	
	return std::pair<const std::vector<Instruction>&, std::vector<Instruction>::const_iterator>(
		ir_first_i.first,
		std::next(ir_first_i.second, line_within_ir));
}
