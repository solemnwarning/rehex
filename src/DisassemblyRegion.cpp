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
#include <iterator>
#include <numeric>
#include <string.h>
#include <tuple>
#include <vector>

#include "App.hpp"
#include "CodeAnalyser.hpp"
#include "DisassemblyRegion.hpp"
#include "Events.hpp"
#include "util.hpp"

static const off_t SOFT_IR_LIMIT = 10240; /* 100KiB */
static const size_t INSTRUCTION_CACHE_LIMIT = 250000;

REHex::DisassemblyRegion::DisassemblyRegion(SharedDocumentPointer &doc, BitOffset offset, BitOffset length, BitOffset virt_offset, const GenericDataRegion::RangeTextColourFunction &text_colour_func):
	GenericDataRegion(offset, length, virt_offset, virt_offset),
	doc(doc),
	text_colour_func(text_colour_func),
	preferred_asm_syntax(AsmSyntax::INTEL)
{
	assert(d_length.byte_aligned());
	
	longest_instruction = 0;
	longest_disasm = 0;
}

int REHex::DisassemblyRegion::calc_width(DocumentCtrl &doc_ctrl)
{
	const FontCharacterCache &fcc = doc_ctrl.get_fcc();
	
	int indent_width = doc_ctrl.indent_width(indent_depth);
	
	int offset_column_width = doc_ctrl.get_show_offsets()
		? doc_ctrl.get_offset_column_width()
		: 0;
	
	unsigned int bytes_per_group = doc_ctrl.get_bytes_per_group();
	
	off_t bytes_per_line = max_bytes_per_line();
	
	int ascii_column_chars = doc_ctrl.get_show_ascii()
		? bytes_per_line
		: 0;
	
	offset_text_x = indent_width;
	hex_text_x    = offset_text_x + offset_column_width;
	code_text_x   = hex_text_x
		+ fcc.fixed_string_width(
			(bytes_per_line * 2)
			+ ((bytes_per_line - 1) / bytes_per_group)
			+ 1);
	ascii_text_x = code_text_x
		+ fcc.fixed_string_width(longest_disasm + 1);
	
	return ascii_text_x + fcc.fixed_string_width(ascii_column_chars) + indent_width;
}

void REHex::DisassemblyRegion::calc_height(DocumentCtrl &doc_ctrl)
{
	CodeAnalyser *analyser = static_cast<CodeAnalyser*>(doc->get_analyser(d_offset));
	
	AnalysisPosition ap = get_analysis_position(analyser);
	
	off_t up_bytes_per_line = max_bytes_per_line();
	
	off_t up_remaining = ((d_offset + d_length) - ap.offset).byte();
	int64_t up_lines = (up_remaining + (up_bytes_per_line - 1)) / up_bytes_per_line;
	
	y_lines = ap.line + up_lines + indent_final;
}

void REHex::DisassemblyRegion::draw(DocumentCtrl &doc_ctrl, wxDC &dc, int x, int64_t y)
{
	CodeAnalyser *analyser = static_cast<CodeAnalyser*>(doc->get_analyser(d_offset));
	AnalysisPosition ap = get_analysis_position(analyser);
	
	const FontCharacterCache &fcc = doc_ctrl.get_fcc();
	
	draw_container(doc_ctrl, dc, x, y);
	
	int hf_char_height = fcc.fixed_char_height();
	int hf_char_width = fcc.fixed_char_width();
	
	if(doc_ctrl.get_show_offsets())
	{
		draw_full_height_line(&doc_ctrl, dc, x + hex_text_x - (hf_char_width / 2), y);
	}
	
	draw_full_height_line(&doc_ctrl, dc, x + code_text_x - (hf_char_width / 2), y);
	
	if(doc_ctrl.get_show_ascii())
	{
		draw_full_height_line(&doc_ctrl, dc, x + ascii_text_x - (hf_char_width / 2), y);
	}
	
	int64_t line_num = (y < 0 ? (-y / hf_char_height) : 0);
	y += line_num * hf_char_height;
	
	wxSize client_size = doc_ctrl.GetClientSize();
	
	bool alternate = ((y_offset + line_num) % 2) != 0;
	
	BitOffset cursor_pos = doc_ctrl.get_cursor_position();
	
	BitOffset selection_off, selection_len;
	std::tie(selection_off, selection_len) = doc_ctrl.get_selection_in_region(this);
	
	const TextColour hex_selection_highlight(
		(*active_palette)[Palette::PAL_SELECTED_TEXT_FG],
		(doc_ctrl.hex_view_active()
			? (*active_palette)[Palette::PAL_SELECTED_TEXT_BG]
			: active_palette->blend_colours(Palette::PAL_SELECTED_TEXT_BG, Palette::PAL_NORMAL_TEXT_BG)));
	
	auto hex_highlight_func = [&](BitOffset offset)
	{
		if(selection_len > BitOffset::ZERO && offset >= selection_off && offset < (selection_off + selection_len))
		{
			return hex_selection_highlight;
		}
		else{
			return text_colour_func(offset, BitOffset(0, 4));
		}
	};
	
	const TextColour ascii_selection_highlight(
		(*active_palette)[Palette::PAL_SELECTED_TEXT_FG],
		(doc_ctrl.ascii_view_active()
			? (*active_palette)[Palette::PAL_SELECTED_TEXT_BG]
			: active_palette->blend_colours(Palette::PAL_SELECTED_TEXT_BG, Palette::PAL_NORMAL_TEXT_BG)));
	
	auto ascii_highlight_func = [&](BitOffset offset)
	{
		if(selection_len > BitOffset::ZERO && offset >= selection_off && offset < (selection_off + selection_len))
		{
			return ascii_selection_highlight;
		}
		else{
			return text_colour_func(offset, BitOffset(1, 0));
		}
	};

	
	auto set_text_attribs = [&](bool invert, bool selected, const BitOffset *inst_offset = NULL, const off_t *inst_length = NULL)
	{
		dc.SetFont(doc_ctrl.get_font());
		dc.SetBackgroundMode(wxSOLID);
		
		if(invert)
		{
			dc.SetTextForeground((*active_palette)[Palette::PAL_INVERT_TEXT_FG]);
			dc.SetTextBackground((*active_palette)[Palette::PAL_INVERT_TEXT_BG]);
		}
		else if(selected)
		{
			wxColour selected_bg_colour = doc_ctrl.special_view_active()
				? (*active_palette)[Palette::PAL_SELECTED_TEXT_BG]
				: active_palette->blend_colours(Palette::PAL_SELECTED_TEXT_BG, Palette::PAL_NORMAL_TEXT_BG);
			
			dc.SetTextForeground((*active_palette)[Palette::PAL_SELECTED_TEXT_FG]);
			dc.SetTextBackground(selected_bg_colour);
		}
		else{
			if(inst_offset != NULL)
			{
				assert(inst_length != NULL);
				
				TextColour inst_colour = text_colour_func(*inst_offset, *inst_length);
				if(inst_colour)
				{
					dc.SetTextForeground(inst_colour.fg_colour);
					dc.SetTextBackground(inst_colour.bg_colour);
					
					return;
				}
			}
			
			dc.SetTextForeground((*active_palette)[alternate ? Palette::PAL_ALTERNATE_TEXT_FG : Palette::PAL_NORMAL_TEXT_FG]);
			dc.SetTextBackground((*active_palette)[Palette::PAL_NORMAL_TEXT_BG]);
		}
	};
	
	/* Draw disassembled instructions within the visible rows. */
	
	CodeAnalyser::Instruction instr;
	
	bool has_focus = doc_ctrl.HasFocus();
	
	bool is_last_data_region = (doc_ctrl.get_data_regions().back() == this);
	
	while((instr = analyser->instruction_by_line(d_offset, line_num)) && y < client_size.GetHeight() && line_num < (y_lines - indent_final))
	{
		bool is_last_line = is_last_data_region && (line_num + 1) == (y_lines - indent_final);
		
		BitOffset abs_inst_offset = instr.offset();
		BitOffset rel_inst_offset = abs_inst_offset - d_offset;
		
		if(doc_ctrl.get_show_offsets())
		{
			/* Draw the offsets to the left */
			
			BitOffset display_offset = virt_offset + rel_inst_offset;
			
			std::string offset_str = format_offset(display_offset, doc_ctrl.get_offset_display_base(), doc_ctrl.get_end_virt_offset());
			
			set_text_attribs(false, false);
			dc.DrawText(offset_str, x + offset_text_x, y);
		}
		
		const unsigned char *instr_data = (const unsigned char*)(instr.instruction());
		off_t instr_length = instr.length();
		
		draw_hex_line(&doc_ctrl, dc, x + hex_text_x, y, instr_data, instr_length, 0, abs_inst_offset, alternate, has_focus, doc_ctrl.hex_view_active(), hex_highlight_func, is_last_line);
		
		if(doc_ctrl.get_show_ascii())
		{
			draw_ascii_line(&doc_ctrl, dc, x + ascii_text_x, y, instr_data, instr_length, 0, 0, 0, abs_inst_offset, alternate, has_focus, doc_ctrl.ascii_view_active(), ascii_highlight_func, is_last_line);
		}
		
		bool invert = cursor_pos >= abs_inst_offset && cursor_pos < (abs_inst_offset + BitOffset::BYTES(instr_length)) && doc_ctrl.get_cursor_visible() && doc_ctrl.special_view_active();
		bool selected = selection_len > 0 && selection_off <= abs_inst_offset && (selection_off + selection_len) >= (abs_inst_offset + BitOffset::BYTES(instr_length));
		
		BitOffset actual_instr_offset = abs_inst_offset;
		set_text_attribs(invert, selected, &actual_instr_offset, &instr_length);
		
		dc.DrawText(instr.assembly(), x + code_text_x, y);
		
		y += hf_char_height;
		++line_num;
		
		alternate = !alternate;
	}
	
	/* Draw bytes not yet disassembled within the visible rows. */
	
	off_t up_bytes_per_line = max_bytes_per_line();
	
	off_t up_skip_bytes = (line_num - ap.line) * up_bytes_per_line;
	
	BitOffset abs_up_off = ap.offset + BitOffset(up_skip_bytes, 0);
	
	while(abs_up_off < (d_offset + d_length) && y < client_size.GetHeight() && line_num < (y_lines - indent_final))
	{
		bool is_last_line = is_last_data_region && (line_num + 1) == (y_lines - indent_final);
		
		if(doc_ctrl.get_show_offsets())
		{
			/* Draw the offsets to the left */
			
			BitOffset offset_within_region = abs_up_off - d_offset;
			BitOffset display_offset = virt_offset + offset_within_region;
			
			std::string offset_str = format_offset(display_offset, doc_ctrl.get_offset_display_base(), doc_ctrl.get_end_virt_offset());
			
			set_text_attribs(false, false);
			dc.DrawText(offset_str, x + offset_text_x, y);
		}
		
		off_t line_len = std::min(((d_offset + d_length) - abs_up_off).byte(), up_bytes_per_line);
		
		bool data_err = false;
		std::vector<unsigned char> line_data;
		try {
			line_data = doc->read_data(abs_up_off, line_len);
			assert(line_data.size() == (size_t)(line_len));
		}
		catch(const std::exception &e)
		{
			fprintf(stderr, "Exception in REHex::DisassemblyRegion::draw: %s\n", e.what());
			data_err = true;
		}
		
		const unsigned char *ldp = data_err ? NULL : line_data.data();
		size_t ldl = data_err ? line_len : line_data.size();
		
		draw_hex_line(&doc_ctrl, dc, x + hex_text_x, y, ldp, ldl, 0, abs_up_off, alternate, has_focus, doc_ctrl.hex_view_active(), hex_highlight_func, is_last_line);
		
		if(doc_ctrl.get_show_ascii())
		{
			draw_ascii_line(&doc_ctrl, dc, x + ascii_text_x, y, ldp, ldl, 0, 0, 0, abs_up_off, alternate, has_focus, doc_ctrl.ascii_view_active(), ascii_highlight_func, is_last_line);
		}
		
		set_text_attribs(false, false);
		dc.DrawText("<< PROCESSING >>", x + code_text_x, y);
		
		y += hf_char_height;
		++line_num;
		
		abs_up_off += BitOffset(line_len, 0);
		
		alternate = !alternate;
	}
}

unsigned int REHex::DisassemblyRegion::check()
{
	unsigned int state = Region::IDLE;
	
	CodeAnalyser *analyser = get_analyser();
	AnalysisPosition ap = get_analysis_position(analyser);
	
	{
		off_t up_bytes_per_line = max_bytes_per_line();
		
		off_t up_remaining = ((d_offset + d_length) - ap.offset).byte();
		int64_t up_lines = (up_remaining + (up_bytes_per_line - 1)) / up_bytes_per_line;
		
		int64_t new_lines = ap.line + up_lines + indent_final;
		
		if(new_lines != y_lines)
		{
			state |= (StateFlag)Region::HEIGHT_CHANGE;
		}
	}
	
	if(analyser->longest_instruction() > longest_instruction)
	{
		longest_instruction = analyser->longest_instruction();
		state |= (StateFlag)Region::WIDTH_CHANGE;
	}
	
	if(analyser->longest_disasm() > longest_disasm)
	{
		longest_disasm = analyser->longest_disasm();
		state |= (StateFlag)Region::WIDTH_CHANGE;
	}
	
	if(ap.offset < (d_offset + d_length))
	{
		state |= (StateFlag)Region::PROCESSING;
	}
	
	return state;
}

std::pair<REHex::BitOffset, REHex::DocumentCtrl::GenericDataRegion::ScreenArea> REHex::DisassemblyRegion::offset_at_xy(DocumentCtrl &doc_ctrl, int mouse_x_px, int64_t mouse_y_lines)
{
	const FontCharacterCache &fcc = doc_ctrl.get_fcc();
	
	CodeAnalyser *analyser = get_analyser();
	AnalysisPosition ap = get_analysis_position(analyser);
	
	if(mouse_y_lines < ap.line)
	{
		/* Line has been processed. */
		
		CodeAnalyser::Instruction instr = analyser->instruction_by_line(d_offset, mouse_y_lines);
		if(!instr)
		{
			/* Couldn't get instruction. Don't know how long the line is. */
			return std::make_pair(BitOffset::INVALID, SA_NONE);
		}
		
		if(doc_ctrl.get_show_ascii() && mouse_x_px >= ascii_text_x)
		{
			/* Mouse in ASCII area. */
			
			unsigned int line_offset = fcc.fixed_char_at_x(mouse_x_px - ascii_text_x);
			if(line_offset >= instr.length())
			{
				return std::make_pair(BitOffset::INVALID, SA_NONE);
			}
			
			return std::make_pair(instr.offset() + BitOffset(line_offset, 0), SA_ASCII);
		}
		else if(mouse_x_px >= code_text_x)
		{
			/* Mouse in code area. */
			
			unsigned int char_offset = fcc.fixed_char_at_x(mouse_x_px - code_text_x);
			if(char_offset < instr.assembly().length())
			{
				return std::make_pair(instr.offset(), SA_SPECIAL);
			}
		}
		else if(mouse_x_px >= hex_text_x)
		{
			/* Mouse in hex area. */
			int line_offset = offset_at_x_hex(&doc_ctrl, (mouse_x_px - hex_text_x));
			if(line_offset < 0 || line_offset >= instr.length())
			{
				return std::make_pair(BitOffset::INVALID, SA_NONE);
			}
			
			return std::make_pair((instr.offset() + BitOffset(line_offset, 0)), SA_HEX);
		}
		else{
			/* Mouse in offset area. */
			return std::make_pair(BitOffset::INVALID, SA_NONE);
		}
	}
	else{
		/* Line isn't processed yet. */
		
		off_t up_base = (ap.offset - d_offset).byte();
		off_t up_bytes_per_line = max_bytes_per_line();
		
		int64_t up_row = mouse_y_lines - ap.line;
		
		off_t line_base = up_base + (up_row * up_bytes_per_line);
		off_t line_end  = std::min((line_base + up_bytes_per_line), d_length.byte());
		off_t line_len  = line_end - line_base;
		
		if(doc_ctrl.get_show_ascii() && mouse_x_px >= ascii_text_x)
		{
			/* Mouse in ASCII area. */
			
			unsigned int line_offset = fcc.fixed_char_at_x(mouse_x_px - ascii_text_x);
			if(line_offset >= line_len)
			{
				return std::make_pair(BitOffset::INVALID, SA_NONE);
			}
			
			return std::make_pair((d_offset + BitOffset((line_base + line_offset), 0)), SA_ASCII);
		}
		else if(mouse_x_px >= hex_text_x)
		{
			/* Mouse in hex area. */
			int line_offset = offset_at_x_hex(&doc_ctrl, (mouse_x_px - hex_text_x));
			if(line_offset < 0 || line_offset >= line_len)
			{
				return std::make_pair(BitOffset::INVALID, SA_NONE);
			}
			
			return std::make_pair((d_offset + BitOffset((line_base + line_offset), 0)), SA_HEX);
		}
		else{
			/* Mouse in offset area. */
			return std::make_pair(BitOffset::INVALID, SA_NONE);
		}
	}
	
	return std::make_pair(BitOffset::INVALID, SA_NONE);
}

std::pair<REHex::BitOffset, REHex::DocumentCtrl::GenericDataRegion::ScreenArea> REHex::DisassemblyRegion::offset_near_xy(DocumentCtrl &doc_ctrl, int mouse_x_px, int64_t mouse_y_lines, ScreenArea type_hint)
{
	const FontCharacterCache &fcc = doc_ctrl.get_fcc();
	
	CodeAnalyser *analyser = get_analyser();
	AnalysisPosition ap = get_analysis_position(analyser);
	
	if(mouse_y_lines < ap.line)
	{
		/* Line has been processed. */
		
		CodeAnalyser::Instruction instr = analyser->instruction_by_line(d_offset, mouse_y_lines);
		if(!instr)
		{
			/* Couldn't get instruction. Don't know how long the line is. */
			return std::make_pair(BitOffset::INVALID, SA_NONE);
		}
		
		off_t instr_base = (instr.offset() - d_offset).byte();
		off_t instr_end  = instr_base + instr.length();
		
		if(doc_ctrl.get_show_ascii() && ((mouse_x_px >= ascii_text_x && type_hint == SA_NONE) || type_hint == SA_ASCII))
		{
			/* Mouse in ASCII area. */
			
			if(mouse_x_px < ascii_text_x)
			{
				return std::make_pair(d_offset + BitOffset(std::max<off_t>((instr_base - 1), 0), 0), SA_ASCII);
			}
			else{
				unsigned int line_offset = fcc.fixed_char_at_x(mouse_x_px - ascii_text_x);
				
				off_t real_offset = std::min(
					(instr_base + line_offset),
					(instr_end - 1));
				
				return std::make_pair(d_offset + BitOffset(real_offset, 0), SA_ASCII);
			}
		}
		else if((mouse_x_px >= code_text_x && type_hint == SA_NONE) || type_hint == SA_SPECIAL)
		{
			/* Mouse in code area. */
			
			if(mouse_x_px < code_text_x)
			{
				return std::make_pair(BitOffset(std::max<off_t>((instr_base - 1), 0), 0), SA_SPECIAL);
			}
			
			unsigned int char_offset = fcc.fixed_char_at_x(mouse_x_px - code_text_x);
			if(char_offset < instr.assembly().length())
			{
				return std::make_pair(d_offset + BitOffset(instr_base, 0), SA_SPECIAL);
			}
			else{
				return std::make_pair(d_offset + BitOffset((instr_base + instr.length() - 1), 0), SA_SPECIAL);
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
			
			return std::make_pair(d_offset + BitOffset(real_offset, 0), SA_HEX);
		}
		else{
			/* Mouse in offset area. */
			return std::make_pair(BitOffset::INVALID, SA_NONE);
		}
	}
	else{
		/* Line isn't processed yet. */
		
		off_t up_base = (ap.offset - d_offset).byte();
		off_t up_bytes_per_line = max_bytes_per_line();
		
		int64_t up_row = mouse_y_lines - ap.line;
		
		off_t line_base = up_base + (up_row * up_bytes_per_line);
		off_t line_end  = std::min((line_base + up_bytes_per_line), (d_length.byte() - 1));
		
		if(doc_ctrl.get_show_ascii() && ((mouse_x_px >= ascii_text_x && type_hint == SA_NONE) || type_hint == SA_ASCII))
		{
			/* Mouse in ASCII area. */
			
			if(mouse_x_px < ascii_text_x)
			{
				return std::make_pair(d_offset + BitOffset(std::max<off_t>((line_base - 1), 0), 0), SA_ASCII);
			}
			else{
				unsigned int line_offset = fcc.fixed_char_at_x(mouse_x_px - ascii_text_x);
				
				off_t real_offset = std::min(
					(line_base + line_offset),
					(line_end - 1));
				
				return std::make_pair(d_offset + BitOffset(real_offset, 0), SA_ASCII);
			}
		}
		else if(mouse_x_px >= hex_text_x || type_hint == SA_HEX)
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
			
			return std::make_pair(d_offset + BitOffset(real_offset, 0), SA_HEX);
		}
		else{
			/* Mouse in offset area. */
			return std::make_pair(BitOffset::INVALID, SA_NONE);
		}
	}
	
	return std::make_pair(BitOffset::INVALID, SA_NONE);
}

REHex::BitOffset REHex::DisassemblyRegion::cursor_left_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	off_t rel_pos = (pos - d_offset).byte();
	
	CodeAnalyser *analyser = get_analyser();
	AnalysisPosition ap = get_analysis_position(analyser);
	
	off_t up_off = (ap.offset - d_offset).byte();
	
	if(active_type == SA_SPECIAL && rel_pos < up_off)
	{
		CodeAnalyser::Instruction instr = analyser->instruction_by_abs_offset(pos);
		if(!instr)
		{
			/* Couldn't get instruction. */
			return pos;
		}
		
		if(instr.offset() <= d_offset)
		{
			/* Already on first instruction in region. */
			return CURSOR_PREV_REGION;
		}
		
		CodeAnalyser::Instruction prev_instr = analyser->instruction_by_abs_offset(instr.offset() - BitOffset(0, 1));
		if(!prev_instr)
		{
			/* Couldn't get instruction. */
			return pos;
		}
		
		return prev_instr.offset();
	}
	else if(pos > d_offset)
	{
		return pos - BitOffset(1, 0);
	}
	else{
		return CURSOR_PREV_REGION;
	}
}

REHex::BitOffset REHex::DisassemblyRegion::cursor_right_from(BitOffset pos, ScreenArea active_area, DocumentCtrl *doc_ctrl)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	CodeAnalyser *analyser = get_analyser();
	AnalysisPosition ap = get_analysis_position(analyser);
	
	if(active_area == SA_SPECIAL && pos < ap.offset)
	{
		CodeAnalyser::Instruction instr = analyser->instruction_by_abs_offset(pos);
		if(!instr)
		{
			/* Couldn't get instruction. */
			return pos;
		}
		
		BitOffset next_instr_offset = instr.offset() + BitOffset(instr.length(), 0);
		
		if(next_instr_offset >= (d_offset + d_length))
		{
			/* Already on last instruction in region. */
			return CURSOR_NEXT_REGION;
		}
		
		return next_instr_offset;
	}
	else if((pos + BitOffset(1, 0)) < (d_offset + d_length))
	{
		return pos + BitOffset(1, 0);
	}
	else{
		return CURSOR_NEXT_REGION;
	}
}

REHex::BitOffset REHex::DisassemblyRegion::cursor_up_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	CodeAnalyser *analyser = get_analyser();
	AnalysisPosition ap = get_analysis_position(analyser);
	
	off_t up_bytes_per_line = max_bytes_per_line();
	
	if(pos < ap.offset)
	{
		CodeAnalyser::Instruction instr = analyser->instruction_by_abs_offset(pos);
		if(!instr)
		{
			/* Couldn't get instruction. */
			return pos;
		}
		
		if(instr.offset() <= d_offset)
		{
			/* Already on first line in region. */
			return CURSOR_PREV_REGION;
		}
		
		CodeAnalyser::Instruction prev_instr = analyser->instruction_by_abs_offset(instr.offset() - BitOffset(0, 1));
		if(!prev_instr)
		{
			/* Couldn't get instruction. */
			return pos;
		}
		
		BitOffset goto_off = std::min(
			(prev_instr.offset() + (pos - instr.offset())),
			(prev_instr.offset() + BitOffset((instr.length() - 1), 0)));
		
		return goto_off;
	}
	else if(pos < (ap.offset + BitOffset(up_bytes_per_line, 0)))
	{
		/* Move from top of unprocessed data to last line of disassembly. */
		
		if(ap.offset <= d_offset)
		{
			return CURSOR_PREV_REGION;
		}
		else{
			CodeAnalyser::Instruction instr = analyser->instruction_by_abs_offset(ap.offset - BitOffset(0, 1));
			if(!instr)
			{
				/* Couldn't get instruction. */
				return pos;
			}
			
			if(active_type == SA_SPECIAL)
			{
				return instr.offset();
			}
			else{
				BitOffset goto_off = std::min(
					(instr.offset() + (pos - ap.offset)),
					(instr.offset() + BitOffset((instr.length() - 1), 0)));
				
				return goto_off;
			}
		}
	}
	else{
		/* Move between unprocessed lines. */
		return pos - up_bytes_per_line;
	}
}

REHex::BitOffset REHex::DisassemblyRegion::cursor_down_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	CodeAnalyser *analyser = get_analyser();
	AnalysisPosition ap = get_analysis_position(analyser);
	
	off_t up_bytes_per_line = max_bytes_per_line();
	
	if(pos < ap.offset)
	{
		/* Move down a line from within disassembly. */
		
		CodeAnalyser::Instruction instr = analyser->instruction_by_abs_offset(pos);
		if(!instr)
		{
			/* Couldn't get instruction. */
			return pos;
		}
		
		BitOffset next_instr_offset = instr.offset() + BitOffset(instr.length(), 0);
		
		if(next_instr_offset >= (d_offset + d_length))
		{
			/* Already on last line in region. */
			return CURSOR_NEXT_REGION;
		}
		else if(next_instr_offset >= ap.offset)
		{
			/* On last line in disassembly. */
			
			return std::min(
				std::min(
					/* Same byte offset on next line. */
					(next_instr_offset + (pos - instr.offset())),
					
					/* Last byte on next line. */
					(next_instr_offset + BitOffset((up_bytes_per_line - 1), 0))),
				
				/* Last byte in this region. */
				(d_offset + d_length - BitOffset(1, 0)));
		}
		
		CodeAnalyser::Instruction next_instr = analyser->instruction_by_abs_offset(next_instr_offset);
		if(!next_instr)
		{
			/* Couldn't get instruction. */
			return pos;
		}
		
		if(active_type == SA_SPECIAL)
		{
			return next_instr.offset();
		}
		else{
			return std::min(
				/* Same byte offset in next instruction. */
				(next_instr.offset() + (pos - instr.offset())),
				
				/* Last byte in next instruction. */
				(next_instr.offset() + BitOffset((next_instr.length() - 1), 0)));
		}
	}
	else{
		/* Move down a line from within unprocessed data. */
		BitOffset line_pos = (pos - ap.offset) % BitOffset(up_bytes_per_line, 0);
		BitOffset next_line_begin = line_pos + BitOffset(up_bytes_per_line, 0);
		BitOffset next_line_pos = pos + BitOffset(up_bytes_per_line, 0);
		
		if(next_line_pos < (d_offset + d_length))
		{
			/* Move to same position in next line. */
			return next_line_pos;
		}
		else if(next_line_begin < (d_offset + d_length))
		{
			/* Move to last byte of next (last) line. */
			return (d_offset + d_length - BitOffset::BYTES(1));
		}
		else{
			/* Move to next region. */
			return CURSOR_NEXT_REGION;
		}
	}
}

REHex::BitOffset REHex::DisassemblyRegion::cursor_home_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	CodeAnalyser *analyser = get_analyser();
	AnalysisPosition ap = get_analysis_position(analyser);
	
	off_t up_bytes_per_line = max_bytes_per_line();
	
	if(pos < ap.offset)
	{
		/* Move to start of line in disassembly. */
		
		CodeAnalyser::Instruction instr = analyser->instruction_by_abs_offset(pos);
		if(!instr)
		{
			/* Couldn't get Instruction. */
			return pos;
		}
		
		return instr.offset();
	}
	else{
		/* Move to start of unprocessed line. */
		off_t line_pos = (pos - ap.offset).byte() % up_bytes_per_line;
		return pos - BitOffset(line_pos, 0);
	}
}

REHex::BitOffset REHex::DisassemblyRegion::cursor_end_from(BitOffset pos, ScreenArea active_type, DocumentCtrl *doc_ctrl)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	CodeAnalyser *analyser = get_analyser();
	AnalysisPosition ap = get_analysis_position(analyser);
	
	off_t up_bytes_per_line = max_bytes_per_line();
	
	if(pos < ap.offset)
	{
		/* Move to end of line in disassembly. */
		
		CodeAnalyser::Instruction instr = analyser->instruction_by_abs_offset(pos);
		if(!instr)
		{
			/* Couldn't get Instruction. */
			return pos;
		}
		
		return instr.offset() + BitOffset((instr.length() - 1), 0);
	}
	else{
		/* Move to end of unprocessed line. */
		off_t line_pos = (pos - ap.offset).byte() % up_bytes_per_line;
		
		return std::min(
			((pos - BitOffset::BYTES(line_pos)) + BitOffset::BYTES(up_bytes_per_line - 1)),
			(d_offset + d_length - 1));
	}
}

int REHex::DisassemblyRegion::cursor_column(BitOffset pos)
{
	assert(pos >= d_offset);
	assert(pos <= (d_offset + d_length));
	
	CodeAnalyser *analyser = get_analyser();
	AnalysisPosition ap = get_analysis_position(analyser);
	
	if(pos < ap.offset)
	{
		/* Offset is within disassembled area. */
		
		CodeAnalyser::Instruction instr = analyser->instruction_by_abs_offset(pos);
		if(!instr)
		{
			/* Couldn't get instruction. Fallback. */
			return 0;
		}
		
		assert(instr.offset() <= pos);
		assert((instr.offset() + BitOffset(instr.length(), 0)) > pos);
		
		return (pos - instr.offset()).byte();
	}
	else{
		/* Offset is within not-yet-processed data. */
		
		return (pos - ap.offset).byte() % max_bytes_per_line();
	}
}

REHex::BitOffset REHex::DisassemblyRegion::first_row_nearest_column(int column)
{
	return nth_row_nearest_column(0, column);
}

REHex::BitOffset REHex::DisassemblyRegion::last_row_nearest_column(int column)
{
	return nth_row_nearest_column(y_lines, column);
}

REHex::BitOffset REHex::DisassemblyRegion::nth_row_nearest_column(int64_t row, int column)
{
	CodeAnalyser *analyser = get_analyser();
	AnalysisPosition ap = get_analysis_position(analyser);
	
	if(row < ap.line)
	{
		/* Line has been processed. */
		
		CodeAnalyser::Instruction instr = analyser->instruction_by_line(d_offset, row);
		if(!instr)
		{
			/* Couldn't get instruction. Fallback. */
			return d_offset;
		}
		
		return std::min(
			/* Requested column byte offset within instruction. */
			(instr.offset() + BitOffset(column, 0)),
			
			/* Last byte within instruction. */
			(instr.offset() + BitOffset((instr.length() - 1), 0)));
	}
	else{
		/* Line isn't processed yet. */
		
		int64_t up_row = row - ap.line;
		
		column = std::min<int>(column, max_bytes_per_line() - 1);
		
		return std::min(
			(ap.offset + BitOffset((up_row * max_bytes_per_line() + column), 0)),
			(d_offset + d_length - BitOffset(1, 0)));
	}
}

REHex::DocumentCtrl::Rect REHex::DisassemblyRegion::calc_offset_bounds(BitOffset offset, DocumentCtrl *doc_ctrl)
{
	assert(offset >= d_offset);
	assert(offset <= (d_offset + d_length));
	
	const FontCharacterCache &fcc = doc_ctrl->get_fcc();
	
	CodeAnalyser *analyser = get_analyser();
	AnalysisPosition ap = get_analysis_position(analyser);
	
	unsigned int bytes_per_group = doc_ctrl->get_bytes_per_group();
	
	if(offset < ap.offset)
	{
		/* Offset is within disassembly. */
		
		CodeAnalyser::Instruction instr = analyser->instruction_by_abs_offset(offset);
		if(!instr)
		{
			/* Couldn't get instruction. Fallback. */
			return DocumentCtrl::Rect(y_offset, y_lines, 1, 1);
		}
		
		assert(instr.offset() <= offset);
		assert((instr.offset() + BitOffset(instr.length(), 0)) > offset);
		
		CodeAnalyser::Instruction base_instr = analyser->instruction_by_abs_offset(d_offset);
		assert(base_instr);
		
		assert(instr.line() >= base_instr.line());
		int64_t instr_line = instr.line() - base_instr.line();
		
		off_t line_off = (offset - instr.offset()).byte();
		
		if(doc_ctrl->hex_view_active())
		{
			return DocumentCtrl::Rect(
				/* Left X co-ordinate of hex byte. */
				hex_text_x + fcc.fixed_string_width((line_off * 2) + (line_off / bytes_per_group)),
				
				/* Line number. */
				(y_offset + instr_line),
				
				/* Width of hex byte. */
				fcc.fixed_string_width(2),
				
				/* Height of instruction (in lines). */
				1);
		}
		else if(doc_ctrl->special_view_active())
		{
			return DocumentCtrl::Rect(
				/* Left X co-ordinate of disassembly. */
				code_text_x,
				
				/* Line number. */
				(y_offset + instr_line),
				
				/* Width of instruction disassembly. */
				fcc.fixed_string_width(instr.assembly().length()),
				
				/* Height of instruction (in lines). */
				1);
		}
		else{
			assert(doc_ctrl->ascii_view_active());
			
			return DocumentCtrl::Rect(
				/* Left X co-ordinate of ASCII character. */
				ascii_text_x + fcc.fixed_string_width(line_off),
				
				/* Line number. */
				(y_offset + instr_line),
				
				/* Width of character. */
				fcc.fixed_char_width(),
				
				/* Height of instruction (in lines). */
				1);
		}
	}
	else{
		/* Offset hasn't been processed yet. */
		
		off_t up_bytes_per_line = max_bytes_per_line();
		
		off_t offset_within_up = (offset - ap.offset).byte();
		off_t line_off = offset_within_up % up_bytes_per_line;
		
		int64_t up_line = offset_within_up / up_bytes_per_line;
		
		if(doc_ctrl->ascii_view_active())
		{
			return DocumentCtrl::Rect(
				/* Left X co-ordinate of ASCII character. */
				ascii_text_x + fcc.fixed_string_width(line_off),
				
				/* Line number. */
				(y_offset + ap.line + up_line),
				
				/* Width of character. */
				fcc.fixed_char_width(),
				
				/* Height of instruction (in lines). */
				1);
		}
		else{
			return DocumentCtrl::Rect(
				/* Left X co-ordinate of hex byte. */
				hex_text_x + fcc.fixed_string_width((line_off * 2) + (line_off / bytes_per_group)),
				
				/* Line number. */
				(y_offset + ap.line + up_line),
				
				/* Width of hex byte. */
				fcc.fixed_string_width(2),
				
				/* Height (in lines). */
				1);
		}
	}
}

REHex::DocumentCtrl::GenericDataRegion::ScreenArea REHex::DisassemblyRegion::screen_areas_at_offset(BitOffset offset, DocumentCtrl *doc_ctrl)
{
	assert(offset >= d_offset);
	assert(offset <= (d_offset + d_length));
	
	ScreenArea areas = SA_HEX;
	
	if(doc_ctrl->get_show_ascii())
	{
		areas = (ScreenArea)(areas | SA_ASCII);
	}
	
	AnalysisPosition ap = get_analysis_position(get_analyser());
	
	if(offset < ap.offset)
	{
		areas = (ScreenArea)(areas | SA_SPECIAL);
	}
	
	return areas;
}

wxDataObject *REHex::DisassemblyRegion::OnCopy(DocumentCtrl &doc_ctrl)
{
	BitOffset selection_off, selection_last;
	std::tie(selection_off, selection_last) = doc_ctrl.get_selection_raw();
	
	assert(selection_off >= d_offset);
	assert(selection_last < (d_offset + d_length));
	
	/* If selection isn't byte aligned within the region, skip. */
	if((selection_off - d_offset).bit() != 0 || (selection_last - d_offset).bit() != 7)
	{
		return NULL;
	}
	
	if(doc_ctrl.special_view_active())
	{
		/* Copy disassembled instructions within selection. */
		
		CodeAnalyser *analyser = get_analyser();
		
		std::string data_string;
		
		BitOffset pos = selection_off;
		CodeAnalyser::Instruction instr;
		
		while(pos <= selection_last
			&& (instr = analyser->instruction_by_abs_offset(pos))
			&& (instr.offset() + BitOffset(instr.length(), 0) - BitOffset(0, 1)) <= selection_last)
		{
			if(instr.offset() >= selection_off)
			{
				if(!data_string.empty())
				{
					data_string.append("\n");
				}
				
				data_string.append(instr.assembly());
			}
			
			pos = instr.offset() + BitOffset(instr.length(), 0);
		}
		
		if(!data_string.empty())
		{
			return new wxTextDataObject(data_string);
		}
		else{
			return NULL;
		}
	}
	
	/* Fall back to default handling - copy selected bytes. */
	return NULL;
}

off_t REHex::DisassemblyRegion::max_bytes_per_line() const
{
	return (longest_instruction > 0)
		? longest_instruction
		: 8;
}

REHex::CodeAnalyser *REHex::DisassemblyRegion::get_analyser()
{
	DataAnalyser *base_analyser = doc->get_analyser(d_offset);
	assert(base_analyser != NULL);
	
	assert(dynamic_cast<CodeAnalyser*>(base_analyser) != NULL);
	CodeAnalyser *analyser = static_cast<CodeAnalyser*>(base_analyser);
	
	return analyser;
}

REHex::DisassemblyRegion::AnalysisPosition REHex::DisassemblyRegion::get_analysis_position(CodeAnalyser *analyser) const
{
	CodeAnalyser::AnalysisPosition cap = analyser->get_analysis_position();
	BitOffset end = d_offset + d_length;
	
	AnalysisPosition ap;
	
	if(cap.offset >= end)
	{
		CodeAnalyser::Instruction first_instruction_in_region = analyser->instruction_by_abs_offset(d_offset);
		assert(first_instruction_in_region);
		
		CodeAnalyser::Instruction last_instruction_in_region = analyser->instruction_by_abs_offset(d_offset + d_length - BitOffset(0, 1));
		assert(last_instruction_in_region);
		
		ap.offset = end;
		ap.line = (last_instruction_in_region.line() - first_instruction_in_region.line()) + 1LL;
	}
	else if(cap.offset <= d_offset)
	{
		ap.offset = d_offset;
		ap.line = 0;
	}
	else{
		CodeAnalyser::Instruction first_instruction_in_region = analyser->instruction_by_abs_offset(d_offset);
		assert(first_instruction_in_region);
		
		ap.offset = cap.offset;
		ap.line = (cap.line - first_instruction_in_region.line()) + 1LL;
	}
	
	return ap;
}
