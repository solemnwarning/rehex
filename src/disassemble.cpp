/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018-2020 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <list>
#include <numeric>
#include <string.h>
#include <vector>

#include "app.hpp"
#include "DataType.hpp"
#include "disassemble.hpp"
#include "Events.hpp"
#include <capstone/capstone.h>

static REHex::ToolPanel *Disassemble_factory(wxWindow *parent, REHex::SharedDocumentPointer &document, REHex::DocumentCtrl *document_ctrl)
{
	return new REHex::Disassemble(parent, document, document_ctrl);
}

static REHex::ToolPanelRegistration tpr("Disassemble", "Disassembly", REHex::ToolPanel::TPS_TALL, &Disassemble_factory);

BEGIN_EVENT_TABLE(REHex::Disassemble, wxPanel)
	EVT_CHOICE(wxID_ANY, REHex::Disassemble::OnArch)
END_EVENT_TABLE()

struct CSArchitecture {
	const char *triple;
	const char *label;
	cs_arch arch;
	cs_mode mode;
};

cs_mode operator|(const cs_mode& lhs, const cs_mode& rhs)
{
	return static_cast<cs_mode>(static_cast<int>(lhs) | static_cast<int>(rhs));
}

/* List of all known architectures */
static const CSArchitecture known_arch_list[] = {
	{ "arm",   "ARM",               CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN },
	{ "armeb", "ARM (big endian)",  CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_BIG_ENDIAN },
	/* Add THUMB? */
	
	{ "aarch64",    "AArch64 (ARM64)",              CS_ARCH_ARM64, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN },
	{ "aarch64_be", "AArch64 (ARM64, big endian)",  CS_ARCH_ARM64, CS_MODE_ARM | CS_MODE_BIG_ENDIAN },
	
	#if CS_MAKE_VERSION(CS_API_MAJOR, CS_API_MINOR) >= CS_MAKE_VERSION(4, 0)
	{ "m680x-6301",  "Hitachi 6301/6303",  CS_ARCH_M680X,  CS_MODE_M680X_6301 },
	{ "m680x-6309",  "Hitachi 6309",       CS_ARCH_M680X,  CS_MODE_M680X_6309 },
	#endif
	
	{ "mips",     "MIPS",                           CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN },
	{ "mipsel",   "MIPS (little endian)",           CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN },
	{ "mips64",   "MIPS (64-bit)",                  CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN },
	{ "mips64el", "MIPS (64-bit, little endian)",   CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN },
	
	#if CS_MAKE_VERSION(CS_API_MAJOR, CS_API_MINOR) >= CS_MAKE_VERSION(4, 0)
	{ "m680x-6800",   "Motorola 6800/6802",             CS_ARCH_M680X,  CS_MODE_M680X_6800  },
	{ "m680x-6801",   "Motorola 6801/6803",             CS_ARCH_M680X,  CS_MODE_M680X_6801  },
	{ "m680x-6805",   "Motorola/Freescale 6805",        CS_ARCH_M680X,  CS_MODE_M680X_6805  },
	{ "m680x-6808",   "Motorola/Freescale/NXP 68HC08",  CS_ARCH_M680X,  CS_MODE_M680X_6808  },
	{ "m680x-6809",   "Motorola 6809",                  CS_ARCH_M680X,  CS_MODE_M680X_6809  },
	{ "m680x-6811",   "Motorola/Freescale/NXP 68HC11",  CS_ARCH_M680X,  CS_MODE_M680X_6811  },
	{ "m680x-cpu12",  "Motorola/Freescale/NXP 68HC12",  CS_ARCH_M680X,  CS_MODE_M680X_CPU12 },
	
	{ "m68k-68000", "Motorola 68000", CS_ARCH_M68K, CS_MODE_M68K_000 },
	{ "m68k-68000", "Motorola 68010", CS_ARCH_M68K, CS_MODE_M68K_010 },
	{ "m68k-68000", "Motorola 68020", CS_ARCH_M68K, CS_MODE_M68K_020 },
	{ "m68k-68000", "Motorola 68030", CS_ARCH_M68K, CS_MODE_M68K_030 },
	{ "m68k-68000", "Motorola 68040", CS_ARCH_M68K, CS_MODE_M68K_040 },
	{ "m68k-68000", "Motorola 68060", CS_ARCH_M68K, CS_MODE_M68K_060 },
	#endif
	
	#if CS_MAKE_VERSION(CS_API_MAJOR, CS_API_MINOR) >= CS_MAKE_VERSION(5, 0)
	{ "mos65xx", "MOS 65XX (including 6502)", CS_ARCH_MOS65XX, CS_MODE_LITTLE_ENDIAN },
	#endif
	
	{ "powerpc",     "PowerPC",                     CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN },
	{ "powerpc64",   "PowerPC (64-bit)",            CS_ARCH_PPC, CS_MODE_64 | CS_MODE_BIG_ENDIAN },
	{ "powerpc64le", "PowerPC (64-bit) (little endian)",CS_ARCH_PPC, CS_MODE_64 | CS_MODE_LITTLE_ENDIAN },
	
	{ "sparc",   "SPARC",                   CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN },
	{ "sparcel", "SPARC (little endian)",   CS_ARCH_SPARC, CS_MODE_LITTLE_ENDIAN },
	{ "sparcv9", "SPARC V9 (SPARC64)",      CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN | CS_MODE_V9 },
	
	{ "x86_16", "X86-16",           CS_ARCH_X86, CS_MODE_16 },
	{ "i386",   "X86",              CS_ARCH_X86, CS_MODE_32 },
	{ "x86_64", "X86-64 (AMD64)",   CS_ARCH_X86, CS_MODE_64 },
};

/* List of all supported architectures */
static std::vector<CSArchitecture> arch_list;
static std::list<REHex::DataTypeRegistration> disasm_dtrs;
static const char *DEFAULT_ARCH = "x86_64";

static void Initialize_disassembler()
{
	for(const auto& desc : known_arch_list)
	{
		/* Check if this architecture is supported by the currently used capstone */
		if(cs_support(desc.arch))
		{
			arch_list.push_back(desc);
			
			disasm_dtrs.emplace_back(
				(std::string("code:") + desc.triple),
				(std::string("Machine code (") + desc.label + ")"),
				[desc](REHex::SharedDocumentPointer &doc, off_t offset, off_t length)
				{
					return new REHex::DisassemblyRegion(doc, offset, length, desc.arch, desc.mode);
				});
		}
		else
		{
			/* FIXME: Add debug printing? */
		}
	}
}

static REHex::App::SetupHookRegistration Initialize_disassembler_hook(
	REHex::App::SetupPhase::READY,
	&Initialize_disassembler);

REHex::Disassemble::Disassemble(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl):
	ToolPanel(parent), document(document), document_ctrl(document_ctrl), disassembler(0)
{
	arch = new wxChoice(this, wxID_ANY);
	
	for(int i = 0; i < (int)arch_list.size(); ++i)
	{
		arch->Append(arch_list[i].label);
		
		if(strcmp(arch_list[i].triple, DEFAULT_ARCH) == 0)
		{
			arch->SetSelection(i);
		}
	}
	
	assembly = new CodeCtrl(this, wxID_ANY);
	
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);
	
	sizer->Add(arch, 0, wxEXPAND | wxALL, 0);
	sizer->Add(assembly, 1, wxEXPAND | wxALL, 0);
	
	SetSizerAndFit(sizer);
	
	this->document.auto_cleanup_bind(CURSOR_UPDATE, &REHex::Disassemble::OnCursorUpdate,    this);
	
	this->document.auto_cleanup_bind(DATA_ERASE,     &REHex::Disassemble::OnDataModified, this);
	this->document.auto_cleanup_bind(DATA_INSERT,    &REHex::Disassemble::OnDataModified, this);
	this->document.auto_cleanup_bind(DATA_OVERWRITE, &REHex::Disassemble::OnDataModified, this);
	
	this->document_ctrl.auto_cleanup_bind(EV_DISP_SETTING_CHANGED, &REHex::Disassemble::OnBaseChanged, this);
	
	reinit_disassembler();
	update();
}

REHex::Disassemble::~Disassemble()
{
	if(disassembler != 0)
	{
		cs_close(&disassembler);
	}
}

std::string REHex::Disassemble::name() const
{
	return "Disassemble";
}

void REHex::Disassemble::save_state(wxConfig *config) const
{
	const char *triple = arch_list[ arch->GetSelection() ].triple;
	config->Write("arch", triple);
}

void REHex::Disassemble::load_state(wxConfig *config)
{
	std::string cur_triple = arch_list[ arch->GetSelection() ].triple;
	std::string new_triple = config->Read("arch", cur_triple).ToStdString();
	
	for(int i = 0; i < (int)arch_list.size(); ++i)
	{
		if(new_triple == arch_list[i].triple)
		{
			arch->SetSelection(i);
			break;
		}
	}
	
	reinit_disassembler();
	update();
}

wxSize REHex::Disassemble::DoGetBestClientSize() const
{
	/* TODO: Calculate a reasonable initial size. */
	return wxPanel::DoGetBestClientSize();
}

void REHex::Disassemble::update()
{
	if (!is_visible)
	{
		/* There is no sense in updating this if we are not visible */
		return;
	}
	if(disassembler == 0)
	{
		assembly->clear();
		assembly->append_line(0, "<error>");
		return;
	}
	
	/* Size of window to load to try disassembling. */
	static const off_t WINDOW_SIZE = 256;
	
	off_t position = document->get_cursor_position();
	
	off_t window_base = std::max((position - (WINDOW_SIZE / 2)), (off_t)(0));
	
	std::vector<unsigned char> data;
	try {
		data = document->read_data(window_base, WINDOW_SIZE);
	}
	catch(const std::exception &e)
	{
		assembly->clear();
		assembly->append_line(window_base, e.what());
		
		return;
	}
	
	std::map<off_t, Instruction> instructions;
	
	/* Step 1: We try disassembling each offset from the start of the window up to the current
	 * position, the first one that disassembles to a contiguous series of instructions where
	 * one starts at position is where we display disassembly from.
	*/
	
	for(off_t doc_off = window_base, data_off = 0; doc_off <= position && (size_t)(data_off) < data.size(); ++doc_off, ++data_off)
	{
		std::map<off_t, Instruction> i_instructions = disassemble(doc_off, data.data() + data_off, data.size() - data_off);
		
		if(i_instructions.find(position) != i_instructions.end())
		{
			instructions = i_instructions;
			break;
		}
	}
	
	/* Step 2: If we didn't find a valid disassembly that way, try again, but this time allow
	 * an offset which disassembles to a contiguous series of instructions where one merely
	 * overlaps with the current position.
	*/
	
	if(instructions.empty())
	{
		for(off_t doc_off = window_base, data_off = 0; doc_off <= position && (size_t)(data_off) < data.size(); ++doc_off, ++data_off)
		{
			std::map<off_t, Instruction> i_instructions = disassemble(doc_off, data.data() + data_off, data.size() - data_off);
			
			auto ii = i_instructions.lower_bound(position);
			if(ii != i_instructions.begin()
				&& ii != i_instructions.end()
				&& (--ii, ((ii->first + ii->second.length) > position)))
			{
				instructions = i_instructions;
				break;
			}
		}
	}
	
	assembly->set_offset_display(document_ctrl->get_offset_display_base(), document->buffer_length());
	
	if(!instructions.empty())
	{
		assembly->clear();
		int this_line = 0, highlighted_line = 0;
		
		for(auto i = instructions.begin(); i != instructions.end(); ++i, ++this_line)
		{
			if(i->first <= position && (i->first + i->second.length) > position)
			{
				assembly->append_line(i->first, i->second.disasm.c_str(), true);
				highlighted_line = this_line;
			}
			else{
				assembly->append_line(i->first, i->second.disasm.c_str(), false);
			}
		}
		
		assembly->center_line(highlighted_line);
	}
	else{
		assembly->clear();
		assembly->append_line(position, "<invalid instruction>", true);
	}
}

void REHex::Disassemble::reinit_disassembler()
{
	const CSArchitecture& desc = arch_list[ arch->GetSelection() ];
	
	if(disassembler != 0)
	{
		cs_close(&disassembler);
	}
	
	cs_err error = cs_open(desc.arch, desc.mode, &disassembler);
	if(error != CS_ERR_OK)
	{
		/* TODO: Report error */
		return;
	}
}

std::map<off_t, REHex::Disassemble::Instruction> REHex::Disassemble::disassemble(off_t offset, const void *code, size_t size)
{
	std::map<off_t, Instruction> instructions;
	char disasm_buf[256];
	
	const uint8_t* code_ = static_cast<const uint8_t*>(code);
	size_t code_size = size;
	uint64_t address = offset;
	cs_insn* insn = cs_malloc(disassembler);
	
	/* NOTE: @code, @code_size & @address variables are all updated! */
	while(cs_disasm_iter(disassembler, &code_, &code_size, &address, insn))
	{
		Instruction inst;
		
		snprintf(disasm_buf, sizeof(disasm_buf), "%s\t%s", insn->mnemonic, insn->op_str);
		inst.length = insn->size;
		inst.disasm = disasm_buf;
		
		instructions.insert(std::make_pair(insn->address, inst));
	}
	cs_free(insn, 1);
	
	return instructions;
}

void REHex::Disassemble::OnCursorUpdate(CursorUpdateEvent &event)
{
	update();
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::Disassemble::OnArch(wxCommandEvent &event)
{
	reinit_disassembler();
	update();
}

void REHex::Disassemble::OnDataModified(OffsetLengthEvent &event)
{
	update();
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::Disassemble::OnBaseChanged(wxCommandEvent &event)
{
	update();
	
	/* Continue propogation. */
	event.Skip();
}

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
	
	dirty.set_range(d_offset, d_length);
	
	#if 0
	std::vector<unsigned char> data = doc->read_data(offset, length);
	
	const uint8_t* code_ = static_cast<const uint8_t*>(data.data());
	size_t code_size = data.size();
	uint64_t address = offset;
	cs_insn* insn = cs_malloc(disassembler);
	
	/* NOTE: @code, @code_size & @address variables are all updated! */
	while(cs_disasm_iter(disassembler, &code_, &code_size, &address, insn))
	{
		Instruction inst;
		
		char disasm_buf[256];
		snprintf(disasm_buf, sizeof(disasm_buf), "%s\t%s", insn->mnemonic, insn->op_str);
		
		inst.offset = insn->address;
		inst.length = insn->size;
		inst.disasm = disasm_buf;
		
		instructions.push_back(inst);
		
		longest_instruction = std::max<off_t>(longest_instruction, insn->size);
		longest_disasm = std::max(longest_disasm, inst.disasm.length());
	}
	
	cs_free(insn, 1);
	#endif
}

REHex::DisassemblyRegion::~DisassemblyRegion()
{
	cs_close(&disassembler);
}

int REHex::DisassemblyRegion::calc_width(DocumentCtrl &doc_ctrl)
{
	int indent_width = doc_ctrl.indent_width(indent_depth);
	
	int offset_column_width = doc_ctrl.get_show_offsets()
		? doc_ctrl.get_offset_column_width()
		: 0;
	
	unsigned int bytes_per_group = doc_ctrl.get_bytes_per_group();
	
	off_t bytes_per_line = (longest_instruction > 0)
		? longest_instruction
		: 8;
	
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
	
	off_t up_bytes_per_line = (longest_instruction > 0)
		? longest_instruction
		: 8;
	
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
	
	bool alternate = false;
	
	/* Find the element in processed that encompasses our start line. */
	/* TODO: Optimise. */
	auto pr = std::find_if(processed.begin(), processed.end(),
		[&](const InstructionRange &ir)
		{
			return ir.rel_y_offset <= line_num && (ir.rel_y_offset + ir.y_lines) > line_num;
		});
	
	auto highlight_func = [&](off_t offset)
	{
		/* TODO */
		return NoHighlight();
	};
	
	auto set_text_attribs = [&]()
	{
		dc.SetFont(doc_ctrl.get_font());
		
		dc.SetTextForeground((*active_palette)[alternate ? Palette::PAL_ALTERNATE_TEXT_FG : Palette::PAL_NORMAL_TEXT_FG]);
		dc.SetTextBackground((*active_palette)[Palette::PAL_NORMAL_TEXT_BG]);
	};
	
	while(pr != processed.end() && y < client_size.GetHeight() && line_num < (y_lines - indent_final))
	{
		std::vector<Instruction> instructions;
		
		bool data_err = false;
		std::vector<unsigned char> data = doc->read_data(pr->offset, pr->length);
		
		const uint8_t* code_ = static_cast<const uint8_t*>(data.data());
		size_t code_size = data.size();
		uint64_t address = pr->offset;
		cs_insn* insn = cs_malloc(disassembler);
		
		/* NOTE: @code, @code_size & @address variables are all updated! */
		while(cs_disasm_iter(disassembler, &code_, &code_size, &address, insn))
		{
			Instruction inst;
			
			char disasm_buf[256];
			snprintf(disasm_buf, sizeof(disasm_buf), "%s\t%s", insn->mnemonic, insn->op_str);
			
			inst.offset = insn->address;
			inst.length = insn->size;
			inst.disasm = disasm_buf;
			
			instructions.push_back(inst);
		}
		
		cs_free(insn, 1);
		
		for(size_t i = (line_num - pr->rel_y_offset); i < instructions.size() && y < client_size.GetHeight() && line_num < (y_lines - indent_final); ++i)
		{
			if(doc_ctrl.get_show_offsets())
			{
				/* Draw the offsets to the left */
				
				std::string offset_str = format_offset(instructions[i].offset, doc_ctrl.get_offset_display_base(), doc->buffer_length());
				
				set_text_attribs();
				dc.DrawText(offset_str, x + offset_text_x, y);
				
				int offset_vl_x = x + hex_text_x - (doc_ctrl.hf_char_width() / 2);
				
				wxPen norm_fg_1px((*active_palette)[Palette::PAL_NORMAL_TEXT_FG], 1);
				
				dc.SetPen(norm_fg_1px);
				dc.DrawLine(offset_vl_x, y, offset_vl_x, y + hf_char_height);
			}
			
			alternate = !alternate;
			
			off_t instruction_off_in_pr = instructions[i].offset - pr->offset;
			
			assert(instruction_off_in_pr >= 0);
			assert((instruction_off_in_pr + instructions[i].length) <= pr->length);
			
			draw_hex_line(&doc_ctrl, dc, x + hex_text_x, y, data.data() + instruction_off_in_pr, instructions[i].length, 0, instructions[i].offset, highlight_func);
			
			set_text_attribs();
			dc.DrawText(instructions[i].disasm, x + code_text_x, y);
			
			y += hf_char_height;
			++line_num;
		}
		
		++pr;
	}
	
	off_t up_off    = unprocessed_offset();
	off_t up_remain = unprocessed_bytes();
	
	while(up_remain > 0 && y < client_size.GetHeight() && line_num < (y_lines - indent_final))
	{
		if(doc_ctrl.get_show_offsets())
		{
			/* Draw the offsets to the left */
			
			std::string offset_str = format_offset(up_off, doc_ctrl.get_offset_display_base(), doc->buffer_length());
			
			set_text_attribs();
			dc.DrawText(offset_str, x + offset_text_x, y);
			
			int offset_vl_x = x + hex_text_x - (doc_ctrl.hf_char_width() / 2);
			
			wxPen norm_fg_1px((*active_palette)[Palette::PAL_NORMAL_TEXT_FG], 1);
			
			dc.SetPen(norm_fg_1px);
			dc.DrawLine(offset_vl_x, y, offset_vl_x, y + hf_char_height);
		}
		
		off_t line_len = std::min(up_remain, longest_instruction);
		
		bool data_err = false;
		std::vector<unsigned char> line_data = doc->read_data(up_off, line_len);
		assert(line_data.size() == line_len);
		
		const unsigned char *ldp = data_err ? NULL : line_data.data();
		size_t ldl = data_err ? line_len : line_data.size();
		
		draw_hex_line(&doc_ctrl, dc, x + hex_text_x, y, ldp, ldl, 0, up_off, highlight_func);
		
		set_text_attribs();
		dc.DrawText("<< PROCESSING >>", x + code_text_x, y);
		
		y += hf_char_height;
		++line_num;
		
		up_off    += line_len;
		up_remain -= line_len;
	}
	
	#if 0
	for(size_t i = skip_lines; y < client_size.GetHeight() && i < instructions.size(); ++i)
	{
		dc.SetTextForeground((*active_palette)[Palette::PAL_NORMAL_TEXT_FG]);
		dc.SetTextBackground((*active_palette)[Palette::PAL_NORMAL_TEXT_BG]);
		
		if(doc_ctrl.get_show_offsets())
		{
			/* Draw the offsets to the left */
			
			std::string offset_str = format_offset(instructions[i].offset, doc_ctrl.get_offset_display_base(), doc->buffer_length());
			
			dc.DrawText(offset_str, x + offset_text_x, y);
			
			int offset_vl_x = x + hex_text_x - (doc_ctrl.hf_char_width() / 2);
			
			wxPen norm_fg_1px((*active_palette)[Palette::PAL_NORMAL_TEXT_FG], 1);
			
			dc.SetPen(norm_fg_1px);
			dc.DrawLine(offset_vl_x, y, offset_vl_x, y + hf_char_height);
		}
		
		if(alternate)
		{
			dc.SetTextForeground((*active_palette)[Palette::PAL_ALTERNATE_TEXT_FG]);
		}
		
		alternate = !alternate;
		
		bool data_err = false;
		std::vector<unsigned char> data = doc->read_data(instructions[i].offset, instructions[i].length);
		
		unsigned int bytes_per_group = doc_ctrl.get_bytes_per_group();
		
		for(size_t j = 0; j < data.size(); ++j)
		{
			const char *nibble_to_hex = data_err
				? "????????????????"
				: "0123456789ABCDEF";
			
			const char hex_str[] = {
				nibble_to_hex[ (data[j] & 0xF0) >> 4 ],
				nibble_to_hex[ data[j] & 0x0F ],
				'\0'
			};
			
			dc.DrawText(hex_str, (x + hex_text_x + doc_ctrl.hf_string_width((j * 2) + (j / bytes_per_group))), y);
		}
		
		dc.DrawText(instructions[i].disasm, x + code_text_x, y);
		
		y += hf_char_height;
	}
	#endif
}

unsigned int REHex::DisassemblyRegion::check()
{
	if(dirty.empty())
	{
		/* Range is fully analysed. */
		return Region::IDLE;
	}
	
	unsigned int state = Region::IDLE;
	
	static const off_t SOFT_IR_LIMIT = 10240; /* 100KiB */
	
	ByteRangeSet::Range first_dirty_range = dirty[0];
	
	off_t process_base = first_dirty_range.offset;
	off_t process_len  = std::min(first_dirty_range.length, SOFT_IR_LIMIT);
	
	std::vector<unsigned char> data = doc->read_data(process_base, process_len);
	
	const uint8_t* code_ = static_cast<const uint8_t*>(data.data());
	size_t code_size = data.size();
	uint64_t address = process_base;
	cs_insn* insn = cs_malloc(disassembler);
	
	// TODO: Handle instructions straddling ranges
	// cs_option(disassembler, CS_OPT_SKIPDATA, CS_OPT_OFF);
	
	InstructionRange new_ir;
	new_ir.offset               = process_base;
	new_ir.length               = 0;
	new_ir.longest_instruction  = 0;
	new_ir.longest_disasm       = 0;
	new_ir.rel_y_offset         = processed.empty() ? 0 : (processed.back().rel_y_offset + processed.back().y_lines);
	new_ir.y_lines              = 0;
	
	/* NOTE: @code, @code_size & @address variables are all updated! */
	while(cs_disasm_iter(disassembler, &code_, &code_size, &address, insn))
	{
		size_t disasm_length = strlen(insn->mnemonic) + 1 + strlen(insn->op_str);
		
		new_ir.length += insn->size;
		
		new_ir.longest_instruction = std::max<off_t>(new_ir.longest_instruction, insn->size);
		new_ir.longest_disasm = std::max(new_ir.longest_disasm, disasm_length);
		
		++(new_ir.y_lines);
		
		state |= (StateFlag)Region::HEIGHT_CHANGE;
	}
	
	cs_free(insn, 1);
	
	// TODO: Merge into processed
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
	return std::make_pair<off_t, ScreenArea>(-1, SA_NONE);
}

std::pair<off_t, REHex::DocumentCtrl::GenericDataRegion::ScreenArea> REHex::DisassemblyRegion::offset_near_xy(DocumentCtrl &doc_ctrl, int mouse_x_px, int64_t mouse_y_lines, ScreenArea type_hint)
{
	return std::make_pair(d_offset, SA_SPECIAL);
}

off_t REHex::DisassemblyRegion::cursor_left_from(off_t pos) { return d_offset; }
off_t REHex::DisassemblyRegion::cursor_right_from(off_t pos) { return d_offset; }
off_t REHex::DisassemblyRegion::cursor_up_from(off_t pos) { return d_offset; }
off_t REHex::DisassemblyRegion::cursor_down_from(off_t pos) { return d_offset; }
off_t REHex::DisassemblyRegion::cursor_home_from(off_t pos) { return d_offset; }
off_t REHex::DisassemblyRegion::cursor_end_from(off_t pos) { return d_offset; }

int REHex::DisassemblyRegion::cursor_column(off_t pos)
{
	return 0;
}

off_t REHex::DisassemblyRegion::first_row_nearest_column(int column)
{
	return d_offset;
	//return instructions.front().offset;
}

off_t REHex::DisassemblyRegion::last_row_nearest_column(int column)
{
	return d_offset;
	// return instructions.back().offset;
}

off_t REHex::DisassemblyRegion::nth_row_nearest_column(int64_t row, int column)
{
	return d_offset;
	// return instructions.back().offset;
}

REHex::DocumentCtrl::Rect REHex::DisassemblyRegion::calc_offset_bounds(off_t offset, DocumentCtrl *doc_ctrl)
{
	abort();
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
