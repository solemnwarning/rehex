/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <list>
#include <numeric>
#include <string.h>
#include <tuple>
#include <vector>

#include "App.hpp"
#include "DataType.hpp"
#include "disassemble.hpp"
#include "DisassemblyRegion.hpp"
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

	#if CS_MAKE_VERSION(CS_API_MAJOR, CS_API_MINOR) >= CS_MAKE_VERSION(5, 0)
	{ "riscv32", "RISC-V RV32G", CS_ARCH_RISCV, CS_MODE_RISCV32 },
	{ "riscv64", "RISC-V RV64G", CS_ARCH_RISCV, CS_MODE_RISCV64 },
	{ "riscvc", "RISC-V Compressed Instruction Set", CS_ARCH_RISCV, CS_MODE_RISCVC },
	#endif
	
	{ "sparc",   "SPARC",                   CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN },
	{ "sparcel", "SPARC (little endian)",   CS_ARCH_SPARC, CS_MODE_LITTLE_ENDIAN },
	{ "sparcv9", "SPARC V9 (SPARC64)",      CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN | CS_MODE_V9 },

	#if CS_MAKE_VERSION(CS_API_MAJOR, CS_API_MINOR) >= CS_MAKE_VERSION(5, 0)
	{ "WASM",   "WebAssembly",   CS_ARCH_WASM, CS_MODE_LITTLE_ENDIAN },
	#endif
	
	{ "x86_16", "X86-16",           CS_ARCH_X86, CS_MODE_16 },
	{ "i386",   "X86",              CS_ARCH_X86, CS_MODE_32 },
	{ "x86_64", "X86-64 (AMD64)",   CS_ARCH_X86, CS_MODE_64 },
};

/* List of all supported architectures */
static std::vector<CSArchitecture> arch_list;
static std::list<REHex::StaticDataTypeRegistration> disasm_dtrs;
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
				std::vector<std::string>({ "Machine code" }),
				REHex::DataType()
					.WithWordSize(REHex::BitOffset(1, 0))
					.WithVariableSizeRegion(
						[desc](REHex::SharedDocumentPointer &doc, REHex::BitOffset offset, REHex::BitOffset length, REHex::BitOffset virt_offset)
						{
							return new REHex::DisassemblyRegion(doc, offset, length, virt_offset, desc.arch, desc.mode);
						}));
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
	
	wxGetApp().settings->Bind(PREFERRED_ASM_SYNTAX_CHANGED, &REHex::Disassemble::OnAsmSyntaxChanged, this);
	
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

std::string REHex::Disassemble::label() const
{
	return "Disassembly";
}

REHex::ToolPanel::Shape REHex::Disassemble::shape() const
{
	return ToolPanel::TPS_TALL;
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
	
	BitOffset position = document->get_cursor_position();
	
	BitOffset window_base = std::max((position - BitOffset((WINDOW_SIZE / 2), 0)), BitOffset(0, position.bit()));
	
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
	
	std::map<BitOffset, Instruction> instructions;
	
	/* Step 1: We try disassembling each offset from the start of the window up to the current
	 * position, the first one that disassembles to a contiguous series of instructions where
	 * one starts at position is where we display disassembly from.
	*/
	
	BitOffset doc_off;
	size_t data_off;
	
	for(doc_off = window_base, data_off = 0; doc_off <= position && data_off < data.size(); doc_off += BitOffset(1, 0), ++data_off)
	{
		std::map<BitOffset, Instruction> i_instructions = disassemble(doc_off, data.data() + data_off, data.size() - data_off);
		
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
		for(doc_off = window_base, data_off = 0; doc_off <= position && data_off < data.size(); doc_off += BitOffset(1, 0), ++data_off)
		{
			std::map<BitOffset, Instruction> i_instructions = disassemble(doc_off, data.data() + data_off, data.size() - data_off);
			
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
	
	if(desc.arch == CS_ARCH_X86)
	{
		AsmSyntax preferred_asm_syntax = wxGetApp().settings->get_preferred_asm_syntax();
		
		switch(preferred_asm_syntax)
		{
			case AsmSyntax::INTEL:
				cs_option(disassembler, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
				break;
				
			case AsmSyntax::ATT:
				cs_option(disassembler, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
				break;
		}
	}
}

std::map<REHex::BitOffset, REHex::Disassemble::Instruction> REHex::Disassemble::disassemble(BitOffset offset, const void *code, size_t size)
{
	std::map<BitOffset, Instruction> instructions;
	char disasm_buf[256];
	
	const uint8_t* code_ = static_cast<const uint8_t*>(code);
	size_t code_size = size;
	uint64_t address = offset.byte();
	cs_insn* insn = cs_malloc(disassembler);
	
	/* NOTE: @code, @code_size & @address variables are all updated! */
	while(cs_disasm_iter(disassembler, &code_, &code_size, &address, insn))
	{
		Instruction inst;
		
		snprintf(disasm_buf, sizeof(disasm_buf), "%s\t%s", insn->mnemonic, insn->op_str);
		inst.length = insn->size;
		inst.disasm = disasm_buf;
		
		instructions.insert(std::make_pair(BitOffset(insn->address, offset.bit()), inst));
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

void REHex::Disassemble::OnAsmSyntaxChanged(wxCommandEvent &event)
{
	const CSArchitecture& arch_desc = arch_list[ arch->GetSelection() ];
	
	if(arch_desc.arch == CS_ARCH_X86)
	{
		reinit_disassembler();
		update();
	}
}
