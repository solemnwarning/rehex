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

#include <string.h>
#include <vector>

#include "disassemble.hpp"

BEGIN_EVENT_TABLE(REHex::Disassemble, wxPanel)
	EVT_CHOICE(wxID_ANY, REHex::Disassemble::OnArch)
END_EVENT_TABLE()

struct LLVMArchitecture {
	const char *triple;
	const char *label;
};

static LLVMArchitecture arch_list[] = {
	{ "i386",   "X86" },
	{ "x86_64", "X86-64 (AMD64)" },
	{ NULL, NULL },
};

static const char *DEFAULT_ARCH = "x86_64";

REHex::Disassemble::Disassemble(wxWindow *parent, const REHex::Document &document):
	wxPanel(parent, wxID_ANY), document(document), disassembler(NULL)
{
	position = document.get_cursor_position();
	
	arch = new wxChoice(this, wxID_ANY);
	
	for(int i = 0; arch_list[i].triple != NULL; ++i)
	{
		arch->Append(arch_list[i].label);
		
		if(strcmp(arch_list[i].triple, DEFAULT_ARCH) == 0)
		{
			arch->SetSelection(i);
		}
	}
	
	assembly = new wxTextCtrl(this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize,
		(wxTE_MULTILINE | wxTE_READONLY | wxTE_RICH | wxHSCROLL));
	
	/* TODO: Calculate size properly. */
	assembly->SetMinSize(wxSize(200, 100));
	
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);
	
	sizer->Add(arch, 0, wxEXPAND | wxALL, 0);
	sizer->Add(assembly, 1, wxEXPAND | wxALL, 0);
	
	SetSizerAndFit(sizer);
	
	reinit_disassembler();
	update();
}

REHex::Disassemble::~Disassemble()
{
	if(disassembler != NULL)
	{
		LLVMDisasmDispose(disassembler);
		disassembler = NULL;
	}
}

void REHex::Disassemble::set_position(off_t position)
{
	this->position = position;
	update();
}

void REHex::Disassemble::update()
{
	if(disassembler == NULL)
	{
		assembly->SetValue("<error>");
		return;
	}
	
	/* Size of window to load to try disassembling. */
	static const off_t WINDOW_SIZE = 64;
	
	off_t window_base = std::max((position - (WINDOW_SIZE / 2)), (off_t)(0));
	
	std::vector<unsigned char> data = document.read_data(window_base, WINDOW_SIZE);
	
	std::map<off_t, Instruction> instructions;
	
	/* Step 1: We try disassembling each offset from the start of the window up to the current
	 * position, the first one that disassembles to a contiguous series of instructions where
	 * one starts at position is where we display disassembly from.
	*/
	
	for(off_t i = window_base; i <= position; ++i)
	{
		off_t rel_off = i - window_base;
		std::map<off_t, Instruction> i_instructions = disassemble(window_base, data.data() + rel_off, data.size() - rel_off);
		
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
		for(off_t i = window_base; i <= position; ++i)
		{
			off_t rel_off = i - window_base;
			std::map<off_t, Instruction> i_instructions = disassemble(window_base, data.data() + rel_off, data.size() - rel_off);
			
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
	
	if(!instructions.empty())
	{
		wxTextAttr normal = assembly->GetDefaultStyle();
		
		assembly->SetValue("");
		
		for(auto i = instructions.begin(); i != instructions.end(); ++i)
		{
			if(i != instructions.begin())
			{
				assembly->AppendText("\n");
			}
			
			if(i->first <= position && (i->first + i->second.length) > position)
			{
				wxTextAttr active = normal;
				active.SetTextColour(*wxRED);
				
				assembly->SetDefaultStyle(active);
			}
			
			char tmp[256];
			snprintf(tmp, sizeof(tmp), "%08X  %s", (unsigned)(i->first), i->second.disasm.c_str());
			assembly->AppendText(tmp);
			
			if(i->first <= position && (i->first + i->second.length) > position)
			{
				assembly->SetDefaultStyle(normal);
			}
		}
	}
	else{
		assembly->SetValue("<invalid instruction>");
	}
}

void REHex::Disassemble::reinit_disassembler()
{
	const char *triple = arch_list[ arch->GetSelection() ].triple;
	
	if(disassembler != NULL)
	{
		LLVMDisasmDispose(disassembler);
		disassembler = NULL;
	}
	
	disassembler = LLVMCreateDisasm(triple, NULL, 0, NULL, NULL);
	if(disassembler == NULL)
	{
		/* TODO: Report error */
		return;
	}
	
	/* Use Intel assembly syntax. */
	LLVMSetDisasmOptions(disassembler, LLVMDisassembler_Option_AsmPrinterVariant);
}

std::map<off_t, REHex::Disassemble::Instruction> REHex::Disassemble::disassemble(off_t offset, const void *code, size_t size)
{
	/* LLVM takes a NON-CONST buffer, wheee. */
	std::vector<unsigned char> code_copy(
		(const unsigned char*)(code),
		(const unsigned char*)(code) + size);
	
	std::map<off_t, Instruction> instructions;
	
	for(size_t i = 0; i < size;)
	{
		char disasm_buf[256];
		size_t inst_size = LLVMDisasmInstruction(disassembler, code_copy.data() + i, code_copy.size() - i, 0, disasm_buf, sizeof(disasm_buf));
		
		if(inst_size > 0)
		{
			/* LLVM indents decoded instructions?! */
			const char *disasm = disasm_buf + strspn(disasm_buf, "\t ");
			
			Instruction inst;
			inst.length = inst_size;
			inst.disasm = disasm;
			
			instructions.insert(std::make_pair((off_t)(offset + i), inst));
			
			i += inst_size;
		}
		else{
			break;
		}
	}
	
	return instructions;
}

void REHex::Disassemble::OnArch(wxCommandEvent &event)
{
	reinit_disassembler();
	update();
}
