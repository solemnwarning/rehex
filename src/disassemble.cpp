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

REHex::Disassemble::Disassemble(wxWindow *parent, wxWindowID id):
	wxPanel(parent, id), disassembler(NULL)
{
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
	
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);
	
	sizer->Add(arch, 0, wxEXPAND | wxALL, 0);
	sizer->Add(assembly, 1, wxEXPAND | wxALL, 0);
	
	SetSizerAndFit(sizer);
	
	reinit_disassembler();
}

REHex::Disassemble::~Disassemble()
{
	if(disassembler != NULL)
	{
		LLVMDisasmDispose(disassembler);
		disassembler = NULL;
	}
}

void REHex::Disassemble::update(off_t offset, const unsigned char *data, size_t size, off_t position)
{
	if(disassembler == NULL)
	{
		assembly->SetValue("<error>");
		return;
	}
	
	/* Why don't you take a const buffer, LLVM?! */
	std::vector<uint8_t> data_copy(data, data + size);
	
	char assembly_buf[256];
	size_t inst_size = LLVMDisasmInstruction(disassembler, data_copy.data(), size, 0, assembly_buf, sizeof(assembly_buf));
	
	if(inst_size > 0)
	{
		/* LLVM indents decoded instructions?! */
		assembly->SetValue(assembly_buf + strspn(assembly_buf, "\t "));
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

void REHex::Disassemble::OnArch(wxCommandEvent &event)
{
	reinit_disassembler();
}
