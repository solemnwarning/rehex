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

#include <string.h>
#include <vector>

#include "disassemble.hpp"
#include "Events.hpp"

static REHex::ToolPanel *Disassemble_factory(wxWindow *parent, REHex::SharedDocumentPointer &document, REHex::DocumentCtrl *document_ctrl)
{
	return new REHex::Disassemble(parent, document, document_ctrl);
}

static REHex::ToolPanelRegistration tpr("Disassemble", "Disassembly", REHex::ToolPanel::TPS_TALL, &Disassemble_factory);

BEGIN_EVENT_TABLE(REHex::Disassemble, wxPanel)
	EVT_CHOICE(wxID_ANY, REHex::Disassemble::OnArch)
END_EVENT_TABLE()

struct LLVMArchitecture {
	const char *triple;
	const char *label;
};

static LLVMArchitecture arch_list[] = {
	#ifdef LLVM_ENABLE_ARM
	{ "arm",   "ARM" },
	{ "armeb", "ARM (big endian)" },
	#endif
	
	#ifdef LLVM_ENABLE_AARCH64
	{ "aarch64",    "AArch64 (ARM64)" },
	{ "aarch64_be", "AArch64 (ARM64, big endian)" },
	#endif
	
	#ifdef LLVM_ENABLE_MIPS
	{ "mips",     "MIPS" },
	{ "mipsel",   "MIPS (little endian)" },
	{ "mips64",   "MIPS (64-bit)" },
	{ "mips64el", "MIPS (64-bit, little endian)" },
	#endif
	
	#ifdef LLVM_ENABLE_POWERPC
	{ "powerpc",     "PowerPC" },
	{ "powerpc64",   "PowerPC (64-bit)" },
	{ "powerpc64le", "PowerPC (64-bit) (little endian)" },
	#endif
	
	#ifdef LLVM_ENABLE_SPARC
	{ "sparc",   "SPARC" },
	{ "sparcel", "SPARC (little endian)" },
	{ "sparcv9", "SPARC V9 (SPARC64)" },
	#endif
	
	#ifdef LLVM_ENABLE_X86
	{ "i386",   "X86" },
	{ "x86_64", "X86-64 (AMD64)" },
	#endif
	
	{ NULL, NULL },
};

static const char *DEFAULT_ARCH = "x86_64";

REHex::Disassemble::Disassemble(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl):
	ToolPanel(parent), document(document), document_ctrl(document_ctrl), disassembler(NULL)
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
	
	assembly = new CodeCtrl(this, wxID_ANY);
	
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);
	
	sizer->Add(arch, 0, wxEXPAND | wxALL, 0);
	sizer->Add(assembly, 1, wxEXPAND | wxALL, 0);
	
	SetSizerAndFit(sizer);
	
	this->document.auto_cleanup_bind(CURSOR_UPDATE, &REHex::Disassemble::OnCursorUpdate,    this);
	
	this->document.auto_cleanup_bind(DATA_ERASE,     &REHex::Disassemble::OnDataModified, this);
	this->document.auto_cleanup_bind(DATA_INSERT,    &REHex::Disassemble::OnDataModified, this);
	this->document.auto_cleanup_bind(DATA_OVERWRITE, &REHex::Disassemble::OnDataModified, this);
	
	this->document_ctrl.auto_cleanup_bind(EV_BASE_CHANGED, &REHex::Disassemble::OnBaseChanged, this);
	
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
	
	for(int i = 0; arch_list[i].triple != NULL; ++i)
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
	if(disassembler == NULL)
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
