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

#include <llvm-c/Disassembler.h>
#include <llvm-c/Target.h>
#include <map>
#include <string>
#include <wx/choice.h>
#include <wx/panel.h>
#include <wx/wx.h>

#include "CodeCtrl.hpp"
#include "document.hpp"

namespace REHex {
	class Disassemble: public wxPanel
	{
		public:
			Disassemble(wxWindow *parent, const REHex::Document &document);
			virtual ~Disassemble();
			
			virtual wxSize DoGetBestClientSize() const override;
			
			void set_position(off_t position);
			void update();
			
		private:
			struct Instruction {
				off_t length;
				std::string disasm;
			};
			
			const REHex::Document &document;
			off_t position;
			
			LLVMDisasmContextRef disassembler;
			
			wxChoice *arch;
			CodeCtrl *assembly;
			
			void reinit_disassembler();
			std::map<off_t, Instruction> disassemble(off_t offset, const void *code, size_t size);
			
			void OnArch(wxCommandEvent &event);
			
			/* Stays at the bottom because it changes the protection... */
			DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_DISASSEMBLE_HPP */
