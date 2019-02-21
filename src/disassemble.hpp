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
#include "ToolPanel.hpp"

namespace REHex {
	class Disassemble: public ToolPanel
	{
		public:
			Disassemble(wxWindow *parent, REHex::Document *document);
			virtual ~Disassemble();
			
			virtual std::string name() const override;
// 			virtual std::string label() const override;
// 			virtual Shape shape() const override;
			
			virtual void save_state(wxConfig *config) const override;
			virtual void load_state(wxConfig *config) override;
			
			virtual wxSize DoGetBestClientSize() const override;
			
		private:
			struct Instruction {
				off_t length;
				std::string disasm;
			};
			
			REHex::Document *document;
			
			LLVMDisasmContextRef disassembler;
			
			wxChoice *arch;
			CodeCtrl *assembly;
			
			void document_unbind();
			void reinit_disassembler();
			void update();
			std::map<off_t, Instruction> disassemble(off_t offset, const void *code, size_t size);
			
			void OnDocumentDestroy(wxWindowDestroyEvent &event);
			void OnCursorMove(wxCommandEvent &event);
			void OnArch(wxCommandEvent &event);
			
			/* Stays at the bottom because it changes the protection... */
			DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_DISASSEMBLE_HPP */
