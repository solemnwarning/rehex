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
#include <wx/choice.h>
#include <wx/panel.h>
#include <wx/textctrl.h>
#include <wx/wx.h>

namespace REHex {
	class Disassemble: public wxPanel
	{
		public:
			Disassemble(wxWindow *parent, wxWindowID id = wxID_ANY);
			virtual ~Disassemble();
			
			void update(off_t offset, const unsigned char *data, size_t size, off_t position);
			
		private:
			LLVMDisasmContextRef disassembler;
			
			wxChoice *arch;
			wxTextCtrl *assembly;
			
			void reinit_disassembler();
			
			void OnArch(wxCommandEvent &event);
			
			/* Stays at the bottom because it changes the protection... */
			DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_DISASSEMBLE_HPP */
