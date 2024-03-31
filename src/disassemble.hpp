/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <capstone/capstone.h>
#include <map>
#include <string>
#include <utility>
#include <wx/choice.h>
#include <wx/panel.h>
#include <wx/wx.h>

#include "CodeCtrl.hpp"
#include "document.hpp"
#include "Events.hpp"
#include "SafeWindowPointer.hpp"
#include "SharedDocumentPointer.hpp"
#include "ToolPanel.hpp"

namespace REHex {
	class Disassemble: public ToolPanel
	{
		public:
			Disassemble(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			virtual ~Disassemble();
			
			virtual std::string name() const override;
// 			virtual std::string label() const override;
// 			virtual Shape shape() const override;
			
			virtual void save_state(wxConfig *config) const override;
			virtual void load_state(wxConfig *config) override;
			virtual void update() override;
			
			virtual wxSize DoGetBestClientSize() const override;
			
		private:
			struct Instruction {
				off_t length;
				std::string disasm;
			};
			
			SharedDocumentPointer document;
			SafeWindowPointer<DocumentCtrl> document_ctrl;
			
			size_t disassembler;
			
			wxChoice *arch;
			CodeCtrl *assembly;
			
			void reinit_disassembler();
			std::map<BitOffset, Instruction> disassemble(BitOffset offset, const void *code, size_t size);
			
			void OnCursorUpdate(CursorUpdateEvent &event);
			void OnArch(wxCommandEvent &event);
			void OnDataModified(OffsetLengthEvent &event);
			void OnBaseChanged(wxCommandEvent &event);
			void OnAsmSyntaxChanged(wxCommandEvent &event);
			
			/* Stays at the bottom because it changes the protection... */
			DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_DISASSEMBLE_HPP */
