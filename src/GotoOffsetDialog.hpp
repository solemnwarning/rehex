/* Reverse Engineer's Hex Editor
 * Copyright (C) 2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_GOTOFFSETDIALOG_HPP
#define REHEX_GOTOFFSETDIALOG_HPP

#include "BitOffset.hpp"
#include "NumericEntryDialog.hpp"
#include "SafeWindowPointer.hpp"
#include "SharedDocumentPointer.hpp"
#include "Tab.hpp"

namespace REHex {
	class Tab;
	
	/**
	 * @brief "Jump to offset" dialog.
	 *
	 * This specialisation of NumericEntryDialog provides the dialog for the "Jump to offset"
	 * command in the Edit menu and handles moving the cursor position.
	 *
	 * Supports modal and modeless operation.
	 *
	 * Unlike typical dialogs, this must ALWAYS be heap allocated (even for modal use).
	*/
	class GotoOffsetDialog: public NumericEntryDialog<BitOffset>
	{
		public:
			GotoOffsetDialog(wxWindow *parent, Tab *tab);
			
			virtual int ShowModal() override;
			
		private:
			SafeWindowPointer<Tab> tab;
			SharedDocumentPointer document;
			bool is_modal;
			
			static BaseHint get_last_base();
			
			void OnOK(wxCommandEvent &event);
			void OnCancel(wxCommandEvent &event);
			void OnClose(wxCloseEvent &event);
			
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_GOTOFFSETDIALOG_HPP */
