/* Reverse Engineer's Hex Editor
 * Copyright (C) 2019 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_SELECTRANGEDIALOG_HPP
#define REHEX_SELECTRANGEDIALOG_HPP

#include <wx/dialog.h>
#include <wx/radiobut.h>

#include "DocumentCtrl.hpp"
#include "NumericTextCtrl.hpp"

namespace REHex {
	class SelectRangeDialog: public wxDialog
	{
		public:
			SelectRangeDialog(wxWindow *parent, Document &document, DocumentCtrl &document_ctrl);
			virtual ~SelectRangeDialog();
			
		private:
			Document     &document;
			DocumentCtrl &document_ctrl;
			
			NumericTextCtrl *range_from;
			
			wxRadioButton *range_to_enable;
			NumericTextCtrl *range_to;
			
			wxRadioButton *range_len_enable;
			NumericTextCtrl *range_len;
			
			void enable_inputs();
			
			void OnOK(wxCommandEvent &event);
			void OnRadio(wxCommandEvent &event);
			
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_SELECTRANGEDIALOG_HPP */
