/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2023 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_FILLRANGEDIALOG_HPP
#define REHEX_FILLRANGEDIALOG_HPP

#include <wx/dialog.h>
#include <wx/radiobut.h>
#include <wx/textctrl.h>

#include "DocumentCtrl.hpp"
#include "NumericTextCtrl.hpp"

namespace REHex {
	class FillRangeDialog: public wxDialog
	{
		public:
			FillRangeDialog(wxWindow *parent, Document &document, DocumentCtrl &document_ctrl);
			virtual ~FillRangeDialog();
			
		private:
			Document &document;
			
			wxTextCtrl *data_input;
			
			wxRadioButton *overwrite_mode;
			wxRadioButton *insert_mode;
			
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

#endif /* !REHEX_FILLRANGEDIALOG_HPP */
