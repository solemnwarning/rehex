/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_BYTESPERLINEDIALOG_HPP
#define REHEX_BYTESPERLINEDIALOG_HPP

#include <wx/button.h>
#include <wx/checkbox.h>
#include <wx/dialog.h>
#include <wx/radiobut.h>
#include <wx/sizer.h>
#include <wx/spinctrl.h>

namespace REHex
{
	class BytesPerLineDialog: public wxDialog
	{
		public:
			BytesPerLineDialog(wxWindow *parent, int initial_value);
			
			int get_bytes_per_line();
			
		private:
			wxRadioButton *fit_rb;
			wxCheckBox *fit_groups_cb;
			
			wxRadioButton *fixed_rb;
			wxSpinCtrl *fixed_sc;
			
			void OnFit(wxCommandEvent &event);
			void OnFixed(wxCommandEvent &event);
			
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_BYTESPERLINEDIALOG_HPP */
