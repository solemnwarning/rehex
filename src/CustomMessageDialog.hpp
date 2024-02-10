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

#ifndef REHEX_CUSTOMMESSAGEDIALOG_HPP
#define REHEX_CUSTOMMESSAGEDIALOG_HPP

#include <wx/dialog.h>
#include <wx/sizer.h>

namespace REHex
{
	class CustomMessageDialog: public wxDialog
	{
		public:
			CustomMessageDialog(wxWindow *parent, const wxString &message, const wxString &caption, long style = wxDEFAULT_DIALOG_STYLE);
			virtual ~CustomMessageDialog();
			
			void AddButton(wxWindowID id, const wxString &label, const wxBitmap &bitmap = wxNullBitmap);
			void AddButton(wxWindowID id, const wxString &label, const wxArtID &bitmap_id);
			
			void SetAffirmativeId(int id);
		
		private:
			wxBoxSizer *button_sizer;
			
			void OnButtonPress(wxCommandEvent &event);
		
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_CUSTOMMESSAGEDIALOG_HPP */
