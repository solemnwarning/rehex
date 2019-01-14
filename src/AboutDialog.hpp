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

#ifndef REHEX_ABOUTDIALOG_HPP
#define REHEX_ABOUTDIALOG_HPP

#include <wx/dialog.h>

namespace REHex {
	class AboutDialog: public wxDialog
	{
		public:
			AboutDialog(wxWindow *parent, wxWindowID id = wxID_ANY);
			
		private:
			void OnLicense(wxCommandEvent &event);
			
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_ABOUTDIALOG_HPP */
