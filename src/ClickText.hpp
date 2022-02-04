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

#ifndef REHEX_CLICKTEXT_HPP
#define REHEX_CLICKTEXT_HPP

#include <wx/panel.h>
#include <wx/stattext.h>

namespace REHex {
	/* This should really just be a wxStaticText subclass, but wxWindow::SetCursor() on a
	 * wxStaticText under wxGTK propogates up to the parent window, so we have to wrap it in
	 * a wxPanel to work around that.
	*/
	
	/**
	 * @brief Hyperlink look-alike control that raises a wxEVT_BUTTON event when clicked.
	*/
	class ClickText: public wxPanel
	{
		public:
			ClickText(wxWindow *parent, wxWindowID id, const wxString &label, const wxPoint &pos = wxDefaultPosition, const wxSize &size = wxDefaultSize, long style = 0);
		
		private:
			wxStaticText *text;
	};
}

#endif /* !REHEX_CLICKTEXT_HPP */
