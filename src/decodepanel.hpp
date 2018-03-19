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

#ifndef REHEX_VALUEPANEL_HPP
#define REHEX_VALUEPANEL_HPP

#include <wx/panel.h>
#include <wx/wx.h>

namespace REHex {
	class DecodePanel: public wxPanel
	{
		public:
			DecodePanel(wxWindow *parent, wxWindowID id = wxID_ANY);
			
			void update(const unsigned char *data, size_t size);
			
		private:
			wxTextCtrl *s8,    *u8,    *h8,    *o8;
			wxTextCtrl *s16be, *u16be, *h16be, *o16be;
			wxTextCtrl *s16le, *u16le, *h16le, *o16le;
			wxTextCtrl *s32be, *u32be, *h32be, *o32be;
			wxTextCtrl *s32le, *u32le, *h32le, *o32le;
			wxTextCtrl *s64be, *u64be, *h64be, *o64be;
			wxTextCtrl *s64le, *u64le, *h64le, *o64le;
	};
}

#endif /* !REHEX_VALUEPANEL_HPP */
