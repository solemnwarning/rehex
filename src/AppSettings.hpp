/* Reverse Engineer's Hex Editor
 * Copyright (C) 2022 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_APPSETTINGS_HPP
#define REHEX_APPSETTINGS_HPP

#include <wx/config.h>
#include <wx/wx.h>

namespace REHex
{
	enum class AsmSyntax
	{
		INTEL = 1,
		ATT   = 2,
	};
	
	class AppSettings: public wxEvtHandler
	{
		public:
			AppSettings();
			AppSettings(wxConfig *config);
			
			void write(wxConfig *config);
			
			AsmSyntax get_preferred_asm_syntax() const;
			void set_preferred_asm_syntax(AsmSyntax preferred_asm_syntax);
			
		private:
			AsmSyntax preferred_asm_syntax;
	};
	
	wxDECLARE_EVENT(PREFERRED_ASM_SYNTAX_CHANGED, wxCommandEvent);
}

#endif /* !REHEX_APPSETTINGS_HPP */
