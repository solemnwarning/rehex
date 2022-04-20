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

#include "platform.hpp"

#include "AppSettings.hpp"

wxDEFINE_EVENT(REHex::PREFERRED_ASM_SYNTAX_CHANGED, wxCommandEvent);

REHex::AppSettings::AppSettings():
	preferred_asm_syntax(AsmSyntax::INTEL) {}

REHex::AppSettings::AppSettings(wxConfig *config): AppSettings()
{
	long preferred_asm_syntax = config->ReadLong("preferred-asm-syntax", -1);
	switch(preferred_asm_syntax)
	{
		case (long)(AsmSyntax::INTEL):
		case (long)(AsmSyntax::ATT):
			this->preferred_asm_syntax = (AsmSyntax)(preferred_asm_syntax);
			break;
			
		default:
			break;
	}
}

void REHex::AppSettings::write(wxConfig *config)
{
	config->Write("preferred-asm-syntax", (long)(preferred_asm_syntax));
}

REHex::AsmSyntax REHex::AppSettings::get_preferred_asm_syntax() const
{
	return preferred_asm_syntax;
}

void REHex::AppSettings::set_preferred_asm_syntax(AsmSyntax preferred_asm_syntax)
{
	if(this->preferred_asm_syntax != preferred_asm_syntax)
	{
		this->preferred_asm_syntax = preferred_asm_syntax;
		
		wxCommandEvent event(PREFERRED_ASM_SYNTAX_CHANGED);
		event.SetEventObject(this);
		
		wxPostEvent(this, event);
	}
}
