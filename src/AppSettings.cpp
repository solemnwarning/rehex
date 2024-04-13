/* Reverse Engineer's Hex Editor
 * Copyright (C) 2022-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "App.hpp"
#include "AppSettings.hpp"

wxDEFINE_EVENT(REHex::PREFERRED_ASM_SYNTAX_CHANGED, wxCommandEvent);

REHex::AppSettings::AppSettings():
	preferred_asm_syntax(AsmSyntax::INTEL),
	goto_offset_base(GotoOffsetBase::AUTO),
	highlight_colours(HighlightColourMap::defaults()) {}

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
	
	long goto_offset_base = config->ReadLong("goto-offset-base", -1);
	switch(goto_offset_base)
	{
		case (long)(GotoOffsetBase::AUTO):
		case (long)(GotoOffsetBase::OCT):
		case (long)(GotoOffsetBase::DEC):
		case (long)(GotoOffsetBase::HEX):
			this->goto_offset_base = (GotoOffsetBase)(goto_offset_base);
			break;
			
		default:
			break;
	}
	
	if(config->HasGroup("highlight-colours"))
	{
		try {
			wxConfigPathChanger scoped_path(config, "highlight-colours/");
			highlight_colours = HighlightColourMap::from_config(config);
		}
		catch(const std::exception &e)
		{
			wxGetApp().printf_error("Error loading highlight colours: %s\n", e.what());
		}
	}
}

void REHex::AppSettings::write(wxConfig *config)
{
	config->Write("preferred-asm-syntax", (long)(preferred_asm_syntax));
	config->Write("goto-offset-base", (long)(goto_offset_base));
	
	{
		config->DeleteGroup("highlight-colours");
		
		wxConfigPathChanger scoped_path(config, "highlight-colours/");
		highlight_colours.to_config(config);
	}
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

REHex::GotoOffsetBase REHex::AppSettings::get_goto_offset_base() const
{
	return goto_offset_base;
}

void REHex::AppSettings::set_goto_offset_base(GotoOffsetBase goto_offset_base)
{
	this->goto_offset_base = goto_offset_base;
}

const REHex::HighlightColourMap &REHex::AppSettings::get_highlight_colours() const
{
	return highlight_colours;
}

void REHex::AppSettings::set_highlight_colours(const HighlightColourMap &highlight_colours)
{
	this->highlight_colours = highlight_colours;
}
