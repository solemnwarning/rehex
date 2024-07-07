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

#ifndef REHEX_APPSETTINGS_HPP
#define REHEX_APPSETTINGS_HPP

#include <map>
#include <memory>
#include <wx/config.h>
#include <wx/wx.h>

#include "BitOffset.hpp"
#include "ByteColourMap.hpp"
#include "HighlightColourMap.hpp"
#include "WindowCommands.hpp"

namespace REHex
{
	enum class AsmSyntax
	{
		INTEL = 1,
		ATT   = 2,
	};
	
	enum class GotoOffsetBase
	{
		AUTO = 0,
		OCT  = 8,
		DEC  = 10,
		HEX  = 16,
	};
	
	enum class CursorNavMode
	{
		BYTE   = 1,
		NIBBLE = 2,
	};
	
	class AppSettings: public wxEvtHandler
	{
		public:
			AppSettings();
			AppSettings(wxConfig *config);
			
			~AppSettings();
			
			void write(wxConfig *config);
			
			AsmSyntax get_preferred_asm_syntax() const;
			void set_preferred_asm_syntax(AsmSyntax preferred_asm_syntax);
			
			GotoOffsetBase get_goto_offset_base() const;
			void set_goto_offset_base(GotoOffsetBase goto_offset_base);
			
			const HighlightColourMap &get_highlight_colours() const;
			void set_highlight_colours(const HighlightColourMap &highlight_colours);
			
			std::map< int, std::shared_ptr<const ByteColourMap> > get_byte_colour_maps() const;
			void set_byte_colour_maps(const std::map<int, ByteColourMap> &byte_colour_maps);
			
			const WindowCommandTable &get_main_window_commands() const;
			void set_main_window_accelerators(const WindowCommandTable &new_accelerators);
			
			CursorNavMode get_cursor_nav_mode() const;
			void set_cursor_nav_mode(CursorNavMode cursor_nav_mode);
			BitOffset get_cursor_nav_alignment() const;
			
		private:
			AsmSyntax preferred_asm_syntax;
			GotoOffsetBase goto_offset_base;
			HighlightColourMap highlight_colours;
			std::map< int, std::shared_ptr<ByteColourMap> > byte_colour_maps;
			WindowCommandTable main_window_commands;
			CursorNavMode cursor_nav_mode;
			
			void OnColourPaletteChanged(wxCommandEvent &event);
	};
	
	wxDECLARE_EVENT(PREFERRED_ASM_SYNTAX_CHANGED, wxCommandEvent);
	wxDECLARE_EVENT(BYTE_COLOUR_MAPS_CHANGED, wxCommandEvent);
	wxDECLARE_EVENT(MAIN_WINDOW_ACCELERATORS_CHANGED, wxCommandEvent);
}

#endif /* !REHEX_APPSETTINGS_HPP */
