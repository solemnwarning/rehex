/* Reverse Engineer's Hex Editor
 * Copyright (C) 2022-2026 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <wx/font.h>
#include <wx/wx.h>

#include "BitOffset.hpp"
#include "ByteColourMap.hpp"
#include "HighlightColourMap.hpp"
#include "util.hpp"
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
	
	enum class DirtyByteDisplayMode
	{
		NORMAL = 1,    /**< Do not colour changed bytes differently. */
		
		COLOURED = 2,  /**< Colour changed bytes as PAL_DIRTY_TEXT_FG/PAL_DIRTY_TEXT_BG when . */
		INVERTED = 3,  /**< Colour changed bytes as PAL_DIRTY_TEXT_FG/PAL_DIRTY_TEXT_BG (inverted). */
		
		COLOURED_UNLESS_BCM = 4, /**< COLOURED, unless a Value Colour Map is selected, then NORMAL. */
		INVERTED_UNLESS_BCM = 5, /**< INVERTED, unless a Value Colour Map is selected, then NORMAL. */
	};

	extern const float PRESET_FONT_SCALES[];
	extern const size_t NUM_PRESET_FONT_SCALES;

	static constexpr float MIN_FONT_SCALE = 0.25;
	static constexpr float MAX_FONT_SCALE = 4.0;

	class ScaledFont
	{
		public:
			ScaledFont(const std::string &name, float scale);

			std::string name() const;
			float scale() const;

			wxFont create_font() const;

		private:
			std::string m_name;
			float m_scale;
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

			int get_default_byte_colour_map() const;
			void set_default_byte_colour_map(int id);
			
			const WindowCommandTable &get_main_window_commands() const;
			void set_main_window_accelerators(const WindowCommandTable &new_accelerators);
			
			CursorNavMode get_cursor_nav_mode() const;
			void set_cursor_nav_mode(CursorNavMode cursor_nav_mode);
			BitOffset get_cursor_nav_alignment() const;
			
			bool get_goto_offset_modal() const;
			void set_goto_offset_modal(bool goto_offset_modal);
			
			SizeUnit get_size_unit() const;
			void set_size_unit(SizeUnit unit);
			
			#ifdef REHEX_ENABLE_PRIMARY_SELECTION
			static constexpr size_t DEFAULT_PRIMARY_COPY_LIMIT = 1024;
			
			size_t get_primary_copy_limit() const;
			void set_primary_copy_limit(size_t primary_copy_limit);
			#endif
			
			DirtyByteDisplayMode get_dirty_byte_display_mode() const;
			void set_dirty_byte_display_mode(DirtyByteDisplayMode dirty_byte_display_mode);

			/**
			 * @brief Get the (fixed-pitch) font to use for drawing data.
			*/
			ScaledFont get_primary_font() const;

			/**
			 * @brief Set the primary font.
			*/
			void set_primary_font(const ScaledFont &font);

			/**
			 * @brief Get the default primary font.
			*/
			static ScaledFont get_default_primary_font();

			/**
			 * @brief Get the list of available font faces for the primary font.
			*/
			static std::vector<std::string> get_primary_font_faces();

			/**
			 * @brief Get whether the application state should be saved on exit.
			*/
			bool get_auto_save_state() const;

			/**
			 * @brief Set whether the application state should be saved on exit.
			*/
			void set_auto_save_state(bool auto_save_state);
			
		private:
			AsmSyntax preferred_asm_syntax;
			GotoOffsetBase goto_offset_base;
			HighlightColourMap highlight_colours;
			std::map< int, std::shared_ptr<ByteColourMap> > byte_colour_maps;
			int default_byte_colour_map;
			WindowCommandTable main_window_commands;
			CursorNavMode cursor_nav_mode;
			bool goto_offset_modal;
			SizeUnit size_unit;
			size_t primary_copy_limit;
			DirtyByteDisplayMode dirty_byte_display_mode;
			ScaledFont primary_font;
			bool auto_save_state;
			
			void OnColourPaletteChanged(wxCommandEvent &event);
	};
	
	wxDECLARE_EVENT(PREFERRED_ASM_SYNTAX_CHANGED, wxCommandEvent);
	wxDECLARE_EVENT(BYTE_COLOUR_MAPS_CHANGED, wxCommandEvent);
	wxDECLARE_EVENT(MAIN_WINDOW_ACCELERATORS_CHANGED, wxCommandEvent);
	wxDECLARE_EVENT(PRIMARY_FONT_CHANGED, wxCommandEvent);
}

#endif /* !REHEX_APPSETTINGS_HPP */
