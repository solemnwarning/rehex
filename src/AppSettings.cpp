/* Reverse Engineer's Hex Editor
 * Copyright (C) 2022-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include "mainwindow.hpp"

wxDEFINE_EVENT(REHex::PREFERRED_ASM_SYNTAX_CHANGED, wxCommandEvent);
wxDEFINE_EVENT(REHex::BYTE_COLOUR_MAPS_CHANGED, wxCommandEvent);
wxDEFINE_EVENT(REHex::MAIN_WINDOW_ACCELERATORS_CHANGED, wxCommandEvent);

REHex::AppSettings::AppSettings():
	preferred_asm_syntax(AsmSyntax::INTEL),
	goto_offset_base(GotoOffsetBase::AUTO),
	highlight_colours(HighlightColourMap::defaults()),
	main_window_commands(MainWindow::get_template_commands()),
	cursor_nav_mode(CursorNavMode::BYTE),
	goto_offset_modal(true),
	size_unit(SizeUnit::AUTO_XiB)
{
	ByteColourMap bcm_types;
	bcm_types.set_label("ASCII Values");
	
	bcm_types.set_colour(0x00, ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_1_FG));
	bcm_types.set_colour_range(0x01, 0x1F, ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_2_FG));
	bcm_types.set_colour_range(0x20, 0x7E, ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_5_FG));
	bcm_types.set_colour(0x7F, ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_2_FG));
	
	byte_colour_maps[1] = std::make_shared<ByteColourMap>(bcm_types);
	
	ByteColourMap bcm_gradient1;
	bcm_gradient1.set_label("Gradient 1");
	
	bcm_gradient1.set_colour_gradient(0x00, 0xFF,
		ByteColourMap::Colour(Palette::PAL_NORMAL_TEXT_FG),
		ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_1_FG));
	
	byte_colour_maps[2] = std::make_shared<ByteColourMap>(bcm_gradient1);
	
	ByteColourMap bcm_gradient2;
	bcm_gradient2.set_label("Gradient 2");
	
	bcm_gradient2.set_colour_gradient(0x00, 0x7E,
		ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_2_FG),
		ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_4_FG));
	
	bcm_gradient2.set_colour_gradient(0x7F, 0xFF,
		ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_4_FG),
		ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_1_FG));
	
	byte_colour_maps[3] = std::make_shared<ByteColourMap>(bcm_gradient2);
	
#if 0
	ByteColourMap bcm_colour_test;
	bcm_colour_test.set_label("Colour test");
	
	bcm_colour_test.set_colour_range(0x10, 0x1F, ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_1_FG));
	bcm_colour_test.set_colour_range(0x20, 0x2F, ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_2_FG));
	bcm_colour_test.set_colour_range(0x30, 0x3F, ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_3_FG));
	bcm_colour_test.set_colour_range(0x40, 0x4F, ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_4_FG));
	bcm_colour_test.set_colour_range(0x50, 0x5F, ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_5_FG));
	
	byte_colour_maps[4] = std::make_shared<ByteColourMap>(bcm_colour_test);
#endif
	
	wxGetApp().Bind(PALETTE_CHANGED, &REHex::AppSettings::OnColourPaletteChanged, this);
}

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
	
	if(config->HasGroup("byte-colour-maps"))
	{
		try {
			std::map< int, std::shared_ptr<ByteColourMap> > loaded_byte_colour_maps;
			
			wxConfigPathChanger scoped_path(config, "byte-colour-maps/");
			
			wxString group_path;
			long group_idx;
			bool group_valid = config->GetFirstGroup(group_path, group_idx);
			
			while(group_valid)
			{
				{
					wxConfigPathChanger scoped_path(config, group_path + "/");
					
					loaded_byte_colour_maps.emplace(
						(loaded_byte_colour_maps.size() + 1),
						std::make_shared<ByteColourMap>(ByteColourMap::load(config)));
				}
				
				group_valid = config->GetNextGroup(group_path, group_idx);
			}
			
			byte_colour_maps = loaded_byte_colour_maps;
		}
		catch(const std::exception &e)
		{
			wxGetApp().printf_error("Error loading value colour maps: %s\n", e.what());
		}
	}
	
	if(config->HasGroup("main-window-accelerators"))
	{
		wxConfigPathChanger scoped_path(config, "main-window-accelerators/");
		main_window_commands.load_accelerators(config);
	}
	
	long cursor_nav_mode = config->ReadLong("cursor-nav-mode", -1);
	switch(cursor_nav_mode)
	{
		case (long)(CursorNavMode::BYTE):
		case (long)(CursorNavMode::NIBBLE):
			this->cursor_nav_mode = (CursorNavMode)(cursor_nav_mode);
			
		default:
			break;
	}
	
	goto_offset_modal = config->ReadBool("goto-offset-modal", goto_offset_modal);
	
	long size_unit = config->ReadLong("size-unit", -1);
	switch(size_unit)
	{
		case (long)(SizeUnit::B):
		case (long)(SizeUnit::KiB):
		case (long)(SizeUnit::MiB):
		case (long)(SizeUnit::GiB):
		case (long)(SizeUnit::TiB):
		case (long)(SizeUnit::kB):
		case (long)(SizeUnit::MB):
		case (long)(SizeUnit::GB):
		case (long)(SizeUnit::TB):
		case (long)(SizeUnit::AUTO_XiB):
		case (long)(SizeUnit::AUTO_XB):
			this->size_unit = (SizeUnit)(size_unit);
			
		default:
			break;
	}
	
	wxGetApp().Bind(PALETTE_CHANGED, &REHex::AppSettings::OnColourPaletteChanged, this);
}

REHex::AppSettings::~AppSettings()
{
	wxGetApp().Unbind(PALETTE_CHANGED, &REHex::AppSettings::OnColourPaletteChanged, this);
}

void REHex::AppSettings::write(wxConfig *config)
{
	config->Write("cursor-nav-mode", (long)(cursor_nav_mode));
	config->Write("preferred-asm-syntax", (long)(preferred_asm_syntax));
	config->Write("goto-offset-base", (long)(goto_offset_base));
	
	{
		config->DeleteGroup("highlight-colours");
		
		wxConfigPathChanger scoped_path(config, "highlight-colours/");
		highlight_colours.to_config(config);
	}
	
	{
		config->DeleteGroup("byte-colour-maps");
		
		wxConfigPathChanger scoped_path(config, "byte-colour-maps/");
		
		int idx = 0;
		for(auto i = byte_colour_maps.begin(); i != byte_colour_maps.end(); ++i, ++idx)
		{
			char idx_path[16];
			snprintf(idx_path, sizeof(idx_path), "%d/", idx);
			
			wxConfigPathChanger scoped_path(config, idx_path);
			
			i->second->save(config);
		}
	}
	
	{
		config->DeleteGroup("main-window-accelerators");
		
		wxConfigPathChanger scoped_path(config, "main-window-accelerators/");
		main_window_commands.save_accelerators(config);
	}
	
	config->Write("goto-offset-modal", goto_offset_modal);
	config->Write("size-unit", (long)(size_unit));
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

std::map<int, std::shared_ptr<const REHex::ByteColourMap> > REHex::AppSettings::get_byte_colour_maps() const
{
	return std::map<int, std::shared_ptr<const REHex::ByteColourMap> >(byte_colour_maps.begin(), byte_colour_maps.end());
}

void REHex::AppSettings::set_byte_colour_maps(const std::map<int, ByteColourMap> &byte_colour_maps)
{
	for(auto i = byte_colour_maps.begin(); i != byte_colour_maps.end(); ++i)
	{
		auto j = this->byte_colour_maps.find(i->first);
		
		if(j != this->byte_colour_maps.end())
		{
			*(j->second) = i->second;
		}
		else{
			this->byte_colour_maps.emplace(i->first, std::make_shared<ByteColourMap>(i->second));
		}
	}
	
	for(auto i = this->byte_colour_maps.begin(); i != this->byte_colour_maps.end();)
	{
		if(byte_colour_maps.find(i->first) == byte_colour_maps.end())
		{
			i = this->byte_colour_maps.erase(i);
		}
		else{
			++i;
		}
	}
	
	wxCommandEvent event(BYTE_COLOUR_MAPS_CHANGED);
	event.SetEventObject(this);
	
	wxPostEvent(this, event);
}

const REHex::WindowCommandTable &REHex::AppSettings::get_main_window_commands() const
{
	return main_window_commands;
}

void REHex::AppSettings::set_main_window_accelerators(const WindowCommandTable &new_accelerators)
{
	main_window_commands.replace_accelerators(new_accelerators);
	
	wxCommandEvent event(MAIN_WINDOW_ACCELERATORS_CHANGED);
	event.SetEventObject(this);
	
	wxPostEvent(this, event);
}

REHex::CursorNavMode REHex::AppSettings::get_cursor_nav_mode() const
{
	return cursor_nav_mode;
}

void REHex::AppSettings::set_cursor_nav_mode(CursorNavMode cursor_nav_mode)
{
	this->cursor_nav_mode = cursor_nav_mode;
}

REHex::BitOffset REHex::AppSettings::get_cursor_nav_alignment() const
{
	switch(cursor_nav_mode)
	{
		case CursorNavMode::BYTE:    return BitOffset(1, 0);
		case CursorNavMode::NIBBLE:  return BitOffset(0, 4);
	}
	
	abort(); /* Unreachable. */
}

bool REHex::AppSettings::get_goto_offset_modal() const
{
	return goto_offset_modal;
}

void REHex::AppSettings::set_goto_offset_modal(bool goto_offset_modal)
{
	this->goto_offset_modal = goto_offset_modal;
}

REHex::SizeUnit REHex::AppSettings::get_size_unit() const
{
	return size_unit;
}

void REHex::AppSettings::set_size_unit(SizeUnit unit)
{
	size_unit = unit;
}

void REHex::AppSettings::OnColourPaletteChanged(wxCommandEvent &event)
{
	highlight_colours.set_default_lightness(active_palette->get_default_highlight_lightness());
	event.Skip();
}
