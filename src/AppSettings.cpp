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

#include "platform.hpp"

#include <wx/fontenum.h>
#include <wx/fontutil.h>
#include <wx/version.h>
#include <utility>

#include "App.hpp"
#include "AppSettings.hpp"
#include "mainwindow.hpp"

/* Font scale presets are based on the zoom level increments in Firefox. */
const float REHex::PRESET_FONT_SCALES[] = {
	0.50,
	0.67,
	0.80,
	0.90,
	1.00,
	1.10,
	1.20,
	1.20,
	1.33,
	1.50,
	1.70,
	2.00,
};

const size_t REHex::NUM_PRESET_FONT_SCALES = sizeof(REHex::PRESET_FONT_SCALES) / sizeof(*REHex::PRESET_FONT_SCALES);

wxDEFINE_EVENT(REHex::PREFERRED_ASM_SYNTAX_CHANGED, wxCommandEvent);
wxDEFINE_EVENT(REHex::BYTE_COLOUR_MAPS_CHANGED, wxCommandEvent);
wxDEFINE_EVENT(REHex::MAIN_WINDOW_ACCELERATORS_CHANGED, wxCommandEvent);
wxDEFINE_EVENT(REHex::PRIMARY_FONT_CHANGED, wxCommandEvent);

REHex::AppSettings::AppSettings():
	preferred_asm_syntax(AsmSyntax::INTEL),
	goto_offset_base(GotoOffsetBase::AUTO),
	highlight_colours(HighlightColourMap::defaults()),
	default_byte_colour_map(-1),
	main_window_commands(MainWindow::get_template_commands()),
	cursor_nav_mode(CursorNavMode::BYTE),
	goto_offset_modal(true),
	size_unit(SizeUnit::AUTO_XiB),
	#ifdef REHEX_ENABLE_PRIMARY_SELECTION
	primary_copy_limit(DEFAULT_PRIMARY_COPY_LIMIT),
	#endif
	dirty_byte_display_mode(DirtyByteDisplayMode::COLOURED_UNLESS_BCM),
	primary_font(get_default_primary_font()),
	auto_save_state(false)
{
	ByteColourMap bcm_types;
	bcm_types.set_label("ASCII Values");
	
	bcm_types.set_colour(0x00, ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_6_FG));
	bcm_types.set_colour_range(0x01, 0x20, ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_3_FG));
	bcm_types.set_colour_range(0x21, 0x7F, ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_2_FG));
	
	byte_colour_maps[1] = std::make_shared<ByteColourMap>(bcm_types);
	
	ByteColourMap bcm_gradient1;
	bcm_gradient1.set_label("Red / Green");
	
	bcm_gradient1.set_colour(0x00, Palette::PAL_CONTRAST_TEXT_6_FG);
	
	bcm_gradient1.set_colour_gradient(0x01, 0x7F,
		ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_1_FG),
		ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_5_FG));
	
	bcm_gradient1.set_colour_gradient(0x80, 0xFF,
		ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_5_FG),
		ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_3_FG));
	
	byte_colour_maps[2] = std::make_shared<ByteColourMap>(bcm_gradient1);
	
	ByteColourMap bcm_gradient2;
	bcm_gradient2.set_label("Blue / Red");
	
	bcm_gradient2.set_colour(0x00, Palette::PAL_CONTRAST_TEXT_6_FG);
	
	bcm_gradient2.set_colour_gradient(0x01, 0x7F,
		ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_2_FG),
		ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_4_FG));
	
	bcm_gradient2.set_colour_gradient(0x80, 0xFF,
		ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_4_FG),
		ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_1_FG));
	
	byte_colour_maps[3] = std::make_shared<ByteColourMap>(bcm_gradient2);
	
	/* "Rainbow" colour map based on colours chosen by Alice Pellerin:
	 * https://simonomi.dev/blog/color-code-your-bytes/
	*/
	
	ByteColourMap bcm_rainbow;
	bcm_rainbow.set_label("Rainbow");
	
	bcm_rainbow.set_colour(0x00,
		ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_6_FG));
	
	bcm_rainbow.set_colour_gradient(0x01, 0x3F,
		ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_1_FG),
		ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_5_FG));
	
	bcm_rainbow.set_colour_gradient(0x40, 0x7F,
		ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_5_FG),
		ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_3_FG));
	
	bcm_rainbow.set_colour_gradient(0x80, 0xCF,
		ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_3_FG),
		ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_2_FG));
	
	bcm_rainbow.set_colour_gradient(0xD0, 0xFE,
		ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_2_FG),
		ByteColourMap::Colour(Palette::PAL_CONTRAST_TEXT_4_FG));
	
	byte_colour_maps[4] = std::make_shared<ByteColourMap>(bcm_rainbow);
	
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

	long default_byte_colour_map = config->ReadLong("default-byte-colour-map", -1);
	if(default_byte_colour_map == -1 || byte_colour_maps.find(default_byte_colour_map) != byte_colour_maps.end())
	{
		this->default_byte_colour_map = default_byte_colour_map;
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
	
	#ifdef REHEX_ENABLE_PRIMARY_SELECTION
	primary_copy_limit = config->ReadLong("primary-copy-limit", primary_copy_limit);
	#endif
	
	long dbd = config->ReadLong("dirty-byte-display-mode", -1);
	switch(dbd)
	{
		case (long)(DirtyByteDisplayMode::NORMAL):
		case (long)(DirtyByteDisplayMode::COLOURED):
		case (long)(DirtyByteDisplayMode::INVERTED):
		case (long)(DirtyByteDisplayMode::COLOURED_UNLESS_BCM):
		case (long)(DirtyByteDisplayMode::INVERTED_UNLESS_BCM):
			this->dirty_byte_display_mode = (DirtyByteDisplayMode)(dbd);
			
		default:
			break;
	}
	
	wxGetApp().Bind(PALETTE_CHANGED, &REHex::AppSettings::OnColourPaletteChanged, this);

	primary_font = ScaledFont(
		config->Read("primary-font-name", primary_font.name()).ToStdString(),
		config->ReadDouble("primary-font-scale", primary_font.scale()));

	auto_save_state = config->ReadBool("auto-save-state", auto_save_state);
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

	config->Write("default-byte-colour-map", (long)(default_byte_colour_map));
	
	{
		config->DeleteGroup("main-window-accelerators");
		
		wxConfigPathChanger scoped_path(config, "main-window-accelerators/");
		main_window_commands.save_accelerators(config);
	}
	
	config->Write("goto-offset-modal", goto_offset_modal);
	config->Write("size-unit", (long)(size_unit));
	
	#ifdef REHEX_ENABLE_PRIMARY_SELECTION
	config->Write("primary-copy-limit", (long)(primary_copy_limit));
	#endif
	
	config->Write("dirty-byte-display-mode", (long)(dirty_byte_display_mode));

	config->Write("primary-font-name", wxString(primary_font.name()));
	config->Write("primary-font-scale", primary_font.scale());

	config->Write("auto-save-state", auto_save_state);
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
			if(i->first == default_byte_colour_map)
			{
				/* The default byte colour map has been deleted. */
				default_byte_colour_map = -1;
			}

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

int REHex::AppSettings::get_default_byte_colour_map() const
{
	return default_byte_colour_map;
}

void REHex::AppSettings::set_default_byte_colour_map(int id)
{
	if(byte_colour_maps.find(id) != byte_colour_maps.end())
	{
		default_byte_colour_map = id;
	}
	else{
		default_byte_colour_map = -1;
	}
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

#ifdef REHEX_ENABLE_PRIMARY_SELECTION
size_t REHex::AppSettings::get_primary_copy_limit() const
{
	return primary_copy_limit;
}

void REHex::AppSettings::set_primary_copy_limit(size_t primary_copy_limit)
{
	this->primary_copy_limit = primary_copy_limit;
}
#endif

REHex::DirtyByteDisplayMode REHex::AppSettings::get_dirty_byte_display_mode() const
{
	return dirty_byte_display_mode;
}

void REHex::AppSettings::set_dirty_byte_display_mode(DirtyByteDisplayMode dirty_byte_display_mode)
{
	this->dirty_byte_display_mode = dirty_byte_display_mode;
}

void REHex::AppSettings::OnColourPaletteChanged(wxCommandEvent &event)
{
	highlight_colours.set_default_lightness(active_palette->get_default_highlight_lightness());
	event.Skip();
}

REHex::ScaledFont REHex::AppSettings::get_primary_font() const
{
	return primary_font;
}

void REHex::AppSettings::set_primary_font(const ScaledFont &font)
{
	assert(font.create_font().IsFixedWidth());

	primary_font = font;

	wxCommandEvent event(PRIMARY_FONT_CHANGED);
	event.SetEventObject(this);

	wxPostEvent(this, event);
}

REHex::ScaledFont REHex::AppSettings::get_default_primary_font()
{
	wxFont default_font(wxFontInfo().Family(wxFONTFAMILY_MODERN));
	
	#ifdef __APPLE__
	std::string font_name = default_font.GetNativeFontInfo()->GetFaceName().ToStdString();
	#else
	std::string font_name = default_font.GetFaceName().ToStdString();
	#endif
	
	return ScaledFont(font_name, 1.0f);
}

std::vector<std::string> REHex::AppSettings::get_primary_font_faces()
{
	wxArrayString font_names = wxFontEnumerator::GetFacenames(wxFONTENCODING_SYSTEM, true);

	std::vector<std::string> font_names2;
	font_names2.reserve(font_names.Count());

	for(size_t i = 0; i < font_names.Count(); ++i)
	{
		font_names2.emplace_back(font_names[i].ToStdString());
	}

	return font_names2;
}

bool REHex::AppSettings::get_auto_save_state() const
{
	return auto_save_state;
}

void REHex::AppSettings::set_auto_save_state(bool auto_save_state)
{
	this->auto_save_state = auto_save_state;
}

REHex::ScaledFont::ScaledFont(const std::string &name, float scale):
	m_name(name),
	m_scale(scale) {}

std::string REHex::ScaledFont::name() const
{
	return m_name;
}

float REHex::ScaledFont::scale() const
{
	return m_scale;
}

wxFont REHex::ScaledFont::create_font() const
{
	wxFont font(wxFontInfo().FaceName(m_name));

#if wxCHECK_VERSION(3, 1, 2)
	font.SetFractionalPointSize(font.GetFractionalPointSize() * m_scale);
#else
	font.SetPointSize((int)((float)(font.GetPointSize()) * m_scale));
#endif

	return font;
}
