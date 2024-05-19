/* Reverse Engineer's Hex Editor
 * Copyright (C) 2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <algorithm>
#include <wx/menu.h>
#include <wx/menuitem.h>

#include "WindowCommands.hpp"

REHex::WindowCommandTable::WindowCommandTable(const std::vector<WindowCommand> &commands, wxFrame *window):
	window(window),
	commands(commands)
{
	update_window_accelerators();
}

void REHex::WindowCommandTable::save_accelerators(wxConfigBase *config) const
{
	for(auto i = commands.begin(); i != commands.end(); ++i)
	{
		if(i->accel_keycode != WXK_NONE)
		{
			wxAcceleratorEntry accel(i->accel_modifiers, i->accel_keycode);
			config->Write(i->name, accel.ToRawString());
		}
		else{
			config->Write(i->name, "");
		}
	}
}

void REHex::WindowCommandTable::load_accelerators(const wxConfigBase *config)
{
	for(auto i = commands.begin(); i != commands.end(); ++i)
	{
		if(config->HasEntry(i->name))
		{
			wxString accel_string = config->Read(i->name, wxEmptyString);
			
			wxAcceleratorEntry accel;
			if(!accel_string.empty() && accel.FromString(accel_string))
			{
				clear_accelerator(accel.GetFlags(), accel.GetKeyCode());
				
				i->accel_modifiers = accel.GetFlags();
				i->accel_keycode   = accel.GetKeyCode();
			}
			else{
				/* Couldn't deserialise accelerator key. */
				i->accel_modifiers = 0;
				i->accel_keycode   = WXK_NONE;
			}
		}
		else{
			/* Command isn't present in configuation - leave default accelerator in place. */
		}
	}
	
	update_window_accelerators();
}

void REHex::WindowCommandTable::replace_accelerators(const WindowCommandTable &new_commands)
{
	assert(new_commands.commands.size() == commands.size());
	
	std::vector<wxAcceleratorEntry> window_accelerators;
	
	for(size_t idx = 0; idx < commands.size(); ++idx)
	{
		WindowCommand &command = commands[idx];
		const WindowCommand &new_command = new_commands.commands[idx];
		
		assert(new_command.name == command.name);
		assert(new_command.id == command.id);
		
		command.accel_modifiers = new_command.accel_modifiers;
		command.accel_keycode   = new_command.accel_keycode;
	}
	
	update_window_accelerators();
}

const std::vector<REHex::WindowCommand> &REHex::WindowCommandTable::get_commands() const
{
	return commands;
}

std::vector<REHex::WindowCommand>::const_iterator REHex::WindowCommandTable::begin() const
{
	return commands.begin();
}

std::vector<REHex::WindowCommand>::const_iterator REHex::WindowCommandTable::end() const
{
	return commands.end();
}

const REHex::WindowCommand &REHex::WindowCommandTable::get_command_by_name(const std::string &name) const
{
	auto it = std::find_if(commands.begin(), commands.end(), [&](const WindowCommand &elem) { return elem.name == name; });
	assert(it != commands.end());
	
	return *it;
}

const REHex::WindowCommand &REHex::WindowCommandTable::get_command_by_id(int id) const
{
	auto it = std::find_if(commands.begin(), commands.end(), [&](const WindowCommand &elem) { return elem.id == id; });
	assert(it != commands.end());
	
	return *it;
}

void REHex::WindowCommandTable::set_command_accelerator(const std::string &name, int accel_modifiers, int accel_keycode)
{
	clear_accelerator(accel_modifiers, accel_keycode);
	
	auto it = std::find_if(commands.begin(), commands.end(), [&](const WindowCommand &elem) { return elem.name == name; });
	assert(it != commands.end());
	
	it->accel_modifiers = accel_modifiers;
	it->accel_keycode   = accel_keycode;
	
	update_window_accelerators();
}

void REHex::WindowCommandTable::set_command_accelerator(int id, int accel_modifiers, int accel_keycode)
{
	clear_accelerator(accel_modifiers, accel_keycode);
	
	auto it = std::find_if(commands.begin(), commands.end(), [&](const WindowCommand &elem) { return elem.id == id; });
	assert(it != commands.end());
	
	it->accel_modifiers = accel_modifiers;
	it->accel_keycode   = accel_keycode;
	
	update_window_accelerators();
}

void REHex::WindowCommandTable::clear_command_accelerator(const std::string &name)
{
	auto it = std::find_if(commands.begin(), commands.end(), [&](const WindowCommand &elem) { return elem.name == name; });
	assert(it != commands.end());
	
	it->accel_modifiers = 0;
	it->accel_keycode   = WXK_NONE;
	
	update_window_accelerators();
}

void REHex::WindowCommandTable::clear_command_accelerator(int id)
{
	auto it = std::find_if(commands.begin(), commands.end(), [&](const WindowCommand &elem) { return elem.id == id; });
	assert(it != commands.end());
	
	it->accel_modifiers = 0;
	it->accel_keycode   = WXK_NONE;
	
	update_window_accelerators();
}

void REHex::WindowCommandTable::update_window_accelerators()
{
	if(window == NULL)
	{
		return;
	}
	
	wxMenuBar *menubar = window->GetMenuBar();
	
	std::vector<wxAcceleratorEntry> window_accelerators;
	
	for(auto i = commands.begin(); i != commands.end(); ++i)
	{
		/* If the window has a menu bar and entry with the command ID, then we set the
		 * accelerator on the menu item, otherwise we add it to the accelerator table.
		*/
		
		wxMenuItem *menu_item = menubar != NULL
			? menubar->FindItem(i->id)
			: NULL;
		
		if(i->accel_keycode != WXK_NONE)
		{
			wxAcceleratorEntry accel(i->accel_modifiers, i->accel_keycode, i->id);
			
			if(menu_item != NULL)
			{
				/* Set accelerator on menu item. */
				menu_item->SetAccel(&accel);
			}
			else{
				/* Add accelerator to wxWindow accelerator table. */
				window_accelerators.push_back(accel);
			}
		}
		else if(menu_item != NULL)
		{
			/* Clear any previous accelerator from the menu item. */
			menu_item->SetAccel(NULL);
		}
	}
	
	wxAcceleratorTable accel_table(window_accelerators.size(), window_accelerators.data());
	window->SetAcceleratorTable(accel_table);
}

void REHex::WindowCommandTable::set_menu_item_accelerator(wxMenuItem *menu_item, const std::string &command_name) const
{
	auto it = std::find_if(commands.begin(), commands.end(), [&](const WindowCommand &elem) { return elem.name == command_name; });
	assert(it != commands.end());
	
	if(it->accel_keycode != WXK_NONE)
	{
		wxAcceleratorEntry accel(it->accel_modifiers, it->accel_keycode);
		menu_item->SetAccel(&accel);
	}
	else{
		menu_item->SetAccel(NULL);
	}
}

void REHex::WindowCommandTable::set_menu_item_accelerator(wxMenuItem *menu_item, int command_id) const
{
	auto it = std::find_if(commands.begin(), commands.end(), [&](const WindowCommand &elem) { return elem.id == command_id; });
	assert(it != commands.end());
	
	if(it->accel_keycode != WXK_NONE)
	{
		wxAcceleratorEntry accel(it->accel_modifiers, it->accel_keycode);
		menu_item->SetAccel(&accel);
	}
	else{
		menu_item->SetAccel(NULL);
	}
}

void REHex::WindowCommandTable::clear_accelerator(int accel_modifiers, int accel_keycode)
{
	auto it = std::find_if(commands.begin(), commands.end(),
		[&](const WindowCommand &elem) { return elem.accel_modifiers == accel_modifiers && elem.accel_keycode == accel_keycode; });
	
	if(it != commands.end())
	{
		it->accel_modifiers = 0;
		it->accel_keycode   = WXK_NONE;
	}
}
