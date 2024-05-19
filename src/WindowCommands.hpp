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

#ifndef REHEX_WINDOWCOMMANDS_HPP
#define REHEX_WINDOWCOMMANDS_HPP

#include <stdlib.h>
#include <string>
#include <vector>
#include <wx/config.h>
#include <wx/frame.h>
#include <wx/string.h>

namespace REHex
{
	/**
	 * @brief Window command with optional accelerator key.
	*/
	struct WindowCommand
	{
		std::string name; /**< Name of command, for storing in configuration. */
		
		wxString label; /**< Label of command, for display to user. */
		int id;         /**< wxID of menu item/command event. */
		
		int accel_modifiers; /**< wxAcceleratorEntryFlags modifier key flags (zero if no accelerator set). */
		int accel_keycode;   /**< wxKeyCode key code (WXK_NONE if no accelerator set). */
		
		WindowCommand(const std::string &name, const wxString &label, int id):
			name(name),
			label(label),
			id(id),
			accel_modifiers(0),
			accel_keycode(WXK_NONE) {}
		
		WindowCommand(const std::string &name, const wxString &label, int id, int accel_modifiers, int accel_keycode):
			name(name),
			label(label),
			id(id),
			accel_modifiers(accel_modifiers),
			accel_keycode(accel_keycode) {}
	};
	
	/**
	 * @brief Helper class for managing window accelerators.
	 *
	 * This class holds a list of commands (e.g. menu items) which are supported by a window
	 * and the "accelerators" (keyboard shortcuts) currently assigned to them.
	 *
	 * This class can be instantiated with no associated window just for storing or
	 * manipulating the configured accelerators, or with an associated window to automatically
	 * update the menu bar and/or accelerator table of the window when the accelerator(s) are
	 * changed.
	*/
	class WindowCommandTable
	{
		private:
			wxFrame *window;
			std::vector<WindowCommand> commands;
			
			/**
			 * @brief Remove the given accelerator from its assigned command (if any).
			 *
			 * @param accel_modifiers  wxAcceleratorEntryFlags modifier key flags
			 * @param accel_keycode    wxKeyCode key code
			*/
			void clear_accelerator(int accel_modifiers, int accel_keycode);
			
		public:
			WindowCommandTable(const std::vector<WindowCommand> &commands, wxFrame *window = NULL);
			
			WindowCommandTable(const WindowCommandTable &src) = delete;
			
			/**
			 * @brief Save the currently configured accelerator keys.
			*/
			void save_accelerators(wxConfigBase *config) const;
			
			/**
			 * @brief Load previously saved accelerator keys.
			*/
			void load_accelerators(const wxConfigBase *config);
			
			/**
			 * @brief Replace the window accelerators.
			 *
			 * This updates the accelerators in the internal commands list and on the
			 * associated wxWindow (if there is one).
			 *
			 * The provided WindowCommandTable instance *MUST* have the same list of
			 * commands in the same order as the ones in this object.
			*/
			void replace_accelerators(const WindowCommandTable &new_commands);
			
			/**
			 * @brief Get a reference to the internal commands vector.
			*/
			const std::vector<WindowCommand> &get_commands() const;
			
			/**
			 * @brief Get the begin iterator of the internal commands vector.
			*/
			std::vector<WindowCommand>::const_iterator begin() const;
			
			/**
			 * @brief Get the end iterator of the internal commands vector.
			*/
			std::vector<WindowCommand>::const_iterator end() const;
			
			/**
			 * @brief Find a command by name.
			*/
			const WindowCommand &get_command_by_name(const std::string &name) const;
			
			/**
			 * @brief Find a command by id.
			*/
			const WindowCommand &get_command_by_id(int id) const;
			
			/**
			 * @brief Set the accelerator of a command, referenced by name.
			 *
			 * @param name             Name of the command to replace the accelerator on.
			 * @param accel_modifiers  Accelerator modifier key(s), using wxAcceleratorEntryFlags bits.
			 * @param accel_keycode    Accelerator key code, as a wxKeyCode.
			*/
			void set_command_accelerator(const std::string &name, int accel_modifiers, int accel_keycode);
			
			/**
			 * @brief Set the accelerator of a command, referenced by ID.
			 *
			 * @param id               ID of the command to replace the accelerator on.
			 * @param accel_modifiers  Accelerator modifier key(s), using wxAcceleratorEntryFlags bits.
			 * @param accel_keycode    Accelerator key code, as a wxKeyCode.
			*/
			void set_command_accelerator(int id, int accel_modifiers, int accel_keycode);
			
			/**
			 * @brief Remove the accelerator of a command, referenced by name.
			 *
			 * @param name  Name of the command to remove the accelerator from.
			*/
			void clear_command_accelerator(const std::string &name);
			
			/**
			 * @brief Remove the accelerator of a command, referenced by ID.
			 *
			 * @param id  ID of the command to remove the accelerator from.
			*/
			void clear_command_accelerator(int id);
			
			/**
			 * @brief Update the accelerators of the associated window.
			 *
			 * This method updates the accelerators of any menu bar items on the
			 * associated window and the window's accelerator table for commands which
			 * don't have a menu bar entry.
			 *
			 * Menu items without a matching command registered are not affected.
			*/
			void update_window_accelerators();
			
			/**
			 * @brief Apply accelerator from a command to a menu item.
			 *
			 * @param menu_item     Menu item to clear/set accelerator on.
			 * @param command_name  Name of command to load accelerator from.
			*/
			void set_menu_item_accelerator(wxMenuItem *menu_item, const std::string &command_name) const;
			
			/**
			 * @brief Apply accelerator from a command to a menu item.
			 *
			 * @param menu_item   Menu item to clear/set accelerator on.
			 * @param command_id  ID of command to load accelerator from.
			*/
			void set_menu_item_accelerator(wxMenuItem *menu_item, int command_id) const;
	};
}

#endif /* !REHEX_WINDOWCOMMANDS_HPP */
