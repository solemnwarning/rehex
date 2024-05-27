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

#ifndef REHEX_SETTINGSDIALOGKEYBOARD_HPP
#define REHEX_SETTINGSDIALOGKEYBOARD_HPP

#include <wx/listctrl.h>
#include <wx/stattext.h>

#include "SettingsDialog.hpp"
#include "WindowCommands.hpp"

namespace REHex
{
	class SettingsDialogKeyboard: public SettingsDialogPanel
	{
		private:
			WindowCommandTable main_window_commands;
			
			wxListCtrl *listctrl;
			
			void OnListItemActivated(wxListEvent &event);
			
		public:
			SettingsDialogKeyboard();
			
			virtual bool Create(wxWindow *parent) override;
			
			virtual std::string label() const override;
			// virtual std::string help_page() const override;
			
			virtual bool validate() override;
			virtual void save() override;
			virtual void reset() override;
			
		DECLARE_EVENT_TABLE()
	};
	
	struct KeyCombination
	{
		int modifiers;
		int keycode;
		
		KeyCombination():
			modifiers(wxMOD_NONE),
			keycode(WXK_NONE) {}
		
		operator bool() const
		{
			return keycode != WXK_NONE;
		}
	};
	
	class KeyCombinationDialog: public wxDialog
	{
		private:
			KeyCombination combination;
			
			wxStaticText *prompt_text;
			
			void update_prompt();
			
			void OnKeyDown(wxKeyEvent &event);
			void OnKeyUp(wxKeyEvent &event);
			
			KeyCombinationDialog(wxWindow *parent);
			
		public:
			static KeyCombination prompt(wxWindow *parent_window);
	};
}

#endif /* !REHEX_SETTINGSDIALOGKEYBOARD_HPP */
