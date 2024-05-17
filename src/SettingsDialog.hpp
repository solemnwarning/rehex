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

#ifndef REHEX_SETTINGSDIALOG_HPP
#define REHEX_SETTINGSDIALOG_HPP

#include <map>
#include <memory>
#include <string>
#include <vector>
#include <wx/dialog.h>
#include <wx/panel.h>
#include <wx/treectrl.h>
#include <wx/window.h>

namespace REHex
{
	class SettingsDialogPanel: public wxPanel
	{
		public:
			virtual ~SettingsDialogPanel() = default;
			
			/**
			 * @brief Creates the wxPanel and any child widgets.
			 *
			 * We use two-step creation for settings dialog panels so that the
			 * SettingsDialogPanel objects can be constructed alone and then passed to
			 * the SettingsDialog object which will create the actual window controls
			 * under itself.
			*/
			virtual bool Create(wxWindow *parent) = 0;
			
			/**
			 * @brief Returns the user-facing label of this settings panel.
			*/
			virtual std::string label() const = 0;
			
			/**
			 * @brief Returns the name of the manual page for this settings panel.
			*/
			virtual std::string help_page() const
			{
				return ""; /* Empty string is "none" */
			}
			
			/**
			 * @brief Validate the panel settings.
			 *
			 * This method will be called by SettingsDialog before saving the settings
			 * from each panel, it should return false if there is a validation error,
			 * in which case the panel will be selected to highlight the error.
			*/
			virtual bool validate() = 0;
			
			/**
			 * @brief Save the panel settings.
			*/
			virtual void save() = 0;
			
			/**
			 * @brief Reset the panel settings to current values.
			*/
			virtual void reset() = 0;
	};
	
	class SettingsDialog: public wxDialog
	{
		private:
			wxTreeCtrl *treectrl;
			
			std::vector< std::unique_ptr<SettingsDialogPanel> > panels;
			std::map<wxTreeItemId, SettingsDialogPanel*> panel_tree_items;
			
			SettingsDialogPanel *selected_panel;
			
			void OnClose(wxCloseEvent &event);
			void OnTreeSelect(wxTreeEvent &event);
			void OnHelp(wxCommandEvent &event);
			void OnOK(wxCommandEvent &event);
			void OnCancel(wxCommandEvent &event);
			
		public:
			static constexpr int MARGIN = 8;
			
			SettingsDialog(wxWindow *parent, const wxString &title, std::vector< std::unique_ptr<SettingsDialogPanel> > &&panels);
			
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_SETTINGSDIALOG_HPP */
