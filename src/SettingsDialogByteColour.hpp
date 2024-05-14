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

#ifndef REHEX_SETTINGSDIALOGBYTECOLOUR_HPP
#define REHEX_SETTINGSDIALOGBYTECOLOUR_HPP

#include <map>
#include <vector>
#include <wx/choice.h>
#include <wx/colour.h>
#include <wx/stattext.h>

#include "ByteColourMap.hpp"
#include "ColourPickerCtrl.hpp"
#include "DocumentCtrl.hpp"
#include "Palette.hpp"
#include "SettingsDialog.hpp"

namespace REHex
{
	class SettingsDialogByteColour: public SettingsDialogPanel
	{
		private:
			static int next_map_key;
			
			std::map<int, ByteColourMap> maps;
			std::map<int, ByteColourMap>::iterator selected_map;
			
			wxChoice *map_choice;
			std::vector<int> map_choice_keys;
			
			wxButton *new_button;
			wxButton *rename_button;
			wxButton *delete_button;
			
			DocumentCtrl *dummy_doc_ctrl;
			
			wxStaticText *selection_text;
			
			ColourPickerCtrl *colour1_picker;
			ColourPickerCtrl *colour2_picker;
			
			int low_byte;
			int high_byte;
			
			void map_choice_selected(int choice_idx);
			
			void OnMapChange(wxCommandEvent &event);
			void OnNewMap(wxCommandEvent &event);
			void OnRenameMap(wxCommandEvent &event);
			void OnDeleteMap(wxCommandEvent &event);
			
			void OnColour1Change(wxCommandEvent &event);
			void OnColour2Change(wxCommandEvent &event);
			
		public:
			SettingsDialogByteColour();
			
			virtual bool Create(wxWindow *parent) override;
			
			virtual std::string label() const override;
			virtual std::string help_page() const override;
			
			virtual bool validate() override;
			virtual void save() override;
			virtual void reset() override;
			
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_SETTINGSDIALOGBYTECOLOUR_HPP */
