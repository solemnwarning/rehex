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

#ifndef REHEX_SETTINGSDIALOGHIGHLIGHTS_HPP
#define REHEX_SETTINGSDIALOGHIGHLIGHTS_HPP

#include <string>
#include <vector>
#include <wx/button.h>
#include <wx/clrpicker.h>
#include <wx/grid.h>
#include <wx/textctrl.h>

#include "HighlightColourMap.hpp"
#include "SharedDocumentPointer.hpp"
#include "SettingsDialog.hpp"

namespace REHex
{
	class SettingsDialogHighlights: public SettingsDialogPanel
	{
		private:
			HighlightColourMap colours;
			
			wxGrid *grid;
			std::vector<size_t> grid_row_indices;
			int selected_grid_row;
			int selected_highlight_idx;
			
			wxButton *add_button;
			wxButton *del_button;
			
			wxTextCtrl *label_input;
			wxColourPickerCtrl *primary_picker;
			wxColourPickerCtrl *secondary_picker;
			
		protected:
			SettingsDialogHighlights();
			
			virtual HighlightColourMap load_colours() const = 0;
			virtual void save_colours(const HighlightColourMap &colours) const = 0;
			
		public:
			virtual bool Create(wxWindow *parent) override;
			
			virtual std::string label() const override;
			virtual std::string help_page() const override;
			
			virtual bool validate() override;
			virtual void save() override;
			virtual void reset() override;
	};
	
	class SettingsDialogAppHighlights: public SettingsDialogHighlights
	{
		protected:
			virtual HighlightColourMap load_colours() const override;
			virtual void save_colours(const HighlightColourMap &colours) const override;
			
		public:
			SettingsDialogAppHighlights();
	};
	
	class SettingsDialogDocHighlights: public SettingsDialogHighlights
	{
		private:
			SharedDocumentPointer doc;
			
		protected:
			virtual HighlightColourMap load_colours() const override;
			virtual void save_colours(const HighlightColourMap &colours) const override;
			
		public:
			SettingsDialogDocHighlights(const SharedDocumentPointer &doc);
	};
}

#endif /* !REHEX_SETTINGSDIALOGHIGHLIGHTS_HPP */
