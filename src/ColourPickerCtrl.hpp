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

#ifndef REHEX_COLOURPICKERCTRL_HPP
#define REHEX_COLOURPICKERCTRL_HPP

#include <vector>
#include <wx/colour.h>
#include <wx/panel.h>
#include <wx/tglbtn.h>

#include "Palette.hpp"

namespace REHex
{
	/**
	 * @brief Control for picking a palette colour, or a custom colour.
	*/
	class ColourPickerCtrl: public wxPanel
	{
		private:
			static constexpr int CUSTOM_BUTTON_ID = 9;
			static constexpr int BUTTON_BASE_ID = 10;
			
			std::vector<Palette::ColourIndex> colours;
			std::vector<wxBitmapToggleButton*> buttons;
			
			wxColour custom_colour;
			wxToggleButton *custom_button;
			
			static constexpr int SELECTED_COLOUR_NONE = -1;
			static constexpr int SELECTED_COLOUR_CUSTOM = -2;
			
			int selected_colour_idx;
			
			static wxBitmap make_button_bitmap(const wxColour &colour);
			
			void OnButtonToggle(wxCommandEvent &event);
			
		public:
			/**
			 * @brief Construct a ColourPickerCtrl.
			 *
			 * @param parent        Parent wxWindow pointer.
			 * @param id            wxWindow window ID.
			 * @param colours       List of palette colours to choose from.
			 * @param allow_custom  Whether to allow selecting a custom colour.
			*/
			ColourPickerCtrl(wxWindow *parent, wxWindowID id, const std::vector<Palette::ColourIndex> &colours, bool allow_custom = false);
			
			/**
			 * @brief Get the palette index of the selected colour.
			 *
			 * Returns one of the palette colours provided to the constructor, or
			 * PAL_INVALID if no colour or a custom colour has been selected.
			*/
			Palette::ColourIndex GetColourIndex() const;
			
			/**
			 * @brief Select a palette colour.
			*/
			void SetColourIndex(Palette::ColourIndex colour);
			
			/**
			 * @brief Get the selected custom colour.
			 *
			 * Returns the selected custom colour, or wxNullColour if no colour or a
			 * palette colour has been selected.
			*/
			wxColour GetCustomColour() const;
			
			/**
			 * @brief Select a custom colour.
			*/
			void SetCustomColour(const wxColour &colour);
			
		DECLARE_EVENT_TABLE()
	};
	
	wxDECLARE_EVENT(COLOUR_SELECTED, wxCommandEvent);
}

#endif /* !REHEX_COLOURPICKERCTRL_HPP */
