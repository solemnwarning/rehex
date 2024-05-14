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
#include <wx/colordlg.h>
#include <wx/dcmemory.h>
#include <wx/sizer.h>

#include "ColourPickerCtrl.hpp"

BEGIN_EVENT_TABLE(REHex::ColourPickerCtrl, wxPanel)
	EVT_TOGGLEBUTTON(wxID_ANY, REHex::ColourPickerCtrl::OnButtonToggle)
END_EVENT_TABLE()

wxDEFINE_EVENT(REHex::COLOUR_SELECTED, wxCommandEvent);

REHex::ColourPickerCtrl::ColourPickerCtrl(wxWindow *parent, wxWindowID id, const std::vector<Palette::ColourIndex> &colours, bool allow_custom):
	wxPanel(parent, id),
	colours(colours),
	custom_colour(wxNullColour),
	selected_colour_idx(SELECTED_COLOUR_NONE)
{
	wxBoxSizer *top_sizer = new wxBoxSizer(wxVERTICAL);
	
	wxGridSizer *sizer = new wxGridSizer(3);
	top_sizer->Add(sizer);
	
	for(size_t idx = 0; idx < colours.size(); ++idx)
	{
		wxBitmap bmp = make_button_bitmap((*active_palette)[ colours[idx] ]);
		
		buttons.push_back(new wxBitmapToggleButton(this, (BUTTON_BASE_ID + idx), bmp));
		sizer->Add(buttons.back());
	}
	
	if(allow_custom)
	{
		wxBoxSizer *custom_sizer = new wxBoxSizer(wxHORIZONTAL);
		top_sizer->Add(custom_sizer, 0, wxEXPAND);
		
		custom_button = new wxToggleButton(this, CUSTOM_BUTTON_ID, "Custom...");
		custom_sizer->Add(custom_button, 1);
	}
	
	SetSizerAndFit(top_sizer);
}

void REHex::ColourPickerCtrl::OnButtonToggle(wxCommandEvent &event)
{
	if(event.GetId() == CUSTOM_BUTTON_ID)
	{
		wxColourData colour_data;
		colour_data.SetColour(custom_colour);
		
		wxColourDialog colour_dialog(this, &colour_data);
		
		if(colour_dialog.ShowModal() == wxID_OK)
		{
			custom_colour = colour_dialog.GetColourData().GetColour();
			
			wxBitmap custom_button_bmp = make_button_bitmap(custom_colour);
			custom_button->SetBitmap(custom_button_bmp);
		}
		else{
			if(selected_colour_idx != SELECTED_COLOUR_CUSTOM)
			{
				custom_button->SetValue(false);
			}
			
			return;
		}
	}
	
	if(!event.IsChecked())
	{
		/* The buttons in this control behave like radio buttons, so we need to re-select
		 * the selected button if the user tries to toggle it off.
		*/
		
		if(event.GetId() == CUSTOM_BUTTON_ID)
		{
			custom_button->SetValue(true);
			goto RAISE_EVENT;
		}
		else{
			assert(selected_colour_idx >= 0);
			assert(selected_colour_idx < (int)(buttons.size()));
			
			buttons[selected_colour_idx]->SetValue(true);
		}
		
		return;
	}
	
	/* Toggle the previously selected colour off. */
	
	if(selected_colour_idx == SELECTED_COLOUR_CUSTOM)
	{
		custom_button->SetValue(false);
	}
	else if(selected_colour_idx != SELECTED_COLOUR_NONE)
	{
		assert(selected_colour_idx < (int)(buttons.size()));
		buttons[selected_colour_idx]->SetValue(false);
	}
	
	/* Raise event so our parent knows a new colour has been selected. */
	RAISE_EVENT:
	
	wxCommandEvent new_event(COLOUR_SELECTED, GetId());
	new_event.SetEventObject(this);
	
	if(event.GetId() == CUSTOM_BUTTON_ID)
	{
		selected_colour_idx = SELECTED_COLOUR_CUSTOM;
		new_event.SetInt(SELECTED_COLOUR_NONE);
	}
	else{
		selected_colour_idx = event.GetId() - BUTTON_BASE_ID;
		new_event.SetInt(colours[selected_colour_idx]);
	}
	
	ProcessWindowEvent(new_event);
}

REHex::Palette::ColourIndex REHex::ColourPickerCtrl::GetColourIndex() const
{
	if(selected_colour_idx >= 0)
	{
		assert(selected_colour_idx < (int)(colours.size()));
		return colours[selected_colour_idx];
	}
	else{
		return Palette::PAL_INVALID;
	}
}

void REHex::ColourPickerCtrl::SetColourIndex(Palette::ColourIndex colour)
{
	/* Toggle the previously selected colour off. */
	if(selected_colour_idx == SELECTED_COLOUR_CUSTOM)
	{
		custom_button->SetValue(false);
	}
	else if(selected_colour_idx != SELECTED_COLOUR_NONE)
	{
		assert(selected_colour_idx < (int)(buttons.size()));
		buttons[selected_colour_idx]->SetValue(false);
	}
	
	if(colour == Palette::PAL_INVALID)
	{
		selected_colour_idx = SELECTED_COLOUR_NONE;
	}
	else{
		auto colour_it = std::find(colours.begin(), colours.end(), colour);
		assert(colour_it != colours.end());
		
		selected_colour_idx = colour_it - colours.begin();
		
		buttons[selected_colour_idx]->SetValue(true);
	}
}

wxColour REHex::ColourPickerCtrl::GetCustomColour() const
{
	return selected_colour_idx == SELECTED_COLOUR_CUSTOM
		? custom_colour
		: wxNullColour;
}

void REHex::ColourPickerCtrl::SetCustomColour(const wxColour &colour)
{
	/* Toggle the previously selected colour off. */
	if(selected_colour_idx >= 0)
	{
		assert(selected_colour_idx < (int)(buttons.size()));
		buttons[selected_colour_idx]->SetValue(false);
	}
	
	custom_colour = colour;
	
	wxBitmap custom_button_bmp = make_button_bitmap(custom_colour);
	custom_button->SetBitmap(custom_button_bmp);
	
	selected_colour_idx = SELECTED_COLOUR_CUSTOM;
	custom_button->SetValue(true);
}

wxBitmap REHex::ColourPickerCtrl::make_button_bitmap(const wxColour &colour)
{
	wxBitmap bmp(16, 16);
	
	wxMemoryDC memdc;
	memdc.SelectObject(bmp);
	memdc.SetBackground(colour);
	memdc.Clear();
	
	return bmp;
}
