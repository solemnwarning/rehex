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

#include <wx/sizer.h>
#include <wx/statline.h>
#include <wx/stattext.h>

#include "App.hpp"
#include "SettingsDialogHighlights.hpp"

REHex::SettingsDialogHighlights::SettingsDialogHighlights():
	selected_grid_row(-1),
	selected_highlight_idx(-1) {}

bool REHex::SettingsDialogHighlights::Create(wxWindow *parent)
{
	colours = wxGetApp().settings->get_highlight_colours();
	
	wxPanel::Create(parent);
	
	wxBoxSizer *top_sizer = new wxBoxSizer(wxHORIZONTAL);
	
	grid = new wxGrid(this, wxID_ANY);
	top_sizer->Add(grid, 1, (wxEXPAND | wxTOP | wxLEFT | wxBOTTOM), 4);
	
	grid->CreateGrid(0, 1);
	
	grid->SetRowLabelSize(0);
	grid->SetColLabelSize(0);
	
	grid->SetMinSize(wxSize(400, 200));
	
	grid->EnableDragGridSize(false);
	grid->EnableEditing(false);
	grid->SetTabBehaviour(wxGrid::Tab_Leave);
	
	wxFont hex_font(wxFontInfo().FaceName(wxGetApp().get_font_name()));
	
	int font_size_adjustment = wxGetApp().get_font_size_adjustment();
	for(int i = 0; i < font_size_adjustment; ++i) { hex_font.MakeLarger(); }
	for(int i = 0; i > font_size_adjustment; --i) { hex_font.MakeSmaller(); }
	
	for(auto h_it = colours.begin(); h_it != colours.end(); ++h_it)
	{
		int grid_row = grid->GetNumberRows();
		
		grid->InsertRows(grid_row, 1);
		grid_row_indices.push_back(h_it->first);
		
		grid->SetCellTextColour(grid_row, 0, h_it->second.secondary_colour);
		grid->SetCellBackgroundColour(grid_row, 0, h_it->second.primary_colour);
		grid->SetCellValue(grid_row, 0, h_it->second.label);
		grid->SetCellFont(grid_row, 0, hex_font);
	}
	
	wxBoxSizer *button_sizer = new wxBoxSizer(wxVERTICAL);
	top_sizer->Add(button_sizer, 0, (wxTOP | wxLEFT), 4);
	
	add_button = new wxButton(this, wxID_ADD);
	button_sizer->Add(add_button, 0, wxBOTTOM, 4);
	
	add_button->Bind(wxEVT_BUTTON, [=](wxCommandEvent &event)
	{
		assert(colours.size() < HighlightColourMap::MAX_NUM);
		
		auto h_it = colours.add();
		
		for(size_t grid_row = 0;; ++grid_row)
		{
			if(grid_row == grid_row_indices.size() || grid_row_indices[grid_row] > h_it->first)
			{
				grid_row_indices.insert(std::next(grid_row_indices.begin(), grid_row), h_it->first);
				grid->InsertRows(grid_row, 1);
				
				grid->SetCellTextColour(grid_row, 0, h_it->second.secondary_colour);
				grid->SetCellBackgroundColour(grid_row, 0, h_it->second.primary_colour);
				grid->SetCellValue(grid_row, 0, h_it->second.label);
				grid->SetCellFont(grid_row, 0, hex_font);
				
				break;
			}
		}
		
		add_button->Enable(colours.size() < HighlightColourMap::MAX_NUM);
	});
	
	add_button->Enable(colours.size() < HighlightColourMap::MAX_NUM);
	
	del_button = new wxButton(this, wxID_DELETE);
	button_sizer->Add(del_button, 0, wxBOTTOM, 4);
	
	del_button->Bind(wxEVT_BUTTON, [=](wxCommandEvent &event)
	{
		assert(selected_grid_row >= 0);
		assert(selected_highlight_idx >= 0);
		
		colours.erase(selected_highlight_idx);
		
		grid_row_indices.erase(std::next(grid_row_indices.begin(), selected_grid_row));
		grid->DeleteRows(selected_grid_row, 1);
		
		selected_grid_row = -1;
		selected_highlight_idx = -1;
		
		del_button->Disable();
		label_input->Disable();
		primary_picker->Disable();
		secondary_picker->Disable();
		
		add_button->Enable(colours.size() < HighlightColourMap::MAX_NUM);
	});
	
	del_button->Disable();
	
	button_sizer->Add(new wxStaticLine(this), 0, (wxEXPAND | wxBOTTOM), 4);
	
	button_sizer->Add(new wxStaticText(this, wxID_ANY, "Label"));
	
	label_input = new wxTextCtrl(this, wxID_ANY);
	button_sizer->Add(label_input, 0, wxBOTTOM, 4);
	
	label_input->Bind(wxEVT_TEXT, [=](wxCommandEvent &event)
	{
		assert(selected_grid_row >= 0);
		assert(grid_row_indices[selected_grid_row] == (size_t)(selected_highlight_idx));
		
		assert(selected_highlight_idx >= 0);
		assert(colours.find(selected_highlight_idx) != colours.end());
		
		colours[selected_highlight_idx].label = label_input->GetValue();
		colours[selected_highlight_idx].label_is_default = false;
		
		grid->SetCellValue(selected_grid_row, 0, label_input->GetValue());
		grid->Refresh();
	});
	
	label_input->Disable();
	
	button_sizer->Add(new wxStaticText(this, wxID_ANY, "Primary colour"));
	
	primary_picker = new wxColourPickerCtrl(this, wxID_ANY);
	button_sizer->Add(primary_picker, 0, wxBOTTOM, 4);
	
	primary_picker->Bind(wxEVT_COLOURPICKER_CHANGED, [=](wxColourPickerEvent &event)
	{
		assert(selected_grid_row >= 0);
		assert(grid_row_indices[selected_grid_row] == (size_t)(selected_highlight_idx));
		
		assert(selected_highlight_idx >= 0);
		assert(colours.find(selected_highlight_idx) != colours.end());
		
		colours[selected_highlight_idx].primary_colour = event.GetColour();
		colours[selected_highlight_idx].primary_colour_is_default = false;
		
		grid->SetCellBackgroundColour(selected_grid_row, 0, event.GetColour());
		grid->Refresh();
	});
	
	primary_picker->Disable();
	
	button_sizer->Add(new wxStaticText(this, wxID_ANY, "Secondary colour"));
	
	secondary_picker = new wxColourPickerCtrl(this, wxID_ANY);
	button_sizer->Add(secondary_picker);
	
	secondary_picker->Bind(wxEVT_COLOURPICKER_CHANGED, [=](wxColourPickerEvent &event)
	{
		assert(selected_grid_row >= 0);
		assert(grid_row_indices[selected_grid_row] == (size_t)(selected_highlight_idx));
		
		assert(selected_highlight_idx >= 0);
		assert(colours.find(selected_highlight_idx) != colours.end());
		
		colours[selected_highlight_idx].secondary_colour = event.GetColour();
		colours[selected_highlight_idx].secondary_colour_is_default = false;
		
		grid->SetCellTextColour(selected_grid_row, 0, event.GetColour());
		grid->Refresh();
	});
	
	secondary_picker->Disable();
	
	grid->Bind(wxEVT_GRID_SELECT_CELL, [=](wxGridEvent &event)
	{
		selected_grid_row = event.GetRow();
		selected_highlight_idx = grid_row_indices[selected_grid_row];
		
		del_button->Enable();
		
		label_input->ChangeValue(colours[selected_highlight_idx].label);
		label_input->Enable();
		
		primary_picker->SetColour(colours[selected_highlight_idx].primary_colour);
		primary_picker->Enable();
		
		secondary_picker->SetColour(colours[selected_highlight_idx].secondary_colour);
		secondary_picker->Enable();
	});
	
	grid->Bind(wxEVT_GRID_RANGE_SELECT, [=](wxGridRangeSelectEvent &event)
	{
		/* We can't disallow range selections in wxGrid, or Veto them,
		 * so we clear any when we're told about them.
		*/
		
		if(event.Selecting())
		{
			grid->ClearSelection();
		}
	});
	
	SetSizerAndFit(top_sizer);
	
	grid->SetColSize(0, grid->GetClientSize().GetWidth());
	
	return true;
}

std::string REHex::SettingsDialogHighlights::label() const
{
	return "Highlight colours";
}

bool REHex::SettingsDialogHighlights::validate() { return true; }

void REHex::SettingsDialogHighlights::save()
{
	wxGetApp().settings->set_highlight_colours(colours);
}

void REHex::SettingsDialogHighlights::reset() {}
