/* Reverse Engineer's Hex Editor
 * Copyright (C) 2024-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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
	colours = load_colours();
	
	wxPanel::Create(parent);
	
	wxBoxSizer *top_sizer = new wxBoxSizer(wxHORIZONTAL);
	
	grid = new wxGrid(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, (wxBORDER_SIMPLE | wxWANTS_CHARS));
	top_sizer->Add(grid, 1, wxEXPAND);
	
	grid->CreateGrid(0, 1);
	
	grid->SetRowLabelSize(0);
	grid->SetColLabelSize(0);
	
	/* Resize column width to fit control. */
	grid->Bind(wxEVT_SIZE, [&](wxSizeEvent &event)
	{
		grid->SetColSize(0, grid->GetClientSize().GetWidth());
		event.Skip();
	});
	
	grid->EnableDragGridSize(false);
	grid->EnableEditing(false);
	grid->SetTabBehaviour(wxGrid::Tab_Leave);
	
	/* Arbitrary minimum size because the default is FOR ANTS. */
	grid->SetMinSize(wxSize(300, 100));
	
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
	
	wxBoxSizer *side_sizer = new wxBoxSizer(wxVERTICAL);
	top_sizer->Add(side_sizer, 0, (wxTOP | wxLEFT), SettingsDialog::MARGIN);
	
	wxBoxSizer *button_sizer = new wxBoxSizer(wxHORIZONTAL);
	side_sizer->Add(button_sizer, 0, wxBOTTOM, SettingsDialog::MARGIN);
	
	add_button = new wxButton(this, wxID_ADD);
	button_sizer->Add(add_button);
	
	add_button->Bind(wxEVT_BUTTON, [this, hex_font](wxCommandEvent &event)
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
	button_sizer->Add(del_button, 0, wxLEFT, SettingsDialog::MARGIN);
	
	del_button->Bind(wxEVT_BUTTON, [this](wxCommandEvent &event)
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
	
	side_sizer->Add(new wxStaticLine(this), 0, (wxEXPAND | wxBOTTOM), SettingsDialog::MARGIN);
	
	side_sizer->Add(new wxStaticText(this, wxID_ANY, "Label"));
	
	label_input = new wxTextCtrl(this, wxID_ANY);
	side_sizer->Add(label_input, 0, (wxBOTTOM | wxEXPAND), SettingsDialog::MARGIN);
	
	label_input->Bind(wxEVT_TEXT, [this](wxCommandEvent &event)
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
	
	side_sizer->Add(new wxStaticText(this, wxID_ANY, "Primary colour"));
	
	primary_picker = new wxColourPickerCtrl(this, wxID_ANY);
	side_sizer->Add(primary_picker, 0, wxBOTTOM, SettingsDialog::MARGIN);
	
	primary_picker->Bind(wxEVT_COLOURPICKER_CHANGED, [this](wxColourPickerEvent &event)
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
	
	side_sizer->Add(new wxStaticText(this, wxID_ANY, "Secondary colour"));
	
	secondary_picker = new wxColourPickerCtrl(this, wxID_ANY);
	side_sizer->Add(secondary_picker);
	
	secondary_picker->Bind(wxEVT_COLOURPICKER_CHANGED, [this](wxColourPickerEvent &event)
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
	
	grid->Bind(wxEVT_GRID_SELECT_CELL, [this](wxGridEvent &event)
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
	
	grid->Bind(wxEVT_GRID_RANGE_SELECT, [this](wxGridRangeSelectEvent &event)
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

std::string REHex::SettingsDialogHighlights::help_page() const
{
	return "highlights";
}

bool REHex::SettingsDialogHighlights::validate() { return true; }

void REHex::SettingsDialogHighlights::save()
{
	save_colours(colours);
}

void REHex::SettingsDialogHighlights::reset() {}

REHex::SettingsDialogAppHighlights::SettingsDialogAppHighlights():
	SettingsDialogHighlights() {}

REHex::HighlightColourMap REHex::SettingsDialogAppHighlights::load_colours() const
{
	return wxGetApp().settings->get_highlight_colours();
}

void REHex::SettingsDialogAppHighlights::save_colours(const HighlightColourMap &colours) const
{
	wxGetApp().settings->set_highlight_colours(colours);
}

REHex::SettingsDialogDocHighlights::SettingsDialogDocHighlights(const SharedDocumentPointer &doc):
	SettingsDialogHighlights(),
	doc(doc) {}

REHex::HighlightColourMap REHex::SettingsDialogDocHighlights::load_colours() const
{
	return doc->get_highlight_colours();
}

void REHex::SettingsDialogDocHighlights::save_colours(const HighlightColourMap &colours) const
{
	if(doc->get_highlight_colours() != colours)
	{
		doc->set_highlight_colours(colours);
	}
}
