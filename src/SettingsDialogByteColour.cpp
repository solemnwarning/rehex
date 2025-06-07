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

#include <wx/colordlg.h>
#include <wx/statline.h>

#include "App.hpp"
#include "document.hpp"
#include "DocumentCtrl.hpp"
#include "SettingsDialogByteColour.hpp"
#include "SharedDocumentPointer.hpp"

enum {
	ID_MAP_CHOICE = 1,
	ID_COLOUR1_PICKER,
	ID_COLOUR2_PICKER,
};

BEGIN_EVENT_TABLE(REHex::SettingsDialogByteColour, wxPanel)
	EVT_CHOICE(ID_MAP_CHOICE, REHex::SettingsDialogByteColour::OnMapChange)
	
	EVT_COMMAND(ID_COLOUR1_PICKER, COLOUR_SELECTED, REHex::SettingsDialogByteColour::OnColour1Change)
	EVT_COMMAND(ID_COLOUR2_PICKER, COLOUR_SELECTED, REHex::SettingsDialogByteColour::OnColour2Change)
	
	EVT_BUTTON(wxID_ADD,    REHex::SettingsDialogByteColour::OnNewMap)
	EVT_BUTTON(wxID_EDIT,   REHex::SettingsDialogByteColour::OnRenameMap)
	EVT_BUTTON(wxID_DELETE, REHex::SettingsDialogByteColour::OnDeleteMap)
END_EVENT_TABLE()

int REHex::SettingsDialogByteColour::next_map_key = -1;

REHex::SettingsDialogByteColour::SettingsDialogByteColour()
{
	auto maps = wxGetApp().settings->get_byte_colour_maps();
	
	for(auto i = maps.begin(); i != maps.end(); ++i)
	{
		this->maps.emplace(i->first, *(i->second));
		
		/* Find the highest existing key plus one. */
		next_map_key = std::max(next_map_key, (i->first + 1));
	}
	
	this->selected_map = this->maps.end();
}

bool REHex::SettingsDialogByteColour::Create(wxWindow *parent)
{
	wxPanel::Create(parent);
	
	wxBoxSizer *top_sizer = new wxBoxSizer(wxVERTICAL);
	
	wxStaticBoxSizer *profile_box = new wxStaticBoxSizer(wxHORIZONTAL, this, "Maps");
	top_sizer->Add(profile_box, 0, (wxEXPAND | wxBOTTOM), SettingsDialog::MARGIN);
	
	profile_box->Add(new wxStaticText(profile_box->GetStaticBox(), wxID_ANY, "Selected map:"), 0, (wxBOTTOM | wxRIGHT | wxLEFT | wxALIGN_CENTRE), SettingsDialog::MARGIN);
	
	map_choice = new wxChoice(profile_box->GetStaticBox(), ID_MAP_CHOICE);
	profile_box->Add(map_choice, 1, (wxBOTTOM | wxRIGHT | wxALIGN_CENTRE), SettingsDialog::MARGIN);
	
	for(auto i = maps.begin(); i != maps.end(); ++i)
	{
		map_choice->Append(i->second.get_label());
		map_choice_keys.push_back(i->first);
	}
	
	new_button = new wxButton(profile_box->GetStaticBox(), wxID_ADD, "New");
	profile_box->Add(new_button, 0, (wxBOTTOM | wxRIGHT | wxALIGN_CENTRE), SettingsDialog::MARGIN);
	
	rename_button = new wxButton(profile_box->GetStaticBox(), wxID_EDIT, "Rename");
	profile_box->Add(rename_button, 0, (wxBOTTOM | wxRIGHT | wxALIGN_CENTRE), SettingsDialog::MARGIN);
	
	delete_button = new wxButton(profile_box->GetStaticBox(), wxID_DELETE, "Delete");
	profile_box->Add(delete_button, 0, (wxBOTTOM | wxRIGHT | wxALIGN_CENTRE), SettingsDialog::MARGIN);
	
	wxBoxSizer *profile_sizer = new wxBoxSizer(wxHORIZONTAL);
	top_sizer->Add(profile_sizer, 0, wxEXPAND);
	
	SharedDocumentPointer dummy_doc = SharedDocumentPointer::make();
	
	for(int i = 0; i < 256; ++i)
	{
		unsigned char byte = i;
		dummy_doc->insert_data(i, &byte, 1);
	}
	
	dummy_doc->reset_to_clean();
	
	wxStaticBoxSizer *ddc_sizer = new wxStaticBoxSizer(wxHORIZONTAL, this, "Preview");
	profile_sizer->Add(ddc_sizer, 0, (wxBOTTOM | wxRIGHT), SettingsDialog::MARGIN);
	
	dummy_doc_ctrl = new DocumentCtrl(this, dummy_doc, (DCTRL_LOCK_SCROLL | DCTRL_HIDE_CURSOR));
	ddc_sizer->Add(dummy_doc_ctrl, 0, (wxRIGHT | wxBOTTOM | wxLEFT), SettingsDialog::MARGIN);
	
	dummy_doc_ctrl->SetMinClientSize(
		wxSize(dummy_doc_ctrl->hf_string_width(16 * 4), (dummy_doc_ctrl->hf_char_height() * 16)));
	
	class Foo: public REHex::DocumentCtrl::DataRegion
	{
		private:
			const REHex::SettingsDialogByteColour *sdbc;
			
		public:
			Foo(REHex::SharedDocumentPointer &document, REHex::BitOffset d_offset, REHex::BitOffset d_length, REHex::BitOffset virt_offset, const REHex::SettingsDialogByteColour *sdbc):
				DataRegion(document, d_offset, d_length, virt_offset),
				sdbc(sdbc) {}
			
		protected:
			virtual Highlight highlight_at_off(REHex::BitOffset off) const override
			{
				assert(off.byte() >= 0);
				assert(off.byte() <= 255);
				
				if(sdbc->selected_map != sdbc->maps.end())
				{
					wxColour fg_colour = sdbc->selected_map->second.get_colour(off.byte());
					
					return Highlight(
						fg_colour,
						(*REHex::active_palette)[REHex::Palette::PAL_NORMAL_TEXT_BG]);
				}
				else{
					return Highlight(
						(*REHex::active_palette)[REHex::Palette::PAL_NORMAL_TEXT_FG],
						(*REHex::active_palette)[REHex::Palette::PAL_NORMAL_TEXT_BG]);
				}
			}
	};
	
	std::vector<DocumentCtrl::Region*> regions;
	regions.push_back(new Foo(dummy_doc, 0, 256, 0, this));
	
	dummy_doc_ctrl->replace_all_regions(regions);
	
	dummy_doc_ctrl->set_show_offsets(false);
	dummy_doc_ctrl->set_show_ascii(true);
	dummy_doc_ctrl->set_bytes_per_line(16);
	dummy_doc_ctrl->set_bytes_per_group(1);
	
	wxPanel *colour_panel = new wxPanel(this);
	profile_sizer->Add(colour_panel);
	
	wxBoxSizer *colour_sizer = new wxBoxSizer(wxVERTICAL);
	
	selection_text = new wxStaticText(colour_panel, wxID_ANY, "Select bytes to the left");
	colour_sizer->Add(selection_text);
	
	wxSize selection_text_req_size = selection_text->GetTextExtent("Selected: 255 (X) - 255 (X)");
	selection_text->SetMinClientSize(selection_text_req_size);
	
	std::vector<Palette::ColourIndex> pal_colours = {
		Palette::PAL_NORMAL_TEXT_FG,
		Palette::PAL_CONTRAST_TEXT_1_FG,
		Palette::PAL_CONTRAST_TEXT_2_FG,
		Palette::PAL_CONTRAST_TEXT_3_FG,
		Palette::PAL_CONTRAST_TEXT_4_FG,
		Palette::PAL_CONTRAST_TEXT_5_FG,
	};
	
	colour_sizer->Add(new wxStaticLine(colour_panel), 0, (wxEXPAND | wxTOP), SettingsDialog::MARGIN);
	
	colour_sizer->Add(new wxStaticText(colour_panel, wxID_ANY, "Base colour:"));
	
	colour1_picker = new ColourPickerCtrl(colour_panel, ID_COLOUR1_PICKER, pal_colours, true);
	colour1_picker->Disable();
	colour_sizer->Add(colour1_picker);
	
	colour_sizer->Add(new wxStaticLine(colour_panel), 0, (wxEXPAND | wxTOP), SettingsDialog::MARGIN);
	
	colour_sizer->Add(new wxStaticText(colour_panel, wxID_ANY, "Gradient colour:"));
	
	colour2_picker = new ColourPickerCtrl(colour_panel, ID_COLOUR2_PICKER, pal_colours, true);
	colour2_picker->Disable();
	colour_sizer->Add(colour2_picker);
	
	dummy_doc_ctrl->Bind(EV_SELECTION_CHANGED, [=,this](wxCommandEvent &event)
	{
		BitOffset selection_begin, selection_last;
		std::tie(selection_begin, selection_last) = dummy_doc_ctrl->get_selection_raw();
		
		if(selection_begin >= BitOffset::ZERO)
		{
			low_byte = selection_begin.byte();
			high_byte = selection_last.byte();
			
			auto low_value = selected_map->second[low_byte];
			auto high_value = selected_map->second[high_byte];
			
			if(low_value.is_single() || low_value.is_start())
			{
				if(low_value.colour1.is_palette_colour())
				{
					colour1_picker->SetColourIndex(low_value.colour1.get_palette_colour());
				}
				else{
					assert(low_value.colour1.is_custom_colour());
					colour1_picker->SetCustomColour(low_value.colour1.get_custom_colour());
				}
			}
			else{
				colour1_picker->SetColourIndex(Palette::PAL_INVALID);
			}
			
			if(high_value.is_end())
			{
				if(high_value.colour2.is_palette_colour())
				{
					colour2_picker->SetColourIndex(high_value.colour2.get_palette_colour());
				}
				else{
					assert(high_value.colour2.is_custom_colour());
					colour2_picker->SetCustomColour(high_value.colour2.get_custom_colour());
				}
			}
			else{
				colour2_picker->SetColourIndex(Palette::PAL_INVALID);
			}
			
			std::string begin_s = isascii(selection_begin.byte()) && isprint(selection_begin.byte())
				? std::to_string(selection_begin.byte()) + " (" + std::string(1, (char)(selection_begin.byte())) + ")"
				: std::to_string(selection_begin.byte());
			
			std::string last_s = isascii(selection_last.byte()) && isprint(selection_last.byte())
				? std::to_string(selection_last.byte()) + " (" + std::string(1, (char)(selection_last.byte())) + ")"
				: std::to_string(selection_last.byte());
			
			selection_text->SetLabel("Selected: " + begin_s + " - " + last_s);
			
			colour1_picker->Enable();
			colour2_picker->Enable(selection_begin.byte() != selection_last.byte());
		}
	});
	
	colour_panel->SetSizerAndFit(colour_sizer);
	
	SetSizerAndFit(top_sizer);
	
	map_choice->SetSelection(0);
	map_choice_selected(0);
	
	delete_button->Enable(maps.size() > 1);
	
	return true;
}

void REHex::SettingsDialogByteColour::map_choice_selected(int choice_idx)
{
	int map_key = map_choice_keys[choice_idx];
	
	selected_map = maps.find(map_key);
	assert(selected_map != maps.end());
	
	dummy_doc_ctrl->Refresh();
}

void REHex::SettingsDialogByteColour::OnMapChange(wxCommandEvent &event)
{
	map_choice_selected(event.GetInt());
}

void REHex::SettingsDialogByteColour::OnNewMap(wxCommandEvent &event)
{
	wxString new_label;
	
	while(true)
	{
		wxTextEntryDialog name_dialog(this, "Enter name for value colour map", "New map");
		
		if(name_dialog.ShowModal() == wxID_OK)
		{
			if(name_dialog.GetValue() == "")
			{
				wxMessageBox("A name is required", "Error", (wxOK | wxICON_ERROR), this);
				continue;
			}
			
			new_label = name_dialog.GetValue();
		}
		
		break;
	}
	
	int new_key = next_map_key;
	++next_map_key;
	
	maps.insert(std::make_pair(new_key, ByteColourMap()));
	map_choice_keys.push_back(new_key);
	
	maps[new_key].set_label(new_label);
	map_choice->Append(new_label);
	
	map_choice->SetSelection(map_choice_keys.size() - 1);
	map_choice_selected(map_choice_keys.size() - 1);
	
	delete_button->Enable(maps.size() > 1);
}

void REHex::SettingsDialogByteColour::OnRenameMap(wxCommandEvent &event)
{
	int choice_idx = map_choice->GetSelection();
	assert(choice_idx != wxNOT_FOUND);
	
	while(true)
	{
		wxTextEntryDialog name_dialog(this, "Enter name for value colour map", "Rename map", selected_map->second.get_label());
		
		if(name_dialog.ShowModal() == wxID_OK)
		{
			if(name_dialog.GetValue() == "")
			{
				wxMessageBox("A name is required", "Error", (wxOK | wxICON_ERROR), this);
				continue;
			}
			
			selected_map->second.set_label(name_dialog.GetValue());
			map_choice->SetString(choice_idx, name_dialog.GetValue());
		}
		
		break;
	}
}

void REHex::SettingsDialogByteColour::OnDeleteMap(wxCommandEvent &event)
{
	int choice_idx = map_choice->GetSelection();
	if(choice_idx != wxNOT_FOUND)
	{
		maps.erase(selected_map);
		
		map_choice->Delete(choice_idx);
		map_choice_keys.erase(std::next(map_choice_keys.begin(), choice_idx));
		
		if((unsigned int)(choice_idx) < map_choice->GetCount())
		{
			map_choice->SetSelection(choice_idx);
			map_choice_selected(choice_idx);
		}
		else if(choice_idx > 0)
		{
			map_choice->SetSelection(choice_idx - 1);
			map_choice_selected(choice_idx - 1);
		}
		else{
			map_choice->SetSelection(wxNOT_FOUND);
			map_choice_selected(wxNOT_FOUND);
		}
	}
	
	delete_button->Enable(maps.size() > 1);
}

void REHex::SettingsDialogByteColour::OnColour1Change(wxCommandEvent &event)
{
	ByteColourMap::Colour colour;
	
	if(colour1_picker->GetColourIndex() != Palette::PAL_INVALID)
	{
		colour = ByteColourMap::Colour(colour1_picker->GetColourIndex());
	}
	else{
		assert(colour1_picker->GetCustomColour() != wxNullColour);
		colour = ByteColourMap::Colour(colour1_picker->GetCustomColour());
	}
	
	selected_map->second.set_colour_range(low_byte, high_byte, colour);
	dummy_doc_ctrl->Refresh();
	
	colour2_picker->SetColourIndex(Palette::PAL_INVALID);
}

void REHex::SettingsDialogByteColour::OnColour2Change(wxCommandEvent &event)
{
	ByteColourMap::Colour c1_colour, c2_colour;
	
	if(colour1_picker->GetColourIndex() != Palette::PAL_INVALID)
	{
		c1_colour = ByteColourMap::Colour(colour1_picker->GetColourIndex());
	}
	else{
		assert(colour1_picker->GetCustomColour() != wxNullColour);
		c1_colour = ByteColourMap::Colour(colour1_picker->GetCustomColour());
	}
	
	if(colour2_picker->GetColourIndex() != Palette::PAL_INVALID)
	{
		c2_colour = ByteColourMap::Colour(colour2_picker->GetColourIndex());
	}
	else{
		assert(colour2_picker->GetCustomColour() != wxNullColour);
		c2_colour = ByteColourMap::Colour(colour2_picker->GetCustomColour());
	}
	
	selected_map->second.set_colour_gradient(low_byte, high_byte, c1_colour, c2_colour);
	dummy_doc_ctrl->Refresh();
}

std::string REHex::SettingsDialogByteColour::label() const
{
	return "Value colour maps";
}

std::string REHex::SettingsDialogByteColour::help_page() const
{
	return "value-colour-map";
}

bool REHex::SettingsDialogByteColour::validate()
{
	return true;
}

void REHex::SettingsDialogByteColour::save()
{
	wxGetApp().settings->set_byte_colour_maps(maps);
}

void REHex::SettingsDialogByteColour::reset()
{
	
}
