/* Reverse Engineer's Hex Editor
 * Copyright (C) 2024-2026 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <wx/fontenum.h>
#include <wx/statline.h>

#include "App.hpp"
#include "document.hpp"
#include "DocumentCtrl.hpp"
#include "MathUtils.hpp"
#include "SettingsDialogFont.hpp"
#include "SharedDocumentPointer.hpp"

enum {
	ID_FONT_CHOICE = 1,
	ID_FONT_SIZE,
};

BEGIN_EVENT_TABLE(REHex::SettingsDialogFont, wxPanel)
	EVT_CHOICE(ID_FONT_CHOICE, REHex::SettingsDialogFont::OnFontChange)
	EVT_COMBOBOX(ID_FONT_SIZE, REHex::SettingsDialogFont::OnFontSize)
	EVT_TEXT(ID_FONT_SIZE, REHex::SettingsDialogFont::OnFontSize)
END_EVENT_TABLE()

REHex::SettingsDialogFont::SettingsDialogFont() {}

bool REHex::SettingsDialogFont::Create(wxWindow *parent)
{
	wxPanel::Create(parent);
	
	wxBoxSizer *top_sizer = new wxBoxSizer(wxVERTICAL);
	
	wxStaticBoxSizer *profile_box = new wxStaticBoxSizer(wxHORIZONTAL, this, "Font");
	top_sizer->Add(profile_box, 0, (wxEXPAND | wxBOTTOM), SettingsDialog::MARGIN);
	
	font_choice = new wxChoice(profile_box->GetStaticBox(), ID_FONT_CHOICE);
	profile_box->Add(font_choice, 1, (wxBOTTOM | wxLEFT | wxRIGHT | wxALIGN_CENTRE), SettingsDialog::MARGIN);

	std::vector<std::string> font_names = AppSettings::get_primary_font_faces();
	for(size_t i = 0; i < font_names.size(); ++i)
	{
		font_choice->Append(font_names[i]);
	}

	font_scale = new wxComboBox(profile_box->GetStaticBox(), ID_FONT_SIZE);
	profile_box->Add(font_scale, 0, (wxBOTTOM | wxRIGHT | wxALIGN_CENTRE), SettingsDialog::MARGIN);

	for(size_t i = 0; i < NUM_PRESET_FONT_SCALES; ++i)
	{
		char s[32];
		snprintf(s, sizeof(s), "%d%%", (int)(PRESET_FONT_SCALES[i] * 100.0f));
		font_scale->Append(s);
	}

	/* Normalise the displayed scale value when the scale control loses focus. */
	font_scale->Bind(wxEVT_KILL_FOCUS, [this](wxFocusEvent &event)
	{
		ScaledFont f = get_font();

		char s[32];
		snprintf(s, sizeof(s), "%d%%", (int)(f.scale() * 100.0f));

		font_scale->ChangeValue(s);
	});
	
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
	profile_sizer->Add(ddc_sizer, 1, (wxBOTTOM | wxRIGHT | wxEXPAND), SettingsDialog::MARGIN);
	
	dummy_doc_ctrl = new DocumentCtrl(this, dummy_doc, DCTRL_HIDE_CURSOR);
	ddc_sizer->Add(dummy_doc_ctrl, 1, (wxRIGHT | wxBOTTOM | wxLEFT | wxEXPAND), SettingsDialog::MARGIN);
	
	std::vector<DocumentCtrl::Region*> regions;
	regions.push_back(new DocumentCtrl::DataRegion(dummy_doc, 0, 256, 0));
	
	dummy_doc_ctrl->replace_all_regions(regions);
	
	dummy_doc_ctrl->set_show_offsets(true);
	dummy_doc_ctrl->set_show_ascii(true);
	dummy_doc_ctrl->set_bytes_per_line(16);
	dummy_doc_ctrl->set_bytes_per_group(1);
	
	SetSizerAndFit(top_sizer);

	set_font(wxGetApp().settings->get_primary_font());
	
	return true;
}

void REHex::SettingsDialogFont::set_font(const ScaledFont &font)
{
	for(unsigned int i = 0, count = font_choice->GetCount(); i < count; ++i)
	{
		if(font_choice->GetString(i).ToStdString() == font.name())
		{
			font_choice->SetSelection(i);
			break;
		}
	}

	char s[32];
	snprintf(s, sizeof(s), "%d%%", (int)(font.scale() * 100.0f));
	font_scale->SetValue(s);

	for(unsigned int i = 0, count = font_scale->GetCount(); i < count; ++i)
	{
		if(strcmp(font_scale->GetString(i).c_str(), s) == 0)
		{
			font_scale->SetSelection(i);
			break;
		}
	}
}

REHex::ScaledFont REHex::SettingsDialogFont::get_font()
{
	wxString face = font_choice->GetString(font_choice->GetSelection());
	double scale = atof(font_scale->GetValue().c_str()) / 100.0f;

	scale = std::max<double>(scale, MIN_FONT_SCALE);
	scale = std::min<double>(scale, MAX_FONT_SCALE);

	return ScaledFont(face.ToStdString(), scale);
}

void REHex::SettingsDialogFont::OnFontChange(wxCommandEvent &event)
{
	dummy_doc_ctrl->set_font(get_font().create_font());
}

void REHex::SettingsDialogFont::OnFontSize(wxCommandEvent &event)
{
	dummy_doc_ctrl->set_font(get_font().create_font());
}

std::string REHex::SettingsDialogFont::label() const
{
	return "Font & Text Size";
}

bool REHex::SettingsDialogFont::validate()
{
	return true;
}

void REHex::SettingsDialogFont::save()
{
	wxGetApp().settings->set_primary_font(get_font());
}

void REHex::SettingsDialogFont::reset()
{
	ScaledFont default_font = AppSettings::get_default_primary_font();

	set_font(default_font);
	dummy_doc_ctrl->set_font(default_font.create_font());
}
