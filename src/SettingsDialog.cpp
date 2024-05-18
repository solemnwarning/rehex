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

#include <vector>
#include <wx/button.h>
#include <wx/sizer.h>
#include <wx/statline.h>

#include "App.hpp"
#include "SettingsDialog.hpp"

BEGIN_EVENT_TABLE(REHex::SettingsDialog, wxDialog)
	EVT_CLOSE(REHex::SettingsDialog::OnClose)
	EVT_TREE_SEL_CHANGED(wxID_ANY, REHex::SettingsDialog::OnTreeSelect)
	EVT_BUTTON(wxID_HELP, REHex::SettingsDialog::OnHelp)
	EVT_BUTTON(wxID_OK, REHex::SettingsDialog::OnOK)
	EVT_BUTTON(wxID_CANCEL, REHex::SettingsDialog::OnCancel)
END_EVENT_TABLE()

REHex::SettingsDialog::SettingsDialog(wxWindow *parent, const wxString &title, std::vector< std::unique_ptr<SettingsDialogPanel> > &&panels):
	wxDialog(parent, wxID_ANY, title),
	panels(std::move(panels))
{
	wxSizer *top_sizer = new wxBoxSizer(wxVERTICAL);
	
	wxSizer *tree_panel_sizer = new wxBoxSizer(wxHORIZONTAL);
	top_sizer->Add(tree_panel_sizer, 1, (wxALL | wxEXPAND), MARGIN);
	
	treectrl = new wxTreeCtrl(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, (wxBORDER_SIMPLE | wxTR_HAS_BUTTONS | wxTR_HIDE_ROOT));
	tree_panel_sizer->Add(treectrl, 0, (wxEXPAND | wxRIGHT), MARGIN);
	
	wxTreeItemId tree_root = treectrl->AddRoot(wxEmptyString);
	std::vector<wxTreeItemId> panel_items;
	
	for(auto p = this->panels.begin(); p != this->panels.end(); ++p)
	{
		(*p)->Create(this);
		tree_panel_sizer->Add(p->get(), 1, wxEXPAND);
		
		wxTreeItemId p_item = treectrl->AppendItem(tree_root, (*p)->label());
		
		assert(panel_tree_items.find(p_item) == panel_tree_items.end());
		panel_tree_items[p_item] = p->get();
		
		panel_items.push_back(p_item);
		
		if(p == this->panels.begin())
		{
			treectrl->SelectItem(p_item);
		}
		else{
			(*p)->Hide();
		}
	}
	
	top_sizer->Add(new wxStaticLine(this), 0, (wxEXPAND | wxLEFT | wxRIGHT), MARGIN);
	
	wxSizer *button_sizer = new wxBoxSizer(wxHORIZONTAL);
	top_sizer->Add(button_sizer, 0, (wxALL | wxEXPAND), MARGIN);
	
	#ifdef BUILD_HELP
	wxButton *help_button = new wxButton(this, wxID_HELP);
	button_sizer->Add(help_button);
	#endif
	
	button_sizer->AddStretchSpacer(1);
	
	wxButton *ok_button = new wxButton(this, wxID_OK);
	button_sizer->Add(ok_button, 0, wxRIGHT, MARGIN);
	
	wxButton *cancel_button = new wxButton(this, wxID_CANCEL);
	button_sizer->Add(cancel_button);
	
	int max_window_width = -1;
	int max_window_height = -1;
	
	for(auto i = panel_items.begin(); i != panel_items.end(); ++i)
	{
		treectrl->SelectItem(*i);
		
		SetSizerAndFit(top_sizer);
		wxSize this_panel_window_size = GetSize();
		
		max_window_width  = std::max(max_window_width,  this_panel_window_size.GetWidth());
		max_window_height = std::max(max_window_height, this_panel_window_size.GetHeight());
	}
	
	SetSize(wxSize(max_window_width, max_window_height));
	
	treectrl->SelectItem(panel_items.front());
}

void REHex::SettingsDialog::OnClose(wxCloseEvent &event)
{
	Destroy();
}

void REHex::SettingsDialog::OnTreeSelect(wxTreeEvent &event)
{
	auto old_item = panel_tree_items.find(event.GetOldItem());
	if(old_item != panel_tree_items.end())
	{
		old_item->second->Hide();
	}
	
	auto new_item = panel_tree_items.find(event.GetItem());
	if(new_item != panel_tree_items.end())
	{
		selected_panel = new_item->second;
		new_item->second->Show();
	}
	
	Layout();
}

void REHex::SettingsDialog::OnHelp(wxCommandEvent &event)
{
#ifdef BUILD_HELP
	std::string help_page_basename = selected_panel->help_page();
	
	if(help_page_basename.empty())
	{
		wxMessageBox("There is no help for these settings", "No help available", (wxOK | wxCENTRE | wxICON_INFORMATION), this);
	}
	else{
		wxGetApp().show_help_page(this, help_page_basename);
	}
#endif
}

void REHex::SettingsDialog::OnOK(wxCommandEvent &event)
{
	for(auto i = panels.begin(); i != panels.end(); ++i)
	{
		if(!(*i)->validate())
		{
			/* TODO */
			abort();
		}
	}
	
	for(auto i = panels.begin(); i != panels.end(); ++i)
	{
		(*i)->save();
	}
	
	Destroy();
}

void REHex::SettingsDialog::OnCancel(wxCommandEvent &event)
{
	Close();
}
