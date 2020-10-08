/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020 Daniel Collins <solemnwarning@solemnwarning.net>
 * Copyright (C) 2020 Mark Jansen <mark.jansen@reactos.org>
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

#include "../src/SharedDocumentPointer.hpp"
#include "hooks.hpp"
#include "PluginPanel.hpp"

enum {
	ID_OUTPUT_CTRL = 1,
};


static REHex::PluginPanel* g_Panel = nullptr;

// This cannot live in the PluginPanel!
// We can receive logging before the UI is created, and we cannot create the panel without a window!
std::mutex lock;
std::list<wxString> new_text;
bool need_update = false;


static REHex::ToolPanel *PluginPanel_factory(wxWindow *parent, REHex::SharedDocumentPointer& document, REHex::DocumentCtrl* document_ctrl)
{
	//FIXME: THIS DOES NOT WORK!
	// WE NEED ONE WINDOW PER DOCUMENT.......
	//if (g_Panel == nullptr)
	{
		g_Panel = new REHex::PluginPanel(parent);
	}
	return g_Panel;
}

static REHex::ToolPanelRegistration tpr("PluginPanel", "Plugins", REHex::ToolPanel::TPS_WIDE, &PluginPanel_factory);

BEGIN_EVENT_TABLE(REHex::PluginPanel, wxPanel)
	EVT_COMMAND(wxID_ANY, wxEVT_USER_FIRST, REHex::PluginPanel::onPlugintextAdded)
END_EVENT_TABLE()

REHex::PluginPanel::PluginPanel(wxWindow *parent):
	ToolPanel(parent)
{
	output_text = new wxTextCtrl(this, ID_OUTPUT_CTRL, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_MULTILINE | wxTE_READONLY);
	
	wxBoxSizer* sizer = new wxBoxSizer(wxHORIZONTAL);
	sizer->Add(output_text, 1, wxEXPAND);
	SetSizer(sizer);
}

REHex::PluginPanel::~PluginPanel()
{
	if (g_Panel == this)
	{
		g_Panel = nullptr;
	}
}

std::string REHex::PluginPanel::name() const
{
	return "PluginPanel";
}

void REHex::PluginPanel::save_state(wxConfig *config) const
{
	/* TODO */
}

void REHex::PluginPanel::load_state(wxConfig *config)
{
	/* TODO */
}

wxSize REHex::PluginPanel::DoGetBestClientSize() const
{
	/* TODO */
	return wxSize(-1, 140);
}

void REHex::PluginPanel::update()
{
	if (!is_visible)
	{
		/* There is no sense in updating this if we are not visible */
		return;
	}

	std::list<wxString> extra_strings;
	if (need_update)
	{
		std::unique_lock<std::mutex> l(lock);
		std::swap(extra_strings, new_text);
		need_update = false;
	}

	if (!extra_strings.empty())
	{
		for (const auto& txt : extra_strings)
		{
			output_text->AppendText(txt);
		}
	}
}


void REHex::PluginPanel::onPlugintextAdded(wxCommandEvent& evt)
{
	update();
}


void plugin_hooks::log(const wxString& output)
{
	bool post_update = false;

	{
		std::unique_lock<std::mutex> l(lock);
		new_text.push_back(output);
		// Check if we need to post an update request to the UI thread
		post_update = need_update == false;
		need_update = true;
	}


	if (post_update && g_Panel)
	{
		// We need to update the UI, post an event so we can handle this later (no longer in the context of the plugin)
		wxCommandEvent event(wxEVT_USER_FIRST, wxEVT_ANY);
		g_Panel->GetEventHandler()->AddPendingEvent(event);
	}
}
