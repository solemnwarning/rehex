/* Reverse Engineer's Hex Editor
 * Copyright (C) 2021 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "app.hpp"
#include "ConsolePanel.hpp"

static REHex::ToolPanel *main_console_factory(wxWindow *parent, REHex::SharedDocumentPointer &document, REHex::DocumentCtrl *document_ctrl)
{
	return new REHex::ConsolePanel(parent, wxGetApp().console, "MainConsole");
}

static REHex::ToolPanelRegistration main_console_tpr("MainConsole", "Console", REHex::ToolPanel::TPS_WIDE, &main_console_factory);

REHex::ConsolePanel::ConsolePanel(wxWindow *parent, ConsoleBuffer *buffer, const std::string &panel_name):
	ToolPanel(parent), buffer(buffer), panel_name(panel_name)
{
	output_text = new wxTextCtrl(this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_MULTILINE | wxTE_READONLY);
	
	wxBoxSizer* sizer = new wxBoxSizer(wxHORIZONTAL);
	sizer->Add(output_text, 1, wxEXPAND);
	SetSizer(sizer);
	
	buffer->Bind(CONSOLE_PRINT, &REHex::ConsolePanel::OnConsolePrint, this);
	buffer->Bind(CONSOLE_ERASE, &REHex::ConsolePanel::OnConsoleErase, this);
	
	output_text->AppendText(buffer->get_messages_text());
}

REHex::ConsolePanel::~ConsolePanel()
{
	buffer->Unbind(CONSOLE_ERASE, &REHex::ConsolePanel::OnConsoleErase, this);
	buffer->Unbind(CONSOLE_PRINT, &REHex::ConsolePanel::OnConsolePrint, this);
}

std::string REHex::ConsolePanel::name() const
{
	return panel_name;
}

void REHex::ConsolePanel::save_state(wxConfig *config) const {}
void REHex::ConsolePanel::load_state(wxConfig *config) {}

wxSize REHex::ConsolePanel::DoGetBestClientSize() const
{
	/* TODO */
	return wxSize(-1, 140);
}

void REHex::ConsolePanel::update() {}

void REHex::ConsolePanel::OnConsolePrint(ConsolePrintEvent &event)
{
	output_text->AppendText(event.text);
	
	event.Skip(); /* Continue propagation */
}

void REHex::ConsolePanel::OnConsoleErase(ConsoleEraseEvent &event)
{
	output_text->Remove(0, event.count);
	output_text->SetInsertionPointEnd();
	
	event.Skip(); /* Continue propagation */
}
