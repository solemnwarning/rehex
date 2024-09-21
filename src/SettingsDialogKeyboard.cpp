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
#include <wx/statbmp.h>
#include <wx/stattext.h>

#include "App.hpp"
#include "mainwindow.hpp"
#include "SettingsDialogKeyboard.hpp"

#include "../res/shortcut48.h"

BEGIN_EVENT_TABLE(REHex::SettingsDialogKeyboard, wxPanel)
	EVT_LIST_ITEM_ACTIVATED(wxID_ANY, REHex::SettingsDialogKeyboard::OnListItemActivated)
END_EVENT_TABLE()

REHex::SettingsDialogKeyboard::SettingsDialogKeyboard():
	main_window_commands(wxGetApp().settings->get_main_window_commands().get_commands()) {}

bool REHex::SettingsDialogKeyboard::Create(wxWindow *parent)
{
	wxPanel::Create(parent);
	
	wxBoxSizer *top_sizer = new wxBoxSizer(wxVERTICAL);
	
	listctrl = new wxListCtrl(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLC_REPORT);
	top_sizer->Add(listctrl, 1, wxEXPAND);
	
	listctrl->AppendColumn("Command");
	listctrl->AppendColumn("Shortcut");
	
	for(auto i = main_window_commands.begin(); i != main_window_commands.end(); ++i)
	{
		long ii = listctrl->InsertItem(listctrl->GetItemCount(), i->label);
		
		if(i->accel_keycode != WXK_NONE)
		{
			wxAcceleratorEntry accel(i->accel_modifiers, i->accel_keycode);
			listctrl->SetItem(ii, 1, accel.ToString());
		}
		else{
			listctrl->SetItem(ii, 1, "<none>");
		}
		
		listctrl->SetItemData(ii, i->id);
	}
	
	/* Size command column to fit longest one. */
	listctrl->SetColumnWidth(0, wxLIST_AUTOSIZE);
	
	/* Hook the wxListCtrl being resized... */
	listctrl->Bind(wxEVT_SIZE, [this](wxSizeEvent &event)
	{
		/* ...defer to the base implementation... */
		event.Skip();
		
		/* ...and resize the other column to take the remaining space afterwards. */
		CallAfter([&]()
		{
			int listctrl_client_width = listctrl->GetClientSize().GetWidth();
			int col0_width            = listctrl->GetColumnWidth(0);
			
			listctrl->SetColumnWidth(1, (listctrl_client_width - col0_width));
		});
	});
	
	SetSizerAndFit(top_sizer);
	
	return true;
}

std::string REHex::SettingsDialogKeyboard::label() const
{
	return "Keyboard shortcuts";
}

bool REHex::SettingsDialogKeyboard::validate() { return true; }

void REHex::SettingsDialogKeyboard::save()
{
	wxGetApp().settings->set_main_window_accelerators(main_window_commands);
}

void REHex::SettingsDialogKeyboard::reset() {}

void REHex::SettingsDialogKeyboard::OnListItemActivated(wxListEvent &event)
{
	long item_idx = event.GetIndex();
	int item_id = listctrl->GetItemData(item_idx);
	
	/* Find the top-level window to parent the KeyCombinationDialog under. */
	wxWindow *frame = this;
	while(!frame->IsTopLevel())
	{
		frame = frame->GetParent();
	}
	
	KeyCombination c = KeyCombinationDialog::prompt(frame);
	
	if(c)
	{
		wxAcceleratorEntry ae(c.modifiers, c.keycode);
		listctrl->SetItem(item_idx, 1, ae.ToString());
		
		main_window_commands.set_command_accelerator(item_id, c.modifiers, c.keycode);
	}
	else{
		listctrl->SetItem(item_idx, 1, "<none>");
		
		main_window_commands.clear_command_accelerator(item_id);
	}
}

REHex::KeyCombination REHex::KeyCombinationDialog::prompt(wxWindow *parent)
{
	KeyCombinationDialog kcg(parent);
	kcg.ShowModal();
	
	return kcg.combination;
}

REHex::KeyCombinationDialog::KeyCombinationDialog(wxWindow *parent):
	wxDialog(parent, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0)
{
	wxSizer *top_sizer = new wxBoxSizer(wxVERTICAL);
	
	wxPanel *p = new wxPanel(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxWANTS_CHARS);
	top_sizer->Add(p);
	
	wxBoxSizer *p_sizer = new wxBoxSizer(wxHORIZONTAL);
	
	p->Bind(wxEVT_KEY_DOWN, &REHex::KeyCombinationDialog::OnKeyDown, this);
	p->Bind(wxEVT_KEY_UP,   &REHex::KeyCombinationDialog::OnKeyUp,   this);
	
	wxStaticBitmap *p_bitmap = new wxStaticBitmap(p, wxID_ANY, wxBITMAP_PNG_FROM_DATA(shortcut48));
	p_sizer->Add(p_bitmap, 0, (wxALL | wxALIGN_CENTER_VERTICAL), 10);
	
	prompt_text = new wxStaticText(p, wxID_ANY, wxEmptyString);
	p_sizer->Add(prompt_text, 0, (wxRIGHT | wxALIGN_CENTER_VERTICAL), 10);
	
	update_prompt();
	
	p->SetSizerAndFit(p_sizer);
	SetSizerAndFit(top_sizer);
}

void REHex::KeyCombinationDialog::update_prompt()
{
	if(combination.modifiers == 0)
	{
#ifdef __WXGTK__
		/* https://github.com/wxWidgets/wxWidgets/issues/17611 */
		prompt_text->SetLabel("Press a key combination...\n(including ctrl and/or alt)");
#else
		prompt_text->SetLabel("Press a key combination...");
#endif
	}
	else{
		std::string prompt = "";
		
		if((combination.modifiers & wxACCEL_CTRL) != 0)
		{
#ifdef __APPLE__
			prompt += "COMMAND + ";
#else
			prompt += "CTRL + ";
#endif
		}
		
#ifdef __APPLE__
		if((combination.modifiers & wxACCEL_RAW_CTRL) != 0)
		{
			prompt += "CTRL + ";
		}
#endif
		
		if((combination.modifiers & wxACCEL_ALT) != 0)
		{
			prompt += "ALT + ";
		}
		
		if((combination.modifiers & wxACCEL_SHIFT) != 0)
		{
			prompt += "SHIFT + ";
		}
		
		prompt += "...";
		
		prompt_text->SetLabel(prompt);
	}
}

void REHex::KeyCombinationDialog::OnKeyDown(wxKeyEvent &event)
{
	int keycode = event.GetKeyCode();
	
	switch(keycode)
	{
		case WXK_CONTROL:
			combination.modifiers |= wxACCEL_CTRL;
			break;
			
		case WXK_ALT:
			combination.modifiers |= wxACCEL_ALT;
			break;
			
		case WXK_SHIFT:
			combination.modifiers |= wxACCEL_SHIFT;
			break;
			
#ifdef __APPLE__
		case WXK_RAW_CONTROL:
			combination.modifiers |= wxACCEL_RAW_CTRL;
			break;
#endif
			
		default:
#ifdef __WXGTK__
			/* https://github.com/wxWidgets/wxWidgets/issues/17611 */
			if((combination.modifiers & (wxACCEL_CTRL | wxACCEL_ALT)) == 0)
			{
				break;
			}
#endif
			
			combination.keycode = keycode;
			
		case WXK_ESCAPE:
			EndModal(0);
			return;
	}
	
	update_prompt();
}

void REHex::KeyCombinationDialog::OnKeyUp(wxKeyEvent &event)
{
	int keycode = event.GetKeyCode();
	
	switch(keycode)
	{
		case WXK_CONTROL:
			combination.modifiers &= ~wxACCEL_CTRL;
			break;
			
		case WXK_ALT:
			combination.modifiers &= ~wxACCEL_ALT;
			break;
			
		case WXK_SHIFT:
			combination.modifiers &= ~wxACCEL_SHIFT;
			break;
			
#ifdef __APPLE__
		case WXK_RAW_CONTROL:
			combination.modifiers &= ~wxACCEL_RAW_CTRL;
			break;
#endif
			
		default:
			break;
	}
	
	update_prompt();
}
