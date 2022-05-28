/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018-2022 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_NUMERICENTRYDIALOG_HPP
#define REHEX_NUMERICENTRYDIALOG_HPP

#include <sstream>
#include <string>
#include <type_traits>
#include <wx/dialog.h>
#include <wx/radiobut.h>
#include <wx/stattext.h>

#include "NumericTextCtrl.hpp"

namespace REHex {
	template<typename T> class NumericEntryDialog: public wxDialog
	{
		public:
			enum class BaseHint
			{
				AUTO_FORCE,
				AUTO,
				DEC,
				HEX,
				OCT,
			};
			
		private:
			const T min_value;
			const T max_value;
			const T rel_base;
			
			BaseHint base;
			
			NumericTextCtrl *textbox;
			
			static std::string format_value(T value, BaseHint base)
			{
				std::ostringstream ss;
				
				switch(base)
				{
					case BaseHint::AUTO_FORCE:
					case BaseHint::AUTO:
					case BaseHint::DEC:
						ss << value;
						break;
						
					case BaseHint::HEX:
						ss << std::hex << value;
						break;
						
					case BaseHint::OCT:
						ss << std::oct << value;
						break;
				}
				
				return ss.str();
			}
			
			void OnBaseChanged(BaseHint base)
			{
				try {
					T value = GetValue();
					std::string s_value = format_value(value, base);
					textbox->SetValue(s_value);
				}
				catch(const REHex::NumericTextCtrl::InputError &e) {}
				
				this->base = base;
			}
			
		public:
			NumericEntryDialog(wxWindow *parent, const std::string &title, const std::string &text, T initial_value, T min_value = std::numeric_limits<T>::min(), T max_value = std::numeric_limits<T>::max(), T rel_base = 0, BaseHint base = BaseHint::AUTO_FORCE):
				wxDialog(parent, wxID_ANY, title),
				min_value(min_value),
				max_value(max_value),
				rel_base(rel_base),
				base(base)
			{
				wxBoxSizer *topsizer = new wxBoxSizer(wxVERTICAL);
				
				wxStaticText *st = new wxStaticText(this, wxID_ANY, text);
				topsizer->Add(st, 1, wxEXPAND | wxTOP | wxLEFT | wxRIGHT, 10);
				
				std::string initial_text = format_value(initial_value, base);
				
				textbox = new NumericTextCtrl(this, wxID_ANY, initial_text);
				topsizer->Add(textbox, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 10);
				
				if(base != BaseHint::AUTO_FORCE)
				{
					wxBoxSizer *base_sizer = new wxBoxSizer(wxHORIZONTAL);
					topsizer->Add(base_sizer, 0, wxEXPAND | wxLEFT | wxRIGHT, 10);
					
					auto add_base_btn = [&](const char *label, BaseHint btn_base)
					{
						wxRadioButton *btn = new wxRadioButton(this, wxID_ANY, label);
						btn->Bind(wxEVT_RADIOBUTTON, [this, btn_base](wxCommandEvent &event) { OnBaseChanged(btn_base); });
						btn->SetValue(btn_base == base);
						
						base_sizer->Add(btn, 1);
					};
					
					add_base_btn("&Any", BaseHint::AUTO);
					add_base_btn("&Dec", BaseHint::DEC);
					add_base_btn("He&x", BaseHint::HEX);
					add_base_btn("Oc&t", BaseHint::OCT);
				}
				
				wxBoxSizer *button_sizer = new wxBoxSizer(wxHORIZONTAL);
				
				wxButton *ok     = new wxButton(this, wxID_OK,     "OK");
				wxButton *cancel = new wxButton(this, wxID_CANCEL, "Cancel");
				
				button_sizer->Add(ok,     0, wxALL, 10);
				button_sizer->Add(cancel, 0, wxALL, 10);
				
				topsizer->Add(button_sizer, 0, wxALIGN_RIGHT);
				
				SetSizerAndFit(topsizer);
				
				/* Trigger the "OK" button if enter is pressed. */
				ok->SetDefault();
				
				ok->Bind(wxEVT_COMMAND_BUTTON_CLICKED, [this](wxCommandEvent &event)
				{
					try {
						GetValue();
					}
					catch(const REHex::NumericTextCtrl::InputError &e)
					{
						wxMessageBox(e.what(), "Error", (wxOK | wxICON_EXCLAMATION | wxCENTRE), this);
						return;
					}
					
					/* Continue on to handling in base class. */
					event.Skip();
				});
			}
			
			T GetValue()
			{
				switch(base)
				{
					case BaseHint::AUTO_FORCE:
					case BaseHint::AUTO:
						return textbox->GetValue(min_value, max_value, rel_base, 0);
						
					case BaseHint::DEC:
						return textbox->GetValue(min_value, max_value, rel_base, 10);
						
					case BaseHint::HEX:
						return textbox->GetValue(min_value, max_value, rel_base, 16);
						
					case BaseHint::OCT:
						return textbox->GetValue(min_value, max_value, rel_base, 8);
				}
				
				/* Unreachable. */
				abort();
			}
			
			BaseHint GetBase()
			{
				return base;
			}
	};
}

#endif /* !REHEX_NUMERICENTRYDIALOG_HPP */
