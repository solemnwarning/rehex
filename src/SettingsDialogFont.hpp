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

#ifndef REHEX_SETTINGSDIALOGFONT_HPP
#define REHEX_SETTINGSDIALOGFONT_HPP

#include <wx/choice.h>
#include <wx/combobox.h>

#include "AppSettings.hpp"
#include "DocumentCtrl.hpp"
#include "SettingsDialog.hpp"

namespace REHex
{
	class SettingsDialogFont: public SettingsDialogPanel
	{
		private:
			wxChoice *font_choice;
			wxComboBox *font_scale;
			
			DocumentCtrl *dummy_doc_ctrl;

			void set_font(const ScaledFont &font);
			ScaledFont get_font();
			
			void OnFontChange(wxCommandEvent &event);
			void OnFontSize(wxCommandEvent &event);
			
		public:
			SettingsDialogFont();
			
			virtual bool Create(wxWindow *parent) override;
			
			virtual std::string label() const override;
			// virtual std::string help_page() const override;
			
			virtual bool validate() override;
			virtual void save() override;
			virtual void reset() override;
			
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_SETTINGSDIALOGFONT_HPP */
