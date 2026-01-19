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

#ifndef REHEX_SETTINGSDIALOGGENERAL_HPP
#define REHEX_SETTINGSDIALOGGENERAL_HPP

#include <wx/checkbox.h>
#include <wx/radiobut.h>
#include <wx/spinctrl.h>

#include "SettingsDialog.hpp"
#include "WindowCommands.hpp"

namespace REHex
{
	class SettingsDialogGeneral: public SettingsDialogPanel
	{
		private:
			wxRadioButton *cnm_byte;
			wxRadioButton *cnm_nibble;
			
			wxRadioButton *su_byte;
			wxRadioButton *su_xib;
			wxRadioButton *su_xb;
			
			wxCheckBox *goto_offset_modeless;
			
			#ifdef REHEX_ENABLE_PRIMARY_SELECTION
			wxCheckBox *primary_copy_enable;
			wxSpinCtrl *primary_copy_kb;
			#endif
			
		public:
			virtual bool Create(wxWindow *parent) override;
			
			virtual std::string label() const override;
			// virtual std::string help_page() const override;
			
			virtual bool validate() override;
			virtual void save() override;
			virtual void reset() override;
	};
}

#endif /* !REHEX_SETTINGSDIALOGGENERAL_HPP */
