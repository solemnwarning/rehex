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

#ifndef REHEX_CONSOLEPANEL_HPP
#define REHEX_CONSOLEPANEL_HPP

#include <wx/panel.h>
#include <wx/textctrl.h>

#include "ConsoleBuffer.hpp"
#include "ToolPanel.hpp"

namespace REHex
{
	class ConsolePanel: public ToolPanel
	{
		public:
			ConsolePanel(wxWindow *parent, ConsoleBuffer *buffer, const std::string &panel_name);
			~ConsolePanel();
			
			virtual std::string name() const override;
			
			virtual void save_state(wxConfig *config) const override;
			virtual void load_state(wxConfig *config) override;
			virtual void update() override;
			
			virtual wxSize DoGetBestClientSize() const override;
			
		private:
			ConsoleBuffer *buffer;
			
			wxTextCtrl *output_text;
			std::string panel_name;
			
			void OnConsolePrint(ConsolePrintEvent &event);
			void OnConsoleErase(ConsoleEraseEvent &event);
			void OnFirstIdle(wxIdleEvent &event);
		
	};
}

#endif /* !REHEX_CONSOLEPANEL_HPP */
