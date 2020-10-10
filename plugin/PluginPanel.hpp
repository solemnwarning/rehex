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

#ifndef REHEX_PLUGINPANEL_HPP
#define REHEX_PLUGINPANEL_HPP

#include <wx/panel.h>
#include <wx/textctrl.h>
#include "../src/ToolPanel.hpp"

namespace REHex
{
	class PluginPanel: public ToolPanel
	{
		public:
			PluginPanel(wxWindow *parent);
			~PluginPanel();
			
			virtual std::string name() const override;
			
			virtual void save_state(wxConfig *config) const override;
			virtual void load_state(wxConfig *config) override;
			virtual void update() override;
			
			virtual wxSize DoGetBestClientSize() const override;

			void log(const wxString& output);

		protected:
			void onPlugintextAdded(wxCommandEvent& evt);

		private:
			wxTextCtrl *output_text;

			std::mutex lock;
			std::list<wxString> new_text;
			bool need_update = false;

		DECLARE_EVENT_TABLE()
		
	};
}

#endif /* !REHEX_PLUGINPANEL_HPP */
