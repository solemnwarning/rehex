/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_APP_HPP
#define REHEX_APP_HPP

#include <string>
#include <wx/config.h>
#include <wx/filehistory.h>
#include <wx/wx.h>

namespace REHex {
	class App: public wxApp
	{
		public:
			wxConfig *config;
			wxFileHistory *recent_files;
			
			const std::string &get_last_directory();
			void set_last_directory(const std::string &last_directory);
			
			int get_font_size_adjustment() const;
			void set_font_size_adjustment(int font_size_adjustment);
			
			virtual bool OnInit();
			virtual int OnExit();
			
		private:
			std::string last_directory;
			int font_size_adjustment;
	};
}

DECLARE_APP(REHex::App);

#endif /* !REHEX_APP_HPP */
