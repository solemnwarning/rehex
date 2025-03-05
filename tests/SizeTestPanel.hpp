/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_SIZETESTPANEL_HPP
#define REHEX_SIZETESTPANEL_HPP

#include <string>

#include "../src/ToolPanel.hpp"

class SizeTestPanel: public REHex::ToolPanel
{
	private:
		const std::string name_s;
		const std::string label_s;
		const Shape shape_;
		
		const int min_width, min_height;
		const int best_width, best_height;
		const int max_width, max_height;
		
		void OnPaint(wxPaintEvent &event);
		
	public:
		SizeTestPanel(wxWindow *parent, int min_width, int min_height, int best_width, int best_height, int max_width, int max_height, const std::string &name_s, const std::string &label_s, Shape shape);
		virtual wxSize DoGetBestClientSize() const override;
		
		virtual std::string name() const override { return name_s; }
		virtual std::string label() const override { return label_s; }
		virtual Shape shape() const override { return shape_; }
		
		virtual void save_state(wxConfig *config) const override {}
		virtual void load_state(wxConfig *config) override {}
		virtual void update() override {}
		
	DECLARE_EVENT_TABLE()
};

#endif /* !REHEX_SIZETESTPANEL_HPP */
