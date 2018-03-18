/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "decodepanel.hpp"

REHex::DecodePanel::DecodePanel(wxWindow *parent, wxWindowID id):
	wxPanel(parent, id)
{
	wxFlexGridSizer *sizer = new wxFlexGridSizer(5, 0, 10);
	
	auto add_st = [this,sizer](const char *text)
	{
		sizer->Add(new wxStaticText(this, wxID_ANY, text), wxSizerFlags().Center());
	};
	
	add_st("");
	add_st("Signed");
	add_st("Unsigned");
	add_st("Hex");
	add_st("Octal");
	
	int textbox_char_width;
	int textbox_height;
	
	{
		wxTextCtrl *tc = new wxTextCtrl(this, wxID_ANY);
		textbox_height = tc->GetSize().GetHeight();
		
		wxSize te = tc->GetTextExtent("O");
		textbox_char_width = te.GetWidth();
		
		delete tc;
	}
	
	auto add_tc = [this,&sizer,textbox_char_width,textbox_height](wxTextCtrl* &tc, int width_chars)
	{
		tc = new wxTextCtrl(this, wxID_ANY, "", wxDefaultPosition, wxSize((width_chars + 1) * textbox_char_width, textbox_height));
		
		sizer->Add(tc, wxSizerFlags().Right());
	};
	
	sizer->Add(new wxStaticText(this, wxID_ANY, "8 bit"));
	add_tc(s8, 4);
	add_tc(u8, 3);
	add_tc(h8, 2);
	add_tc(o8, 3);
	
	sizer->Add(new wxStaticText(this, wxID_ANY, "16 bit BE"));
	add_tc(s16be, 6);
	add_tc(u16be, 5);
	add_tc(h16be, 4);
	add_tc(o16be, 6);
	
	sizer->Add(new wxStaticText(this, wxID_ANY, "16 bit LE"));
	add_tc(s16le, 6);
	add_tc(u16le, 5);
	add_tc(h16le, 4);
	add_tc(o16le, 6);
	
	sizer->Add(new wxStaticText(this, wxID_ANY, "32 bit BE"));
	add_tc(s32be, 11);
	add_tc(u32be, 10);
	add_tc(h32be, 8);
	add_tc(o32be, 11);
	
	sizer->Add(new wxStaticText(this, wxID_ANY, "32 bit LE"));
	add_tc(s32le, 11);
	add_tc(u32le, 10);
	add_tc(h32le, 8);
	add_tc(o32le, 11);
	
	sizer->Add(new wxStaticText(this, wxID_ANY, "64 bit BE"));
	add_tc(s64be, 21);
	add_tc(u64be, 20);
	add_tc(h64be, 16);
	add_tc(o64be, 22);
	
	sizer->Add(new wxStaticText(this, wxID_ANY, "64 bit LE"));
	add_tc(s64le, 21);
	add_tc(u64le, 20);
	add_tc(h64le, 16);
	add_tc(o64le, 22);
	
	SetSizerAndFit(sizer);
}
