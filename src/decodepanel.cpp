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

#include <endian.h>
#include <inttypes.h>

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

/* TODO: Make this is templated lambda whenever I move to C++14 */
#define TC_UPDATE(field, T, format, expr) \
	if(size >= sizeof(T)) \
	{ \
		char buf[64]; \
		snprintf(buf, sizeof(buf), format, expr); \
		field->ChangeValue(buf); \
		field->Enable(); \
	} \
	else{ \
		field->ChangeValue(""); \
		field->Disable(); \
	}

void REHex::DecodePanel::update(const unsigned char *data, size_t size)
{
	TC_UPDATE(s8, int8_t,  "%" PRId8, (*(int8_t*)(data)));
	TC_UPDATE(u8, uint8_t, "%" PRIu8, (*(uint8_t*)(data)));
	TC_UPDATE(h8, uint8_t, "%" PRIx8, (*(uint8_t*)(data)));
	TC_UPDATE(o8, uint8_t, "%" PRIo8, (*(uint8_t*)(data)));
	
	TC_UPDATE(s16be, int16_t, "%" PRId16, be16toh(*(int16_t*)(data)));
	TC_UPDATE(u16be, int16_t, "%" PRIu16, be16toh(*(uint16_t*)(data)));
	TC_UPDATE(h16be, int16_t, "%" PRIx16, be16toh(*(uint16_t*)(data)));
	TC_UPDATE(o16be, int16_t, "%" PRIo16, be16toh(*(uint16_t*)(data)));
	
	TC_UPDATE(s16le, int16_t, "%" PRId16, le16toh(*(int16_t*)(data)));
	TC_UPDATE(u16le, int16_t, "%" PRIu16, le16toh(*(uint16_t*)(data)));
	TC_UPDATE(h16le, int16_t, "%" PRIx16, le16toh(*(uint16_t*)(data)));
	TC_UPDATE(o16le, int16_t, "%" PRIo16, le16toh(*(uint16_t*)(data)));
	
	TC_UPDATE(s32be, int32_t, "%" PRId32, be32toh(*(int32_t*)(data)));
	TC_UPDATE(u32be, int32_t, "%" PRIu32, be32toh(*(uint32_t*)(data)));
	TC_UPDATE(h32be, int32_t, "%" PRIx32, be32toh(*(uint32_t*)(data)));
	TC_UPDATE(o32be, int32_t, "%" PRIo32, be32toh(*(uint32_t*)(data)));
	
	TC_UPDATE(s32le, int32_t, "%" PRId32, le32toh(*(int32_t*)(data)));
	TC_UPDATE(u32le, int32_t, "%" PRIu32, le32toh(*(uint32_t*)(data)));
	TC_UPDATE(h32le, int32_t, "%" PRIx32, le32toh(*(uint32_t*)(data)));
	TC_UPDATE(o32le, int32_t, "%" PRIo32, le32toh(*(uint32_t*)(data)));
	
	TC_UPDATE(s64be, int64_t, "%" PRId64, be64toh(*(int64_t*)(data)));
	TC_UPDATE(u64be, int64_t, "%" PRIu64, be64toh(*(uint64_t*)(data)));
	TC_UPDATE(h64be, int64_t, "%" PRIx64, be64toh(*(uint64_t*)(data)));
	TC_UPDATE(o64be, int64_t, "%" PRIo64, be64toh(*(uint64_t*)(data)));
	
	TC_UPDATE(s64le, int64_t, "%" PRId64, le64toh(*(int64_t*)(data)));
	TC_UPDATE(u64le, int64_t, "%" PRIu64, le64toh(*(uint64_t*)(data)));
	TC_UPDATE(h64le, int64_t, "%" PRIx64, le64toh(*(uint64_t*)(data)));
	TC_UPDATE(o64le, int64_t, "%" PRIo64, le64toh(*(uint64_t*)(data)));
}
