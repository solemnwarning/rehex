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

#define __STDC_FORMAT_MACROS

#include <assert.h>
#include <inttypes.h>

#include "decodepanel.hpp"

/* This MUST come after the wxWidgets headers have been included, else we pull in windows.h BEFORE the wxWidgets
 * headers when building on Windows and this causes unicode-flavoured pointer conversion errors.
*/
#include <portable_endian.h>

wxDEFINE_EVENT(REHex::EV_VALUE_CHANGE, REHex::ValueChange);
wxDEFINE_EVENT(REHex::EV_VALUE_FOCUS,  REHex::ValueFocus);

/* Endianness conversion functions for use with the OnText() template method. */
static uint8_t  hto8_u   (uint8_t  host_8bits)  { return host_8bits; }
static int8_t   hto8_s   (int8_t   host_8bits)  { return host_8bits; }
static uint16_t htobe16_u(uint16_t host_16bits) { return htobe16(host_16bits); }
static int16_t  htobe16_s( int16_t host_16bits) { return htobe16(host_16bits); }
static uint16_t htole16_u(uint16_t host_16bits) { return htole16(host_16bits); }
static int16_t  htole16_s( int16_t host_16bits) { return htole16(host_16bits); }
static uint32_t htobe32_u(uint32_t host_32bits) { return htobe32(host_32bits); }
static int32_t  htobe32_s( int32_t host_32bits) { return htobe32(host_32bits); }
static uint32_t htole32_u(uint32_t host_32bits) { return htole32(host_32bits); }
static int32_t  htole32_s( int32_t host_32bits) { return htole32(host_32bits); }
static uint64_t htobe64_u(uint64_t host_64bits) { return htobe64(host_64bits); }
static int64_t  htobe64_s( int64_t host_64bits) { return htobe64(host_64bits); }
static uint64_t htole64_u(uint64_t host_64bits) { return htole64(host_64bits); }
static int64_t  htole64_s( int64_t host_64bits) { return htole64(host_64bits); }

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
		tc = new wxTextCtrl(this, wxID_ANY, "", wxDefaultPosition,
			wxSize((width_chars + 1) * textbox_char_width, textbox_height),
			wxTE_RIGHT);
		
		sizer->Add(tc, wxSizerFlags().Right());
	};
	
	sizer->Add(new wxStaticText(this, wxID_ANY, "8 bit"));
	add_tc(s8, 4);
	add_tc(u8, 3);
	add_tc(h8, 2);
	add_tc(o8, 3);
	
	s8->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<int8_t,  10, &hto8_s>, this);
	u8->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<uint8_t, 10, &hto8_u>, this);
	h8->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<uint8_t, 16, &hto8_u>, this);
	o8->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<uint8_t,  8, &hto8_u>, this);
	
	s8->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<int8_t>,  this);
	u8->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<uint8_t>, this);
	h8->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<uint8_t>, this);
	o8->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<uint8_t>, this);
	
	sizer->Add(new wxStaticText(this, wxID_ANY, "16 bit BE"));
	add_tc(s16be, 6);
	add_tc(u16be, 5);
	add_tc(h16be, 4);
	add_tc(o16be, 6);
	
	s16be->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<int16_t,  10, &htobe16_s>, this);
	u16be->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<uint16_t, 10, &htobe16_u>, this);
	h16be->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<uint16_t, 16, &htobe16_u>, this);
	o16be->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<uint16_t,  8, &htobe16_u>, this);
	
	s16be->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<int16_t>,  this);
	u16be->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<uint16_t>, this);
	h16be->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<uint16_t>, this);
	o16be->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<uint16_t>, this);
	
	sizer->Add(new wxStaticText(this, wxID_ANY, "16 bit LE"));
	add_tc(s16le, 6);
	add_tc(u16le, 5);
	add_tc(h16le, 4);
	add_tc(o16le, 6);
	
	s16le->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<int16_t,  10, &htole16_s>, this);
	u16le->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<uint16_t, 10, &htole16_u>, this);
	h16le->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<uint16_t, 16, &htole16_u>, this);
	o16le->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<uint16_t,  8, &htole16_u>, this);
	
	s16le->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<int16_t>,  this);
	u16le->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<uint16_t>, this);
	h16le->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<uint16_t>, this);
	o16le->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<uint16_t>, this);
	
	sizer->Add(new wxStaticText(this, wxID_ANY, "32 bit BE"));
	add_tc(s32be, 11);
	add_tc(u32be, 10);
	add_tc(h32be, 8);
	add_tc(o32be, 11);
	
	s32be->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<int32_t,  10, &htobe32_s>, this);
	u32be->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<uint32_t, 10, &htobe32_u>, this);
	h32be->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<uint32_t, 16, &htobe32_u>, this);
	o32be->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<uint32_t,  8, &htobe32_u>, this);
	
	s32be->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<int32_t>,  this);
	u32be->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<uint32_t>, this);
	h32be->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<uint32_t>, this);
	o32be->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<uint32_t>, this);
	
	sizer->Add(new wxStaticText(this, wxID_ANY, "32 bit LE"));
	add_tc(s32le, 11);
	add_tc(u32le, 10);
	add_tc(h32le, 8);
	add_tc(o32le, 11);
	
	s32le->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<int32_t,  10, &htole32_s>, this);
	u32le->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<uint32_t, 10, &htole32_u>, this);
	h32le->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<uint32_t, 16, &htole32_u>, this);
	o32le->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<uint32_t,  8, &htole32_u>, this);
	
	s32le->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<int32_t>,  this);
	u32le->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<uint32_t>, this);
	h32le->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<uint32_t>, this);
	o32le->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<uint32_t>, this);
	
	sizer->Add(new wxStaticText(this, wxID_ANY, "64 bit BE"));
	add_tc(s64be, 21);
	add_tc(u64be, 20);
	add_tc(h64be, 16);
	add_tc(o64be, 22);
	
	s64be->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<int64_t,  10, &htobe64_s>, this);
	u64be->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<uint64_t, 10, &htobe64_u>, this);
	h64be->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<uint64_t, 16, &htobe64_u>, this);
	o64be->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<uint64_t,  8, &htobe64_u>, this);
	
	s64be->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<int64_t>,  this);
	u64be->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<uint64_t>, this);
	h64be->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<uint64_t>, this);
	o64be->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<uint64_t>, this);
	
	sizer->Add(new wxStaticText(this, wxID_ANY, "64 bit LE"));
	add_tc(s64le, 21);
	add_tc(u64le, 20);
	add_tc(h64le, 16);
	add_tc(o64le, 22);
	
	s64le->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<int64_t,  10, &htole64_s>, this);
	u64le->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<uint64_t, 10, &htole64_u>, this);
	h64le->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<uint64_t, 16, &htole64_u>, this);
	o64le->Bind(wxEVT_TEXT, &REHex::DecodePanel::OnText<uint64_t,  8, &htole64_u>, this);
	
	s64le->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<int64_t>,  this);
	u64le->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<uint64_t>, this);
	h64le->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<uint64_t>, this);
	o64le->Bind(wxEVT_SET_FOCUS, &REHex::DecodePanel::OnSetFocus<uint64_t>, this);
	
	SetSizerAndFit(sizer);
}

/* TODO: Make this is templated lambda whenever I move to C++14 */
#define TC_UPDATE(field, T, format, expr) \
	if(field != skip_control) \
	{ \
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
		} \
	}

void REHex::DecodePanel::update(const unsigned char *data, size_t size, wxWindow *skip_control)
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

template<typename T, int base, T (*htoX)(T)> void REHex::DecodePanel::OnText(wxCommandEvent &event)
{
	auto tc = dynamic_cast<wxTextCtrl*>(event.GetEventObject());
	assert(tc != NULL);
	
	std::string sval = tc->GetValue().ToStdString();
	if(sval.length() == 0)
	{
		return;
	}
	
	errno = 0;
	char *endptr;
	
	T tval;
	
	if(std::numeric_limits<T>::is_signed)
	{
		long long int ival = strtoll(sval.c_str(), &endptr, base);
		if(*endptr != '\0')
		{
			/* Invalid characters */
			return;
		}
		if((ival == LLONG_MIN || ival == LLONG_MAX) && errno == ERANGE)
		{
			/* Out of range of long long */
			return;
		}
		
		if(ival < std::numeric_limits<T>::min() || ival > std::numeric_limits<T>::max())
		{
			/* Out of range of T */
			return;
		}
		
		tval = htoX(ival);
	}
	else{
		unsigned long long int uval = strtoll(sval.c_str(), &endptr, base);
		if(*endptr != '\0')
		{
			/* Invalid characters */
			return;
		}
		if(uval == ULLONG_MAX && errno == ERANGE)
		{
			/* Out of range of unsigned long long */
			return;
		}
		
		if(uval > std::numeric_limits<T>::max())
		{
			/* Out of range of T */
			return;
		}
		
		tval = htoX(uval);
	}
	
	ValueChange change_ev(tval, tc);
	change_ev.SetEventObject(this);
	
	wxPostEvent(this, change_ev);
}

template<typename T> void REHex::DecodePanel::OnSetFocus(wxFocusEvent &event)
{
	ValueFocus focus_ev(sizeof(T));
	focus_ev.SetEventObject(this);
	
	wxPostEvent(this, focus_ev);
}
