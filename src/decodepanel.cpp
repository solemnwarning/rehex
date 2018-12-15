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

/* Endianness conversion functions for use with the OnXXXValue() template methods. */
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

/* Endian conversion for floats.
 * These won't work on crazy platforms where integers and floats have different
 * endianness.
*/

static_assert(sizeof(float) == sizeof(int32_t), "float must be the same size as int32_t");
static_assert(sizeof(double) == sizeof(int64_t), "double must be the same size as int64_t");

static float beftoh(float be_float)
{
	int32_t he_float = be32toh(*(int32_t*)(&be_float));
	return *(float*)(&he_float);
}

static double bedtoh(double be_double)
{
	int64_t he_double = be64toh(*(int64_t*)(&be_double));
	return *(double*)(&he_double);
}

static float leftoh(float le_float)
{
	int32_t he_float = le32toh(*(int32_t*)(&le_float));
	return *(float*)(&he_float);
}

static double ledtoh(double le_double)
{
	int64_t he_double = le64toh(*(int64_t*)(&le_double));
	return *(double*)(&he_double);
}

static float  htobef(float  he_float)  { return beftoh(he_float); }
static double htobed(double he_double) { return bedtoh(he_double); }
static float  htolef(float  he_float)  { return leftoh(he_float); }
static double htoled(double he_double) { return ledtoh(he_double); }

BEGIN_EVENT_TABLE(REHex::DecodePanel, wxPanel)
	EVT_PG_CHANGED(wxID_ANY, REHex::DecodePanel::OnPropertyGridChanged)
	EVT_PG_SELECTED(wxID_ANY, REHex::DecodePanel::OnPropertyGridSelected)
	EVT_CHOICE(wxID_ANY, REHex::DecodePanel::OnEndian)
	EVT_SIZE(REHex::DecodePanel::OnSize)
END_EVENT_TABLE()

REHex::DecodePanel::DecodePanel(wxWindow *parent, wxWindowID id):
	wxPanel(parent, id)
{
	endian = new wxChoice(this, wxID_ANY);
	
	endian->Append("Big endian");
	endian->Append("Little endian");
	endian->SetSelection(1);
	
	pgrid = new wxPropertyGrid(this, wxID_ANY, wxDefaultPosition, wxDefaultSize,
		wxPG_STATIC_SPLITTER);
	
	pgrid->Append(c8 = new wxPropertyCategory("8 bit integer"));
	pgrid->AppendIn(c8, (s8 = new wxStringProperty("S Dec", "s8")));
	pgrid->AppendIn(c8, (u8 = new wxStringProperty("U Dec", "u8")));
	pgrid->AppendIn(c8, (h8 = new wxStringProperty("U Hex", "h8")));
	pgrid->AppendIn(c8, (o8 = new wxStringProperty("U Oct", "o8")));
	
	pgrid->Append(c16 = new wxPropertyCategory("16 bit integer"));
	pgrid->AppendIn(c16, (s16 = new wxStringProperty("S Dec", "s16")));
	pgrid->AppendIn(c16, (u16 = new wxStringProperty("U Dec", "u16")));
	pgrid->AppendIn(c16, (h16 = new wxStringProperty("U Hex", "h16")));
	pgrid->AppendIn(c16, (o16 = new wxStringProperty("U Oct", "o16")));
	
	pgrid->Append(c32 = new wxPropertyCategory("32 bit integer"));
	pgrid->AppendIn(c32, (s32 = new wxStringProperty("S Dec", "s32")));
	pgrid->AppendIn(c32, (u32 = new wxStringProperty("U Dec", "u32")));
	pgrid->AppendIn(c32, (h32 = new wxStringProperty("U Hex", "h32")));
	pgrid->AppendIn(c32, (o32 = new wxStringProperty("U Oct", "o32")));
	
	pgrid->Append(c64 = new wxPropertyCategory("64 bit integer"));
	pgrid->AppendIn(c64, (s64 = new wxStringProperty("S Dec", "s64")));
	pgrid->AppendIn(c64, (u64 = new wxStringProperty("U Dec", "u64")));
	pgrid->AppendIn(c64, (h64 = new wxStringProperty("U Hex", "h64")));
	pgrid->AppendIn(c64, (o64 = new wxStringProperty("U Oct", "o64")));
	
	pgrid->Append(c32f = new wxPropertyCategory("32 bit float"));
	pgrid->AppendIn(c32f, (f32 = new wxStringProperty("Dec", "f32")));
	
	pgrid->Append(c64f = new wxPropertyCategory("64 bit float (double)"));
	pgrid->AppendIn(c64f, (f64 = new wxStringProperty("Dec", "f64")));
	
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);
	
	sizer->Add(endian, 0, wxEXPAND | wxALL, 0);
	sizer->Add(pgrid, 1, wxEXPAND | wxALL, 0);
	
	SetSizerAndFit(sizer);
	
	pgrid->SetSplitterLeft();
}

/* TODO: Make this is templated lambda whenever I move to C++14 */
#define TC_UPDATE(field, T, format, expr) \
	if(field != skip_control) \
	{ \
		if(size >= sizeof(T)) \
		{ \
			char buf[64]; \
			snprintf(buf, sizeof(buf), format, expr); \
			field->SetValueFromString(buf); \
			pgrid->EnableProperty(field); \
		} \
		else{ \
			field->SetValueFromString(""); \
			pgrid->DisableProperty(field); \
		} \
	}

void REHex::DecodePanel::update(const unsigned char *data, size_t size, wxPGProperty *skip_control)
{
	TC_UPDATE(s8, int8_t,  "%" PRId8, (*(int8_t*)(data)));
	TC_UPDATE(u8, uint8_t, "%" PRIu8, (*(uint8_t*)(data)));
	TC_UPDATE(h8, uint8_t, "%" PRIx8, (*(uint8_t*)(data)));
	TC_UPDATE(o8, uint8_t, "%" PRIo8, (*(uint8_t*)(data)));
	
	if(endian->GetSelection() == 0)
	{
		/* Big endian */
		
		TC_UPDATE(s16, int16_t, "%" PRId16, be16toh(*(int16_t*)(data)));
		TC_UPDATE(u16, int16_t, "%" PRIu16, be16toh(*(uint16_t*)(data)));
		TC_UPDATE(h16, int16_t, "%" PRIx16, be16toh(*(uint16_t*)(data)));
		TC_UPDATE(o16, int16_t, "%" PRIo16, be16toh(*(uint16_t*)(data)));
		
		TC_UPDATE(s32, int32_t, "%" PRId32, be32toh(*(int32_t*)(data)));
		TC_UPDATE(u32, int32_t, "%" PRIu32, be32toh(*(uint32_t*)(data)));
		TC_UPDATE(h32, int32_t, "%" PRIx32, be32toh(*(uint32_t*)(data)));
		TC_UPDATE(o32, int32_t, "%" PRIo32, be32toh(*(uint32_t*)(data)));
		
		TC_UPDATE(s64, int64_t, "%" PRId64, be64toh(*(int64_t*)(data)));
		TC_UPDATE(u64, int64_t, "%" PRIu64, be64toh(*(uint64_t*)(data)));
		TC_UPDATE(h64, int64_t, "%" PRIx64, be64toh(*(uint64_t*)(data)));
		TC_UPDATE(o64, int64_t, "%" PRIo64, be64toh(*(uint64_t*)(data)));
		
		TC_UPDATE(f32, float,  "%.9g", beftoh(*(float*)(data)));
		TC_UPDATE(f64, double, "%.9g", bedtoh(*(double*)(data)));
	}
	else{
		/* Little endian */
		
		TC_UPDATE(s16, int16_t, "%" PRId16, le16toh(*(int16_t*)(data)));
		TC_UPDATE(u16, int16_t, "%" PRIu16, le16toh(*(uint16_t*)(data)));
		TC_UPDATE(h16, int16_t, "%" PRIx16, le16toh(*(uint16_t*)(data)));
		TC_UPDATE(o16, int16_t, "%" PRIo16, le16toh(*(uint16_t*)(data)));
		
		TC_UPDATE(s32, int32_t, "%" PRId32, le32toh(*(int32_t*)(data)));
		TC_UPDATE(u32, int32_t, "%" PRIu32, le32toh(*(uint32_t*)(data)));
		TC_UPDATE(h32, int32_t, "%" PRIx32, le32toh(*(uint32_t*)(data)));
		TC_UPDATE(o32, int32_t, "%" PRIo32, le32toh(*(uint32_t*)(data)));
		
		TC_UPDATE(s64, int64_t, "%" PRId64, le64toh(*(int64_t*)(data)));
		TC_UPDATE(u64, int64_t, "%" PRIu64, le64toh(*(uint64_t*)(data)));
		TC_UPDATE(h64, int64_t, "%" PRIx64, le64toh(*(uint64_t*)(data)));
		TC_UPDATE(o64, int64_t, "%" PRIo64, le64toh(*(uint64_t*)(data)));
		
		TC_UPDATE(f32, float,  "%.9g", leftoh(*(float*)(data)));
		TC_UPDATE(f64, double, "%.9g", ledtoh(*(double*)(data)));
	}
	
	last_data.resize(size);
	memmove(last_data.data(), data, size);
}

void REHex::DecodePanel::OnPropertyGridChanged(wxPropertyGridEvent &event)
{
	wxPGProperty *property = event.GetProperty();
	
	     if(property == (wxPGProperty*)(s8)) { OnSignedValue  <int8_t,  10, &hto8_s>((wxStringProperty*)(property)); }
	else if(property == (wxPGProperty*)(u8)) { OnUnsignedValue<uint8_t, 10, &hto8_u>((wxStringProperty*)(property)); }
	else if(property == (wxPGProperty*)(h8)) { OnUnsignedValue<uint8_t, 16, &hto8_u>((wxStringProperty*)(property)); }
	else if(property == (wxPGProperty*)(o8)) { OnUnsignedValue<uint8_t,  8, &hto8_u>((wxStringProperty*)(property)); }
	
	if(endian->GetSelection() == 0)
	{
		/* Big endian */
		
		     if(property == (wxPGProperty*)(s16)) { OnSignedValue  <int16_t,  10, &htobe16_s>((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(u16)) { OnUnsignedValue<uint16_t, 10, &htobe16_u>((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(h16)) { OnUnsignedValue<uint16_t, 16, &htobe16_u>((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(o16)) { OnUnsignedValue<uint16_t,  8, &htobe16_u>((wxStringProperty*)(property)); }
		
		else if(property == (wxPGProperty*)(s32)) { OnSignedValue  <int32_t,  10, &htobe32_s>((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(u32)) { OnUnsignedValue<uint32_t, 10, &htobe32_u>((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(h32)) { OnUnsignedValue<uint32_t, 16, &htobe32_u>((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(o32)) { OnUnsignedValue<uint32_t,  8, &htobe32_u>((wxStringProperty*)(property)); }
		
		else if(property == (wxPGProperty*)(s64)) { OnSignedValue  <int64_t,  10, &htobe64_s>((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(u64)) { OnUnsignedValue<uint64_t, 10, &htobe64_u>((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(h64)) { OnUnsignedValue<uint64_t, 16, &htobe64_u>((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(o64)) { OnUnsignedValue<uint64_t,  8, &htobe64_u>((wxStringProperty*)(property)); }
		
		else if(property == (wxPGProperty*)(f32)) { OnFloatValue<&htobef>((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(f64)) { OnDoubleValue<&htobed>((wxStringProperty*)(property)); }
	}
	else{
		/* Little endian */
		
		     if(property == (wxPGProperty*)(s16)) { OnSignedValue  <int16_t,  10, &htole16_s>((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(u16)) { OnUnsignedValue<uint16_t, 10, &htole16_u>((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(h16)) { OnUnsignedValue<uint16_t, 16, &htole16_u>((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(o16)) { OnUnsignedValue<uint16_t,  8, &htole16_u>((wxStringProperty*)(property)); }
		
		else if(property == (wxPGProperty*)(s32)) { OnSignedValue  <int32_t,  10, &htole32_s>((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(u32)) { OnUnsignedValue<uint32_t, 10, &htole32_u>((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(h32)) { OnUnsignedValue<uint32_t, 16, &htole32_u>((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(o32)) { OnUnsignedValue<uint32_t,  8, &htole32_u>((wxStringProperty*)(property)); }
		
		else if(property == (wxPGProperty*)(s64)) { OnSignedValue  <int64_t,  10, &htole64_s>((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(u64)) { OnUnsignedValue<uint64_t, 10, &htole64_u>((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(h64)) { OnUnsignedValue<uint64_t, 16, &htole64_u>((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(o64)) { OnUnsignedValue<uint64_t,  8, &htole64_u>((wxStringProperty*)(property)); }
		
		else if(property == (wxPGProperty*)(f32)) { OnFloatValue<&htolef>((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(f64)) { OnDoubleValue<&htoled>((wxStringProperty*)(property)); }
	}
}

void REHex::DecodePanel::OnPropertyGridSelected(wxPropertyGridEvent &event)
{
	wxPGProperty *property = event.GetProperty();
	int size = 0;
	
	if(property == s8 || property == u8 || property == h8 || property == o8)
	{
		size = sizeof(uint8_t);
	}
	else if(property == s16 || property == u16 || property == h16 || property == o16)
	{
		size = sizeof(uint16_t);
	}
	else if(property == s32 || property == u32 || property == h32 || property == o32)
	{
		size = sizeof(uint32_t);
	}
	else if(property == s64 || property == u64 || property == h64 || property == o64)
	{
		size = sizeof(uint64_t);
	}
	else if(property == f32)
	{
		size = sizeof(float);
	}
	else if(property == f64)
	{
		size = sizeof(double);
	}
	
	if(size > 0)
	{
		ValueFocus focus_ev(size);
		focus_ev.SetEventObject(this);
		
		wxPostEvent(this, focus_ev);
	}
}

void REHex::DecodePanel::OnEndian(wxCommandEvent &event)
{
	update(last_data.data(), last_data.size(), NULL);
}

void REHex::DecodePanel::OnSize(wxSizeEvent &event)
{
	pgrid->SetSplitterLeft();
	
	/* Continue propogation of EVT_SIZE event. */
	event.Skip();
}

template<typename T, int base, T (*htoX)(T)> void REHex::DecodePanel::OnSignedValue(wxStringProperty *property)
{
	static_assert(std::numeric_limits<T>::is_integer, "OnSignedValue() instantiated with non-integer type");
	static_assert(std::numeric_limits<T>::is_signed,  "OnSignedValue() instantiated with unsigned type");
	
	std::string sval = property->GetValueAsString().ToStdString();
	if(sval.length() == 0)
	{
		return;
	}
	
	errno = 0;
	char *endptr;
	
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
	
	T tval = htoX(ival);
	
	ValueChange change_ev(tval, property);
	change_ev.SetEventObject(this);
	
	wxPostEvent(this, change_ev);
}

template<typename T, int base, T (*htoX)(T)> void REHex::DecodePanel::OnUnsignedValue(wxStringProperty *property)
{
	static_assert(std::numeric_limits<T>::is_integer, "OnUnsignedValue() instantiated with non-integer type");
	static_assert(!std::numeric_limits<T>::is_signed, "OnUnsignedValue() instantiated with signed type");
	
	std::string sval = property->GetValueAsString().ToStdString();
	if(sval.length() == 0)
	{
		return;
	}
	
	errno = 0;
	char *endptr;
	
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
	
	T tval = htoX(uval);
	
	ValueChange change_ev(tval, property);
	change_ev.SetEventObject(this);
	
	wxPostEvent(this, change_ev);
}

template<float (*htoX)(float)> void REHex::DecodePanel::OnFloatValue(wxStringProperty *property)
{
	std::string sval = property->GetValueAsString().ToStdString();
	if(sval.length() == 0)
	{
		return;
	}
	
	errno = 0;
	char *endptr;
	
	float uval = strtof(sval.c_str(), &endptr);
	if(*endptr != '\0')
	{
		/* Invalid characters */
		return;
	}
	if((uval == HUGE_VALF || uval == -HUGE_VALF) && errno == ERANGE)
	{
		/* Out of range of float */
		return;
	}
	
	float tval = htoX(uval);
	
	ValueChange change_ev(tval, property);
	change_ev.SetEventObject(this);
	
	wxPostEvent(this, change_ev);
}

template<double (*htoX)(double)> void REHex::DecodePanel::OnDoubleValue(wxStringProperty *property)
{
	std::string sval = property->GetValueAsString().ToStdString();
	if(sval.length() == 0)
	{
		return;
	}
	
	errno = 0;
	char *endptr;
	
	double uval = strtod(sval.c_str(), &endptr);
	if(*endptr != '\0')
	{
		/* Invalid characters */
		return;
	}
	if((uval == HUGE_VAL || uval == -HUGE_VAL) && errno == ERANGE)
	{
		/* Out of range of double */
		return;
	}
	
	double tval = htoX(uval);
	
	ValueChange change_ev(tval, property);
	change_ev.SetEventObject(this);
	
	wxPostEvent(this, change_ev);
}
