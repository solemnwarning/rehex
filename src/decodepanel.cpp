/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "platform.hpp"
#include <assert.h>
#include <inttypes.h>

#include "App.hpp"
#include "decodepanel.hpp"
#include "Events.hpp"

/* This MUST come after the wxWidgets headers have been included, else we pull in windows.h BEFORE the wxWidgets
 * headers when building on Windows and this causes unicode-flavoured pointer conversion errors.
*/
#include "endian_conv.hpp"

static REHex::ToolPanel *DecodePanel_factory(wxWindow *parent, REHex::SharedDocumentPointer &document, REHex::DocumentCtrl *document_ctrl)
{
	return new REHex::DecodePanel(parent, document, document_ctrl);
}

static REHex::ToolPanelRegistration tpr("DecodePanel", "Decode values", REHex::ToolPanel::TPS_TALL, &DecodePanel_factory);

/* Endianness conversion functions for use with the OnXXXValue() template methods. */
static uint8_t  hto8_u   (uint8_t  host_8bits)  { return host_8bits; }
static int8_t   hto8_s   (int8_t   host_8bits)  { return host_8bits; }

BEGIN_EVENT_TABLE(REHex::DecodePanel, wxPanel)
	EVT_PG_CHANGED(wxID_ANY, REHex::DecodePanel::OnPropertyGridChanged)
	EVT_PG_SELECTED(wxID_ANY, REHex::DecodePanel::OnPropertyGridSelected)
	EVT_CHOICE(wxID_ANY, REHex::DecodePanel::OnEndian)
	EVT_SIZE(REHex::DecodePanel::OnSize)
END_EVENT_TABLE()

REHex::DecodePanel::DecodePanel(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl):
	ToolPanel(parent),
	document(document),
	document_ctrl(document_ctrl)
{
	endian = new wxChoice(this, wxID_ANY);
	
	endian->Append("Big endian");
	endian->Append("Little endian");
	endian->SetSelection(1);
	
	pgrid = new wxPropertyGrid(this, wxID_ANY, wxDefaultPosition, wxDefaultSize,
		wxPG_STATIC_SPLITTER);
	
	wxGetApp().Bind(PALETTE_CHANGED, &REHex::DecodePanel::OnColourPaletteChanged, this);
	set_pgrid_colours();
	
	pgrid->Append(c8 = new wxPropertyCategory("8 bit integer"));
	pgrid->AppendIn(c8, (s8 = new wxStringProperty("S Dec", "s8", "0000000000000000")));
	pgrid->AppendIn(c8, (u8 = new wxStringProperty("U Dec", "u8", "0000000000000000")));
	pgrid->AppendIn(c8, (h8 = new wxStringProperty("U Hex", "h8", "0000000000000000")));
	pgrid->AppendIn(c8, (o8 = new wxStringProperty("U Oct", "o8", "0000000000000000")));
	
	pgrid->Append(c16 = new wxPropertyCategory("16 bit integer"));
	pgrid->AppendIn(c16, (s16 = new wxStringProperty("S Dec", "s16", "0000000000000000")));
	pgrid->AppendIn(c16, (u16 = new wxStringProperty("U Dec", "u16", "0000000000000000")));
	pgrid->AppendIn(c16, (h16 = new wxStringProperty("U Hex", "h16", "0000000000000000")));
	pgrid->AppendIn(c16, (o16 = new wxStringProperty("U Oct", "o16", "0000000000000000")));
	
	pgrid->Append(c32 = new wxPropertyCategory("32 bit integer"));
	pgrid->AppendIn(c32, (s32 = new wxStringProperty("S Dec", "s32", "0000000000000000")));
	pgrid->AppendIn(c32, (u32 = new wxStringProperty("U Dec", "u32", "0000000000000000")));
	pgrid->AppendIn(c32, (h32 = new wxStringProperty("U Hex", "h32", "0000000000000000")));
	pgrid->AppendIn(c32, (o32 = new wxStringProperty("U Oct", "o32", "0000000000000000")));
	
	pgrid->Append(c64 = new wxPropertyCategory("64 bit integer"));
	pgrid->AppendIn(c64, (s64 = new wxStringProperty("S Dec", "s64", "0000000000000000")));
	pgrid->AppendIn(c64, (u64 = new wxStringProperty("U Dec", "u64", "0000000000000000")));
	pgrid->AppendIn(c64, (h64 = new wxStringProperty("U Hex", "h64", "0000000000000000")));
	pgrid->AppendIn(c64, (o64 = new wxStringProperty("U Oct", "o64", "0000000000000000")));
	
	pgrid->Append(c32f = new wxPropertyCategory("32 bit float"));
	pgrid->AppendIn(c32f, (f32 = new wxStringProperty("Dec", "f32", "0000000000000000")));
	
	pgrid->Append(c64f = new wxPropertyCategory("64 bit float (double)"));
	pgrid->AppendIn(c64f, (f64 = new wxStringProperty("Dec", "f64", "0000000000000000")));
	
	/* Compute minimum width needed to render without cutting off labels or reasonable numeric
	 * values in the wxPropertyGrid.
	 *
	 * Size is initially set to a large value, where everything will fit. Then we call
	 * FitColumns() to lay out the columns nicely, yielding the minimum internal grid size.
	 * Finally we add that to the margin and scrollbar width to come to the minimum width. No
	 * minimum height is enforced.
	 *
	 * TODO: Do it in a way that doesn't require us to change our size.
	*/
	
	pgrid->SetSize(wxSize(1024, 1024));
	
	int pg_min_grid_width = pgrid->FitColumns().GetWidth();
	int pg_margin_width   = pgrid->GetMarginWidth();
	int pg_border_width   = pgrid->GetWindowBorderSize().GetWidth();
	int v_scroll_width    = wxSystemSettings::GetMetric(wxSYS_VSCROLL_X);
	
	pgrid_best_width = pg_min_grid_width + pg_margin_width + v_scroll_width + pg_border_width;
	
	/* Arbitrary minimum size for panel. */
	endian->SetMinSize(wxSize(80, -1));
	pgrid->SetMinSize(wxSize(80, -1));
	
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);
	
	sizer->Add(endian, 0, wxEXPAND | wxALL, 0);
	sizer->Add(pgrid, 1, wxEXPAND | wxALL, 0);
	
	SetSizerAndFit(sizer);
	
	pgrid->SetSplitterLeft();
	
	this->document.auto_cleanup_bind(CURSOR_UPDATE, &REHex::DecodePanel::OnCursorUpdate,    this);
	
	this->document.auto_cleanup_bind(DATA_ERASE,     &REHex::DecodePanel::OnDataModified, this);
	this->document.auto_cleanup_bind(DATA_INSERT,    &REHex::DecodePanel::OnDataModified, this);
	this->document.auto_cleanup_bind(DATA_OVERWRITE, &REHex::DecodePanel::OnDataModified, this);
	
	update();
}

REHex::DecodePanel::~DecodePanel()
{
	wxGetApp().Unbind(PALETTE_CHANGED, &REHex::DecodePanel::OnColourPaletteChanged, this);
}

std::string REHex::DecodePanel::name() const
{
	return "DecodePanel";
}

void REHex::DecodePanel::save_state(wxConfig *config) const
{
	bool big_endian = (endian->GetSelection() == 0);
	config->Write("big-endian", big_endian);
}

void REHex::DecodePanel::load_state(wxConfig *config)
{
	bool big_endian = config->Read("big-endian", (endian->GetSelection() == 0));
	if(big_endian)
	{
		endian->SetSelection(0);
	}
	else{
		endian->SetSelection(1);
	}
	
	update();
}

void REHex::DecodePanel::set_pgrid_colours()
{
	pgrid->SetCaptionBackgroundColour(    (*active_palette)[Palette::PAL_COMMENT_BG]         );
	pgrid->SetCaptionTextColour(          (*active_palette)[Palette::PAL_ALTERNATE_TEXT_FG]  );
	pgrid->SetCellBackgroundColour(       (*active_palette)[Palette::PAL_NORMAL_TEXT_BG]     );
	pgrid->SetCellDisabledTextColour(     (*active_palette)[Palette::PAL_ALTERNATE_TEXT_FG]  );
	pgrid->SetCellTextColour(             (*active_palette)[Palette::PAL_NORMAL_TEXT_FG]     );
	pgrid->SetEmptySpaceColour(           (*active_palette)[Palette::PAL_NORMAL_TEXT_BG]     );
	pgrid->SetLineColour(                 (*active_palette)[Palette::PAL_COMMENT_BG]         );
	pgrid->SetMarginColour(               (*active_palette)[Palette::PAL_COMMENT_BG]         );
	pgrid->SetSelectionBackgroundColour(  (*active_palette)[Palette::PAL_SELECTED_TEXT_BG]   );
	pgrid->SetSelectionTextColour(        (*active_palette)[Palette::PAL_SELECTED_TEXT_FG]   );
}

wxSize REHex::DecodePanel::DoGetBestClientSize() const
{
	return wxSize(pgrid_best_width, -1);
}

/* TODO: Make this is templated lambda whenever I move to C++14 */
#define TC_UPDATE(field, T, format, expr) \
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

#define TC_ERR(field) \
{ \
	field->SetValueFromString(e.what()); \
	pgrid->DisableProperty(field); \
}

#define TC_ERR4(f1, f2, f3, f4) \
	TC_ERR(f1); \
	TC_ERR(f2); \
	TC_ERR(f3); \
	TC_ERR(f4);

void REHex::DecodePanel::update()
{
	if (!is_visible)
	{
		/* There is no sense in updating this if we are not visible */
		return;
	}
	assert(document != NULL);
	
	std::vector<unsigned char> data_at_cur;
	try {
		data_at_cur = document->read_data(document->get_cursor_position(), 8);
	}
	catch(const std::exception &e)
	{
		TC_ERR4(s8,  u8,  h8,  o8);
		TC_ERR4(s16, u16, h16, o16);
		TC_ERR4(s32, u32, h32, o32);
		TC_ERR4(s64, u64, h64, o64);
		
		TC_ERR(f32);
		TC_ERR(f64);
		
		return;
	}
	
	const unsigned char *data = data_at_cur.data();
	size_t               size = data_at_cur.size();
	
	TC_UPDATE(s8, int8_t,  "%" PRId8, (*(int8_t*)(data)));
	TC_UPDATE(u8, uint8_t, "%" PRIu8, (*(uint8_t*)(data)));
	TC_UPDATE(h8, uint8_t, "%" PRIx8, (*(uint8_t*)(data)));
	TC_UPDATE(o8, uint8_t, "%" PRIo8, (*(uint8_t*)(data)));
	
	if(endian->GetSelection() == 0)
	{
		/* Big endian */
		
		TC_UPDATE(s16, int16_t, "%" PRId16, beXXXtoh_p<int16_t>(data));
		TC_UPDATE(u16, int16_t, "%" PRIu16, beXXXtoh_p<uint16_t>(data));
		TC_UPDATE(h16, int16_t, "%" PRIx16, beXXXtoh_p<uint16_t>(data));
		TC_UPDATE(o16, int16_t, "%" PRIo16, beXXXtoh_p<uint16_t>(data));
		
		TC_UPDATE(s32, int32_t, "%" PRId32, beXXXtoh_p<int32_t>(data));
		TC_UPDATE(u32, int32_t, "%" PRIu32, beXXXtoh_p<uint32_t>(data));
		TC_UPDATE(h32, int32_t, "%" PRIx32, beXXXtoh_p<uint32_t>(data));
		TC_UPDATE(o32, int32_t, "%" PRIo32, beXXXtoh_p<uint32_t>(data));
		
		TC_UPDATE(s64, int64_t, "%" PRId64, beXXXtoh_p<int64_t>(data));
		TC_UPDATE(u64, int64_t, "%" PRIu64, beXXXtoh_p<uint64_t>(data));
		TC_UPDATE(h64, int64_t, "%" PRIx64, beXXXtoh_p<uint64_t>(data));
		TC_UPDATE(o64, int64_t, "%" PRIo64, beXXXtoh_p<uint64_t>(data));
		
		TC_UPDATE(f32, float,  "%.9g", beXXXtoh_p<float>(data));
		TC_UPDATE(f64, double, "%.9g", beXXXtoh_p<double>(data));
	}
	else{
		/* Little endian */
		
		TC_UPDATE(s16, int16_t, "%" PRId16, leXXXtoh_p<int16_t>(data));
		TC_UPDATE(u16, int16_t, "%" PRIu16, leXXXtoh_p<uint16_t>(data));
		TC_UPDATE(h16, int16_t, "%" PRIx16, leXXXtoh_p<uint16_t>(data));
		TC_UPDATE(o16, int16_t, "%" PRIo16, leXXXtoh_p<uint16_t>(data));
		
		TC_UPDATE(s32, int32_t, "%" PRId32, leXXXtoh_p<int32_t>(data));
		TC_UPDATE(u32, int32_t, "%" PRIu32, leXXXtoh_p<uint32_t>(data));
		TC_UPDATE(h32, int32_t, "%" PRIx32, leXXXtoh_p<uint32_t>(data));
		TC_UPDATE(o32, int32_t, "%" PRIo32, leXXXtoh_p<uint32_t>(data));
		
		TC_UPDATE(s64, int64_t, "%" PRId64, leXXXtoh_p<int64_t>(data));
		TC_UPDATE(u64, int64_t, "%" PRIu64, leXXXtoh_p<uint64_t>(data));
		TC_UPDATE(h64, int64_t, "%" PRIx64, leXXXtoh_p<uint64_t>(data));
		TC_UPDATE(o64, int64_t, "%" PRIo64, leXXXtoh_p<uint64_t>(data));
		
		TC_UPDATE(f32, float,  "%.9g", leXXXtoh_p<float>(data));
		TC_UPDATE(f64, double, "%.9g", leXXXtoh_p<double>(data));
	}
	
	last_data.resize(size);
	memmove(last_data.data(), data, size);
}

void REHex::DecodePanel::OnCursorUpdate(CursorUpdateEvent &event)
{
	update();
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::DecodePanel::OnDataModified(OffsetLengthEvent &event)
{
	update();
	
	/* Continue propogation. */
	event.Skip();
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
		
		     if(property == (wxPGProperty*)(s16)) { OnSignedValue  <int16_t,  10, &htobeXXX<int16_t> >((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(u16)) { OnUnsignedValue<uint16_t, 10, &htobeXXX<uint16_t> >((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(h16)) { OnUnsignedValue<uint16_t, 16, &htobeXXX<uint16_t> >((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(o16)) { OnUnsignedValue<uint16_t,  8, &htobeXXX<uint16_t> >((wxStringProperty*)(property)); }
		
		else if(property == (wxPGProperty*)(s32)) { OnSignedValue  <int32_t,  10, &htobeXXX<int32_t> >((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(u32)) { OnUnsignedValue<uint32_t, 10, &htobeXXX<uint32_t> >((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(h32)) { OnUnsignedValue<uint32_t, 16, &htobeXXX<uint32_t> >((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(o32)) { OnUnsignedValue<uint32_t,  8, &htobeXXX<uint32_t> >((wxStringProperty*)(property)); }
		
		else if(property == (wxPGProperty*)(s64)) { OnSignedValue  <int64_t,  10, &htobeXXX<int64_t> >((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(u64)) { OnUnsignedValue<uint64_t, 10, &htobeXXX<uint64_t> >((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(h64)) { OnUnsignedValue<uint64_t, 16, &htobeXXX<uint64_t> >((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(o64)) { OnUnsignedValue<uint64_t,  8, &htobeXXX<uint64_t> >((wxStringProperty*)(property)); }
		
		else if(property == (wxPGProperty*)(f32)) { OnFloatValue< &htobeXXX<float> >((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(f64)) { OnDoubleValue< &htobeXXX<double> >((wxStringProperty*)(property)); }
	}
	else{
		/* Little endian */
		
		     if(property == (wxPGProperty*)(s16)) { OnSignedValue  <int16_t,  10, &htoleXXX<int16_t> >((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(u16)) { OnUnsignedValue<uint16_t, 10, &htoleXXX<uint16_t> >((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(h16)) { OnUnsignedValue<uint16_t, 16, &htoleXXX<uint16_t> >((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(o16)) { OnUnsignedValue<uint16_t,  8, &htoleXXX<uint16_t> >((wxStringProperty*)(property)); }
		
		else if(property == (wxPGProperty*)(s32)) { OnSignedValue  <int32_t,  10, &htoleXXX<int32_t> >((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(u32)) { OnUnsignedValue<uint32_t, 10, &htoleXXX<uint32_t> >((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(h32)) { OnUnsignedValue<uint32_t, 16, &htoleXXX<uint32_t> >((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(o32)) { OnUnsignedValue<uint32_t,  8, &htoleXXX<uint32_t> >((wxStringProperty*)(property)); }
		
		else if(property == (wxPGProperty*)(s64)) { OnSignedValue  <int64_t,  10, &htoleXXX<int64_t> >((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(u64)) { OnUnsignedValue<uint64_t, 10, &htoleXXX<uint64_t> >((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(h64)) { OnUnsignedValue<uint64_t, 16, &htoleXXX<uint64_t> >((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(o64)) { OnUnsignedValue<uint64_t,  8, &htoleXXX<uint64_t> >((wxStringProperty*)(property)); }
		
		else if(property == (wxPGProperty*)(f32)) { OnFloatValue< &htoleXXX<float> > ((wxStringProperty*)(property)); }
		else if(property == (wxPGProperty*)(f64)) { OnDoubleValue< &htoleXXX<double> >((wxStringProperty*)(property)); }
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
	
	if(size > 0 && document_ctrl != NULL)
	{
		BitOffset cursor_position = document->get_cursor_position();
		document_ctrl->set_selection_raw(cursor_position, (cursor_position + BitOffset(size, 0) - BitOffset(0, 1)));
	}
}

void REHex::DecodePanel::OnEndian(wxCommandEvent &event)
{
	update();
}

void REHex::DecodePanel::OnSize(wxSizeEvent &event)
{
	pgrid->SetSplitterLeft();
	
	/* Continue propogation of EVT_SIZE event. */
	event.Skip();
}

void REHex::DecodePanel::OnColourPaletteChanged(wxCommandEvent &event)
{
	set_pgrid_colours();
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
	
	if(document != NULL)
	{
		T tval = htoX(ival);
		
		try {
			document->overwrite_data(document->get_cursor_position(), &tval, sizeof(tval));
		}
		catch(const std::exception &e)
		{
			fprintf(stderr, "Exception in REHex::DecodePanel::OnSignedValue: %s\n", e.what());
			update();
		}
	}
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
	
	if(document != NULL)
	{
		T tval = htoX(uval);
		
		try {
			document->overwrite_data(document->get_cursor_position(), &tval, sizeof(tval));
		}
		catch(const std::exception &e)
		{
			fprintf(stderr, "Exception in REHex::DecodePanel::OnUnsignedValue: %s\n", e.what());
			update();
		}
	}
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
	
	if(document != NULL)
	{
		float tval = htoX(uval);
		
		try {
			document->overwrite_data(document->get_cursor_position(), &tval, sizeof(tval));
		}
		catch(const std::exception &e)
		{
			fprintf(stderr, "Exception in REHex::DecodePanel::OnFloatValue: %s\n", e.what());
			update();
		}
	}
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
	
	if(document != NULL)
	{
		double tval = htoX(uval);
		
		try {
			document->overwrite_data(document->get_cursor_position(), &tval, sizeof(tval));
		}
		catch(const std::exception &e)
		{
			fprintf(stderr, "Exception in REHex::DecodePanel::OnDoubleValue: %s\n", e.what());
			update();
		}
	}
}
