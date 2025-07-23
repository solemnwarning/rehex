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

#include "platform.hpp"

#include <functional>
#include <wx/checkbox.h>
#include <wx/choice.h>
#include <wx/clipbrd.h>
#include <wx/colourdata.h>
#include <wx/colordlg.h>
#include <wx/dataobj.h>
#include <wx/filename.h>
#include <wx/rawbmp.h>
#include <wx/scrolwin.h>
#include <wx/sizer.h>
#include <wx/statbmp.h>
#include <wx/stattext.h>

#include "BitmapTool.hpp"
#include "NumericTextCtrl.hpp"
#include "util.hpp"

#include "../res/actual_size_dark_16.h"
#include "../res/actual_size_light_16.h"
#include "../res/bg16.h"
#include "../res/fit_to_screen_dark_16.h"
#include "../res/fit_to_screen_light_16.h"
#include "../res/swap_horiz_dark_16.h"
#include "../res/swap_horiz_light_16.h"
#include "../res/swap_vert_dark_16.h"
#include "../res/swap_vert_light_16.h"
#include "../res/zoom_in_dark_16.h"
#include "../res/zoom_in_light_16.h"
#include "../res/zoom_out_dark_16.h"
#include "../res/zoom_out_light_16.h"

static REHex::ToolPanel *BitmapTool_factory(wxWindow *parent, REHex::SharedDocumentPointer &document, REHex::DocumentCtrl *document_ctrl)
{
	return new REHex::BitmapTool(parent, document, document_ctrl);
}

static REHex::ToolPanelRegistration tpr("BitmapTool", "Bitmap visualisation", REHex::ToolPanel::TPS_TALL, &BitmapTool_factory);

enum {
	ID_COLOUR_DEPTH = 1,
	ID_COLOUR_FORMAT,
	ID_IMAGE_OFFSET,
	ID_FOLLOW_CURSOR,
	ID_IMAGE_WIDTH,
	ID_IMAGE_HEIGHT,
	ID_ROWS_PACKED,
	ID_ROW_LENGTH,
	ID_FLIP_X,
	ID_FLIP_Y,
	ID_SCALE,
	ID_ACTUAL_SIZE,
	ID_ZOOM_IN,
	ID_ZOOM_OUT,
	ID_UPDATE_TIMER,
	ID_BACKGROUND,
};

/* The minimum interval between updates when rendering the preview bitmap.
 * This only comes into play if the system is heavily loaded - normally we will
 * render chunks at a time in idle events and reset the timer.
*/
static const int UPDATE_TIMER_MS = 250;

BEGIN_EVENT_TABLE(REHex::BitmapTool, wxPanel)
	EVT_CHOICE(ID_COLOUR_DEPTH,  REHex::BitmapTool::OnDepth)
	EVT_CHOICE(ID_COLOUR_FORMAT, REHex::BitmapTool::OnFormat)
	
	EVT_TEXT(ID_IMAGE_OFFSET,      REHex::BitmapTool::OnXXX)
	EVT_CHECKBOX(ID_FOLLOW_CURSOR, REHex::BitmapTool::OnFollowCursor)
	
	EVT_SPINCTRL(ID_IMAGE_WIDTH,  REHex::BitmapTool::OnImageWidth)
	EVT_SPINCTRL(ID_IMAGE_HEIGHT, REHex::BitmapTool::OnImageHeight)
	
	EVT_CHECKBOX(ID_ROWS_PACKED, REHex::BitmapTool::OnRowsPacked)
	EVT_SPINCTRL(ID_ROW_LENGTH,  REHex::BitmapTool::OnRowLength)
	
	EVT_TOOL(ID_FLIP_X,       REHex::BitmapTool::OnXXX)
	EVT_TOOL(ID_FLIP_Y,       REHex::BitmapTool::OnXXX)
	EVT_TOOL(ID_SCALE,        REHex::BitmapTool::OnFit)
	EVT_TOOL(ID_ACTUAL_SIZE,  REHex::BitmapTool::OnActualSize)
	EVT_TOOL(ID_ZOOM_IN,      REHex::BitmapTool::OnZoomIn)
	EVT_TOOL(ID_ZOOM_OUT,     REHex::BitmapTool::OnZoomOut)
	EVT_TOOL(ID_BACKGROUND,   REHex::BitmapTool::OnBackground)
	
	EVT_SIZE(REHex::BitmapTool::OnSize)
END_EVENT_TABLE()

enum {
	COLOUR_DEPTH_1BPP = 0,
	COLOUR_DEPTH_2BPP,
	COLOUR_DEPTH_4BPP,
	COLOUR_DEPTH_8BPP,
	COLOUR_DEPTH_16BPP,
	COLOUR_DEPTH_24BPP,
	COLOUR_DEPTH_32BPP,
	
	COLOUR_DEPTH_8BPP_GREYSCALE = 0,
	COLOUR_DEPTH_8BPP_RGB332,
	
	COLOUR_DEPTH_16BPP_RGB565 = 0,
	COLOUR_DEPTH_16BPP_RGB555,
	COLOUR_DEPTH_16BPP_RGB444,
	COLOUR_DEPTH_16BPP_ARGB1555,
	COLOUR_DEPTH_16BPP_BGR565,
	COLOUR_DEPTH_16BPP_BGR555,
	COLOUR_DEPTH_16BPP_BGR444,
	
	COLOUR_DEPTH_24BPP_RGB888 = 0,
	
	COLOUR_DEPTH_32BPP_RGBA8888 = 0,
};

static const int ZOOM_LEVELS[] = {
	10,
	25,
	50,
	75,
	100,
	150,
	200,
	300,
	400,
};

static const int LAST_ZOOM_LEVEL_IDX = sizeof(ZOOM_LEVELS) / sizeof(*ZOOM_LEVELS) - 1;

REHex::BitmapTool::BitmapTool(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl):
	ToolPanel(parent),
	document(document),
	document_ctrl(document_ctrl),
	image_offset(document->get_cursor_position()),
	image_width(256),
	image_height(256),
	row_length(-1),
	fit_to_screen(true),
	actual_size(false)
{
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);
	
	wxFlexGridSizer *grid_sizer = new wxFlexGridSizer(2);
	sizer->Add(grid_sizer);
	
	auto sizer_add_pair = [&](const char *label, wxWindow *window)
	{
		grid_sizer->Add(new wxStaticText(this, wxID_ANY, label), 0, (wxALIGN_CENTER_VERTICAL | wxLEFT | wxTOP), 8);
		grid_sizer->Add(window, 0, (wxALIGN_CENTER_VERTICAL | wxLEFT | wxTOP), 4);
	};
	
	sizer_add_pair("Image offset:", (offset_textctrl = new NumericTextCtrl(this, ID_IMAGE_OFFSET)));
	sizer_add_pair("",              (offset_follow_cb = new wxCheckBox(this, ID_FOLLOW_CURSOR, "Follow cursor")));
	
	wxSize initial_size = offset_textctrl->GetSize();
	wxSize text_size = offset_textctrl->GetTextExtent("0x0000000000000000+0b");
	offset_textctrl->SetMinSize(wxSize(((float)(text_size.GetWidth()) * 1.2f), initial_size.GetHeight()));
	
	OffsetBase base = document_ctrl->get_offset_display_base();
	offset_textctrl->ChangeValue(image_offset.to_string((base == OFFSET_BASE_HEX ? NumBase::HEX : NumBase::DEC), NumFormat::PREFIX));
	offset_follow_cb->SetValue(true);
	
	sizer_add_pair("Image width:",  (width_textctrl = new wxSpinCtrl(this, ID_IMAGE_WIDTH, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxSP_ARROW_KEYS, 1, 10240, image_width)));
	
	{
		wxSize size = width_textctrl->GetSizeFromTextSize(width_textctrl->GetTextExtent("99999"));
		width_textctrl->SetMinSize(size);
		width_textctrl->SetSize(size);
	}
	
	sizer_add_pair("Image height:", (height_textctrl = new wxSpinCtrl(this, ID_IMAGE_HEIGHT, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxSP_ARROW_KEYS, 1, 10240, image_height)));
	
	{
		wxSize size = height_textctrl->GetSizeFromTextSize(height_textctrl->GetTextExtent("99999"));
		height_textctrl->SetMinSize(size);
		height_textctrl->SetSize(size);
	}
	
	sizer_add_pair("Colour depth:", (pixel_fmt_choice = new wxChoice(this, ID_COLOUR_DEPTH)));
	
	pixel_fmt_choice->Append("1 bit/pixel");
	pixel_fmt_choice->Append("2 bits/pixel");
	pixel_fmt_choice->Append("4 bits/pixel");
	pixel_fmt_choice->Append("8 bits/pixel");
	pixel_fmt_choice->Append("16 bits/pixel");
	pixel_fmt_choice->Append("24 bits/pixel");
	pixel_fmt_choice->Append("32 bits/pixel");
	
	pixel_fmt_choice->SetSelection(COLOUR_DEPTH_24BPP);
	
	sizer_add_pair("Colour format:", (colour_fmt_choice = new wxChoice(this, ID_COLOUR_FORMAT)));
	
	update_colour_format_choices();
	update_pixel_fmt();
	
	sizer_add_pair("Row length:", (row_packed_cb = new wxCheckBox(this, ID_ROWS_PACKED, "Packed") ));
	sizer_add_pair("", (row_length_spinner = new wxSpinCtrl(this, ID_ROW_LENGTH, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxSP_ARROW_KEYS, 1, 32768, 256) ));
	
	{
		wxSize size = row_length_spinner->GetSizeFromTextSize(row_length_spinner->GetTextExtent("99999"));
		row_length_spinner->SetMinSize(size);
		row_length_spinner->SetSize(size);
	}
	
	row_packed_cb->SetValue(true);
	row_length_spinner->Enable(false);
	
	reset_row_length_spinner();
	
	toolbar = new wxToolBar(this, wxID_ANY);
	sizer->Add(toolbar, 0, wxEXPAND | wxALIGN_LEFT);
	
	wxColor btn_bg_colour = wxSystemSettings::GetColour(wxSYS_COLOUR_BTNFACE);
	bool light_buttons = Palette::is_colour_light(btn_bg_colour);
	
	toolbar->AddCheckTool(ID_FLIP_X, "Flip X", (light_buttons ? wxBITMAP_PNG_FROM_DATA(swap_horiz_dark_16) : wxBITMAP_PNG_FROM_DATA(swap_horiz_light_16)), wxNullBitmap, "Flip X");
	toolbar->AddCheckTool(ID_FLIP_Y, "Flip Y", (light_buttons ? wxBITMAP_PNG_FROM_DATA(swap_vert_dark_16) : wxBITMAP_PNG_FROM_DATA(swap_vert_light_16)),  wxNullBitmap, "Flip Y");
	
	toolbar->AddStretchableSpace();
	
	toolbar->AddTool(     ID_BACKGROUND,  "Set background", wxBITMAP_PNG_FROM_DATA(bg16),                          "Set background");
	toolbar->AddTool(     ID_ZOOM_IN,     "Zoom in",        (light_buttons ? wxBITMAP_PNG_FROM_DATA(zoom_in_dark_16) : wxBITMAP_PNG_FROM_DATA(zoom_in_light_16)),                           "Zoom in");
	toolbar->AddTool(     ID_ZOOM_OUT,    "Zoom out",       (light_buttons ? wxBITMAP_PNG_FROM_DATA(zoom_out_dark_16) : wxBITMAP_PNG_FROM_DATA(zoom_out_light_16)),                         "Zoom out");
	toolbar->AddCheckTool(ID_SCALE,       "Fit to screen",  (light_buttons ? wxBITMAP_PNG_FROM_DATA(fit_to_screen_dark_16) : wxBITMAP_PNG_FROM_DATA(fit_to_screen_light_16)), wxNullBitmap, "Fit to screen");
	toolbar->AddCheckTool(ID_ACTUAL_SIZE, "Actual size",    (light_buttons ? wxBITMAP_PNG_FROM_DATA(actual_size_dark_16) : wxBITMAP_PNG_FROM_DATA(actual_size_light_16)),     wxNullBitmap, "Actual size");
	
	toolbar->ToggleTool(ID_SCALE, fit_to_screen);
	toolbar->ToggleTool(ID_ACTUAL_SIZE, actual_size);
	
	m_preview_sizer = new wxBoxSizer(wxHORIZONTAL);
	sizer->Add(m_preview_sizer, 1, wxEXPAND | wxALIGN_TOP | wxALIGN_LEFT);
	
	m_preview = new Preview(this, wxSize(16, 16));
	m_preview_sizer->Add(m_preview, 1, wxEXPAND | wxALIGN_TOP | wxALIGN_LEFT);
	
	m_preview->Bind(wxEVT_RIGHT_DOWN, &REHex::BitmapTool::OnBitmapRightDown, this);
	
	SetSizerAndFit(sizer);
	toolbar->Realize();
	
	this->document.auto_cleanup_bind(CURSOR_UPDATE, &REHex::BitmapTool::OnCursorUpdate,    this);
	
	update();
}

std::string REHex::BitmapTool::name() const
{
	return "BitmapTool";
}

std::string REHex::BitmapTool::label() const
{
	return "Bitmap visualisation";
}

REHex::ToolPanel::Shape REHex::BitmapTool::shape() const
{
	return ToolPanel::TPS_TALL;
}

void REHex::BitmapTool::save_state(wxConfig *config) const
{
	// TODO
}

void REHex::BitmapTool::load_state(wxConfig *config)
{
	// TODO
}

wxSize REHex::BitmapTool::DoGetBestClientSize() const
{
	/* TODO: Calculate a reasonable initial size. */
	return wxPanel::DoGetBestClientSize();
}

void REHex::BitmapTool::update_colour_format_choices()
{
	int pixel_fmt_idx = pixel_fmt_choice->GetCurrentSelection();
	
	colour_fmt_choice->Clear();
	
	switch(pixel_fmt_idx)
	{
		case COLOUR_DEPTH_1BPP:
		case COLOUR_DEPTH_2BPP:
		case COLOUR_DEPTH_4BPP:
			colour_fmt_choice->Append("Greyscale");
			break;
			
		case COLOUR_DEPTH_8BPP:
			colour_fmt_choice->Append("Greyscale");
			colour_fmt_choice->Append("RGB 332");
			break;
			
		case COLOUR_DEPTH_16BPP:
			colour_fmt_choice->Append("RGB 565");
			colour_fmt_choice->Append("RGB 555");
			colour_fmt_choice->Append("RGB 444");
			colour_fmt_choice->Append("ARGB 1555");
			
			colour_fmt_choice->Append("BGR 565");
			colour_fmt_choice->Append("BGR 555");
			colour_fmt_choice->Append("BGR 444");
			
			break;
			
		case COLOUR_DEPTH_24BPP:
			colour_fmt_choice->Append("RGB 888");
			break;
			
		case COLOUR_DEPTH_32BPP:
			colour_fmt_choice->Append("RGBA 8888");
			break;
	}
	
	colour_fmt_choice->SetSelection(0);
}

void REHex::BitmapTool::reset_row_length_spinner()
{
	int row_length = image_width;
	
	if(pixel_fmt_div > 1)
	{
		row_length = image_width / pixel_fmt_div;
		
		if((image_width % pixel_fmt_div) != 0)
		{
			/* Round up in case of partial bytes. */
			++row_length;
		}
	}
	else{
		row_length = image_width * pixel_fmt_multi;
	}
	
	row_length_spinner->SetValue(row_length);
}

void REHex::BitmapTool::update()
{
	try {
		image_offset = offset_textctrl->GetValue<BitOffset>(BitOffset::ZERO);
	}
	catch(const NumericTextCtrl::InputError&)
	{
		/* TODO: Placeholder */
		return;
	}
	
	image_width  = width_textctrl->GetValue();
	image_height = height_textctrl->GetValue();
	
	assert(image_width > 0);
	assert(image_height > 0);
	
	bool row_packed = row_packed_cb->GetValue();
	
	row_length_spinner->Enable(!row_packed);
	row_length = row_packed ? -1 : row_length_spinner->GetValue();
	
	fit_to_screen = toolbar->GetToolState(ID_SCALE);
	actual_size = toolbar->GetToolState(ID_ACTUAL_SIZE);
	
	if(actual_size)
	{
		bitmap_width = image_width;
		bitmap_height = image_height;
		
		zoom = 100;
	}
	else if(fit_to_screen)
	{
		/* Figure out how much space is available for the wxStaticBitmap preview.
		 *
		 * At the point we are called, our sizer hasn't been resized or updated the layout
		 * of our child windows. So we need to get the current size of the sizer containing
		 * the preview, and then adjust it by the difference between our size and that of
		 * the sizer to find what its size will be after resizing completes.
		*/
		
		wxSize this_size  = GetSize();
		wxSize sizer_size = GetSizer()->GetSize();
		
		int max_w = m_preview_sizer->GetSize().GetWidth()  - (sizer_size.GetWidth()  - this_size.GetWidth());
		int max_h = m_preview_sizer->GetSize().GetHeight() - (sizer_size.GetHeight() - this_size.GetHeight());
		
		/* Scale the image to fit the available width/height, while preserving aspect ratio. */
		
		double aspect_ratio = (double)(image_width) / (double)(image_height);
		
		if((max_h * aspect_ratio) > max_w)
		{
			bitmap_width = max_w;
			bitmap_height = (double)(max_w) / aspect_ratio;
			
			zoom = ((double)(bitmap_width) / (double)(image_width)) * 100.0;
		}
		else{
			bitmap_width = (double)(max_h) * aspect_ratio;
			bitmap_height = max_h;
			
			zoom = ((double)(bitmap_height) / (double)(image_height)) * 100.0;
		}
		
		/* Clamp to >=1px in case of a ridiculously tall or wide image. */
		bitmap_width = std::max(bitmap_width, 1);
		bitmap_height = std::max(bitmap_height, 1);
	}
	else{
		double aspect_ratio = (double)(image_width) / (double)(image_height);
		
		bitmap_width = (double)(image_width) * ((double)(zoom) / 100.0);
		bitmap_height = (double)(bitmap_width) / aspect_ratio;
		
		/* Clamp to >=1px in case of a ridiculously tall or wide image. */
		bitmap_width = std::max(bitmap_width, 1);
		bitmap_height = std::max(bitmap_height, 1);
	}
	
	toolbar->EnableTool(ID_ZOOM_IN,  ZOOM_LEVELS[LAST_ZOOM_LEVEL_IDX] > zoom);
	toolbar->EnableTool(ID_ZOOM_OUT, ZOOM_LEVELS[0] < zoom);
	
	m_preview->set_bitmap_size(wxSize(bitmap_width, bitmap_height));
	GetSizer()->Layout();
}

/* The following functions take a uint32_t value and extract an X bit wide value whose least
 * significant bit is 'shift' bits away from the least significant bit of the uint32_t and then
 * scales it up to a uint8_t, which is returned.
*/

static inline uint8_t extract_1to8(uint32_t in, int shift)
{
	uint8_t out = shift > 7
		? ((in & (0x01 << shift)) >> (shift - 7))
		: ((in & (0x01 << shift)) << (7 - shift));
	
	out |= (out >> 1);
	out |= (out >> 2);
	out |= (out >> 4);
	
	return out;
}

static inline uint8_t extract_2to8(uint32_t in, int shift)
{
	uint8_t out = shift > 6
		? ((in & (0x03 << shift)) >> (shift - 6))
		: ((in & (0x03 << shift)) << (6 - shift));
	
	out |= (out >> 2);
	out |= (out >> 4);
	
	return out;
}

static inline uint8_t extract_3to8(uint32_t in, int shift)
{
	uint8_t out = shift > 5
		? ((in & (0x07 << shift)) >> (shift - 5))
		: ((in & (0x07 << shift)) << (5 - shift));
	
	out |= (out >> 3);
	out |= (out >> 6);
	
	return out;
}

static inline uint8_t extract_4to8(uint32_t in, int shift)
{
	uint8_t out = shift > 4
		? ((in & (0x0F << shift)) >> (shift - 4))
		: ((in & (0x0F << shift)) << (4 - shift));
	
	out |= (out >> 4);
	
	return out;
}

static inline uint8_t extract_5to8(uint32_t in, int shift)
{
	uint8_t out = shift > 3
		? ((in & (0x1F << shift)) >> (shift - 3))
		: ((in & (0x1F << shift)) << (3 - shift));
	
	out |= (out >> 5);
	
	return out;
}

static inline uint8_t extract_6to8(uint32_t in, int shift)
{
	uint8_t out = shift > 2
		? ((in & (0x3F << shift)) >> (shift - 2))
		: ((in & (0x3F << shift)) << (2 - shift));
	
	out |= (out >> 6);
	
	return out;
}

static inline uint8_t extract_8(uint32_t in, int shift)
{
	uint8_t out = (in & (0xFF << shift)) >> shift;
	return out;
}

void REHex::BitmapTool::update_pixel_fmt()
{
	int pixel_fmt_idx = pixel_fmt_choice->GetCurrentSelection();
	int colour_fmt_idx = colour_fmt_choice->GetCurrentSelection();
	
	pixel_fmt_div   = 1;
	pixel_fmt_multi = 1;
	pixel_fmt_bits  = 255;
	
	colour_fmt_conv = [](uint32_t in)
	{
		in %= 256;
		return wxColour(in, in, in);
	};
	
	switch(pixel_fmt_idx)
	{
		case COLOUR_DEPTH_1BPP:
			pixel_fmt_div  = 8;
			pixel_fmt_bits = 128;
			
			colour_fmt_conv = [](uint32_t in)
			{
				in *= 255;
				return wxColour(in, in, in);
			};
			
			break;
			
		case COLOUR_DEPTH_2BPP:
			pixel_fmt_div  = 4;
			pixel_fmt_bits = 192;
			
			colour_fmt_conv = [](uint32_t in)
			{
				in = in | in << 2;
				in = in | in << 4;
				return wxColour(in, in, in);
			};
			
			break;
			
		case COLOUR_DEPTH_4BPP:
			pixel_fmt_div  = 2;
			pixel_fmt_bits = 240;
			
			colour_fmt_conv = [](uint32_t in)
			{
				in = in | in << 4;
				return wxColour(in, in, in);
			};
			
			break;
			
		case COLOUR_DEPTH_8BPP:
		{
			switch(colour_fmt_idx)
			{
				case COLOUR_DEPTH_8BPP_GREYSCALE:
					break;
					
				case COLOUR_DEPTH_8BPP_RGB332:
					colour_fmt_conv = [](uint32_t in)
					{
						return wxColour(
							extract_3to8(in, 5),
							extract_3to8(in, 2),
							extract_2to8(in, 0));
					};
					
					break;
			}
			
			break;
		}
		
		case COLOUR_DEPTH_16BPP:
		{
			pixel_fmt_multi = 2;
			
			switch(colour_fmt_idx)
			{
				case COLOUR_DEPTH_16BPP_RGB565:
					colour_fmt_conv = [](uint32_t in)
					{
						return wxColour(
							extract_5to8(in, 11),
							extract_6to8(in, 5),
							extract_5to8(in, 0));
					};
					
					break;
					
				case COLOUR_DEPTH_16BPP_RGB555:
					colour_fmt_conv = [](uint32_t in)
					{
						return wxColour(
							extract_5to8(in, 10),
							extract_5to8(in, 5),
							extract_5to8(in, 0));
					};
					
					break;
					
				case COLOUR_DEPTH_16BPP_RGB444:
					colour_fmt_conv = [](uint32_t in)
					{
						return wxColour(
							extract_4to8(in, 8),
							extract_4to8(in, 4),
							extract_4to8(in, 0));
					};
					
					break;
					
				case COLOUR_DEPTH_16BPP_ARGB1555:
					colour_fmt_conv = [](uint32_t in)
					{
						return wxColour(
							extract_5to8(in, 10),
							extract_5to8(in, 5),
							extract_5to8(in, 0),
							extract_1to8(in, 15));
					};
					
					break;
					
				case COLOUR_DEPTH_16BPP_BGR565:
					colour_fmt_conv = [](uint32_t in)
					{
						return wxColour(
							extract_5to8(in, 0),
							extract_6to8(in, 5),
							extract_5to8(in, 11));
					};
					
					break;
					
				case COLOUR_DEPTH_16BPP_BGR555:
					colour_fmt_conv = [](uint32_t in)
					{
						return wxColour(
							extract_5to8(in, 0),
							extract_5to8(in, 5),
							extract_5to8(in, 10));
					};
					
					break;
					
				case COLOUR_DEPTH_16BPP_BGR444:
					colour_fmt_conv = [](uint32_t in)
					{
						return wxColour(
							extract_4to8(in, 0),
							extract_4to8(in, 4),
							extract_4to8(in, 8));
					};
					
					break;
			}
			
			break;
		}
		
		case COLOUR_DEPTH_24BPP:
		{
			pixel_fmt_multi = 3;
			
			switch(colour_fmt_idx)
			{
				case COLOUR_DEPTH_24BPP_RGB888:
					colour_fmt_conv = [](uint32_t in)
					{
						return wxColour(
							extract_8(in, 16),
							extract_8(in, 8),
							extract_8(in, 0));
					};
					
					break;
			}
			
			break;
		}
		
		case COLOUR_DEPTH_32BPP:
			pixel_fmt_multi = 4;
			
			switch(colour_fmt_idx)
			{
				case COLOUR_DEPTH_32BPP_RGBA8888:
					colour_fmt_conv = [](uint32_t in)
					{
						return wxColour(
							extract_8(in, 24),
							extract_8(in, 16),
							extract_8(in, 8),
							extract_8(in, 0));
					};
					
					break;
			}
			
			break;
	}
}

template<typename PDT> void REHex::BitmapTool::render_rect(wxBitmap *bitmap, const wxRect &image_rect, bool blend_bg)
{
	int output_width = bitmap->GetWidth();
	int output_height = bitmap->GetHeight();

	int width = image_width;
	int height = image_height;
	
	bool flip_x = toolbar->GetToolState(ID_FLIP_X);
	bool flip_y = toolbar->GetToolState(ID_FLIP_Y);
	
	/* Read in the image data, convert the source pixel format and write it to the wxBitmap. */
	
	PDT bmp_data(*bitmap);
	assert(bmp_data);
	
	std::vector<unsigned char> data;
	BitOffset data_begin = BitOffset::ZERO, data_end = BitOffset::ZERO;
	
	typename PDT::Iterator output_ptr(bmp_data);
	
	for(int output_y = 0; output_y < output_height; ++output_y)
	{
		int input_y = output_y;
		
		if(image_rect.GetHeight() != bitmap->GetHeight())
		{
			input_y = (double)(input_y) * ((double)(image_rect.GetHeight()) / (double)(bitmap->GetHeight()));
			
			input_y = std::max(input_y, 0);
			input_y = std::min(input_y, height - 1);
		}

		input_y += image_rect.y;
		
		if(flip_y)
		{
			input_y = ((height - 1) - input_y);
		}
		
		off_t line_len = row_length > 0
			? row_length
			: (width * pixel_fmt_multi) / pixel_fmt_div;
		
		BitOffset line_off = row_length > 0
			? image_offset + BitOffset((input_y * line_len), 0)
			: image_offset + BitOffset(((width * input_y * pixel_fmt_multi) / pixel_fmt_div), 0);
		
		if(line_off < data_begin || (line_off + BitOffset(line_len, 0)) > data_end)
		{
			BitOffset data_read_base = line_off;
			off_t data_read_max = line_len * 200;
			
// 			if(flip_y)
// 			{
// 				/* Read current input line and PRECEEDING ones if the Y axis is
// 				 * flipped since we'll be stepping backwards.
// 				*/
// 				
// 				data_read_base -= line_len * 31;
// 				data_read_base = std::max(data_read_base, offset);
// 			}
			
			data = document->read_data(data_read_base, data_read_max);
			
			data_begin = line_off;
			data_end = data_begin + BitOffset(data.size(), 0);
		}
		
		assert((line_off - data_begin).byte_aligned());
		off_t data_line_offset = (line_off - data_begin).byte();
		
		typename PDT::Iterator output_col_ptr = output_ptr;
		
		for(int output_x = 0; output_x < output_width; ++output_x, ++output_col_ptr)
		{
			int input_x = output_x;
			
			if(image_rect.GetWidth() != bitmap->GetWidth())
			{
				input_x = (double)(input_x) * ((double)(image_rect.GetWidth()) / (double)(bitmap->GetWidth()));
				
				input_x = std::max(input_x, 0);
				input_x = std::min(input_x, width - 1);
			}
			
			input_x += image_rect.x;
			
			if(flip_x)
			{
				input_x = ((width - 1) - input_x);
			}
			
			if((off_t)(data.size()) <= data_line_offset)
			{
				continue;
			}
			
			const unsigned char *input_ptr = data.data() + data_line_offset;
			int mask = pixel_fmt_bits, shift = 8 - (8 / pixel_fmt_div);
			
			if(pixel_fmt_div > 1)
			{
				/* Advance to the correct starting bit for <8bpp colour depths. */
				
				assert(pixel_fmt_multi == 1);
				
				bool row_packed = row_packed_cb->GetValue();
				
				int line_pixel_offset = row_packed
					? ((width * input_y) % pixel_fmt_div) + input_x
					: input_x;
				
				input_ptr += line_pixel_offset / pixel_fmt_div;
				
				int sub_byte_offset = line_pixel_offset % pixel_fmt_div;
				for(int i = 0; i < sub_byte_offset; ++i)
				{
					mask >>= (8 / pixel_fmt_div);
					shift -= 8 / pixel_fmt_div;
					
					assert(shift >= 0);
					
					assert(mask < 255);
					assert(mask > 0);
				}
			}
			else{
				input_ptr += input_x * pixel_fmt_multi;
			}
			
			if((input_ptr + pixel_fmt_multi) > (data.data() + data.size()))
			{
				/* Ran out of image data in input file. Carry on looping to fill
				 * the remaining bitmap with the chequerboard pattern.
				*/
				
				continue;
			}
			
			uint32_t rgb = 0;
			
			for(int i = 0; i < pixel_fmt_multi; ++i)
			{
				assert(mask <= 255);
				
				assert(input_ptr >= data.data());
				
				rgb |= ((*input_ptr & mask) >> shift) << (8 * (pixel_fmt_multi - i - 1));
				
				if(pixel_fmt_div > 1)
				{
					mask >>= (8 / pixel_fmt_div);
					shift -= 8 / pixel_fmt_div;
					
					if(shift < 0)
					{
						mask  = pixel_fmt_bits;
						shift = 8 - (8 / pixel_fmt_div);
						
						++input_ptr;
					}
				}
				else{
					++input_ptr;
				}
			}
			
			wxColour colour = colour_fmt_conv(rgb);
			
			if(blend_bg)
			{
				if(colour.Alpha() != wxALPHA_OPAQUE)
				{
					/* Blend colours with an alpha channel into the chequerboard. */
					
					double alpha = (double)(colour.Alpha()) / 255.0;
					
					int red   = ((double)(colour.Red())   * alpha) + ((double)(output_col_ptr.Red())   * (1.0 - alpha));
					int green = ((double)(colour.Green()) * alpha) + ((double)(output_col_ptr.Green()) * (1.0 - alpha));
					int blue  = ((double)(colour.Blue())  * alpha) + ((double)(output_col_ptr.Blue())  * (1.0 - alpha));
					
					colour.Set(red, green, blue);
					
				}
				
				output_col_ptr.Red()   = colour.Red();
				output_col_ptr.Green() = colour.Green();
				output_col_ptr.Blue()  = colour.Blue();
			}
			else{
				output_col_ptr.Red()   = colour.Red();
				output_col_ptr.Green() = colour.Green();
				output_col_ptr.Blue()  = colour.Blue();
				
				if(bitmap->HasAlpha())
				{
					output_col_ptr.Alpha() = colour.Alpha();
				}
			}
		}
		
		output_ptr.OffsetY(bmp_data, 1);
	}
}

void REHex::BitmapTool::OnCursorUpdate(CursorUpdateEvent &event)
{
	if(offset_follow_cb->GetValue())
	{
		OffsetBase base = document_ctrl->get_offset_display_base();
		offset_textctrl->ChangeValue(event.cursor_pos.to_string((base == OFFSET_BASE_HEX ? NumBase::HEX : NumBase::DEC), NumFormat::PREFIX));
		update();
	}
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::BitmapTool::OnDepth(wxCommandEvent &event)
{
	update_colour_format_choices();
	update_pixel_fmt();
	reset_row_length_spinner();
	update();
}

void REHex::BitmapTool::OnFormat(wxCommandEvent &event)
{
	update_pixel_fmt();
	update();
}

void REHex::BitmapTool::OnFollowCursor(wxCommandEvent &event)
{
	if(offset_follow_cb->GetValue())
	{
		OffsetBase base = document_ctrl->get_offset_display_base();
		offset_textctrl->ChangeValue(document->get_cursor_position().to_string((base == OFFSET_BASE_HEX ? NumBase::HEX : NumBase::DEC), NumFormat::PREFIX));
		update();
	}
	else{
		/* Don't need to update anything if option was toggled off. */
	}
}

void REHex::BitmapTool::OnImageWidth(wxSpinEvent &event)
{
	image_width = width_textctrl->GetValue();
	
	reset_row_length_spinner();
	update();
}

void REHex::BitmapTool::OnImageHeight(wxSpinEvent &event)
{
	image_height = height_textctrl->GetValue();
	
	update();
}

void REHex::BitmapTool::OnRowsPacked(wxCommandEvent &event)
{
	update();
}

void REHex::BitmapTool::OnRowLength(wxSpinEvent &event)
{
	update();
}

void REHex::BitmapTool::OnFit(wxCommandEvent &event)
{
	if(toolbar->GetToolState(ID_SCALE))
	{
		toolbar->ToggleTool(ID_ACTUAL_SIZE, false);
		update();
	}
	else{
		toolbar->ToggleTool(ID_SCALE, true); /* Negate the action. */
	}
}

void REHex::BitmapTool::OnActualSize(wxCommandEvent &event)
{
	if(toolbar->GetToolState(ID_ACTUAL_SIZE))
	{
		toolbar->ToggleTool(ID_SCALE, false);
		update();
	}
	else{
		toolbar->ToggleTool(ID_ACTUAL_SIZE, true); /* Negate the action. */
	}
}

void REHex::BitmapTool::OnZoomIn(wxCommandEvent &event)
{
	fit_to_screen = false;
	toolbar->ToggleTool(ID_SCALE, false);
	
	actual_size = false;
	toolbar->ToggleTool(ID_ACTUAL_SIZE, false);
	
	for(int i = 0; i <= LAST_ZOOM_LEVEL_IDX; ++i)
	{
		if(ZOOM_LEVELS[i] > zoom)
		{
			zoom = ZOOM_LEVELS[i];
			update();
			break;
		}
	}
}

void REHex::BitmapTool::OnZoomOut(wxCommandEvent &event)
{
	fit_to_screen = false;
	toolbar->ToggleTool(ID_SCALE, false);
	
	actual_size = false;
	toolbar->ToggleTool(ID_ACTUAL_SIZE, false);
	
	for(int i = LAST_ZOOM_LEVEL_IDX; i >= 0; --i)
	{
		if(ZOOM_LEVELS[i] < zoom)
		{
			zoom = ZOOM_LEVELS[i];
			update();
			break;
		}
	}
}

void REHex::BitmapTool::OnBackground(wxCommandEvent &event)
{
	wxMenu menu;
	
	wxMenuItem *none = menu.Append(wxID_ANY, "None");
	menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
	{
		m_preview->set_bg(wxNullColour);
	}, none->GetId(), none->GetId());
	
	wxMenuItem *colour = menu.Append(wxID_ANY, "Choose colour...");
	menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
	{
		wxColourData cd;
		
		#if wxCHECK_VERSION(3,1,0)
		cd.SetChooseAlpha(false);
		#endif

		wxColourDialog dlg(this, &cd);

		if(dlg.ShowModal() == wxID_OK)
		{
			m_preview->set_bg(dlg.GetColourData().GetColour());
		}
	}, colour->GetId(), colour->GetId());
	
	PopupMenu(&menu);
}

void REHex::BitmapTool::OnXXX(wxCommandEvent &event)
{
	if(event.GetEventObject() == offset_textctrl)
	{
		/* Turn off the "Follow cursor offset" option if the offset is modified by the
		 * user.
		*/
		
		offset_follow_cb->SetValue(false);
	}
	
	update();
}

void REHex::BitmapTool::OnSize(wxSizeEvent &event)
{
	update();
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::BitmapTool::OnBitmapRightDown(wxMouseEvent &event)
{
	wxMenu menu;
	
	wxMenuItem *copy = menu.Append(wxID_ANY, "&Copy image");
	menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
	{
		ClipboardGuard cg;
		if(cg)
		{
			wxBitmap fullsize_bitmap(image_width, image_height, 32);
			render_rect<wxAlphaPixelData>(&fullsize_bitmap, wxRect(0, 0, image_width, image_height), false);
			
			wxTheClipboard->SetData(new wxBitmapDataObject(fullsize_bitmap));
		}
	}, copy->GetId(), copy->GetId());
	
	wxMenuItem *save = menu.Append(wxID_ANY, "&Save image");
	menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
	{
		CallAfter([&]()
		{
			wxFileDialog save_dialog(this, "Save As", wxEmptyString, wxEmptyString, "BMP files (*.bmp)|*.bmp|PNG files (*.png)|*.png", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
			save_dialog.SetFilterIndex(1);
			
			if(save_dialog.ShowModal() == wxID_CANCEL)
				return;
			
			wxFileName save_fn(save_dialog.GetPath());
			wxBitmapType type;
			
			if(save_fn.HasExt())
			{
				wxString ext = save_fn.GetExt().Lower();
				if(ext == "bmp")
				{
					type = wxBITMAP_TYPE_BMP;
				}
				else if(ext == "png")
				{
					type = wxBITMAP_TYPE_PNG;
				}
				else{
					wxMessageBox((std::string("Unsupported file extension: ") + ext), "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
					return;
				}
			}
			else if(save_dialog.GetFilterIndex() == 0)
			{
				save_fn.SetExt("bmp");
				type = wxBITMAP_TYPE_BMP;
			}
			else if(save_dialog.GetFilterIndex() == 1)
			{
				save_fn.SetExt("png");
				type = wxBITMAP_TYPE_PNG;
			}
			else{
				/* Unreachable. */
				abort();
			}
			
			wxBitmap fullsize_bitmap(image_width, image_height, 32);
			render_rect<wxAlphaPixelData>(&fullsize_bitmap, wxRect(0, 0, image_width, image_height), false);
			
			bool save_ok = fullsize_bitmap.SaveFile(save_fn.GetFullPath(), type);
			if(!save_ok)
			{
				wxMessageBox("Unable to save image", "Error", (wxOK | wxICON_ERROR | wxCENTRE), this);
			}
		});
	}, save->GetId(), save->GetId());
	
	PopupMenu(&menu);
}

void REHex::BitmapTool::set_image_offset(BitOffset offset)
{
	offset_textctrl->SetValue(format_offset(offset, OFFSET_BASE_DEC, BitOffset::ZERO));
	offset_follow_cb->SetValue(false);
}

void REHex::BitmapTool::set_image_size(int width, int height)
{
	width_textctrl->SetValue(width);
	height_textctrl->SetValue(height);
}

wxSize REHex::BitmapTool::get_image_size() const
{
	return wxSize(image_width, image_height);
}

void REHex::BitmapTool::set_pixel_format(PixelFormat format)
{
	switch(format)
	{
		case PIXEL_FMT_1BPP:
		case PIXEL_FMT_2BPP:
		case PIXEL_FMT_4BPP:
			pixel_fmt_choice->SetSelection(COLOUR_DEPTH_1BPP + (format - PIXEL_FMT_1BPP));
			update_colour_format_choices();
			colour_fmt_choice->SetSelection(0);
			
			break;
		
		case PIXEL_FMT_8BPP_GREYSCALE:
		case PIXEL_FMT_8BPP_RGB332:
			pixel_fmt_choice->SetSelection(COLOUR_DEPTH_8BPP);
			update_colour_format_choices();
			colour_fmt_choice->SetSelection(COLOUR_DEPTH_8BPP_GREYSCALE + (format - PIXEL_FMT_8BPP_GREYSCALE));
			
			break;
		
		case PIXEL_FMT_16BPP_RGB565:
		case PIXEL_FMT_16BPP_RGB555:
		case PIXEL_FMT_16BPP_RGB444:
		case PIXEL_FMT_16BPP_ARGB1555:
		case PIXEL_FMT_16BPP_BGR565:
		case PIXEL_FMT_16BPP_BGR555:
		case PIXEL_FMT_16BPP_BGR444:
			pixel_fmt_choice->SetSelection(COLOUR_DEPTH_16BPP);
			update_colour_format_choices();
			colour_fmt_choice->SetSelection(COLOUR_DEPTH_16BPP_RGB565 + (format - PIXEL_FMT_16BPP_RGB565));
			
			break;
		
		case PIXEL_FMT_24BPP_RGB888:
			pixel_fmt_choice->SetSelection(COLOUR_DEPTH_24BPP);
			update_colour_format_choices();
			colour_fmt_choice->SetSelection(COLOUR_DEPTH_24BPP_RGB888);
			
			break;
		
		case PIXEL_FMT_32BPP_RGBA8888:
			pixel_fmt_choice->SetSelection(COLOUR_DEPTH_32BPP);
			update_colour_format_choices();
			colour_fmt_choice->SetSelection(COLOUR_DEPTH_32BPP_RGBA8888);
			
			break;
	}
	
	update_pixel_fmt();
	update();
}

void REHex::BitmapTool::set_flip_x(bool flip_x)
{
	toolbar->ToggleTool(ID_FLIP_X, flip_x);
}

void REHex::BitmapTool::set_flip_y(bool flip_y)
{
	toolbar->ToggleTool(ID_FLIP_Y, flip_y);
}

void REHex::BitmapTool::set_row_length(int row_length)
{
	row_packed_cb->SetValue(false);
	row_length_spinner->SetValue(row_length);
	this->row_length = row_length;
}

REHex::BitmapTool::Preview::Preview(BitmapTool *parent, const wxSize &size):
	ProceduralBitmap(parent, wxID_ANY, size),
	m_parent(parent),
	m_bg(wxNullColour) {}

void REHex::BitmapTool::Preview::set_bg(const wxColour &bg)
{
	m_bg = bg;
	Refresh();
}

wxBitmap REHex::BitmapTool::Preview::render_rect(const wxRect &rect)
{
	wxSize image_size = m_parent->get_image_size();
	wxSize bitmap_size = get_bitmap_size();
	
	double ws = (double)(image_size.GetWidth()) / (double)(bitmap_size.GetWidth());
	double hs = (double)(image_size.GetHeight()) / (double)(bitmap_size.GetHeight());
	
	int ix = (double)(rect.x) * ws;
	ix = std::max(0, ix);
	ix = std::min(ix, (image_size.GetWidth() - 1));
	
	int iw = (double)(rect.width) * ws;
	iw = std::max(1, iw);
	iw = std::min(iw, (image_size.GetWidth() - ix));
	
	int iy = (double)(rect.y) * hs;
	iy = std::max(0, iy);
	iy = std::min(iy, (image_size.GetHeight() - 1));
	
	int ih = (double)(rect.height) * hs;
	ih = std::max(1, ih);
	ih = std::min(ih, (image_size.GetHeight() - iy));
	
	wxRect image_rect(ix, iy, iw, ih);
	
	wxBitmap bitmap(rect.GetSize(), wxBITMAP_SCREEN_DEPTH);
	
	fill_bg(&bitmap, rect.x, rect.y);
	m_parent->render_rect<wxNativePixelData>(&bitmap, image_rect, true);
	
	return bitmap;
}

void REHex::BitmapTool::Preview::fill_bg(wxBitmap *bitmap, int base_x, int base_y)
{
	wxNativePixelData bmp_data(*bitmap);
	assert(bmp_data);
	
	wxNativePixelData::Iterator output_ptr(bmp_data);
	
	for(int y = 0; y < bitmap->GetHeight(); ++y)
	{
		wxNativePixelData::Iterator output_col_ptr = output_ptr;
		
		for(int x = 0; x < bitmap->GetWidth(); ++x, ++output_col_ptr)
		{
			if(m_bg.IsOk())
			{
				output_col_ptr.Red() = m_bg.Red();
				output_col_ptr.Green() = m_bg.Green();
				output_col_ptr.Blue() = m_bg.Blue();
			}
			else{
				/* Initialise output to chequerboard pattern. */
				
				bool x_even = ((base_x + x) % 20) >= 10;
				bool y_even = ((base_y + y) % 20) >= 10;
				
				int chequerboard_colour = (x_even ^ y_even) ? 0x66 : 0x99;
				
				output_col_ptr.Red()   = chequerboard_colour;
				output_col_ptr.Green() = chequerboard_colour;
				output_col_ptr.Blue()  = chequerboard_colour;
			}
		}

		output_ptr.OffsetY(bmp_data, 1);
	}
}
