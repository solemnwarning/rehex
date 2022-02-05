/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2022 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <functional>
#include <wx/checkbox.h>
#include <wx/choice.h>
#include <wx/rawbmp.h>
#include <wx/scrolwin.h>
#include <wx/sizer.h>
#include <wx/statbmp.h>
#include <wx/stattext.h>

#include "BitmapTool.hpp"
#include "NumericTextCtrl.hpp"

static REHex::ToolPanel *BitmapTool_factory(wxWindow *parent, REHex::SharedDocumentPointer &document, REHex::DocumentCtrl *document_ctrl)
{
	return new REHex::BitmapTool(parent, document);
}

static REHex::ToolPanelRegistration tpr("BitmapTool", "Bitmap visualisation", REHex::ToolPanel::TPS_TALL, &BitmapTool_factory);

enum {
	ID_COLOUR_DEPTH = 1,
	ID_COLOUR_FORMAT,
	ID_IMAGE_OFFSET,
	ID_FOLLOW_CURSOR,
	ID_IMAGE_WIDTH,
	ID_IMAGE_HEIGHT,
	ID_FLIP_X,
	ID_FLIP_Y,
	ID_SCALE,
};

BEGIN_EVENT_TABLE(REHex::BitmapTool, wxPanel)
	EVT_CHOICE(ID_COLOUR_DEPTH,  REHex::BitmapTool::OnDepth)
	EVT_CHOICE(ID_COLOUR_FORMAT, REHex::BitmapTool::OnFormat)
	
	EVT_TEXT(ID_IMAGE_OFFSET,      REHex::BitmapTool::OnXXX)
	EVT_CHECKBOX(ID_FOLLOW_CURSOR, REHex::BitmapTool::OnFollowCursor)
	
	EVT_TEXT(ID_IMAGE_WIDTH,  REHex::BitmapTool::OnXXX)
	EVT_TEXT(ID_IMAGE_HEIGHT, REHex::BitmapTool::OnXXX)
	EVT_CHECKBOX(ID_FLIP_X,   REHex::BitmapTool::OnXXX)
	EVT_CHECKBOX(ID_FLIP_Y,   REHex::BitmapTool::OnXXX)
	EVT_CHECKBOX(ID_SCALE,    REHex::BitmapTool::OnXXX)
	
	EVT_SIZE(REHex::BitmapTool::OnSize)
	EVT_IDLE(REHex::BitmapTool::OnIdle)
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

static int LINES_PER_IDLE = 200;

REHex::BitmapTool::BitmapTool(wxWindow *parent, SharedDocumentPointer &document):
	ToolPanel(parent),
	document(document),
	bitmap_update_line(-1)
{
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);
	
	wxGridSizer *grid_sizer = new wxGridSizer(2);
	sizer->Add(grid_sizer);
	
	auto sizer_add_pair = [&](const char *label, wxWindow *window)
	{
		grid_sizer->Add(new wxStaticText(this, wxID_ANY, label), 0, wxALIGN_CENTER_VERTICAL);
		grid_sizer->Add(window, 0, wxALIGN_CENTER_VERTICAL);
	};
	
	sizer_add_pair("Image offset:", (offset_textctrl = new NumericTextCtrl(this, ID_IMAGE_OFFSET)));
	sizer_add_pair("",              (offset_follow_cb = new wxCheckBox(this, ID_FOLLOW_CURSOR, "Follow cursor")));
	
	offset_textctrl->ChangeValue(std::to_string(document->get_cursor_position()));
	offset_follow_cb->SetValue(true);
	
	sizer_add_pair("Image width:",  (width_textctrl  = new NumericTextCtrl(this, ID_IMAGE_WIDTH)));
	sizer_add_pair("Image height:", (height_textctrl = new NumericTextCtrl(this, ID_IMAGE_HEIGHT)));
	
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
	
	grid_sizer->Add((flip_x_cb = new wxCheckBox(this, ID_FLIP_X, "Flip X")));
	grid_sizer->Add((flip_y_cb = new wxCheckBox(this, ID_FLIP_Y, "Flip Y")));
	
	grid_sizer->Add((scale_cb = new wxCheckBox(this, ID_SCALE, "Scale")));
	scale_cb->SetValue(true); /* Enable scaling by default */
	
	bitmap_scrollwin = new wxScrolledWindow(this, wxID_ANY);
	sizer->Add(bitmap_scrollwin, 1, wxEXPAND | wxALIGN_TOP | wxALIGN_LEFT);
	
	bitmap_scrollwin->SetScrollRate(10, 10);
	
	bitmap = new wxBitmap(16, 16);
	
	wxNativePixelData bmp_data(*bitmap);
	assert(bmp_data);
	
	wxNativePixelData::Iterator output_ptr(bmp_data);
	
	for(int output_y = 0; output_y < 16; ++output_y)
	{
		wxNativePixelData::Iterator output_col_ptr = output_ptr;
		
		for(int output_x = 0; output_x < 16; ++output_x, ++output_col_ptr)
		{
			output_col_ptr.Red() = 0;
			output_col_ptr.Green() = 0;
			output_col_ptr.Blue() = 0;
		}
		
		output_ptr.OffsetY(bmp_data, 1);
	}
	
	s_bitmap = new wxGenericStaticBitmap(bitmap_scrollwin, wxID_ANY, *bitmap);
	
	SetSizerAndFit(sizer);
	
	this->document.auto_cleanup_bind(CURSOR_UPDATE, &REHex::BitmapTool::OnCursorUpdate,    this);
	
	update();
}

REHex::BitmapTool::~BitmapTool() {}

std::string REHex::BitmapTool::name() const
{
	return "BitmapTool";
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

void REHex::BitmapTool::update()
{
	bitmap_update_line = -1;
	
	try {
		image_offset = offset_textctrl->GetValue<off_t>(0);
		
		image_width  = width_textctrl ->GetValue<int>(1);
		image_height = height_textctrl->GetValue<int>(1);
	}
	catch(const NumericTextCtrl::InputError &e)
	{
		/* TODO: Placeholder */
		return;
	}
	
	assert(image_width > 0);
	assert(image_height > 0);
	
	bitmap_width = image_width;
	bitmap_height = image_height;
	
	if(scale_cb->GetValue())
	{
		/* Figure out how much space is available for the wxStaticBitmap preview.
		 *
		 * At the point we are called, our sizer hasn't been resized or updated the layout
		 * of our child windows. So we need to get the current size of the wxScrolledWindow
		 * that contains the wxStaticBitmap, and then adjust it by the difference between
		 * our size and that of the sizer to find what its size will be after resizing
		 * completes.
		*/
		
		wxSize this_size  = GetSize();
		wxSize sizer_size = GetSizer()->GetSize();
		
		int max_w = bitmap_scrollwin->GetSize().GetWidth()  - (sizer_size.GetWidth()  - this_size.GetWidth());
		int max_h = bitmap_scrollwin->GetSize().GetHeight() - (sizer_size.GetHeight() - this_size.GetHeight());
		
		/* Scale the image to fit the available width/height, while preserving aspect ratio. */
		
		double aspect_ratio = (double)(image_width) / (double)(image_height);
		
		if((max_h * aspect_ratio) > max_w)
		{
			bitmap_width = max_w;
			bitmap_height = (double)(max_w) / aspect_ratio;
		}
		else{
			bitmap_width = (double)(max_h) * aspect_ratio;
			bitmap_height = max_h;
		}
		
		/* Clamp to >=1px in case of a ridiculously tall or wide image. */
		bitmap_width = std::max(bitmap_width, 1);
		bitmap_height = std::max(bitmap_height, 1);
	}
	
	wxBitmap *new_bitmap = new wxBitmap(bitmap_width, bitmap_height);
	s_bitmap->SetBitmap(*new_bitmap);
	
	delete bitmap;
	bitmap = new_bitmap;
	
	render_region(0, LINES_PER_IDLE, image_offset, image_width, image_height);
	
	if(LINES_PER_IDLE < bitmap_height)
	{
		bitmap_update_line = LINES_PER_IDLE;
	}
	
	bitmap_scrollwin->SetVirtualSize(s_bitmap->GetSize());
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

void REHex::BitmapTool::render_region(int region_y, int region_h, off_t offset, int width, int height)
{
	int output_width = bitmap->GetWidth();
	int output_height = bitmap->GetHeight();
	
	int pixel_fmt_idx = pixel_fmt_choice->GetCurrentSelection();
	int colour_fmt_idx = colour_fmt_choice->GetCurrentSelection();
	
	int pixel_fmt_div   = 1;    /* Number of (possibly partial) pixels per byte */
	int pixel_fmt_multi = 1;    /* Number of bytes to consume per pixel */
	int pixel_fmt_bits  = 255;  /* Mask of bits to consume for first pixel in byte */
	
	std::function<wxColour(uint32_t)> colour_fmt_conv = [](uint32_t in)
	{
		in %= 256;
		return wxColour(in, in, in);
	};
	
	switch(pixel_fmt_idx)
	{
		case COLOUR_DEPTH_1BPP:
			pixel_fmt_div  = 8;
			pixel_fmt_bits = 1;
			
			colour_fmt_conv = [](uint32_t in)
			{
				in *= 255;
				return wxColour(in, in, in);
			};
			
			break;
			
		case COLOUR_DEPTH_2BPP:
			pixel_fmt_div  = 4;
			pixel_fmt_bits = 3;
			
			colour_fmt_conv = [](uint32_t in)
			{
				in = in | in << 2;
				in = in | in << 4;
				return wxColour(in, in, in);
			};
			
			break;
			
		case COLOUR_DEPTH_4BPP:
			pixel_fmt_div  = 2;
			pixel_fmt_bits = 15;
			
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
	
	bool flip_x = flip_x_cb->GetValue();
	bool flip_y = flip_y_cb->GetValue();
	
	/* Read in the image data, convert the source pixel format and write it to the wxBitmap. */
	
	wxNativePixelData bmp_data(*bitmap);
	assert(bmp_data);
	
	std::vector<unsigned char> data;
	off_t data_begin = 0, data_end = 0;
	
	int mask = pixel_fmt_bits, shift = 0;
	
	wxNativePixelData::Iterator output_ptr(bmp_data);
	output_ptr.OffsetY(bmp_data, region_y);
	
	for(int output_y = region_y; output_y < output_height && output_y < region_y + region_h; ++output_y)
	{
		int input_y = output_y;
		
		if(height != output_height)
		{
			input_y = (double)(input_y) * ((double)(height) / (double)(output_height));
			
			input_y = std::max(input_y, 0);
			input_y = std::min(input_y, height - 1);
		}
		
		if(flip_y)
		{
			input_y = ((height - 1) - input_y);
		}
		
		off_t line_len = (width * pixel_fmt_multi) / pixel_fmt_div;
		off_t line_off = offset + input_y * line_len;
		
		if(line_off < data_begin || (line_off + line_len) > data_end)
		{
			off_t data_read_base = line_off;
			off_t data_read_max = line_len * 32;
			
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
			data_end = data_begin + data.size();
		}
		
		const unsigned char *line_ptr = data.data() + (line_off - data_begin);
		
		wxNativePixelData::Iterator output_col_ptr = output_ptr;
		
		for(int output_x = 0; output_x < output_width; ++output_x, ++output_col_ptr)
		{
			int input_x = output_x;
			
			if(width != output_width)
			{
				input_x = (double)(input_x) * ((double)(width) / (double)(output_width));
				
				input_x = std::max(input_x, 0);
				input_x = std::min(input_x, width - 1);
			}
			
			if(flip_x)
			{
				input_x = ((width - 1) - input_x);
			}
			
			const unsigned char *input_ptr = line_ptr + (input_x * pixel_fmt_multi) / pixel_fmt_div;
			
			/* Initialise output to chequerboard pattern. */
			
			bool x_even = (output_x % 20) >= 10;
			bool y_even = (output_y % 20) >= 10;
			
			int chequerboard_colour = (x_even ^ y_even) ? 0x66 : 0x99;
			
			output_col_ptr.Red()   = chequerboard_colour;
			output_col_ptr.Green() = chequerboard_colour;
			output_col_ptr.Blue()  = chequerboard_colour;
			
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
				
				rgb |= ((*input_ptr & mask) >> shift) << (8 * i);
				
				if(pixel_fmt_div > 1)
				{
					mask <<= (8 / pixel_fmt_div);
					shift += 8 / pixel_fmt_div;
					
					if(mask > 255)
					{
						assert((mask & 255) == 0);
						
						mask  = pixel_fmt_bits;
						shift = 0;
						
						++input_ptr;
					}
				}
				else{
					++input_ptr;
				}
			}
			
			wxColour colour = colour_fmt_conv(rgb);
			
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
		
		output_ptr.OffsetY(bmp_data, 1);
	}
}

void REHex::BitmapTool::OnCursorUpdate(CursorUpdateEvent &event)
{
	if(offset_follow_cb->GetValue())
	{
		offset_textctrl->ChangeValue(std::to_string(event.cursor_pos));
		update();
	}
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::BitmapTool::OnDepth(wxCommandEvent &event)
{
	update_colour_format_choices();
	update();
}

void REHex::BitmapTool::OnFormat(wxCommandEvent &event)
{
	update();
}

void REHex::BitmapTool::OnFollowCursor(wxCommandEvent &event)
{
	if(offset_follow_cb->GetValue())
	{
		offset_textctrl->ChangeValue(std::to_string(document->get_cursor_position()));
		update();
	}
	else{
		/* Don't need to update anything if option was toggled off. */
	}
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

void REHex::BitmapTool::OnIdle(wxIdleEvent &event)
{
	if(bitmap_update_line >= 0)
	{
		render_region(bitmap_update_line, LINES_PER_IDLE, image_offset, image_width, image_height);
		bitmap_update_line += LINES_PER_IDLE;
		
		s_bitmap->Refresh();
		
		if(bitmap_update_line >= bitmap_height)
		{
			bitmap_update_line = -1;
		}
		else{
			event.RequestMore();
		}
	}
}
