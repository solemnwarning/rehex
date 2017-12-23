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

#include <assert.h>
#include <ctype.h>
#include <iterator>

#include "document.hpp"

static const char *COMMENT_TEXT = "There remains a very delicate balance in this world...\n"
	"Between those who create and those who will experience the creations of others.\n"
	"I can't say that I wasn't aware of this. However, I had never experienced it.\n"
	"Now, thanks to you, I finally have.\n"
	"As long as there is someone who will appreciate the work involved in creation, the effort is time well spent.\n"
	"To this end, I will continue to create for as long as I can.";

BEGIN_EVENT_TABLE(REHex::Document, wxControl)
	EVT_PAINT(REHex::Document::OnPaint)
	EVT_SIZE(REHex::Document::OnSize)
	EVT_SCROLLWIN(REHex::Document::OnScroll)
	EVT_CHAR(REHex::Document::OnChar)
	EVT_LEFT_DOWN(REHex::Document::OnLeftDown)
END_EVENT_TABLE()

REHex::Document::Document(wxWindow *parent, wxWindowID id, REHex::Buffer *buffer):
	wxControl(parent, id, wxDefaultPosition, wxDefaultSize, wxVSCROLL | wxHSCROLL),
	buffer(buffer)
{
	wxFontInfo finfo;
	finfo.Family(wxFONTFAMILY_MODERN);
	
	hex_font = new wxFont(finfo);
}

void REHex::Document::OnPaint(wxPaintEvent &event)
{
	wxPaintDC dc(this);
	
	wxSize client_size         = GetClientSize();
	unsigned int client_width  = client_size.GetWidth();
	unsigned int client_height = client_size.GetHeight();
	
	dc.SetFont(*hex_font);
	
	wxSize char_size         = dc.GetTextExtent("X");
	unsigned int char_width  = char_size.GetWidth();
	unsigned int char_height = char_size.GetHeight();
	
	/* Iterate over the regions to find the last one which does NOT start beyond the current
	 * scroll_y.
	*/
	
	auto region = regions.begin();
	for(auto next = std::next(region); next != regions.end() && (*next)->y_offset <= scroll_yoff; ++next)
	{
		region = next;
	}
	
	uint64_t yo_end = scroll_yoff + (client_height / char_height) + 1;
	for(; region != regions.end() && (*region)->y_offset < yo_end; ++region)
	{
		int x_px = 0 - scroll_xoff;
		
		int64_t y_px = (*region)->y_offset;
		assert(y_px >= 0);
		
		y_px -= scroll_yoff;
		y_px *= char_height;
		
		(*region)->draw(*this, dc, x_px, y_px);
	}
}

void REHex::Document::OnSize(wxSizeEvent &event)
{
	wxClientDC dc(this);
	
	/* Force a vertical scrollbar so the bytes per line doesn't jump around and screw us over.
	 * TODO: Do this less hackily (is this possible on non-win32 wxWidgets?)
	 * TODO: Compute real vertical scrollbar size after deciding if we need a horizontal one.
	*/
	this->SetScrollbar(wxVERTICAL, 0, 1, 2);
	
	/* Get the size of the area we can draw into */
	
	wxSize client_size         = this->GetClientSize();
	unsigned int client_width  = client_size.GetWidth();
	unsigned int client_height = client_size.GetHeight();
	
	/* Get the size of a character in the (fixed-width) font we use for the hex bytes. */
	
	dc.SetFont(*hex_font);
	wxSize char_size         = dc.GetTextExtent("X");
	unsigned int char_width  = char_size.GetWidth();
	unsigned int char_height = char_size.GetHeight();
	unsigned int byte_width  = 2 * char_width;
	
	auto calc_row_width = [this, char_width, byte_width](unsigned int line_bytes)
	{
		return (line_bytes * byte_width)
			+ (((line_bytes - 1) / this->group_bytes) * char_width);
	};
	
	/* Decide how many bytes to display per line */
	
	if(this->line_bytes_cfg == 0) /* 0 is "as many as will fit in the window" */
	{
		/* TODO: Can I do this algorithmically? */
		
		this->line_bytes_calc = 1;
		
		while(calc_row_width(this->line_bytes_calc + 1) <= client_width)
		{
			++(this->line_bytes_calc);
		}
	}
	else{
		this->line_bytes_calc = this->line_bytes_cfg;
	}
	
	/* Calculate the number of pixels necessary to render a full line and decide if we need a
	 * horizontal scroll bar.
	*/
	
	unsigned int row_width_px = calc_row_width(this->line_bytes_calc);
	
	if(row_width_px > client_width)
	{
		this->SetScrollbar(wxHORIZONTAL, 0, client_width, row_width_px);
	}
	else{
		this->SetScrollbar(wxHORIZONTAL, 0, 0, 0);
	}
	
	this->_build_line_ranges(dc);
	
	{
		scroll_yoff = 0; /* just always reset for now */
		
		unsigned int lines_per_screen = client_height / char_height;
		/*unsigned int lines_for_buffer = (this->buffer->length() / this->line_bytes_calc)
			+ !!(this->buffer->length() % this->line_bytes_calc);*/
		
		this->SetScrollbar(wxVERTICAL, this->scroll_yoff, lines_per_screen, this->regions.back()->y_offset + this->regions.back()->y_lines);
	}
	
	/* Force a redraw of the whole control since resizing can change the entire control, not
	 * just the newly visible areas.
	*/
	this->Refresh();
}

void REHex::Document::OnScroll(wxScrollWinEvent &event)
{
	if(event.GetOrientation() == wxHORIZONTAL)
	{
		this->scroll_xoff = event.GetPosition();
		this->Refresh();
	}
	else if(event.GetOrientation() == wxVERTICAL)
	{
		this->scroll_yoff = event.GetPosition();
		this->Refresh();
	}
}

void REHex::Document::OnChar(wxKeyEvent &event)
{
	int key       = event.GetKeyCode();
	int modifiers = event.GetModifiers();
	
	auto cpos_inc = [this]()
	{
		if(this->cpos_off + 1 < this->buffer->length())
		{
			++(this->cpos_off);
		}
		
		this->editing_byte = false;
	};
	
	auto cpos_dec = [this]()
	{
		if(this->cpos_off > 0)
		{
			--(this->cpos_off);
		}
		
		this->editing_byte = false;
	};
	
	if(modifiers == wxMOD_CONTROL)
	{
		if(key == 1 + ('G' - 'A'))
		{
			/* Ctrl+G - Go to offset */
		}
	}
	else if((modifiers == wxMOD_NONE || modifiers == wxMOD_SHIFT) && isxdigit(key))
	{
		std::vector<unsigned char> byte = this->buffer->read_data(this->cpos_off, 1);
		
		if(!byte.empty())
		{
			unsigned char nibble;
			switch(key)
			{
				case '0':           nibble = 0x0; break;
				case '1':           nibble = 0x1; break;
				case '2':           nibble = 0x2; break;
				case '3':           nibble = 0x3; break;
				case '4':           nibble = 0x4; break;
				case '5':           nibble = 0x5; break;
				case '6':           nibble = 0x6; break;
				case '7':           nibble = 0x7; break;
				case '8':           nibble = 0x8; break;
				case '9':           nibble = 0x9; break;
				case 'A': case 'a': nibble = 0xA; break;
				case 'B': case 'b': nibble = 0xB; break;
				case 'C': case 'c': nibble = 0xC; break;
				case 'D': case 'd': nibble = 0xD; break;
				case 'E': case 'e': nibble = 0xE; break;
				case 'F': case 'f': nibble = 0xF; break;
			}
			
			if(this->editing_byte)
			{
				byte[0] = (byte[0] & 0xF0) | nibble;
				this->buffer->overwrite_data(this->cpos_off, byte.data(), 1);
				
				cpos_inc();
			}
			else{
				byte[0] = (byte[0] & 0x0F) | (nibble << 4);
				this->buffer->overwrite_data(this->cpos_off, byte.data(), 1);
				
				this->editing_byte = true;
			}
			
			/* TODO: Limit paint to affected area */
			this->Refresh();
		}
	}
	else if(modifiers == wxMOD_NONE)
	{
		if(key == WXK_LEFT)
		{
			cpos_dec();
			
			/* TODO: Limit paint to affected area */
			this->Refresh();
		}
		else if(key == WXK_RIGHT)
		{
			cpos_inc();
			
			/* TODO: Limit paint to affected area */
			this->Refresh();
		}
	}
}

void REHex::Document::OnLeftDown(wxMouseEvent &event)
{
	wxClientDC dc(this);
	
	unsigned int mouse_x = event.GetX();
	unsigned int rel_x   = mouse_x + this->scroll_xoff;
	unsigned int mouse_y = event.GetY();
	
	printf("Mouse click at (%u, %u) (rel_x = %u)\n", mouse_x, mouse_y, rel_x);
	
	dc.SetFont(*hex_font);
	
	wxSize char_size         = dc.GetTextExtent("X");
	unsigned int char_width  = char_size.GetWidth();
	unsigned int char_height = char_size.GetHeight();
	
	/* Iterate over the regions to find the last one which does NOT start beyond the current
	 * scroll_y.
	*/
	
	auto region = regions.begin();
	for(auto next = std::next(region); next != regions.end() && (*next)->y_offset <= scroll_yoff; ++next)
	{
		region = next;
	}
	
	/* If we are scrolled past the start of the regiomn, will need to skip some of the first one. */
	unsigned int skip_lines_in_region = (this->scroll_yoff - (*region)->y_offset);
	
	unsigned int line_off = (mouse_y / char_height) + skip_lines_in_region;
	
	while(region != regions.end() && line_off >= (*region)->y_lines)
	{
		line_off -= (*region)->y_lines;
		++region;
	}
	
	if(region != regions.end())
	{
		printf("...at line %u in region (%u lines)\n", line_off, (unsigned)((*region)->y_lines));
		
		REHex::Document::Region::Data *dr = dynamic_cast<REHex::Document::Region::Data*>(*region);
		if(dr != NULL)
		{
			unsigned int char_offset = (rel_x / char_width);
			printf("...character offset %u\n", char_offset);
			if(((char_offset + 1) % ((this->group_bytes * 2) + 1)) == 0)
			{
				printf("...in a space\n");
			}
			else{
				unsigned int char_offset_sub_spaces = char_offset - (char_offset / ((this->group_bytes * 2) + 1));
				printf("...character offset sub spaces %u\n", char_offset_sub_spaces);
				
				size_t line_data_off = this->line_bytes_calc * line_off;
				size_t byte_off = dr->d_offset + line_data_off + (char_offset_sub_spaces / 2);
				size_t data_len_clamp = std::min(dr->d_length, (line_data_off + this->line_bytes_calc));
				
				if(byte_off < (dr->d_offset + data_len_clamp))
				{
					printf("...which is byte offset %u\n", (unsigned)(byte_off));
					
					this->cpos_off = byte_off;
					this->editing_byte = false;
					
					/* TODO: Limit paint to affected area */
					this->Refresh();
				}
				else{
					printf("...which is past the end of the data\n");
				}
			}
		}
	}
}

void REHex::Document::_build_line_ranges(wxDC &dc)
{
	/* Clear the old regions list. */
	while(!regions.empty())
	{
		delete regions.front();
		regions.pop_front();
	}
	
	size_t next_line = 0, comment_in = 128, data_off = 0, remain = this->buffer->length();
	
	do {
		/* Add the fake comment. */
		REHex::Document::Region::Comment *cr = new REHex::Document::Region::Comment(*this, dc, next_line);
		
		regions.push_back(cr);
		next_line += cr->y_lines;
		
		/* Add some actual data from the Buffer. */
		size_t block_len = std::min(remain, comment_in);
		REHex::Document::Region::Data *dr = new REHex::Document::Region::Data(*this, next_line, data_off, block_len);
		
		regions.push_back(dr);
		next_line += dr->y_lines;
		
		comment_in = std::min(comment_in * 2, (size_t)(4096));
		data_off += block_len;
		remain   -= block_len;
	} while(remain > 0);
}

std::list<std::string> REHex::Document::_format_text(const std::string &text, unsigned int cols, unsigned int from_line, unsigned int max_lines)
{
	/* TODO: Throw myself into the abyss and support Unicode properly...
	 * (This function assumes one byte is one full-width character on the screen.
	*/
	
	std::list<std::string> lines;
	
	for(size_t at = 0; at < text.size();)
	{
		size_t newline_at = text.find_first_of('\n', at);
		
		if(newline_at != std::string::npos && newline_at <= (at + cols))
		{
			/* There is a newline within one row's worth of text of our current position.
			 * Add all the text up to it and continue from after it.
			*/
			lines.push_back(text.substr(at, newline_at - at));
			at = newline_at + 1;
		}
		else{
			/* The line is too long, just wrap it at whatever character is on the boundary.
			 *
			 * std::string::substr() will clamp the length if it goes beyond the end of
			 * the string.
			*/
			lines.push_back(text.substr(at, cols));
			at += cols;
		}
	}
	
	lines.erase(lines.begin(), std::next(lines.begin(), std::min((size_t)(from_line), lines.size())));
	lines.erase(std::next(lines.begin(), std::min((size_t)(max_lines), lines.size())), lines.end());
	
	return lines;
}

REHex::Document::Region::~Region() {}

REHex::Document::Region::Data::Data(REHex::Document &doc, uint64_t y_offset, size_t d_offset, size_t d_length):
	d_offset(d_offset), d_length(d_length)
{
	this->y_offset = y_offset;
	
	/* Height of the region is simply the number of complete lines of data plus an incomplete
	 * one if the data isn't a round number of lines.
	*/
	y_lines = (d_length / doc.line_bytes_calc) + !!(d_length % doc.line_bytes_calc);
}

void REHex::Document::Region::Data::draw(REHex::Document &doc, wxDC &dc, int x, int64_t y)
{
	/* Get the size of the area we can draw into */
	
	wxSize client_size         = doc.GetClientSize();
	int client_height = client_size.GetHeight();
	
	/* Get the size of a character in the (fixed-width) font we use for the hex bytes. */
	
	dc.SetFont(*(doc.hex_font));
	wxSize char_size         = dc.GetTextExtent("X");
	int char_width  = char_size.GetWidth();
	int char_height = char_size.GetHeight();
	
	/* If we are scrolled part-way into a data region, don't render data above the client area
	 * as it would get expensive very quickly with large files.
	*/
	int64_t skip_lines = (y < 0 ? (-y / char_height) : 0);
	size_t skip_bytes  = skip_lines * doc.line_bytes_calc;
	
	/* Increment y up to our real drawing start point. We can now trust it to be within a
	 * char_height of zero, not the stratospheric integer-overflow-causing values it could
	 * previously have on huge files.
	*/
	y += skip_lines * char_height;
	
	/* The maximum amount of data that can be drawn on the screen before we're past the bottom
	 * of the client area. Drawing more than this would be pointless and very expensive in the
	 * case of large files.
	*/
	int max_lines = ((client_height - y) / char_height) + 1;
	int max_bytes = max_lines * doc.line_bytes_calc;
	
	/* Fetch the data to be drawn. */
	std::vector<unsigned char> data = doc.buffer->read_data(d_offset + skip_bytes, std::min((size_t)(max_bytes), (d_length - skip_bytes)));
	
	/* The offset of the character in the Buffer currently being drawn. */
	size_t cur_off = d_offset + skip_bytes;
	
	for(auto di = data.begin(); di != data.end();)
	{
		int line_x = x;
		
		int norm_x = line_x;
		wxString norm_str;
		
		for(unsigned int c = 0; c < doc.line_bytes_calc && di != data.end(); ++c)
		{
			if(c > 0 && (c % doc.group_bytes) == 0)
			{
				norm_str.append(1, ' ');
				line_x += char_width;
			}
			
			unsigned char byte        = *(di++);
			unsigned char high_nibble = (byte & 0xF0) >> 4;
			unsigned char low_nibble  = (byte & 0x0F);
			
			auto draw_nibble = [&line_x,y,&dc,char_width,&norm_str](unsigned char nibble, bool invert)
			{
				const char *nibble_to_hex = "0123456789ABCDEF";
				
				if(invert)
				{
					dc.SetTextForeground(*wxWHITE);
					dc.SetTextBackground(*wxBLACK);
					dc.SetBackgroundMode(wxSOLID);
					
					char str[] = { nibble_to_hex[nibble], '\0' };
					dc.DrawText(str, line_x, y);
					
					dc.SetTextForeground(*wxBLACK);
					dc.SetBackgroundMode(wxTRANSPARENT);
					
					norm_str.append(1, ' ');
				}
				else{
					norm_str.append(1, nibble_to_hex[nibble]);
				}
				
				line_x += char_width;
			};
			
			draw_nibble(high_nibble, (cur_off == doc.cpos_off && !doc.editing_byte));
			draw_nibble(low_nibble,  (cur_off == doc.cpos_off));
			
			++cur_off;
		}
		
		dc.DrawText(norm_str, norm_x, y);
		
		y += char_height;
	}
}

REHex::Document::Region::Comment::Comment(REHex::Document &doc, wxDC &dc, uint64_t y_offset)
{
	wxSize client_size        = doc.GetClientSize();
	unsigned int client_width = client_size.GetWidth();
	
	dc.SetFont(*(doc.hex_font));
	unsigned int char_width = dc.GetCharWidth();
	
	unsigned int row_chars = client_width / char_width;
	
	auto comment_lines = _format_text(COMMENT_TEXT, row_chars - 1);
	
	this->y_offset = y_offset;
	this->y_lines  = comment_lines.size() + 1;
}

void REHex::Document::Region::Comment::draw(REHex::Document &doc, wxDC &dc, int x, int64_t y)
{
	/* Comments are currently drawn at the width of the client area, always being fully visible
	 * (along their X axis) and not scrolling with the file data.
	*/
	x = 0;
	
	/* Get the size of the area we can draw into */
	
	wxSize client_size        = doc.GetClientSize();
	unsigned int client_width = client_size.GetWidth();
	
	/* Get the size of a character in the (fixed-width) font we use for the hex bytes. */
	
	dc.SetFont(*(doc.hex_font));
	
	wxSize char_size         = dc.GetTextExtent("X");
	unsigned int char_width  = char_size.GetWidth();
	unsigned int char_height = char_size.GetHeight();
	
	auto lines = _format_text(COMMENT_TEXT, (client_width / char_width) - 1);
	
	{
		int box_x = x + (char_width / 4);
		int box_y = y + (char_height / 4);
		
		unsigned int box_w = client_width - (char_width / 2);
		unsigned int box_h = (lines.size() * char_height) + (char_height / 2);
		
		dc.SetBrush(*wxLIGHT_GREY_BRUSH);
		dc.DrawRectangle(box_x, box_y, box_w, box_h);
	}
	
	y += char_height / 2;
	
	for(auto li = lines.begin(); li != lines.end(); ++li)
	{
		dc.DrawText(*li, (x + (char_width / 2)), y);
		y += char_height;
	}
}
