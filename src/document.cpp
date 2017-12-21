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
	
	wxSize client_size         = dc.GetSize();
	unsigned int client_width  = client_size.GetWidth();
	unsigned int client_height = client_size.GetHeight();
	
	dc.SetFont(*hex_font);
	
	wxSize char_size         = dc.GetTextExtent("X");
	unsigned int char_width  = char_size.GetWidth();
	unsigned int char_height = char_size.GetHeight();
	
	/* Iterate over the LineRanges to find the last block which does NOT start beyond the current
	 * scroll_y.
	*/
	
	auto begin_lr = this->lineranges.begin();
	for(auto next_lr = std::next(begin_lr); next_lr != this->lineranges.end() && next_lr->start <= scroll_yoff; ++next_lr)
	{
		begin_lr = next_lr;
	}
	
	/* If we are scrolled past the start of the LineRange, will need to skip some of the first one. */
	unsigned int skip_lines_in_lr = (this->scroll_yoff - begin_lr->start);
	
	unsigned int y = 0;
	while(begin_lr != this->lineranges.end() && y < client_height)
	{
		/* The maximum number of lines of text that can be drawn on the screen before we're past
		 * the bottom of the client area. Drawing more than this would be pointless.
		*/
		unsigned int max_lines = ((client_height - y) / char_height) + 1;
		
		if(begin_lr->type == REHex::Document::LineRange::LR_DATA)
		{
			unsigned int max_bytes_to_draw = max_lines * this->line_bytes_calc;
			
			/* Fetch the data to be rendered from this LineRange. */
			size_t buf_off = begin_lr->data.offset + (skip_lines_in_lr * this->line_bytes_calc);
			size_t buf_len = std::min(begin_lr->data.length - (skip_lines_in_lr * this->line_bytes_calc), max_bytes_to_draw);
			std::vector<unsigned char> data = this->buffer->read_data(buf_off, buf_len);
			
			//printf("Rendering LR_DATA at y = %u, buf_off = %u, buf_len = %u\n", y, (unsigned)(buf_off), (unsigned)(buf_len));
			
			for(auto di = data.begin(); di != data.end() && y < client_height;)
			{
				int x = (0 - this->scroll_xoff);
				
				int norm_x = x;
				wxString norm_str;
				
				for(unsigned int c = 0; c < this->line_bytes_calc && di != data.end(); ++c)
				{
					if(c > 0 && (c % this->group_bytes) == 0)
					{
						norm_str.append(1, ' ');
						x += char_width;
					}
					
					unsigned char byte        = *(di++);
					unsigned char high_nibble = (byte & 0xF0) >> 4;
					unsigned char low_nibble  = (byte & 0x0F);
					
					auto draw_nibble = [&x,y,&dc,char_width,&norm_str](unsigned char nibble, bool invert)
					{
						const char *nibble_to_hex = "0123456789ABCDEF";
						
						if(invert)
						{
							dc.SetTextForeground(*wxWHITE);
							dc.SetTextBackground(*wxBLACK);
							dc.SetBackgroundMode(wxSOLID);
							
							char str[] = { nibble_to_hex[nibble], '\0' };
							dc.DrawText(str, x, y);
							
							dc.SetTextForeground(*wxBLACK);
							dc.SetBackgroundMode(wxTRANSPARENT);
							
							norm_str.append(1, ' ');
						}
						else{
							norm_str.append(1, nibble_to_hex[nibble]);
						}
						
						x += char_width;
					};
					
					draw_nibble(high_nibble, (buf_off == this->cpos_off && !this->editing_byte));
					draw_nibble(low_nibble,  (buf_off == this->cpos_off));
					
					++buf_off;
				}
				
				dc.DrawText(norm_str, norm_x, y);
				
				y += char_height;
			}
		}
		else if(begin_lr->type == REHex::Document::LineRange::LR_COMMENT)
		{
			//printf("Rendering LR_COMMENT at y = %u\n", y);
			
			unsigned int box_y_sub = 0;
			if(skip_lines_in_lr > 0)
			{
				box_y_sub = char_height;
				--skip_lines_in_lr;
			}
			
			auto lines = _format_text(COMMENT_TEXT, (client_width / char_width) - 1, skip_lines_in_lr, max_lines);
			
			{
				unsigned int box_x = char_width / 4;
				unsigned int box_y = (y + (char_height / 4)) - box_y_sub;
				
				unsigned int box_w = client_width - (char_width / 2);
				unsigned int box_h = (lines.size() * char_height) + (char_height / 2);
				
				dc.SetBrush(*wxLIGHT_GREY_BRUSH);
				dc.DrawRectangle(box_x, box_y, box_w, box_h);
			}
			
			y -= box_y_sub;
			y += char_height / 2;
			
			for(auto li = lines.begin(); li != lines.end(); ++li)
			{
				dc.DrawText(*li, (char_width / 2), y);
				y += char_height;
			}
			
			y += (char_height / 2) + (char_height % 2);
		}
		
		/* Only the first LineRange should have lines skipped. */
		skip_lines_in_lr = 0;
		
		++begin_lr;
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
	
	this->_build_line_ranges((client_width / char_width) - 2);
	
	{
		scroll_yoff = 0; /* just always reset for now */
		
		unsigned int lines_per_screen = client_height / char_height;
		/*unsigned int lines_for_buffer = (this->buffer->length() / this->line_bytes_calc)
			+ !!(this->buffer->length() % this->line_bytes_calc);*/
		
		this->SetScrollbar(wxVERTICAL, this->scroll_yoff, lines_per_screen, this->lineranges.back().start + this->lineranges.back().lines);
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
	int key = event.GetKeyCode();
	
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
	else if(isxdigit(key))
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
}

void REHex::Document::_build_line_ranges(unsigned int cols)
{
	this->lineranges.clear();
	
	size_t next_line = 0, comment_in = 128, data_off = 0, remain = this->buffer->length();
	
	auto comment_lines = _format_text(COMMENT_TEXT, cols);
	
	do {
		{
			REHex::Document::LineRange r;
			r.start = next_line;
			r.lines = comment_lines.size() + 1;
			r.type  = REHex::Document::LineRange::LR_COMMENT;
			
			this->lineranges.push_back(r);
			next_line += r.lines;
		}
		
		size_t block_len = std::min(remain, comment_in);
		
		REHex::Document::LineRange r;
		r.start = next_line;
		r.lines = (block_len / this->line_bytes_calc)
			+ !!(block_len % this->line_bytes_calc);
		
		r.type  = REHex::Document::LineRange::LR_DATA;
		r.data.offset = data_off;
		r.data.length = block_len;
		
		this->lineranges.push_back(r);
		next_line += r.lines;
		
		comment_in = std::min(comment_in * 2, (unsigned)(4096));
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
	
	lines.erase(lines.begin(), std::next(lines.begin(), std::min(from_line, lines.size())));
	lines.erase(std::next(lines.begin(), std::min(max_lines, lines.size())), lines.end());
	
	return lines;
}
