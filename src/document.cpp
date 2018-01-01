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
#include <inttypes.h>
#include <iterator>

#include "document.hpp"
#include "textentrydialog.hpp"

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
	_init_regions();
	
	wxFontInfo finfo;
	finfo.Family(wxFONTFAMILY_MODERN);
	
	hex_font = new wxFont(finfo);
	assert(hex_font->IsFixedWidth());
}

REHex::Document::~Document()
{
	for(auto region = regions.begin(); region != regions.end(); ++region)
	{
		delete *region;
	}
}

void REHex::Document::save()
{
	buffer->write_inplace();
}

void REHex::Document::save(const std::string &filename)
{
	buffer->write_inplace(filename);
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
	
	/* Calculate how much space (if any) to reserve for the offsets to the left. */
	
	if(offset_column)
	{
		offset_column_width = 18 * char_width;
		client_width -= offset_column_width;
	}
	else{
		offset_column_width = 0;
	}
	
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
	
	this->_recalc_regions(dc);
	
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
		if(this->cpos_off + !insert_mode < this->buffer->length())
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
		if(key == WXK_CONTROL_G)
		{
			/* Ctrl+G - Go to offset */
			printf("TODO: Implement jump to offset\n");
		}
	}
	else if((modifiers == wxMOD_NONE || modifiers == wxMOD_SHIFT) && isxdigit(key))
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
			std::vector<unsigned char> byte = this->buffer->read_data(this->cpos_off, 1);
			assert(!byte.empty());
			
			byte[0] = (byte[0] & 0xF0) | nibble;
			
			wxClientDC dc(this);
			_overwrite_data(dc, this->cpos_off, byte.data(), 1);
			
			cpos_inc();
		}
		else if(this->insert_mode)
		{
			unsigned char byte = (nibble << 4);
			
			wxClientDC dc(this);
			_insert_data(dc, this->cpos_off, &byte, 1);
			
			this->editing_byte = true;
		}
		else{
			std::vector<unsigned char> byte = this->buffer->read_data(this->cpos_off, 1);
			
			if(!byte.empty())
			{
				byte[0] = (byte[0] & 0x0F) | (nibble << 4);
				
				wxClientDC dc(this);
				_overwrite_data(dc, this->cpos_off, byte.data(), 1);
				
				this->editing_byte = true;
			}
		}
		
		/* TODO: Limit paint to affected area */
		this->Refresh();
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
		else if(key == WXK_INSERT)
		{
			insert_mode  = !insert_mode;
			
			if(!insert_mode && cpos_off == buffer->length())
			{
				/* Move cursor back if going from insert to overwrite mode and it
				 * was at the end of the file.
				*/
				cpos_dec();
			}
			
			/* TODO: Limit paint to affected area */
			this->Refresh();
		}
		else if(key == WXK_DELETE)
		{
			if(this->cpos_off < this->buffer->length())
			{
				wxClientDC dc(this);
				_erase_data(dc, this->cpos_off, 1);
				
				this->editing_byte = false;
				
				/* TODO: Limit paint to affected area */
				this->Refresh();
			}
		}
		else if(key == WXK_BACK)
		{
			if(this->cpos_off > 0)
			{
				wxClientDC dc(this);
				_erase_data(dc, --(this->cpos_off), 1);
				
				this->editing_byte = false;
				
				/* TODO: Limit paint to affected area */
				this->Refresh();
			}
		}
		else if(key == '/')
		{
			REHex::TextEntryDialog te(this, "Enter comment", _get_comment_text(cpos_off));
			
			int rc = te.ShowModal();
			if(rc == wxID_OK)
			{
				std::string comment_text = te.get_text();
				wxClientDC dc(this);
				
				if(comment_text.empty())
				{
					_delete_comment(dc, cpos_off);
				}
				else{
					_set_comment_text(dc, cpos_off, te.get_text());
				}
				
				/* TODO: Limit paint to affected area */
				this->Refresh();
			}
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
	uint64_t skip_lines_in_region = (this->scroll_yoff - (*region)->y_offset);
	
	uint64_t line_off = (mouse_y / char_height) + skip_lines_in_region;
	
	while(region != regions.end() && line_off >= (*region)->y_lines)
	{
		line_off -= (*region)->y_lines;
		++region;
	}
	
	if(region != regions.end())
	{
		// printf("...at line %" PRIu64 " in region (%" PRIu64 " lines)\n", line_off, (*region)->y_lines);
		
		/* TODO: Move this logic into the Region::Data class */
		
		REHex::Document::Region::Data *dr = dynamic_cast<REHex::Document::Region::Data*>(*region);
		if(dr != NULL)
		{
			if(rel_x < offset_column_width)
			{
				/* Click was within the offset area */
				return;
			}
			
			rel_x -= offset_column_width;
			
			unsigned int char_offset = (rel_x / char_width);
			printf("...character offset %u\n", char_offset);
			if(((char_offset + 1) % ((this->group_bytes * 2) + 1)) == 0)
			{
				printf("...in a space\n");
			}
			else{
				unsigned int char_offset_sub_spaces = char_offset - (char_offset / ((this->group_bytes * 2) + 1));
				printf("...character offset sub spaces %u\n", char_offset_sub_spaces);
				
				off_t line_data_off = (off_t)(this->line_bytes_calc) * (off_t)(line_off);
				off_t byte_off = dr->d_offset + line_data_off + (char_offset_sub_spaces / 2);
				off_t data_len_clamp = std::min(dr->d_length, (line_data_off + this->line_bytes_calc));
				
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

void REHex::Document::_init_regions()
{
	assert(regions.empty());
	
	data_regions_count = 0;
	
#if 0
	size_t comment_in = 128, data_off = 0, remain = this->buffer->length();
	
	do {
		/* Add the fake comment. */
		REHex::Document::Region::Comment *cr = new REHex::Document::Region::Comment(data_off, COMMENT_TEXT);
		regions.push_back(cr);
		
		/* Add some actual data from the Buffer. */
		size_t block_len = std::min(remain, comment_in);
		REHex::Document::Region::Data *dr = new REHex::Document::Region::Data(data_off, block_len);
		regions.push_back(dr);
		
		++data_regions_count;
		
		comment_in = std::min(comment_in * 2, (size_t)(4096));
		data_off += block_len;
		remain   -= block_len;
	} while(remain > 0);
#else
	regions.push_back(new REHex::Document::Region::Data(0, buffer->length()));
	++data_regions_count;
#endif
}

void REHex::Document::_recalc_regions(wxDC &dc)
{
	uint64_t next_yo = 0;
	auto i = regions.begin();
	
	for(; i != regions.end(); ++i)
	{
		(*i)->y_offset = next_yo;
		(*i)->update_lines(*this, dc);
		
		next_yo += (*i)->y_lines;
	}
}

void REHex::Document::_overwrite_data(wxDC &dc, off_t offset, const unsigned char *data, off_t length)
{
	bool ok = buffer->overwrite_data(offset, data, length);
	assert(ok);
}

/* Insert some data into the Buffer and update our own data structures. */
void REHex::Document::_insert_data(wxDC &dc, off_t offset, const unsigned char *data, off_t length)
{
	bool ok = buffer->insert_data(offset, data, length);
	assert(ok);
	
	if(ok)
	{
		auto region = regions.begin();
		
		/* Increment region until it is pointing at the Data region which encompasses the
		 * point we have inserted at.
		*/
		for(;; ++region)
		{
			assert(region != regions.end());
			auto dr = dynamic_cast<REHex::Document::Region::Data*>(*region);
			
			if(dr == NULL)
			{
				/* Not a data region, carry on searching... */
				continue;
			}
			
			if((dr->d_offset + dr->d_length) > offset)
			{
				/* Regions are ordered, so the first one whose offset plus length
				 * encompasses our starting point is the one.
				*/
				break;
			}
			
			if((dr->d_offset + dr->d_length) == offset && std::next(region) == regions.end())
			{
				/* Special case: Inserting at the end of the last region. */
				break;
			}
		}
		
		/* Grow the length of the region. */
		
		{
			auto dr = dynamic_cast<REHex::Document::Region::Data*>(*region);
			assert(dr != NULL);
			
			dr->d_length += length;
			
			dr->update_lines(*this, dc);
		}
		
		/* Shuffle the rest of the regions along. */
		
		uint64_t next_yo = (*region)->y_offset + (*region)->y_lines;
		++region;
		
		while(region != regions.end())
		{
			auto dr = dynamic_cast<REHex::Document::Region::Data*>(*region);
			if(dr != NULL)
			{
				dr->d_offset += length;
			}
			
			auto cr = dynamic_cast<REHex::Document::Region::Comment*>(*region);
			if(cr != NULL)
			{
				cr->c_offset += length;
			}
			
			(*region)->y_offset = next_yo;
			next_yo += (*region)->y_lines;
			
			++region;
		}
	}
	
}

/* Erase a range of data from the Buffer and update our own data structures. */
void REHex::Document::_erase_data(wxDC &dc, off_t offset, off_t length)
{
	bool ok = buffer->erase_data(offset, length);
	assert(ok);
	
	if(ok)
	{
		auto region = regions.begin();
		
		/* Increment region until it is pointing at the Data region which encompasses the
		 * start of the data being erased.
		*/
		for(REHex::Document::Region::Data *d; (d = dynamic_cast<REHex::Document::Region::Data*>(*region)) == NULL || (d->d_offset + d->d_length) <= offset; ++region) {}
		assert(region != regions.end());
		
		uint64_t next_yo = (*region)->y_offset;
		
		off_t to_shift  = 0;
		off_t to_shrink = length;
		off_t dr_offset = offset - dynamic_cast<REHex::Document::Region::Data*>(*region)->d_offset;
		
		while(region != regions.end())
		{
			auto dr = dynamic_cast<REHex::Document::Region::Data*>(*region);
			if(dr != NULL)
			{
				/* This is a data region, so we need to munge the d_offset and
				 * d_length values according to our state within the erase.
				*/
				
				off_t to_shrink_here = std::min(to_shrink, dr->d_length - dr_offset);
				
				dr->d_offset -= to_shift;
				dr->d_length -= to_shrink_here;
				
				to_shift  += to_shrink_here;
				to_shrink -= to_shrink_here;
				dr_offset = 0;
				
				if(region != regions.begin() && dr->d_length == 0)
				{
					/* If this isn't the first region, it is now zero bytes long
					 * and was preceeded by a comment, delete that comment.
					*/
					
					auto prev = std::prev(region);
					auto cr = dynamic_cast<REHex::Document::Region::Comment*>(*prev);
					if(cr != NULL)
					{
						next_yo = (*prev)->y_offset;
						
						delete *prev;
						region = regions.erase(prev);
					}
				}
				
				if(dr->d_length == 0 && data_regions_count > 1)
				{
					/* If we've shrunk this region to zero bytes and it isn't
					 * the last one, get rid of it.
					*/
					
					delete *region;
					region = regions.erase(region);
					
					--data_regions_count;
					
					/* ...and carry on to the next one. */
					continue;
				}
				else if(to_shrink_here > 0)
				{
					(*region)->update_lines(*this, dc);
				}
			}
			
			auto cr = dynamic_cast<REHex::Document::Region::Comment*>(*region);
			if(cr != NULL)
			{
				cr->c_offset -= to_shift;
			}
			
			/* All blocks from the point where we started erasing must have their
			 * y_offset values updated, since region heights may have changed.
			*/
			
			(*region)->y_offset = next_yo;
			next_yo += (*region)->y_lines;
			
			++region;
		}
		
		assert(to_shift == length);
		assert(to_shrink == 0);
	}
}

std::string REHex::Document::_get_comment_text(off_t offset)
{
	for(auto region = regions.begin(); region != regions.end(); ++region)
	{
		auto cr = dynamic_cast<REHex::Document::Region::Comment*>(*region);
		if(cr != NULL && cr->c_offset == offset)
		{
			return cr->c_text;
		}
	}
	
	return "";
}

void REHex::Document::_set_comment_text(wxDC &dc, off_t offset, const std::string &text)
{
	for(auto region = regions.begin(); region != regions.end(); ++region)
	{
		auto cr = dynamic_cast<REHex::Document::Region::Comment*>(*region);
		if(cr != NULL && cr->c_offset == offset)
		{
			/* Updating an existing comment. */
			cr->c_text = text;
			break;
		}
		
		auto dr = dynamic_cast<REHex::Document::Region::Data*>(*region);
		if(dr != NULL)
		{
			if(dr->d_offset == offset)
			{
				/* Placing a comment at the start of a Data region. */
				regions.insert(region, new REHex::Document::Region::Comment(offset, text));
				break;
			}
			else if((dr->d_offset + dr->d_length) > offset)
			{
				/* Splitting a Data region in two and placing a comment in between
				 * them.
				*/
				
				off_t rel_off = offset - dr->d_offset;
				
				auto ci = regions.insert(region, new REHex::Document::Region::Comment(offset, text));
				regions.insert(ci, new REHex::Document::Region::Data(dr->d_offset, rel_off));
				++data_regions_count;
				
				dr->d_offset += rel_off;
				dr->d_length -= rel_off;
				
				break;
			}
		}
	}
	
	_recalc_regions(dc);
}

void REHex::Document::_delete_comment(wxDC &dc, off_t offset)
{
	auto region = regions.begin();
	uint64_t next_yo = 0;
	
	for(; region != regions.end(); ++region)
	{
		auto cr = dynamic_cast<REHex::Document::Region::Comment*>(*region);
		if(cr != NULL && cr->c_offset == offset)
		{
			/* Found the requested comment Region, destroy it. */
			delete *region;
			region = regions.erase(region);
			
			/* ...and merge the Data regions from either side
			 * (unless we deleted a comment from the beginning).
			*/
			if(region != regions.begin())
			{
				/* ...get the Data region from before the comment... */
				auto dr1 = dynamic_cast<REHex::Document::Region::Data*>(*(std::prev(region)));
				assert(dr1 != NULL);
				
				/* ...get the Data region from after the comment... */
				auto dr2 = dynamic_cast<REHex::Document::Region::Data*>(*region);
				assert(dr2 != NULL);
				
				/* ...extend the first to encompass the second... */
				dr1->d_length += dr2->d_length;
				dr1->update_lines(*this, dc);
				
				/* ...and make the second go away. */
				delete *region;
				region = regions.erase(region);
				--data_regions_count;
				
				/* Set the y_offset for regions after this to begin at. */
				next_yo = dr1->y_offset + dr1->y_lines;
			}
			
			break;
		}
	}
	
	/* Fixup the y_offset of all following regions */
	for(; region != regions.end(); ++region)
	{
		(*region)->y_offset = next_yo;
		next_yo += (*region)->y_lines;
	}
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

REHex::Document::Region::Data::Data(off_t d_offset, off_t d_length):
	d_offset(d_offset), d_length(d_length) {}

void REHex::Document::Region::Data::update_lines(REHex::Document &doc, wxDC &dc)
{
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
	off_t skip_bytes  = skip_lines * doc.line_bytes_calc;
	
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
	std::vector<unsigned char> data = doc.buffer->read_data(d_offset + skip_bytes, std::min((off_t)(max_bytes), (d_length - skip_bytes)));
	
	/* The offset of the character in the Buffer currently being drawn. */
	off_t cur_off = d_offset + skip_bytes;
	
	for(auto di = data.begin(); di != data.end();)
	{
		int line_x = x;
		
		if(doc.offset_column)
		{
			/* Draw the offsets to the left */
			char offset_str[64];
			snprintf(offset_str, sizeof(offset_str), "%08X:%08X",
				(unsigned)((cur_off & 0xFFFFFFFF00000000) >> 32),
				(unsigned)(cur_off & 0xFFFFFFFF));
			
			dc.DrawText(offset_str, line_x, y);
			line_x += doc.offset_column_width;
			
			dc.DrawLine((line_x - (char_width / 2)), y,
				    (line_x - (char_width / 2)), y + char_height);
		}
		
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
			
			if(cur_off == doc.cpos_off && doc.insert_mode && !doc.editing_byte)
			{
				dc.DrawLine(line_x, y, line_x, y + char_height);
			}
			
			draw_nibble(high_nibble, (cur_off == doc.cpos_off && !doc.editing_byte && !doc.insert_mode));
			draw_nibble(low_nibble,  (cur_off == doc.cpos_off && (doc.editing_byte || !doc.insert_mode)));
			
			++cur_off;
		}
		
		if(cur_off == doc.cpos_off && cur_off == doc.buffer->length())
		{
			/* Draw the insert cursor past the end of the line if we've just written
			 * the last byte to the screen.
			 *
			 * TODO: Draw on next line if we're at the end of one.
			*/
			dc.DrawLine(line_x, y, line_x, y + char_height);
		}
		
		dc.DrawText(norm_str, norm_x, y);
		
		y += char_height;
	}
}

REHex::Document::Region::Comment::Comment(off_t c_offset, const std::string &c_text):
	c_offset(c_offset), c_text(c_text) {}

void REHex::Document::Region::Comment::update_lines(REHex::Document &doc, wxDC &dc)
{
	wxSize client_size        = doc.GetClientSize();
	unsigned int client_width = client_size.GetWidth();
	
	dc.SetFont(*(doc.hex_font));
	unsigned int char_width = dc.GetCharWidth();
	
	unsigned int row_chars = client_width / char_width;
	
	auto comment_lines = _format_text(c_text, row_chars - 1);
	
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
	
	auto lines = _format_text(c_text, (client_width / char_width) - 1);
	
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
