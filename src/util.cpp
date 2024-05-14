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

#include "platform.hpp"
#include <ctype.h>
#include <float.h>
#include <inttypes.h>
#include <string>
#include <vector>
#include <wx/clipbrd.h>
#include <wx/filename.h>
#include <wx/utils.h>

#include "App.hpp"
#include "CharacterEncoder.hpp"
#include "DataType.hpp"
#include "document.hpp"
#include "DocumentCtrl.hpp"
#include "SafeWindowPointer.hpp"
#include "util.hpp"

/* These MUST come after any wxWidgets headers. */
#ifdef _WIN32
#include <shlobj.h>
#endif

REHex::ParseError::ParseError(const char *what):
	runtime_error(what) {}

std::vector<unsigned char> REHex::parse_hex_string(const std::string &hex_string)
{
	std::vector<unsigned char> data;
	
	for(size_t at = 0; at < hex_string.length();)
	{
		char this_char = hex_string.at(at++);
		
		if(isspace(this_char))
		{
			continue;
		}
		else if(isxdigit(this_char) && at < hex_string.length())
		{
			char next_char;
			do {
				next_char = hex_string.at(at++);
			} while(at < hex_string.length() && isspace(next_char));
			
			if(at <= hex_string.length() && isxdigit(next_char))
			{
				unsigned char low_nibble  = parse_ascii_nibble(next_char);
				unsigned char high_nibble = parse_ascii_nibble(this_char);
				
				data.push_back(low_nibble | (high_nibble << 4));
				
				continue;
			}
		}
		
		throw ParseError("Invalid hex string");
	}
	
	return data;
}

unsigned char REHex::parse_ascii_nibble(char c)
{
	switch(c)
	{
		case '0':           return 0x0;
		case '1':           return 0x1;
		case '2':           return 0x2;
		case '3':           return 0x3;
		case '4':           return 0x4;
		case '5':           return 0x5;
		case '6':           return 0x6;
		case '7':           return 0x7;
		case '8':           return 0x8;
		case '9':           return 0x9;
		case 'A': case 'a': return 0xA;
		case 'B': case 'b': return 0xB;
		case 'C': case 'c': return 0xC;
		case 'D': case 'd': return 0xD;
		case 'E': case 'e': return 0xE;
		case 'F': case 'f': return 0xF;
		
		default:
			throw ParseError("Invalid hex character");
	}
}

void REHex::file_manager_show_file(const std::string &filename)
{
	wxFileName wxfn(filename);
	wxfn.MakeAbsolute();
	
	#if defined(_WIN32)
		wxString abs_filename = wxfn.GetFullPath();
		
		PIDLIST_ABSOLUTE pidl;
		SFGAOF flags;
		
		if(SHParseDisplayName(abs_filename.wc_str(), NULL, &pidl, 0, &flags) == S_OK)
		{
			SHOpenFolderAndSelectItems(pidl, 0, NULL, 0);
			CoTaskMemFree(pidl);
		}
	#elif defined(__APPLE__)
		wxString abs_filename = wxfn.GetFullPath();
		
		const char *argv[] = { "open", "-R", abs_filename.c_str(), NULL };
		wxExecute((char**)(argv));
	#else
		wxString dirname = wxfn.GetPath();
		
		const char *argv[] = { "xdg-open", dirname.c_str(), NULL };
		wxExecute((char**)(argv));
	#endif
}

REHex::ClipboardGuard::ClipboardGuard()
{
	open = wxTheClipboard->Open();
}

REHex::ClipboardGuard::~ClipboardGuard()
{
	if(open)
	{
		wxTheClipboard->Close();
	}
}

void REHex::ClipboardGuard::close()
{
	if(open)
	{
		wxTheClipboard->Close();
		open = false;
	}
}

std::string REHex::format_offset(off_t offset, OffsetBase base, off_t upper_bound)
{
	char fmt_out[24];
	
	if(upper_bound > 0xFFFFFFFF || offset > 0xFFFFFFFF)
	{
		if(base == OFFSET_BASE_HEX)
		{
			snprintf(fmt_out, sizeof(fmt_out), "%08X:%08X",
				(unsigned int)((offset & 0xFFFFFFFF00000000) >> 32),
				(unsigned int)((offset & 0x00000000FFFFFFFF)));
		}
		else if(base == OFFSET_BASE_DEC)
		{
			snprintf(fmt_out, sizeof(fmt_out), "%019" PRId64, (int64_t)(offset));
		}
	}
	else{
		if(base == OFFSET_BASE_HEX)
		{
			snprintf(fmt_out, sizeof(fmt_out), "%04X:%04X",
				(unsigned int)((offset & 0xFFFF0000) >> 16),
				(unsigned int)((offset & 0x0000FFFF)));
		}
		else if(base == OFFSET_BASE_DEC)
		{
			snprintf(fmt_out, sizeof(fmt_out), "%010" PRId64, (int64_t)(offset));
		}
	}
	
	return fmt_out;
}

std::string REHex::format_offset(BitOffset offset, OffsetBase base, BitOffset upper_bound)
{
	std::string fmt_out = format_offset(offset.byte(), base, upper_bound.byte());
	
	if(!offset.byte_aligned())
	{
		fmt_out += "+" + std::to_string(offset.bit()) + "b";
	}
	
	return fmt_out;
}

void REHex::copy_from_doc(REHex::Document *doc, REHex::DocumentCtrl *doc_ctrl, wxWindow *dialog_parent, bool cut)
{
	Document::CursorState cursor_state = doc_ctrl->get_cursor_state();
	
	OrderedBitRangeSet selection = doc_ctrl->get_selection_ranges();
	
	if(selection.empty())
	{
		/* Nothing selected - nothing to copy. */
		wxBell();
		return;
	}
	
	if(cut)
	{
		for(auto s = selection.begin(); s != selection.end(); ++s)
		{
			if(!s->offset.byte_aligned() || !s->length.byte_aligned())
			{
				/* Selection isn't byte-aligned - can't cut */
				wxBell();
				return;
			}
		}
	}
	
	wxDataObject *copy_data = NULL;
	
	/* If the selection is contained within a single Region, give it the chance to do something
	 * special rather than just copying out the hex/ASCII for the selection.
	 *
	 * TODO: Check how much space will be needed and warn the user like below...
	*/
	
	if(selection.size() == 1)
	{
		REHex::DocumentCtrl::GenericDataRegion *selection_region = doc_ctrl->data_region_by_offset(selection[0].offset);
		assert(selection_region != NULL);
		
		assert(selection_region->d_offset <= selection[0].offset);
		
		if((selection_region->d_offset + selection_region->d_length) >= (selection[0].offset + selection[0].length))
		{
			copy_data = selection_region->OnCopy(*doc_ctrl);
		}
	}
	
	/* Warn the user this might be a bad idea before dumping silly amounts
	 * of data (>16MiB) into the clipboard.
	*/
	
	static size_t COPY_MAX_SOFT = 16777216;
	
	size_t upper_limit = cursor_state == Document::CSTATE_ASCII
		? selection.total_bytes().byte()
		: (selection.total_bytes().byte() * 2);
	
	if(copy_data == NULL && upper_limit > COPY_MAX_SOFT)
	{
		char msg[128];
		snprintf(msg, sizeof(msg),
			"You are about to copy %uMB into the clipboard.\n"
			"This may take a long time and/or crash some applications.",
			(unsigned)(upper_limit / 1000000));
		
		int result = wxMessageBox(msg, "Warning", (wxOK | wxCANCEL | wxICON_EXCLAMATION), dialog_parent);
		if(result != wxOK)
		{
			return;
		}
	}
	
	if(copy_data == NULL)
	{
		try {
			wxString data_string;
			data_string.reserve(upper_limit);
			
			const BitRangeMap<Document::TypeInfo> &types = doc->get_data_types();
			
			for(auto sr = selection.begin(); sr != selection.end(); ++sr)
			{
				if(!sr->length.byte_aligned())
				{
					/* Can't copy a sub-byte quantity. */
					wxBell();
					return;
				}
				
				std::vector<unsigned char> selection_data = doc->read_data(sr->offset, sr->length.byte());
				assert((off_t)(selection_data.size()) == sr->length.byte());
				
				if(cursor_state == Document::CSTATE_ASCII)
				{
					for(size_t sd_off = 0; sd_off < selection_data.size();)
					{
						auto type_at_off = types.get_range(sr->offset + (off_t)(sd_off));
						assert(type_at_off != types.end());
						
						static REHex::CharacterEncoderASCII ascii_encoder;
						const CharacterEncoder *encoder = &ascii_encoder;
						if(type_at_off->second.name != "")
						{
							std::shared_ptr<const DataType> dt_reg = DataTypeRegistry::get_type(type_at_off->second.name, type_at_off->second.options);
							assert(dt_reg != NULL);
							
							if(dt_reg->encoder != NULL)
							{
								encoder = dt_reg->encoder;
							}
						}
						
						/* TODO: Should we restrict to printable characters here? */
						EncodedCharacter ec = encoder->decode((selection_data.data() + sd_off), (selection_data.size() - sd_off));
						
						if(ec.valid)
						{
							data_string.append(wxString::FromUTF8(ec.utf8_char().c_str()));
							sd_off += ec.encoded_char().size();
						}
						else{
							/* Ignore invalid characters. */
							++sd_off;
						}
					}
				}
				else{
					for(auto c = selection_data.begin(); c != selection_data.end(); ++c)
					{
						const char *nibble_to_hex = "0123456789ABCDEF";
						
						unsigned char high_nibble = (*c & 0xF0) >> 4;
						unsigned char low_nibble  = (*c & 0x0F);
						
						data_string.append(&(nibble_to_hex[high_nibble]), 1);
						data_string.append(&(nibble_to_hex[low_nibble]), 1);
					}
				}
			}
			
			if(!data_string.empty())
			{
				copy_data = new wxTextDataObject(data_string);
			}
		}
		catch(const std::bad_alloc &)
		{
			wxMessageBox(
				"Memory allocation failed while preparing clipboard buffer.",
				"Error", (wxOK | wxICON_ERROR), dialog_parent);
			return;
		}
		catch(const std::exception &e)
		{
			wxMessageBox(e.what(), "Error", (wxOK | wxICON_ERROR), dialog_parent);
			return;
		}
	}
	
	if(copy_data != NULL)
	{
		ClipboardGuard cg;
		if(cg)
		{
			wxTheClipboard->SetData(copy_data);
			
			if(cut)
			{
				ScopedTransaction t(doc, "cut selection");
				
				for(auto sr = selection.begin(); sr != selection.end(); ++sr)
				{
					doc->erase_data(sr->offset.byte(), sr->length.byte());
				}
				
				t.commit();
			}
		}
		else{
			delete copy_data;
		}
	}
}

class GenuineImmitationMouseCapture
{
	public:
		GenuineImmitationMouseCapture(wxWindow *window);
	
	private:
		REHex::SafeWindowPointer<wxWindow> window;
		wxTimer timer;
		bool left_was_down;
		wxPoint last_mouse_pos;
		
		void OnTimer(wxTimerEvent &event);
		void OnWindowDestroy(wxWindowDestroyEvent &event);
};

GenuineImmitationMouseCapture::GenuineImmitationMouseCapture(wxWindow *window):
	window(window)
{
	left_was_down = wxGetMouseState().LeftIsDown();
	last_mouse_pos = wxGetMousePosition();
	
	timer.Bind(wxEVT_TIMER, &GenuineImmitationMouseCapture::OnTimer, this);
	this->window.auto_cleanup_bind(wxEVT_DESTROY, &GenuineImmitationMouseCapture::OnWindowDestroy, this);
	
	timer.Start(50, wxTIMER_CONTINUOUS);
}

void GenuineImmitationMouseCapture::OnTimer(wxTimerEvent &event)
{
	if(!window->HasCapture()) /* Detect if the window has called ReleaseMouse() */
	{
		timer.Stop();
		
		window->CallAfter([this]()
		{
			/* Destroying the timer in its event handler would probably do bad things. */
			delete this;
		});
		
		return;
	}
	
	wxMouseState mouse_state = wxGetMouseState();
	wxPoint mouse_pos = wxGetMousePosition();
	
	if(mouse_pos != last_mouse_pos)
	{
		last_mouse_pos = mouse_pos;
		
		wxMouseEvent e(wxEVT_MOTION);
		window->ProcessWindowEvent(e);
	}
	
	if(left_was_down && !mouse_state.LeftIsDown())
	{
		left_was_down = false;
		
		wxMouseEvent e(wxEVT_LEFT_UP);
		window->ProcessWindowEvent(e);
	}
	else if(!left_was_down && mouse_state.LeftIsDown())
	{
		left_was_down = true;
		
		wxMouseEvent e(wxEVT_LEFT_DOWN);
		window->ProcessWindowEvent(e);
	}
}

void GenuineImmitationMouseCapture::OnWindowDestroy(wxWindowDestroyEvent &event)
{
	if(event.GetEventObject() == window)
	{
		delete this;
	}
	
	event.Skip();
}

void REHex::fake_broken_mouse_capture(wxWindow *window)
{
	if(!window->HasCapture())
	{
		/* Window isn't trying to capture the mouse... probably? */
		return;
	}
	
	new GenuineImmitationMouseCapture(window);
}

std::string REHex::document_save_as_dialog(wxWindow *modal_parent, Document *document)
{
	std::string dir, name;
	std::string doc_filename = document->get_filename();
	
	if(doc_filename != "")
	{
		wxFileName wxfn(doc_filename);
		wxfn.MakeAbsolute();
		
		dir  = wxfn.GetPath();
		name = wxfn.GetFullName();
	}
	else{
		dir  = wxGetApp().get_last_directory();
		name = "";
	}
	
	wxFileDialog saveFileDialog(modal_parent, "Save As", dir, name, "", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
	if(saveFileDialog.ShowModal() == wxID_CANCEL)
		return "";
	
	std::string filename = saveFileDialog.GetPath().ToStdString();
	
	{
		wxFileName wxfn(filename);
		wxString dirname = wxfn.GetPath();
		
		wxGetApp().set_last_directory(dirname.ToStdString());
	}
	
	return filename;
}

float REHex::parse_float(const std::string &s)
{
	if(s.length() == 0)
	{
		/* String is empty */
		throw ParseErrorEmpty();
	}
	
	if(s.find_first_not_of("\t ") == std::string::npos)
	{
		/* String contains only whitespace */
		throw ParseErrorEmpty();
	}
	
	errno = 0;
	char *endptr;
	
	float n = strtof(s.c_str(), &endptr);
	
	if(*endptr != '\0')
	{
		/* Invalid characters */
		throw ParseErrorFormat();
	}
	if((n == HUGE_VALF || n == FLT_MIN) && errno == ERANGE)
	{
		/* Out of range of float */
		throw ParseErrorRange();
	}
	
	return n;
}

double REHex::parse_double(const std::string &s)
{
	if(s.length() == 0)
	{
		/* String is empty */
		throw ParseErrorEmpty();
	}
	
	if(s.find_first_not_of("\t ") == std::string::npos)
	{
		/* String contains only whitespace */
		throw ParseErrorEmpty();
	}
	
	errno = 0;
	char *endptr;
	
	double n = strtod(s.c_str(), &endptr);
	
	if(*endptr != '\0')
	{
		/* Invalid characters */
		throw ParseErrorFormat();
	}
	if((n == HUGE_VAL || n == DBL_MIN) && errno == ERANGE)
	{
		/* Out of range of float */
		throw ParseErrorRange();
	}
	
	return n;
}

REHex::CarryBits REHex::memcpy_left(void *dst, const void *src, size_t n, int shift)
{
	if(shift == 0)
	{
		memcpy(dst, src, n);
		return CarryBits();
	}
	
	/* shift = 1, mask_a = 01111111, mask_b = 10000000
	 * shift = 2, mask_a = 00111111, mask_b = 11000000
	 * shift = 3, mask_a = 00011111, mask_b = 11100000
	 * shift = 4, mask_a = 00001111, mask_b = 11110000
	 * shift = 5, mask_a = 00000111, mask_b = 11111000
	 * shift = 6, mask_a = 00000011, mask_b = 11111100
	 * shift = 7, mask_a = 00000001, mask_b = 11111110
	*/
	
	unsigned char mask_a = 0xFF;
	unsigned char mask_b = 0x00;
	
	for(int i = 0; i < shift; ++i)
	{
		mask_a &= ~((unsigned char)(128) >> i);
		mask_b |=  ((unsigned char)(128) >> i);
	}
	
	int rshift = 8 - shift;
	
	unsigned char *dst_p = (unsigned char*)(dst);
	const unsigned char *src_p = (const unsigned char*)(src);
	
	unsigned char carry = 0;
	unsigned char carry_mask = 0;
	if(n > 1)
	{
		carry = (*src_p & mask_b) >> rshift;
		
		for(int i = 0; i < shift; ++i)
		{
			carry_mask <<= 1;
			carry_mask |= 1;
		}
	}
	
	while(n > 1)
	{
		*dst_p = ((*src_p & mask_a) << shift) | ((*(src_p + 1) & mask_b) >> rshift);
		++src_p;
		++dst_p;
		--n;
	}
	
	if(n > 0)
	{
		*dst_p = (*src_p & mask_a) << shift;
	}
	
	return CarryBits(carry, carry_mask);
}

REHex::CarryBits REHex::memcpy_right(void *dst, const void *src, size_t n, int shift)
{
	if(shift == 0 || n == 0)
	{
		memcpy(dst, src, n);
		return CarryBits();
	}
	
	/* shift = 1, mask_a = 11111110, mask_b = 00000001
	 * shift = 2, mask_a = 11111100, mask_b = 00000011
	 * shift = 3, mask_a = 11111000, mask_b = 00000111
	 * shift = 4, mask_a = 11110000, mask_b = 00001111
	 * shift = 5, mask_a = 11100000, mask_b = 00011111
	 * shift = 6, mask_a = 11000000, mask_b = 00111111
	 * shift = 7, mask_a = 10000000, mask_b = 01111111
	*/
	
	unsigned char mask_a = 0xFF;
	unsigned char mask_b = 0x00;
	
	for(int i = 0; i < shift; ++i)
	{
		mask_a &= ~((unsigned char)(1) << i);
		mask_b |=  ((unsigned char)(1) << i);
	}
	
	int lshift = 8 - shift;
	
	unsigned char *dst_p = (unsigned char*)(dst);
	const unsigned char *src_p = (const unsigned char*)(src);
	
	*dst_p &= ~(mask_a >> shift);
	*dst_p |= ((*src_p & mask_a) >> shift);
	--n;
	
	while(n > 0)
	{
		*(++dst_p) = ((*src_p & mask_b) << lshift) | ((*(src_p + 1) & mask_a) >> shift);
		++src_p;
		--n;
	}
	
	return CarryBits(((*src_p & mask_b) << lshift), (mask_b << lshift));
}

template<> REHex::BitOffset REHex::add_clamp_overflow(BitOffset a, BitOffset b, bool *overflow)
{
	return _add_clamp_overflow(a, b, overflow, BitOffset::MIN, BitOffset::MAX, BitOffset::ZERO);
}

json_t *REHex::colour_to_json(const wxColour &colour)
{
	std::string s = colour_to_string(colour);
	return json_string(s.c_str());
}

wxColour REHex::colour_from_json(const json_t *json)
{
	const char *s = json_string_value(json);
	
	if(s == NULL)
	{
		throw std::invalid_argument("Invalid colour (expected a string of 6 hex digits)");
	}
	
	return colour_from_string(s);
}

std::string REHex::colour_to_string(const wxColour &colour)
{
	char s[16];
	snprintf(s, sizeof(s), "%02x%02x%02x", (int)(colour.Red()), (int)(colour.Green()), (int)(colour.Blue()));
	
	return s;
}

wxColour REHex::colour_from_string(const std::string &s)
{
	if(s.length() != 6
		|| std::find_if(s.begin(), s.end(), [](char c) { return !isxdigit(c); }) != s.end())
	{
		throw std::invalid_argument("Invalid colour (expected a string of 6 hex digits)");
	}
	
	char rs[] = { s[0], s[1], '\0' };
	char gs[] = { s[2], s[3], '\0' };
	char bs[] = { s[4], s[5], '\0' };
	
	int red = strtol(rs, NULL, 16);
	int green = strtol(gs, NULL, 16);
	int blue = strtol(bs, NULL, 16);
	
	return wxColour(red, green, blue);
}
