/* Reverse Engineer's Hex Editor
 * Copyright (C) 2022-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "RangeChoiceLinear.hpp"
#include "RangeDialog.hpp"
#include "util.hpp"

enum {
	WHOLE_FILE = 0,
	FOLLOW_SELECTION,
	CURRENT_SELECTION,
	ENTER_RANGE,
	FIXED_RANGE,
};

REHex::RangeChoiceLinear::RangeChoiceLinear(wxWindow *parent, wxWindowID id, SharedDocumentPointer &document, DocumentCtrl *doc_ctrl):
	wxChoice(parent, id),
	document(document),
	doc_ctrl(doc_ctrl),
	allow_bit_aligned_offset(false),
	allow_bit_aligned_length(false),
	current_selection(WHOLE_FILE),
	current_offset(0),
	current_length(document->buffer_length()),
	fixed_offset(0),
	fixed_length(0)
{
	Append("Whole file");
	Append("Follow selection");
	Append("Current selection");
	Append("Enter range...");
	
	/* Stop the control from growing if a long fixed offset happens to be entered. */
	
	wxSize max_size(0, 0);
	for(unsigned int i = 0, count = GetCount(); i < count; ++i)
	{
		wxSize this_size = GetSizeFromTextSize(GetTextExtent(GetString(i)));
		
		/* GetSizeFromTextSize() isn't implemented on macOS, so handle that case and fall back to
		 * using the system-provided "best" size as the target size.
		*/
		if(this_size.GetWidth() <= 0 || this_size.GetHeight() <= 0)
		{
			max_size = GetBestSize();
			break;
		}
		
		if(this_size.GetWidth() > max_size.GetWidth())
		{
			max_size.SetWidth(this_size.GetWidth());
		}
		
		if(this_size.GetHeight() > max_size.GetHeight())
		{
			max_size.SetHeight(this_size.GetHeight());
		}
	}
	
	SetMaxSize(max_size);
	SetSize(max_size);
	
	SetSelection(WHOLE_FILE);
	
	Bind(wxEVT_CHOICE, &REHex::RangeChoiceLinear::OnChoice, this);
	
	document->Bind(DATA_ERASE, &REHex::RangeChoiceLinear::OnDocumentDataErase, this);
	document->Bind(DATA_INSERT, &REHex::RangeChoiceLinear::OnDocumentDataInsert, this);
	
	this->doc_ctrl.auto_cleanup_bind(EV_SELECTION_CHANGED, &REHex::RangeChoiceLinear::OnSelectionChanged, this);
}

REHex::RangeChoiceLinear::~RangeChoiceLinear()
{
	document->Unbind(DATA_INSERT, &REHex::RangeChoiceLinear::OnDocumentDataInsert, this);
	document->Unbind(DATA_ERASE, &REHex::RangeChoiceLinear::OnDocumentDataErase, this);
}

std::pair<REHex::BitOffset, REHex::BitOffset> REHex::RangeChoiceLinear::get_range() const
{
	return std::make_pair(current_offset, current_length);
}

bool REHex::RangeChoiceLinear::is_whole_file() const
{
	return GetSelection() == WHOLE_FILE;
}

void REHex::RangeChoiceLinear::set_whole_file()
{
	current_selection = WHOLE_FILE;
	clear_fixed_range();
	
	SetSelection(current_selection);
	update_range();
}

void REHex::RangeChoiceLinear::set_follow_selection()
{
	current_selection = FOLLOW_SELECTION;
	clear_fixed_range();
	
	SetSelection(current_selection);
	update_range();
}

void REHex::RangeChoiceLinear::set_allow_bit_aligned_offset(bool allow_bit_aligned_offset)
{
	this->allow_bit_aligned_offset = allow_bit_aligned_offset;
}

void REHex::RangeChoiceLinear::set_allow_bit_aligned_length(bool allow_bit_aligned_length)
{
	this->allow_bit_aligned_length = allow_bit_aligned_length;
}

void REHex::RangeChoiceLinear::update_range()
{
	BitOffset new_offset, new_length;
	
	switch(GetSelection())
	{
		case WHOLE_FILE:
			new_offset = BitOffset(0, 0);
			new_length = BitOffset(document->buffer_length(), 0);
			break;
			
		case FOLLOW_SELECTION:
		{
			BitOffset selection_offset, selection_length;
			std::tie(selection_offset, selection_length) = doc_ctrl->get_selection_linear();
			
			if(selection_length > BitOffset::ZERO
				&& (allow_bit_aligned_offset || selection_offset.byte_aligned())
				&& (allow_bit_aligned_length || selection_length.byte_aligned()))
			{
				new_offset = selection_offset;
				new_length = selection_length;
			}
			else{
				new_offset = new_length = BitOffset::ZERO;
			}
			
			break;
		}
		
		case FIXED_RANGE:
			new_offset = fixed_offset;
			new_length = fixed_length;
			break;
			
		default:
			return; /* Unreachable. */
	}
	
	if(new_offset != current_offset || new_length != current_length)
	{
		current_offset = new_offset;
		current_length = new_length;
		
		wxCommandEvent event(EV_SELECTION_CHANGED, GetId());
		event.SetEventObject(this);
		
		ProcessEvent(event);
	}
}

void REHex::RangeChoiceLinear::set_fixed_range(BitOffset offset, BitOffset length)
{
	std::string first_s = format_offset(offset, doc_ctrl->get_offset_display_base(), document->buffer_length());
	std::string last_s  = format_offset((offset + length - 1), doc_ctrl->get_offset_display_base(), document->buffer_length());
	std::string s = first_s + " - " + last_s;
	
	#if 0
	if(GetSizeFromTextSize(GetTextExtent(s)).GetWidth() > GetSize().GetWidth())
	{
		while(GetSizeFromTextSize(GetTextExtent(s + "...")).GetWidth() > GetSize().GetWidth())
		{
			s.pop_back();
		}
		
		s += "...";
	}
	#endif
	
	if(fixed_length > BitOffset::ZERO)
	{
		SetString(FIXED_RANGE, s);
	}
	else{
		Append(s);
	}
	
	#if 0
	wxSizer *in_sizer = GetContainingSizer();
	if(in_sizer != NULL)
	{
		in_sizer->Layout();
	}
	#endif
	
	fixed_offset = offset;
	fixed_length = length;
	
	SetSelection(FIXED_RANGE);
	current_selection = FIXED_RANGE;
}

void REHex::RangeChoiceLinear::clear_fixed_range()
{
	if(fixed_length > BitOffset::ZERO)
	{
		fixed_offset = fixed_length = BitOffset::ZERO;
		Delete(FIXED_RANGE);
	}
}

void REHex::RangeChoiceLinear::OnChoice(wxCommandEvent &event)
{
	switch(GetSelection())
	{
		case WHOLE_FILE:
		case FOLLOW_SELECTION:
			clear_fixed_range();
			current_selection = GetSelection();
			break;
			
		case CURRENT_SELECTION:
		{
			std::pair<BitOffset, BitOffset> selection = doc_ctrl->get_selection_linear();
			if(selection.second > BitOffset::ZERO
				&& (allow_bit_aligned_offset || selection.first.byte_aligned())
				&& (allow_bit_aligned_length || selection.second.byte_aligned()))
			{
				set_fixed_range(selection.first, selection.second);
			}
			else{
				wxBell();
				SetSelection(current_selection);
			}
			
			break;
		}
		
		case ENTER_RANGE:
		{
			RangeDialog rd(this, doc_ctrl, "Enter range", false, allow_bit_aligned_offset, allow_bit_aligned_length);
			
			int s = rd.ShowModal();
			if(s == wxID_OK)
			{
				std::pair<BitOffset, BitOffset> range = rd.get_range_linear();
				set_fixed_range(range.first, range.second);
			}
			else{
				SetSelection(current_selection);
			}
			
			break;
		}
		
		default:
			/* Unreachable. */
			abort();
	}
	
	update_range();
}

void REHex::RangeChoiceLinear::OnDocumentDataErase(OffsetLengthEvent &event)
{
	update_range();
	event.Skip();
}

void REHex::RangeChoiceLinear::OnDocumentDataInsert(OffsetLengthEvent &event)
{
	update_range();
	event.Skip();
}

void REHex::RangeChoiceLinear::OnSelectionChanged(wxCommandEvent &event)
{
	if(current_selection == FOLLOW_SELECTION)
	{
		update_range();
	}
	
	event.Skip();
}
