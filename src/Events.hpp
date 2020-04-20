/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_EVENTS_HPP
#define REHEX_EVENTS_HPP

#include <sys/types.h>
#include <wx/event.h>
#include <wx/window.h>

namespace REHex
{
	class OffsetLengthEvent: public wxEvent
	{
		private:
			off_t c_offset;
			off_t c_length;
			
		public:
			OffsetLengthEvent(wxWindow *source, wxEventType event, off_t c_offset, off_t c_length):
				wxEvent(source->GetId(), event), c_offset(c_offset), c_length(c_length)
			{
				SetEventObject(source);
			}
			
			virtual wxEvent *Clone() const override
			{
				return new OffsetLengthEvent(*this);
			}
			
			off_t comment_offset() const;
			off_t comment_length() const;
			
		// DECLARE_DYNAMIC_CLASS(OffsetLengthEvent)
	};
	
	wxDECLARE_EVENT(COMMENT_LEFT_CLICK,     OffsetLengthEvent);
	wxDECLARE_EVENT(COMMENT_RIGHT_CLICK,    OffsetLengthEvent);
	wxDECLARE_EVENT(DATA_RIGHT_CLICK,       wxCommandEvent);
}

#endif /* !REHEX_EVENTS_HPP */
