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

#include "platform.hpp"
#include "Events.hpp"

wxDEFINE_EVENT(REHex::COMMENT_LEFT_CLICK,     REHex::OffsetLengthEvent);
wxDEFINE_EVENT(REHex::COMMENT_RIGHT_CLICK,    REHex::OffsetLengthEvent);
wxDEFINE_EVENT(REHex::DATA_RIGHT_CLICK,       wxCommandEvent);

wxDEFINE_EVENT(REHex::DATA_ERASING,              REHex::OffsetLengthEvent);
wxDEFINE_EVENT(REHex::DATA_ERASE,                REHex::OffsetLengthEvent);
wxDEFINE_EVENT(REHex::DATA_ERASE_ABORTED,        REHex::OffsetLengthEvent);
wxDEFINE_EVENT(REHex::DATA_INSERTING,            REHex::OffsetLengthEvent);
wxDEFINE_EVENT(REHex::DATA_INSERT,               REHex::OffsetLengthEvent);
wxDEFINE_EVENT(REHex::DATA_INSERT_ABORTED,       REHex::OffsetLengthEvent);
wxDEFINE_EVENT(REHex::DATA_OVERWRITING,          REHex::OffsetLengthEvent);
wxDEFINE_EVENT(REHex::DATA_OVERWRITE,            REHex::OffsetLengthEvent);
wxDEFINE_EVENT(REHex::DATA_OVERWRITE_ABORTED,    REHex::OffsetLengthEvent);

wxDEFINE_EVENT(REHex::CURSOR_UPDATE,    REHex::CursorUpdateEvent);

wxDEFINE_EVENT(REHex::DOCUMENT_TITLE_CHANGED,  REHex::DocumentTitleEvent);

wxDEFINE_EVENT(REHex::FONT_SIZE_ADJUSTMENT_CHANGED, REHex::FontSizeAdjustmentEvent);

wxDEFINE_EVENT(REHex::PALETTE_CHANGED, wxCommandEvent);

REHex::OffsetLengthEvent::OffsetLengthEvent(wxWindow *source, wxEventType event, off_t offset, off_t length):
	wxEvent(source->GetId(), event), offset(offset), length(length)
{
	m_propagationLevel = wxEVENT_PROPAGATE_MAX;
	SetEventObject(source);
}

REHex::OffsetLengthEvent::OffsetLengthEvent(wxObject *source, wxEventType event, off_t offset, off_t length):
	wxEvent(wxID_NONE, event), offset(offset), length(length)
{
	m_propagationLevel = wxEVENT_PROPAGATE_MAX;
	SetEventObject(source);
}

wxEvent *REHex::OffsetLengthEvent::Clone() const
{
	return new OffsetLengthEvent(*this);
}

REHex::CursorUpdateEvent::CursorUpdateEvent(wxWindow *source, off_t cursor_pos, Document::CursorState cursor_state):
	wxEvent(source->GetId(), CURSOR_UPDATE),
	cursor_pos(cursor_pos),
	cursor_state(cursor_state)
{
	m_propagationLevel = wxEVENT_PROPAGATE_MAX;
	SetEventObject(source);
}

REHex::CursorUpdateEvent::CursorUpdateEvent(wxObject *source, off_t cursor_pos, Document::CursorState cursor_state):
	wxEvent(wxID_NONE, CURSOR_UPDATE),
	cursor_pos(cursor_pos),
	cursor_state(cursor_state)
{
	m_propagationLevel = wxEVENT_PROPAGATE_MAX;
	SetEventObject(source);
}

wxEvent *REHex::CursorUpdateEvent::Clone() const
{
	return new CursorUpdateEvent(*this);
}

REHex::DocumentTitleEvent::DocumentTitleEvent(wxWindow *source, const std::string &title):
	wxEvent(source->GetId(), DOCUMENT_TITLE_CHANGED),
	title(title)
{
	m_propagationLevel = wxEVENT_PROPAGATE_MAX;
	SetEventObject(source);
}

REHex::DocumentTitleEvent::DocumentTitleEvent(wxObject *source, const std::string &title):
	wxEvent(wxID_NONE, DOCUMENT_TITLE_CHANGED),
	title(title)
{
	m_propagationLevel = wxEVENT_PROPAGATE_MAX;
	SetEventObject(source);
}

wxEvent *REHex::DocumentTitleEvent::Clone() const
{
	return new DocumentTitleEvent(*this);
}

REHex::FontSizeAdjustmentEvent::FontSizeAdjustmentEvent(int font_size_adjustment):
	wxEvent(wxID_NONE, FONT_SIZE_ADJUSTMENT_CHANGED),
	font_size_adjustment(font_size_adjustment) {}

wxEvent *REHex::FontSizeAdjustmentEvent::Clone() const
{
	return new FontSizeAdjustmentEvent(font_size_adjustment);
}
