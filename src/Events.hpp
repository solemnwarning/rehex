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

#include "document.hpp"

namespace REHex
{
	class OffsetLengthEvent: public wxEvent
	{
		public:
			const off_t offset;
			const off_t length;
			
			OffsetLengthEvent(wxWindow *source, wxEventType event, off_t offset, off_t length);
			OffsetLengthEvent(wxObject *source, wxEventType event, off_t offset, off_t length);
			
			virtual wxEvent *Clone() const override;
	};
	
	typedef void (wxEvtHandler::*OffsetLengthEventFunction)(OffsetLengthEvent&);
	
	#define EVT_OFFSETLENGTH(id, type, func) \
		wx__DECLARE_EVT1(type, id, wxEVENT_HANDLER_CAST(OffsetLengthEventFunction, func))
	
	class CursorUpdateEvent: public wxEvent
	{
		public:
			const off_t cursor_pos;
			const Document::CursorState cursor_state;
			
			CursorUpdateEvent(wxWindow *source, off_t cursor_pos, Document::CursorState cursor_state);
			CursorUpdateEvent(wxObject *source, off_t cursor_pos, Document::CursorState cursor_state);
			
			virtual wxEvent *Clone() const override;
	};
	
	typedef void (wxEvtHandler::*CursorUpdateEventFunction)(CursorUpdateEvent&);
	
	#define EVT_CURSORUPDATE(id, func) \
		wx__DECLARE_EVT1(CURSOR_UPDATE, id, wxEVENT_HANDLER_CAST(CursorUpdateEventFunction, func))
	
	/**
	 * @brief Event raised by a Document when its title changes.
	*/
	class DocumentTitleEvent: public wxEvent
	{
		public:
			const std::string title; /**< @brief The new document title. */
			
			DocumentTitleEvent(wxWindow *source, const std::string &title);
			DocumentTitleEvent(wxObject *source, const std::string &title);
			
			virtual wxEvent *Clone() const override;
	};
	
	typedef void (wxEvtHandler::*DocumentTitleEventFunction)(DocumentTitleEvent&);
	
	#define EVT_DOCUMENTTITLE(id, func) \
		wx__DECLARE_EVT1(DOCUMENT_TITLE_CHANGED, id, wxEVENT_HANDLER_CAST(DocumentTitleEventFunction, func))
	
	/**
	 * @brief Event raised by the App when the font size adjustment is changed.
	*/
	class FontSizeAdjustmentEvent: public wxEvent
	{
		public:
			const int font_size_adjustment; /**< @brief The new font size adjustment value. */
			
			FontSizeAdjustmentEvent(int font_size_adjustment);
			
			virtual wxEvent *Clone() const override;
	};
	
	typedef void (wxEvtHandler::*FontSizeAdjustmentEventFunction)(FontSizeAdjustmentEvent&);
	
	#define EVT_FONTSIZEADJUSTMENT(func) \
		wx__DECLARE_EVT1(FONT_SIZE_ADJUSTMENT_CHANGED, wxID_ANY, wxEVENT_HANDLER_CAST(FontSizeAdjustmentEventFunction, func))
	
	wxDECLARE_EVENT(COMMENT_LEFT_CLICK,     OffsetLengthEvent);
	wxDECLARE_EVENT(COMMENT_RIGHT_CLICK,    OffsetLengthEvent);
	wxDECLARE_EVENT(DATA_RIGHT_CLICK,       wxCommandEvent);
	
	wxDECLARE_EVENT(DATA_ERASING,              OffsetLengthEvent);
	wxDECLARE_EVENT(DATA_ERASE,                OffsetLengthEvent);
	wxDECLARE_EVENT(DATA_ERASE_ABORTED,        OffsetLengthEvent);
	wxDECLARE_EVENT(DATA_INSERTING,            OffsetLengthEvent);
	wxDECLARE_EVENT(DATA_INSERT,               OffsetLengthEvent);
	wxDECLARE_EVENT(DATA_INSERT_ABORTED,       OffsetLengthEvent);
	wxDECLARE_EVENT(DATA_OVERWRITING,          OffsetLengthEvent);
	wxDECLARE_EVENT(DATA_OVERWRITE,            OffsetLengthEvent);
	wxDECLARE_EVENT(DATA_OVERWRITE_ABORTED,    OffsetLengthEvent);
	
	wxDECLARE_EVENT(CURSOR_UPDATE,    CursorUpdateEvent);
	
	wxDECLARE_EVENT(DOCUMENT_TITLE_CHANGED,  DocumentTitleEvent);
	
	wxDECLARE_EVENT(FONT_SIZE_ADJUSTMENT_CHANGED, FontSizeAdjustmentEvent);
	
	wxDECLARE_EVENT(PALETTE_CHANGED, wxCommandEvent);
	
	wxDECLARE_EVENT(BULK_UPDATES_FROZEN, wxCommandEvent);
	wxDECLARE_EVENT(BULK_UPDATES_THAWED, wxCommandEvent);
}

#endif /* !REHEX_EVENTS_HPP */
