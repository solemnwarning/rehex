/* Reverse Engineer's Hex Editor
 * Copyright (C) 2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "App.hpp"
#include "GotoOffsetDialog.hpp"

BEGIN_EVENT_TABLE(REHex::GotoOffsetDialog, REHex::NumericEntryDialog<REHex::BitOffset>)
	EVT_BUTTON(wxID_OK,     REHex::GotoOffsetDialog::OnOK)
	EVT_BUTTON(wxID_CANCEL, REHex::GotoOffsetDialog::OnCancel)
	
	EVT_CLOSE(REHex::GotoOffsetDialog::OnClose)
END_EVENT_TABLE()

REHex::GotoOffsetDialog::GotoOffsetDialog(wxWindow *parent, const SharedDocumentPointer &document):
	NumericEntryDialog(
		parent,
		"Jump to offset",
		"Prefix offset with -/+ to jump relative to current cursor position",
		document->get_cursor_position(),
		BitOffset::ZERO,
		BitOffset::MAX,
		document->get_cursor_position(),
		get_last_base()),
	document(document),
	is_modal(false)
{
	this->document.auto_cleanup_bind(CURSOR_UPDATE, &REHex::GotoOffsetDialog::OnDocumentCursorUpdate, this);
}

int REHex::GotoOffsetDialog::ShowModal()
{
	bool was_modal = is_modal;
	
	is_modal = true;
	int result = wxDialog::ShowModal();
	is_modal = was_modal;
	
	return result;
}

REHex::NumericEntryDialog<REHex::BitOffset>::BaseHint REHex::GotoOffsetDialog::get_last_base()
{
	NumericEntryDialog<BitOffset>::BaseHint base;
	switch(wxGetApp().settings->get_goto_offset_base())
	{
		case GotoOffsetBase::AUTO:
			base = NumericEntryDialog<BitOffset>::BaseHint::AUTO;
			break;
		
		case GotoOffsetBase::OCT:
			base = NumericEntryDialog<BitOffset>::BaseHint::OCT;
			break;
		
		case GotoOffsetBase::DEC:
			base = NumericEntryDialog<BitOffset>::BaseHint::DEC;
			break;
		
		case GotoOffsetBase::HEX:
			base = NumericEntryDialog<BitOffset>::BaseHint::HEX;
			break;
	}
	
	return base;
}

void REHex::GotoOffsetDialog::OnDocumentCursorUpdate(CursorUpdateEvent &event)
{
	set_rel_base(event.cursor_pos);
	event.Skip(); /* Continue propagation. */
}

void REHex::GotoOffsetDialog::OnOK(wxCommandEvent &event)
{
	NumericEntryDialog<BitOffset>::BaseHint base = GetBase();
	
	switch(base)
	{
		case NumericEntryDialog<BitOffset>::BaseHint::AUTO:
			wxGetApp().settings->set_goto_offset_base(GotoOffsetBase::AUTO);
			break;
			
		case NumericEntryDialog<BitOffset>::BaseHint::OCT:
			wxGetApp().settings->set_goto_offset_base(GotoOffsetBase::OCT);
			break;
			
		case NumericEntryDialog<BitOffset>::BaseHint::DEC:
			wxGetApp().settings->set_goto_offset_base(GotoOffsetBase::DEC);
			break;
			
		case NumericEntryDialog<BitOffset>::BaseHint::HEX:
			wxGetApp().settings->set_goto_offset_base(GotoOffsetBase::HEX);
			break;
			
		default:
			/* Unreachable. */
			abort();
	}
	
	/* TODO: Check position is valid. */
	
	document->set_cursor_position(GetValue());
	
	if(is_modal)
	{
		Close();
	}
}

void REHex::GotoOffsetDialog::OnCancel(wxCommandEvent &event)
{
	Close();
}

void REHex::GotoOffsetDialog::OnClose(wxCloseEvent &event)
{
	Destroy();
}
