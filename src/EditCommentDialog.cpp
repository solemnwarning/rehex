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

#include "document.hpp"
#include "EditCommentDialog.hpp"
#include "textentrydialog.hpp"

void REHex::EditCommentDialog::run_modal(wxWindow *parent, Document *doc, off_t offset, off_t length)
{
	const NestedOffsetLengthMap<Document::Comment> &comments = doc->get_comments();
	auto old_comment = comments.find(NestedOffsetLengthMapKey(offset, length));
	
	wxString old_comment_text = old_comment != comments.end()
		? *(old_comment->second.text)
		: "";
	
	REHex::TextEntryDialog te(parent, "Enter comment", old_comment_text);
	
	int rc = te.ShowModal();
	if(rc == wxID_OK)
	{
		wxString new_comment_text = te.get_text();
		
		if(new_comment_text.empty() && old_comment_text.empty())
		{
			return;
		}
		
		if(new_comment_text.empty())
		{
			doc->erase_comment(offset, length);
		}
		else{
			doc->set_comment(offset, length, new_comment_text);
		}
	}
}
