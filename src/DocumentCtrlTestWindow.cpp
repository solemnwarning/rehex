#include <list>
#include <string>
#include <wx/clipbrd.h>
#include <wx/frame.h>

#include "DocumentCtrlTestWindow.hpp"
#include "NestedOffsetLengthMap.hpp"
#include "util.hpp"

using namespace REHex;

BEGIN_EVENT_TABLE(REHex::DocumentCtrlTestWindow, wxFrame)
	EVT_CHAR(REHex::DocumentCtrlTestWindow::OnChar)
	
	EVT_OFFSETLENGTH(wxID_ANY, REHex::COMMENT_LEFT_CLICK,  REHex::DocumentCtrlTestWindow::OnCommentLeftClick)
	EVT_OFFSETLENGTH(wxID_ANY, REHex::COMMENT_RIGHT_CLICK, REHex::DocumentCtrlTestWindow::OnCommentRightClick)
END_EVENT_TABLE()

/* Is the given byte a printable 7-bit ASCII character? */
static bool isasciiprint(int c)
{
	return (c >= ' ' && c <= '~');
}

/* Is the given value a 7-bit ASCII character representing a hex digit? */
static bool isasciihex(int c)
{
	return (c >= '0' && c <= '9')
		|| (c >= 'A' && c <= 'F')
		|| (c >= 'a' && c <= 'f');
}

void REHex::DocumentCtrlTestWindow::reinit_regions()
{
	auto comments = doc->get_comments();
	
	Document::InlineCommentMode icm = doc->get_inline_comment_mode();
	bool nest = (icm == Document::ICM_SHORT_INDENT || icm == Document::ICM_FULL_INDENT);
	bool truncate = (icm == Document::ICM_SHORT || icm == Document::ICM_SHORT_INDENT);
	
	/* Construct a list of interlaced comment/data regions. */
	
	auto offset_base = comments.begin();
	off_t next_data = 0, remain_data = doc->buffer_length();
	
	std::list<DocumentCtrl::Region*> regions;
	
	while(remain_data > 0)
	{
		off_t dr_length = remain_data;
		
		assert(offset_base == comments.end() || offset_base->first.offset >= next_data);
		
		/* We process any comments at the same offset from largest to smallest, ensuring
		 * smaller comments are parented to the next-larger one at the same offset.
		 *
		 * This could be optimised by changing the order of keys in the comments map, but
		 * that'll probably break something...
		*/
		
		if(offset_base != comments.end() && offset_base->first.offset == next_data)
		{
			auto next_offset = offset_base;
			while(next_offset != comments.end() && next_offset->first.offset == offset_base->first.offset)
			{
				++next_offset;
			}
			
			auto c = next_offset;
			do {
				--c;
				
				regions.push_back(new DocumentCtrl::CommentRegion(c->first.offset, c->first.length, *(c->second.text), nest, truncate));
				
				if(nest && c->first.length > 0)
				{
					assert(c->first.length <= dr_length);
					dr_length = c->first.length;
				}
			} while(c != offset_base);
			
			offset_base = next_offset;
		}
		
		if(offset_base != comments.end() && dr_length > (offset_base->first.offset - next_data))
		{
			dr_length = offset_base->first.offset - next_data;
		}
		
		regions.push_back(new DocumentCtrl::DataRegionDocHighlight(next_data, dr_length, *doc));
		
		next_data   += dr_length;
		remain_data -= dr_length;
	}
	
	if(regions.empty())
	{
		assert(doc->buffer_length() == 0);
		
		/* Empty buffers need a data region too! */
		regions.push_back(new DocumentCtrl::DataRegionDocHighlight(0, 0, *doc));
	}
	
	doc_ctrl->replace_all_regions(regions);
}

REHex::DocumentCtrlTestWindow::DocumentCtrlTestWindow(Document *doc):
	wxFrame(NULL, wxID_ANY, std::string("DocumentCtrl test (") + doc->get_title() + ")", wxDefaultPosition, wxSize(740, 540)),
	doc(doc)
{
	doc_ctrl = new DocumentCtrl(this, doc);
	
	doc->Bind(EV_COMMENT_MODIFIED,   [this](wxCommandEvent &event) { reinit_regions(); event.Skip(); });
	doc->Bind(EV_HIGHLIGHTS_CHANGED, [this](wxCommandEvent &event) { doc_ctrl->Refresh(); event.Skip(); });
	
	doc->Bind(DATA_ERASE,     [this](OffsetLengthEvent &event) { reinit_regions(); event.Skip(); });
	doc->Bind(DATA_INSERT,    [this](OffsetLengthEvent &event) { reinit_regions(); event.Skip(); });
	doc->Bind(DATA_OVERWRITE, [this](OffsetLengthEvent &event) { doc_ctrl->Refresh(); event.Skip(); });
	
	doc->Bind(CURSOR_UPDATE, [this](CursorUpdateEvent &event) { doc_ctrl->set_cursor_position(event.cursor_pos, event.cursor_state); event.Skip(); });
	
	doc_ctrl->Bind(CURSOR_UPDATE, [this](CursorUpdateEvent &event) { this->doc->set_cursor_position(event.cursor_pos, event.cursor_state); event.Skip(); });
	
	reinit_regions();
}

REHex::DocumentCtrlTestWindow::~DocumentCtrlTestWindow() {}

void REHex::DocumentCtrlTestWindow::OnChar(wxKeyEvent &event)
{
	int key       = event.GetKeyCode();
	int modifiers = event.GetModifiers();
	
	off_t cursor_pos = doc_ctrl->get_cursor_position();
	
	auto selection = doc_ctrl->get_selection();
	off_t selection_off = selection.first;
	off_t selection_length = selection.second;
	
	bool insert_mode = doc_ctrl->get_insert_mode();
	
	Document::CursorState cursor_state = doc_ctrl->get_cursor_state();
	
	if(cursor_state != Document::CSTATE_ASCII && (modifiers == wxMOD_NONE || modifiers == wxMOD_SHIFT) && isasciihex(key))
	{
		unsigned char nibble = REHex::parse_ascii_nibble(key);
		
		if(cursor_state == Document::CSTATE_HEX_MID)
		{
			/* Overwrite least significant nibble of current byte, then move onto
			 * inserting or overwriting at the next byte.
			*/
			
			std::vector<unsigned char> cur_data = doc->read_data(cursor_pos, 1);
			assert(cur_data.size() == 1);
			
			unsigned char old_byte = cur_data[0];
			unsigned char new_byte = (old_byte & 0xF0) | nibble;
			
			doc->overwrite_data(cursor_pos, &new_byte, 1, cursor_pos + 1, Document::CSTATE_HEX, "change data");
		}
		else if(insert_mode)
		{
			/* Inserting a new byte. Initialise the most significant nibble then move
			 * onto overwriting the least significant.
			*/
			
			unsigned char byte = (nibble << 4);
			doc->insert_data(cursor_pos, &byte, 1, cursor_pos, Document::CSTATE_HEX_MID, "change data");
		}
		else{
			/* Overwrite most significant nibble of current byte, then move onto
			 * overwriting the least significant.
			*/
			
			std::vector<unsigned char> cur_data = doc->read_data(cursor_pos, 1);
			
			if(!cur_data.empty())
			{
				unsigned char old_byte = cur_data[0];
				unsigned char new_byte = (old_byte & 0x0F) | (nibble << 4);
				
				doc->overwrite_data(cursor_pos, &new_byte, 1, cursor_pos, Document::CSTATE_HEX_MID, "change data");
			}
		}
		
		doc_ctrl->clear_selection();
		
		/* TODO: Limit paint to affected area */
		this->Refresh();
	}
	else if(cursor_state == Document::CSTATE_ASCII && (modifiers == wxMOD_NONE || modifiers == wxMOD_SHIFT) && isasciiprint(key))
	{
		unsigned char byte = key;
		
		if(insert_mode)
		{
			doc->insert_data(cursor_pos, &byte, 1, cursor_pos + 1, Document::CSTATE_ASCII, "change data");
		}
		else if(cursor_pos < doc->buffer_length())
		{
			std::vector<unsigned char> cur_data = doc->read_data(cursor_pos, 1);
			assert(cur_data.size() == 1);
			
			doc->overwrite_data(cursor_pos, &byte, 1, cursor_pos + 1, Document::CSTATE_ASCII, "change data");
		}
		
		doc_ctrl->clear_selection();
		
		/* TODO: Limit paint to affected area */
		this->Refresh();
	}
	else if(modifiers == wxMOD_NONE)
	{
		if(key == WXK_INSERT)
		{
			doc_ctrl->set_insert_mode(!insert_mode);
		}
		else if(key == WXK_DELETE)
		{
			if(selection_length > 0)
			{
				doc->erase_data(selection_off, selection_length, -1, Document::CSTATE_CURRENT, "delete selection");
			}
			else if(cursor_pos < doc->buffer_length())
			{
				doc->erase_data(cursor_pos, 1, -1, Document::CSTATE_CURRENT, "delete");
			}
		}
		else if(key == WXK_BACK)
		{
			if(selection_length > 0)
			{
				doc->erase_data(selection_off, selection_length, -1, Document::CSTATE_CURRENT, "delete selection");
			}
			else if(cursor_state == Document::CSTATE_HEX_MID)
			{
				/* Backspace while waiting for the second nibble in a byte should erase the current byte
				 * rather than the previous one.
				*/
				doc->erase_data(cursor_pos, 1, -1, Document::CSTATE_CURRENT, "delete");
			}
			else if(cursor_pos > 0)
			{
				doc->erase_data(cursor_pos - 1, 1, -1, Document::CSTATE_CURRENT, "delete");
			}
		}
		else if(key == '/')
		{
			if(cursor_pos < doc->buffer_length())
			{
				doc->edit_comment_popup(cursor_pos, 0);
			}
		}
	}
}

void REHex::DocumentCtrlTestWindow::OnCommentLeftClick(OffsetLengthEvent &event)
{
	doc->edit_comment_popup(event.offset, event.length);
}

void REHex::DocumentCtrlTestWindow::OnCommentRightClick(OffsetLengthEvent &event)
{
	off_t c_offset = event.offset;
	off_t c_length = event.length;
	
	wxMenu menu;
	
	wxMenuItem *edit_comment = menu.Append(wxID_ANY, "&Edit comment");
	menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
	{
		doc->edit_comment_popup(c_offset, c_length);
	}, edit_comment->GetId(), edit_comment->GetId());
	
	wxMenuItem *delete_comment = menu.Append(wxID_ANY, "&Delete comment");
	menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
	{
		doc->erase_comment(c_offset, c_length);
	}, delete_comment->GetId(), delete_comment->GetId());
	
	menu.AppendSeparator();
	
	wxMenuItem *copy_comments = menu.Append(wxID_ANY,  "&Copy comment(s)");
	menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
	{
		ClipboardGuard cg;
		if(cg)
		{
			const NestedOffsetLengthMap<Document::Comment> &comments = doc->get_comments();
			
			auto selected_comments = NestedOffsetLengthMap_get_recursive(comments, NestedOffsetLengthMapKey(c_offset, c_length));
			assert(selected_comments.size() > 0);
			
			wxTheClipboard->SetData(new CommentsDataObject(selected_comments, c_offset));
		}
	}, copy_comments->GetId(), copy_comments->GetId());
	
	PopupMenu(&menu);
}
