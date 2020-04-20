#include <list>
#include <string>
#include <wx/clipbrd.h>
#include <wx/frame.h>

#include "DocumentCtrlTestWindow.hpp"
#include "NestedOffsetLengthMap.hpp"
#include "util.hpp"

using namespace REHex;

BEGIN_EVENT_TABLE(REHex::DocumentCtrlTestWindow, wxFrame)
	EVT_OFFSETLENGTH(wxID_ANY, REHex::COMMENT_LEFT_CLICK,  REHex::DocumentCtrlTestWindow::OnCommentLeftClick)
	EVT_OFFSETLENGTH(wxID_ANY, REHex::COMMENT_RIGHT_CLICK, REHex::DocumentCtrlTestWindow::OnCommentRightClick)
END_EVENT_TABLE()

void REHex::DocumentCtrlTestWindow::reinit_regions()
{
	const std::list<DocumentCtrl::Region*> &old_regions = doc_ctrl->get_regions();
	while(!old_regions.empty())
	{
		doc_ctrl->erase_region(old_regions.begin());
	}
	
	auto comments = doc->get_comments();
	
	/* Construct a list of interlaced comment/data regions. */
	
	auto offset_base = comments.begin();
	off_t next_data = 0, remain_data = doc->buffer_length();
	
	/* Stack of comment ranges around the current position. */
	std::list<DocumentCtrl::CommentRegion*> parents;
	
	while(remain_data > 0)
	{
		off_t dr_length = remain_data;
		
		assert(offset_base == comments.end() || offset_base->first.offset >= next_data);
		
		/* Pop any comments off parents which we have gone past the end of. */
		while(!parents.empty() && (parents.back()->c_offset + parents.back()->c_length) <= next_data)
		{
			if(parents.back()->final_descendant != NULL)
			{
				++(parents.back()->final_descendant->indent_final);
			}
			
			parents.pop_back();
		}
		
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
				
				DocumentCtrl::CommentRegion *cr = new DocumentCtrl::CommentRegion(c->first.offset, c->first.length, *(c->second.text), parents.size());
				
				doc_ctrl->append_region(cr);
				
				for(auto p = parents.begin(); p != parents.end(); ++p)
				{
					(*p)->final_descendant = cr;
				}
				
				if((doc->get_inline_comment_mode() == Document::ICM_SHORT_INDENT || doc->get_inline_comment_mode() == Document::ICM_FULL_INDENT)
					&& c->first.length > 0)
				{
					parents.push_back(cr);
				}
			} while(c != offset_base);
			
			offset_base = next_offset;
		}
		
		if(offset_base != comments.end())
		{
			dr_length = offset_base->first.offset - next_data;
		}
		
		if(!parents.empty() && (parents.back()->c_offset + parents.back()->c_length) < (next_data + dr_length))
		{
			dr_length = (parents.back()->c_offset + parents.back()->c_length) - next_data;
		}
		
		DocumentCtrl::DataRegion *dr = new DocumentCtrl::DataRegion(next_data, dr_length, parents.size());
		
		doc_ctrl->append_region(dr);
		
		for(auto p = parents.begin(); p != parents.end(); ++p)
		{
			(*p)->final_descendant = dr;
		}
		
		next_data   += dr_length;
		remain_data -= dr_length;
	}
	
	while(!parents.empty())
	{
		if(parents.back()->final_descendant != NULL)
		{
			++(parents.back()->final_descendant->indent_final);
		}
		
		parents.pop_back();
	}
	
	if(doc->buffer_length() == 0)
	{
		/* Empty buffers need a data region too! */
		doc_ctrl->append_region(new DocumentCtrl::DataRegion(0, 0, 0));
	}
}

REHex::DocumentCtrlTestWindow::DocumentCtrlTestWindow(Document *doc):
	wxFrame(NULL, wxID_ANY, std::string("DocumentCtrl test (") + doc->get_title() + ")", wxDefaultPosition, wxSize(740, 540)),
	doc(doc)
{
	doc_ctrl = new DocumentCtrl(this, doc);
	
	doc->Bind(EV_COMMENT_MODIFIED, [this](wxCommandEvent &event) { reinit_regions(); event.Skip(); });
	doc->Bind(EV_DATA_MODIFIED,    [this](wxCommandEvent &event) { reinit_regions(); event.Skip(); });
	
	reinit_regions();
}

REHex::DocumentCtrlTestWindow::~DocumentCtrlTestWindow() {}

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
