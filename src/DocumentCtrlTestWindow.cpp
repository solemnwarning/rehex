#include <list>
#include <string>
#include <wx/frame.h>

#include "DocumentCtrlTestWindow.hpp"

using namespace REHex;

static void reinit_regions(REHex::Document *doc, REHex::DocumentCtrl *doc_ctrl)
{
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
	
	// doc_ctrl->append_region(new DocumentCtrl::DataRegion(0, doc->buffer_length()));
	
	reinit_regions(doc, doc_ctrl);
}

REHex::DocumentCtrlTestWindow::~DocumentCtrlTestWindow() {}
