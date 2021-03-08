/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2020 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <algorithm>
#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <iterator>
#include <jansson.h>
#include <limits>
#include <map>
#include <stack>
#include <string>
#include <tuple>
#include <wx/clipbrd.h>
#include <wx/dcbuffer.h>

#include "App.hpp"
#include "document.hpp"
#include "Events.hpp"
#include "Palette.hpp"
#include "textentrydialog.hpp"
#include "util.hpp"

static_assert(std::numeric_limits<json_int_t>::max() >= std::numeric_limits<off_t>::max(),
	"json_int_t must be large enough to store any offset in an off_t");

wxDEFINE_EVENT(REHex::EV_INSERT_TOGGLED,      wxCommandEvent);
wxDEFINE_EVENT(REHex::EV_SELECTION_CHANGED,   wxCommandEvent);
wxDEFINE_EVENT(REHex::EV_COMMENT_MODIFIED,    wxCommandEvent);
wxDEFINE_EVENT(REHex::EV_UNDO_UPDATE,         wxCommandEvent);
wxDEFINE_EVENT(REHex::EV_BECAME_DIRTY,        wxCommandEvent);
wxDEFINE_EVENT(REHex::EV_BECAME_CLEAN,        wxCommandEvent);
wxDEFINE_EVENT(REHex::EV_DISP_SETTING_CHANGED,wxCommandEvent);
wxDEFINE_EVENT(REHex::EV_HIGHLIGHTS_CHANGED,  wxCommandEvent);
wxDEFINE_EVENT(REHex::EV_TYPES_CHANGED,       wxCommandEvent);
wxDEFINE_EVENT(REHex::EV_MAPPINGS_CHANGED,    wxCommandEvent);

REHex::Document::Document():
	dirty(false),
	cursor_state(CSTATE_HEX)
{
	buffer = new REHex::Buffer();
	title  = "Untitled";
}

REHex::Document::Document(const std::string &filename):
	filename(filename),
	dirty(false),
	cursor_state(CSTATE_HEX)
{
	buffer = new REHex::Buffer(filename);
	
	types.set_range(0, buffer->length(), "");
	
	size_t last_slash = filename.find_last_of("/\\");
	title = (last_slash != std::string::npos ? filename.substr(last_slash + 1) : filename);
	
	std::string meta_filename = filename + ".rehex-meta";
	if(wxFileExists(meta_filename))
	{
		_load_metadata(meta_filename);
	}
}

REHex::Document::~Document()
{
	delete buffer;
}

void REHex::Document::save()
{
	buffer->write_inplace();
	_save_metadata(filename + ".rehex-meta");
	
	dirty_bytes.clear_all();
	set_dirty(false);
}

void REHex::Document::save(const std::string &filename)
{
	buffer->write_inplace(filename);
	this->filename = filename;
	
	size_t last_slash = filename.find_last_of("/\\");
	title = (last_slash != std::string::npos ? filename.substr(last_slash + 1) : filename);
	
	_save_metadata(filename + ".rehex-meta");
	
	dirty_bytes.clear_all();
	set_dirty(false);
	
	DocumentTitleEvent document_title_event(this, title);
	ProcessEvent(document_title_event);
}

std::string REHex::Document::get_title()
{
	return title;
}

std::string REHex::Document::get_filename()
{
	return filename;
}

bool REHex::Document::is_dirty()
{
	return dirty;
}

bool REHex::Document::is_byte_dirty(off_t offset) const
{
	return dirty_bytes.isset(offset);
}

off_t REHex::Document::get_cursor_position() const
{
	return this->cpos_off;
}

REHex::Document::CursorState REHex::Document::get_cursor_state() const
{
	return cursor_state;
}

void REHex::Document::set_cursor_position(off_t off, CursorState cursor_state)
{
	_set_cursor_position(off, cursor_state);
}

void REHex::Document::_set_cursor_position(off_t position, enum CursorState cursor_state)
{
	position = std::max<off_t>(position, 0);
	position = std::min(position, buffer_length());
	
	if(cursor_state == CSTATE_GOTO)
	{
		if(this->cursor_state == CSTATE_HEX_MID)
		{
			cursor_state = CSTATE_HEX;
		}
		else{
			cursor_state = this->cursor_state;
		}
	}
	
	bool cursor_updated = (cpos_off != position || this->cursor_state != cursor_state);
	
	cpos_off = position;
	this->cursor_state = cursor_state;
	
	if(cursor_updated)
	{
		CursorUpdateEvent cursor_update_event(this, cpos_off, cursor_state);
		ProcessEvent(cursor_update_event);
	}
}

std::vector<unsigned char> REHex::Document::read_data(off_t offset, off_t max_length) const
{
	return buffer->read_data(offset, max_length);
}

void REHex::Document::overwrite_data(off_t offset, const void *data, off_t length, off_t new_cursor_pos, CursorState new_cursor_state, const char *change_desc)
{
	if(new_cursor_pos < 0)                 { new_cursor_pos = cpos_off; }
	if(new_cursor_state == CSTATE_CURRENT) { new_cursor_state = cursor_state; }
	
	_tracked_overwrite_data(change_desc, offset, (const unsigned char*)(data), length, new_cursor_pos, new_cursor_state);
}

void REHex::Document::insert_data(off_t offset, const unsigned char *data, off_t length, off_t new_cursor_pos, CursorState new_cursor_state, const char *change_desc)
{
	if(new_cursor_pos < 0)                 { new_cursor_pos = cpos_off; }
	if(new_cursor_state == CSTATE_CURRENT) { new_cursor_state = cursor_state; }
	
	_tracked_insert_data(change_desc, offset, data, length, new_cursor_pos, new_cursor_state);
}

void REHex::Document::erase_data(off_t offset, off_t length, off_t new_cursor_pos, CursorState new_cursor_state, const char *change_desc)
{
	if(new_cursor_pos < 0)                 { new_cursor_pos = cpos_off; }
	if(new_cursor_state == CSTATE_CURRENT) { new_cursor_state = cursor_state; }
	
	_tracked_erase_data(change_desc, offset, length, new_cursor_pos, new_cursor_state);
}

void REHex::Document::replace_data(off_t offset, off_t old_data_length, const unsigned char *new_data, off_t new_data_length, off_t new_cursor_pos, CursorState new_cursor_state, const char *change_desc)
{
	if(new_cursor_pos < 0)                 { new_cursor_pos = cpos_off; }
	if(new_cursor_state == CSTATE_CURRENT) { new_cursor_state = cursor_state; }
	
	_tracked_replace_data(change_desc, offset, old_data_length, new_data, new_data_length, new_cursor_pos, new_cursor_state);
}

off_t REHex::Document::buffer_length() const
{
	return buffer->length();
}

const REHex::NestedOffsetLengthMap<REHex::Document::Comment> &REHex::Document::get_comments() const
{
	return comments;
}

bool REHex::Document::set_comment(off_t offset, off_t length, const Comment &comment)
{
	assert(offset >= 0);
	assert(length >= 0);
	
	if(!NestedOffsetLengthMap_can_set(comments, offset, length))
	{
		return false;
	}
	
	_tracked_change("set comment",
		[this, offset, length, comment]()
		{
			NestedOffsetLengthMap_set(comments, offset, length, comment);
			set_dirty(true);
			
			_raise_comment_modified();
		},
		[this]()
		{
			/* Comments are restored implicitly. */
			_raise_comment_modified();
		});
	
	return true;
}

bool REHex::Document::erase_comment(off_t offset, off_t length)
{
	if(comments.find(NestedOffsetLengthMapKey(offset, length)) == comments.end())
	{
		return false;
	}
	
	_tracked_change("delete comment",
		[this, offset, length]()
		{
			comments.erase(NestedOffsetLengthMapKey(offset, length));
			set_dirty(true);
			
			_raise_comment_modified();
		},
		[this]()
		{
			/* Comments are restored implicitly. */
			_raise_comment_modified();
		});
	
	return true;
}

const REHex::NestedOffsetLengthMap<int> &REHex::Document::get_highlights() const
{
	return highlights;
}

bool REHex::Document::set_highlight(off_t off, off_t length, int highlight_colour_idx)
{
	assert(highlight_colour_idx >= 0);
	assert(highlight_colour_idx < Palette::NUM_HIGHLIGHT_COLOURS);
	
	if(off < 0 || length < 1 || (off + length) > buffer_length())
	{
		return false;
	}
	
	if(!NestedOffsetLengthMap_can_set(highlights, off, length))
	{
		return false;
	}
	
	_tracked_change("set highlight",
		[this, off, length, highlight_colour_idx]()
		{
			NestedOffsetLengthMap_set(highlights, off, length, highlight_colour_idx);
			set_dirty(true);

			_raise_highlights_changed();
		},
		
		[this]()
		{
			/* Highlight changes are undone implicitly. */
			_raise_highlights_changed();
		});
	
	return true;
}

bool REHex::Document::erase_highlight(off_t off, off_t length)
{
	if(highlights.find(NestedOffsetLengthMapKey(off, length)) == highlights.end())
	{
		return false;
	}
	
	_tracked_change("remove highlight",
		[this, off, length]()
		{
			highlights.erase(NestedOffsetLengthMapKey(off, length));
			set_dirty(true);

			_raise_highlights_changed();
		},
		
		[this]()
		{
			/* Highlight changes are undone implicitly. */
			_raise_highlights_changed();
		});
	
	return true;
}

const REHex::ByteRangeMap<std::string> &REHex::Document::get_data_types() const
{
	return types;
}

bool REHex::Document::set_data_type(off_t offset, off_t length, const std::string &type)
{
	if(offset < 0 || length < 1 || (offset + length) > buffer_length())
	{
		return false;
	}
	
	_tracked_change("set data type",
		[this, offset, length, type]()
		{
			types.set_range(offset, length, type);
			set_dirty(true);
			
			_raise_types_changed();
		},
		
		[this]()
		{
			/* Data type changes are undone implicitly. */
		});
	
	return true;
}

bool REHex::Document::set_virt_mapping(off_t real_offset, off_t virt_offset, off_t length)
{
	if(real_to_virt_segs.get_range_in(real_offset, length) != real_to_virt_segs.end()
		|| virt_to_real_segs.get_range_in(virt_offset, length) != virt_to_real_segs.end())
	{
		return false;
	}
	
	_tracked_change("set virtual address mapping",
		[this, real_offset, virt_offset, length]()
		{
			assert(real_to_virt_segs.get_range_in(real_offset, length) == real_to_virt_segs.end());
			assert(virt_to_real_segs.get_range_in(virt_offset, length) == virt_to_real_segs.end());
			
			real_to_virt_segs.set_range(real_offset, length, virt_offset);
			virt_to_real_segs.set_range(virt_offset, length, real_offset);
			set_dirty(true);
			
			_raise_mappings_changed();
		},
		
		[this]()
		{
			/* Address mapping changes are undone implicitly. */
		});
	
	return true;
}

void REHex::Document::clear_virt_mapping_r(off_t real_offset, off_t length)
{
	if(real_to_virt_segs.get_range_in(real_offset, length) == real_to_virt_segs.end())
	{
		/* No mapping here - nothing to do. */
		return;
	}
	
	_tracked_change("clear virtual address mapping",
		[this, real_offset, length]()
		{
			assert(real_to_virt_segs.get_range_in(real_offset, length) != real_to_virt_segs.end());
			
			off_t real_end = real_offset + length;
			
			ByteRangeMap<off_t>::const_iterator i;
			while((i = real_to_virt_segs.get_range_in(real_offset, length)) != real_to_virt_segs.end())
			{
				off_t seg_real_off = i->first.offset;
				off_t seg_length   = i->first.length;
				off_t seg_virt_off = i->second;
				
				off_t seg_real_end = seg_real_off + seg_length;
				off_t seg_virt_end = seg_virt_off + seg_length;
				
				off_t virt_off = seg_virt_off + (real_offset - seg_real_off);
				off_t virt_end = virt_off + length;
				
				if(seg_real_end > real_end)
				{
					real_to_virt_segs.set_range(real_end, (seg_real_end - real_end), virt_end);
					virt_to_real_segs.set_range(virt_end, (seg_virt_end - virt_end), real_end);
					
					off_t clear_virt_from = std::max(virt_off, seg_virt_off);
					
					real_to_virt_segs.clear_range(real_offset,     (real_end - real_offset));
					virt_to_real_segs.clear_range(clear_virt_from, (virt_end - clear_virt_from));
				}
				else{
					assert(real_offset < seg_real_end);
					assert(virt_off    < seg_virt_end);
					
					real_to_virt_segs.clear_range(real_offset, (seg_real_end - real_offset));
					virt_to_real_segs.clear_range(virt_off,    (seg_virt_end - virt_off));
				}
			}
			
			set_dirty(true);
			
			_raise_mappings_changed();
		},
		
		[this]()
		{
			/* Address mapping changes are undone implicitly. */
		});
}

void REHex::Document::clear_virt_mapping_v(off_t virt_offset, off_t length)
{
	if(virt_to_real_segs.get_range_in(virt_offset, length) == virt_to_real_segs.end())
	{
		/* No mapping here - nothing to do. */
		return;
	}
	
	_tracked_change("clear virtual address mapping",
		[this, virt_offset, length]()
		{
			assert(virt_to_real_segs.get_range_in(virt_offset, length) != virt_to_real_segs.end());
			
			off_t virt_end = virt_offset + length;
			
			ByteRangeMap<off_t>::const_iterator i;
			while((i = virt_to_real_segs.get_range_in(virt_offset, length)) != virt_to_real_segs.end())
			{
				off_t seg_virt_off = i->first.offset;
				off_t seg_length   = i->first.length;
				off_t seg_real_off = i->second;
				
				off_t seg_real_end = seg_real_off + seg_length;
				off_t seg_virt_end = seg_virt_off + seg_length;
				
				off_t real_off = seg_real_off + (virt_offset - seg_virt_off);
				off_t real_end = real_off + length;
				
				if(seg_virt_end > virt_end)
				{
					real_to_virt_segs.set_range(real_end, (seg_real_end - real_end), virt_end);
					virt_to_real_segs.set_range(virt_end, (seg_virt_end - virt_end), real_end);
					
					off_t clear_real_from = std::max(real_off, seg_real_off);
					
					real_to_virt_segs.clear_range(clear_real_from, (real_end - clear_real_from));
					virt_to_real_segs.clear_range(virt_offset,     (virt_end - virt_offset));
				}
				else{
					assert(real_off    < seg_real_end);
					assert(virt_offset < seg_virt_end);
					
					real_to_virt_segs.clear_range(real_off,    (seg_real_end - real_off));
					virt_to_real_segs.clear_range(virt_offset, (seg_virt_end - virt_offset));
				}
			}
			
			set_dirty(true);
			
			_raise_mappings_changed();
		},
		
		[this]()
		{
			/* Address mapping changes are undone implicitly. */
		});
}

const REHex::ByteRangeMap<off_t> &REHex::Document::get_real_to_virt_segs() const
{
	return real_to_virt_segs;
}

const REHex::ByteRangeMap<off_t> &REHex::Document::get_virt_to_real_segs() const
{
	return virt_to_real_segs;
}

off_t REHex::Document::real_to_virt_offset(off_t real_offset) const
{
	auto i = real_to_virt_segs.get_range(real_offset);
	if(i != real_to_virt_segs.end())
	{
		assert(i->first.offset <= real_offset);
		assert((i->first.offset + i->first.length) > real_offset);
		
		off_t virt_offset = i->second + (real_offset - i->first.offset);
		return virt_offset;
	}
	else{
		return -1;
	}
}

off_t REHex::Document::virt_to_real_offset(off_t virt_offset) const
{
	auto i = virt_to_real_segs.get_range(virt_offset);
	if(i != virt_to_real_segs.end())
	{
		assert(i->first.offset <= virt_offset);
		assert((i->first.offset + i->first.length) > virt_offset);
		
		off_t real_offset = i->second + (virt_offset - i->first.offset);
		
		assert(real_offset >= 0);
		assert(real_offset < buffer_length());
		
		return real_offset;
	}
	else{
		return -1;
	}
}

void REHex::Document::handle_paste(wxWindow *modal_dialog_parent, const NestedOffsetLengthMap<Document::Comment> &clipboard_comments)
{
	off_t cursor_pos = get_cursor_position();
	off_t buffer_length = this->buffer_length();
	
	for(auto cc = clipboard_comments.begin(); cc != clipboard_comments.end(); ++cc)
	{
		if((cursor_pos + cc->first.offset + cc->first.length) >= buffer_length)
		{
			wxMessageBox("Cannot paste comment(s) - would extend beyond end of file", "Error", (wxOK | wxICON_ERROR), modal_dialog_parent);
			return;
		}
		
		if(comments.find(NestedOffsetLengthMapKey(cursor_pos + cc->first.offset, cc->first.length)) != comments.end()
			|| !NestedOffsetLengthMap_can_set(comments, cursor_pos + cc->first.offset, cc->first.length))
		{
			wxMessageBox("Cannot paste comment(s) - would overwrite one or more existing", "Error", (wxOK | wxICON_ERROR), modal_dialog_parent);
			return;
		}
	}
	
	_tracked_change("paste comment(s)",
		[this, cursor_pos, clipboard_comments]()
		{
			for(auto cc = clipboard_comments.begin(); cc != clipboard_comments.end(); ++cc)
			{
				NestedOffsetLengthMap_set(comments, cursor_pos + cc->first.offset, cc->first.length, cc->second);
			}
			
			set_dirty(true);
			
			_raise_comment_modified();
		},
		[this]()
		{
			/* Comments are restored implicitly. */
			_raise_comment_modified();
		});
}

void REHex::Document::undo()
{
	if(!undo_stack.empty())
	{
		auto &act = undo_stack.back();
		act.undo();
		
		bool cursor_updated = (cpos_off != act.old_cpos_off || cursor_state != act.old_cursor_state);
		
		cpos_off     = act.old_cpos_off;
		cursor_state = act.old_cursor_state;
		comments     = act.old_comments;
		highlights   = act.old_highlights;
		dirty_bytes  = act.old_dirty_bytes;
		
		if(types != act.old_types)
		{
			types = act.old_types;
			_raise_types_changed();
		}
		
		if(real_to_virt_segs != act.old_real_to_virt_segs || virt_to_real_segs != act.old_virt_to_real_segs)
		{
			real_to_virt_segs = act.old_real_to_virt_segs;
			virt_to_real_segs = act.old_virt_to_real_segs;
			_raise_mappings_changed();
		}
		
		set_dirty(act.old_dirty);
		
		if(cursor_updated)
		{
			CursorUpdateEvent cursor_update_event(this, cpos_off, cursor_state);
			ProcessEvent(cursor_update_event);
		}
		
		redo_stack.push_back(act);
		undo_stack.pop_back();
		
		_raise_undo_update();
	}
}

const char *REHex::Document::undo_desc()
{
	if(!undo_stack.empty())
	{
		return undo_stack.back().desc;
	}
	else{
		return NULL;
	}
}

void REHex::Document::redo()
{
	if(!redo_stack.empty())
	{
		auto &act = redo_stack.back();
		act.redo();
		
		undo_stack.push_back(act);
		redo_stack.pop_back();
		
		_raise_undo_update();
	}
}

const char *REHex::Document::redo_desc()
{
	if(!redo_stack.empty())
	{
		return redo_stack.back().desc;
	}
	else{
		return NULL;
	}
}

void REHex::Document::_UNTRACKED_overwrite_data(off_t offset, const unsigned char *data, off_t length)
{
	OffsetLengthEvent data_overwriting_event(this, DATA_OVERWRITING, offset, length);
	ProcessEvent(data_overwriting_event);
	
	bool ok = buffer->overwrite_data(offset, data, length);
	assert(ok);
	
	if(ok)
	{
		dirty_bytes.set_range(offset, length);
		set_dirty(true);
		
		OffsetLengthEvent data_overwrite_event(this, DATA_OVERWRITE, offset, length);
		ProcessEvent(data_overwrite_event);
	}
	else{
		OffsetLengthEvent data_overwrite_aborted_event(this, DATA_OVERWRITE_ABORTED, offset, length);
		ProcessEvent(data_overwrite_aborted_event);
	}
}

/* Insert some data into the Buffer and update our own data structures. */
void REHex::Document::_UNTRACKED_insert_data(off_t offset, const unsigned char *data, off_t length)
{
	OffsetLengthEvent data_inserting_event(this, DATA_INSERTING, offset, length);
	ProcessEvent(data_inserting_event);
	
	bool ok = buffer->insert_data(offset, data, length);
	assert(ok);
	
	if(ok)
	{
		dirty_bytes.data_inserted(offset, length);
		dirty_bytes.set_range(offset, length);
		set_dirty(true);
		
		types.data_inserted(offset, length);
		types.set_range(offset, length, "");
		
		OffsetLengthEvent data_insert_event(this, DATA_INSERT, offset, length);
		ProcessEvent(data_insert_event);
		
		if(NestedOffsetLengthMap_data_inserted(comments, offset, length) > 0)
		{
			_raise_comment_modified();
		}
		
		if(NestedOffsetLengthMap_data_inserted(highlights, offset, length) > 0)
		{
			_raise_highlights_changed();
		}
		
		_update_mappings_data_inserted(offset, length);
	}
	else{
		OffsetLengthEvent data_insert_aborted_event(this, DATA_INSERT_ABORTED, offset, length);
		ProcessEvent(data_insert_aborted_event);
	}
}

void REHex::Document::_update_mappings_data_inserted(off_t offset, off_t length)
{
	/* ByteRangeMap::data_inserted() will split elements that span the insertion point leaving
	 * the same values on either side. We need every element to have the point to the base of
	 * the mapped address, so if there is one spanning the insertion point, split it now so the
	 * second half of the element has the right base address after adjustment.
	*/
	
	auto i = real_to_virt_segs.get_range(offset);
	if(i != real_to_virt_segs.end() && i->first.offset < offset)
	{
		off_t seg_real_off = i->first.offset;
		off_t seg_length   = i->first.length;
		off_t seg_virt_off = i->second;
		
		real_to_virt_segs.clear_range(seg_real_off, seg_length);
		virt_to_real_segs.clear_range(seg_virt_off, seg_length);
		
		off_t seg1_real_off = seg_real_off;
		off_t seg1_length   = offset - seg_real_off;
		off_t seg1_virt_off = seg_virt_off;
		
		real_to_virt_segs.set_range(seg1_real_off, seg1_length, seg1_virt_off);
		virt_to_real_segs.set_range(seg1_virt_off, seg1_length, seg1_real_off);
		
		off_t seg2_real_off = seg1_real_off + seg1_length;
		off_t seg2_length   = seg_length - seg1_length;
		off_t seg2_virt_off = seg_virt_off + seg1_length;
		
		real_to_virt_segs.set_range(seg2_real_off, seg2_length, seg2_virt_off);
		virt_to_real_segs.set_range(seg2_virt_off, seg2_length, seg2_real_off);
	}
	
	/* Find the first element on/after the insertion point and adjust the corresponding
	 * elements in the virt_to_real_segs table. We must erase all first and then insert as
	 * separate steps to avoid potential collisions.
	*/
	
	i = std::lower_bound(real_to_virt_segs.begin(), real_to_virt_segs.end(),
		std::make_pair(ByteRangeMap<off_t>::Range(offset, 0), (off_t)(0)));
	
	for(auto j = i; j != real_to_virt_segs.end(); ++j)
	{
		assert(j->first.offset >= offset);
		
		off_t seg_length   = j->first.length;
		off_t seg_virt_off = j->second;
		
		virt_to_real_segs.clear_range(seg_virt_off, seg_length);
	}
	
	for(auto j = i; j != real_to_virt_segs.end(); ++j)
	{
		off_t seg_real_off = j->first.offset;
		off_t seg_length   = j->first.length;
		off_t seg_virt_off = j->second;
		
		seg_real_off += length;
		
		virt_to_real_segs.set_range(seg_virt_off, seg_length, seg_real_off);
	}
	
	/* Raise an EV_MAPPINGS_CHANGED event if any segments were affected by the insertion. */
	
	bool mappings_changed = real_to_virt_segs.data_inserted(offset, length);
	if(mappings_changed)
	{
		_raise_mappings_changed();
	}
}

/* Erase a range of data from the Buffer and update our own data structures. */
void REHex::Document::_UNTRACKED_erase_data(off_t offset, off_t length)
{
	OffsetLengthEvent data_erasing_event(this, DATA_ERASING, offset, length);
	ProcessEvent(data_erasing_event);
	
	bool ok = buffer->erase_data(offset, length);
	assert(ok);
	
	if(ok)
	{
		dirty_bytes.data_erased(offset, length);
		set_dirty(true);
		
		types.data_erased(offset, length);
		
		OffsetLengthEvent data_erase_event(this, DATA_ERASE, offset, length);
		ProcessEvent(data_erase_event);
		
		if(NestedOffsetLengthMap_data_erased(comments, offset, length) > 0)
		{
			_raise_comment_modified();
		}
		
		if(NestedOffsetLengthMap_data_erased(highlights, offset, length) > 0)
		{
			_raise_highlights_changed();
		}
		
		_virt_to_real_segs_data_erased(offset, length);
		bool r2v_updated = real_to_virt_segs.data_erased(offset, length);
		
		if(r2v_updated)
		{
			_raise_mappings_changed();
		}
	}
	else{
		OffsetLengthEvent data_erase_aborted_event(this, DATA_ERASE_ABORTED, offset, length);
		ProcessEvent(data_erase_aborted_event);
	}
}

bool REHex::Document::_virt_to_real_segs_data_erased(off_t offset, off_t length)
{
	auto i = std::lower_bound(real_to_virt_segs.begin(), real_to_virt_segs.end(),
		std::make_pair(ByteRangeMap<off_t>::Range(offset, 0), (off_t)(0)));
	
	if(i != real_to_virt_segs.begin())
	{
		auto i_prev = std::prev(i);
		
		if((i_prev->first.offset + i_prev->first.length) > offset)
		{
			i = i_prev;
		}
	}
	
	bool segs_changed = (i != real_to_virt_segs.end());
	
	for(; i != real_to_virt_segs.end(); ++i)
	{
		off_t seg_real_off = i->first.offset;
		off_t seg_length   = i->first.length;
		off_t seg_virt_off = i->second;
		
		virt_to_real_segs.clear_range(seg_virt_off, seg_length);
		
		if(seg_real_off >= (offset + length))
		{
			/* Segment starts after erased data. Just move it back. */
			seg_real_off -= length;
		}
		else if(seg_real_off >= offset)
		{
			/* Segment starts within erased data. Move back and shrink it. */
			seg_length -= length - (seg_real_off - offset);
			seg_real_off = offset;
		}
		else if((seg_real_off + seg_length) > (offset + length))
		{
			/* Segment straddles both sides of erased data. Shrink. */
			seg_length -= length;
		}
		else{
			/* Segment starts before erased data. Truncate. */
			assert(offset >= seg_real_off);
			seg_length = offset - seg_real_off;
		}
		
		if(seg_length > 0)
		{
			virt_to_real_segs.set_range(seg_virt_off, seg_length, seg_real_off);
		}
	}
	
	return segs_changed;
}

void REHex::Document::_tracked_overwrite_data(const char *change_desc, off_t offset, const unsigned char *data, off_t length, off_t new_cursor_pos, CursorState new_cursor_state)
{
	/* Move data into a std::vector managed by a shared_ptr so that it can be "copied" into
	 * lambdas without actually making a copy.
	*/
	
	std::shared_ptr< std::vector<unsigned char> > old_data(new std::vector<unsigned char>(std::move( read_data(offset, length) )));
	assert(old_data->size() == (size_t)(length));
	
	std::shared_ptr< std::vector<unsigned char> > new_data(new std::vector<unsigned char>(data, data + length));
	
	_tracked_change(change_desc,
		[this, offset, new_data, new_cursor_pos, new_cursor_state]()
		{
			_UNTRACKED_overwrite_data(offset, new_data->data(), new_data->size());
			_set_cursor_position(new_cursor_pos, new_cursor_state);
		},
		 
		[this, offset, old_data]()
		{
			_UNTRACKED_overwrite_data(offset, old_data->data(), old_data->size());
		});
}

void REHex::Document::_tracked_insert_data(const char *change_desc, off_t offset, const unsigned char *data, off_t length, off_t new_cursor_pos, CursorState new_cursor_state)
{
	/* Move data into a std::vector managed by a shared_ptr so that it can be "copied" into
	 * lambdas without actually making a copy.
	*/
	
	std::shared_ptr< std::vector<unsigned char> > data_copy(new std::vector<unsigned char>(data, data + length));
	
	_tracked_change(change_desc,
		[this, offset, data_copy, new_cursor_pos, new_cursor_state]()
		{
			_UNTRACKED_insert_data(offset, data_copy->data(), data_copy->size());
			_set_cursor_position(new_cursor_pos, new_cursor_state);
		},
		 
		[this, offset, length]()
		{
			_UNTRACKED_erase_data(offset, length);
		});
}

void REHex::Document::_tracked_erase_data(const char *change_desc, off_t offset, off_t length, off_t new_cursor_pos, CursorState new_cursor_state)
{
	/* Move data into a std::vector managed by a shared_ptr so that it can be "copied" into
	 * lambdas without actually making a copy.
	*/
	
	std::shared_ptr< std::vector<unsigned char> > erase_data(new std::vector<unsigned char>(std::move( read_data(offset, length) )));
	assert(erase_data->size() == (size_t)(length));
	
	_tracked_change(change_desc,
		[this, offset, length, new_cursor_pos, new_cursor_state]()
		{
			_UNTRACKED_erase_data(offset, length);
			set_cursor_position(new_cursor_pos, new_cursor_state);
		},
		
		[this, offset, erase_data]()
		{
			_UNTRACKED_insert_data(offset, erase_data->data(), erase_data->size());
		});
}

void REHex::Document::_tracked_replace_data(const char *change_desc, off_t offset, off_t old_data_length, const unsigned char *new_data, off_t new_data_length, off_t new_cursor_pos, CursorState new_cursor_state)
{
	if(old_data_length == new_data_length)
	{
		/* Save unnecessary shuffling of the Buffer pages. */
		/* TODO */
	}
	
	/* Move data into a std::vector managed by a shared_ptr so that it can be "copied" into
	 * lambdas without actually making a copy.
	*/
	
	std::shared_ptr< std::vector<unsigned char> > old_data_copy(new std::vector<unsigned char>(std::move( read_data(offset, old_data_length) )));
	assert(old_data_copy->size() == old_data_length);
	
	std::shared_ptr< std::vector<unsigned char> > new_data_copy(new std::vector<unsigned char>(new_data, new_data + new_data_length));
	
	_tracked_change(change_desc,
		[this, offset, old_data_length, new_data_copy, new_cursor_pos, new_cursor_state]()
		{
			_UNTRACKED_erase_data(offset, old_data_length);
			_UNTRACKED_insert_data(offset, new_data_copy->data(), new_data_copy->size());
			_set_cursor_position(new_cursor_pos, new_cursor_state);
		},
		
		[this, offset, old_data_copy, new_data_length]()
		{
			_UNTRACKED_erase_data(offset, new_data_length);
			_UNTRACKED_insert_data(offset, old_data_copy->data(), old_data_copy->size());
		});
}

void REHex::Document::_tracked_change(const char *desc, std::function< void() > do_func, std::function< void() > undo_func)
{
	struct TrackedChange change;
	
	change.desc = desc;
	change.undo = undo_func;
	change.redo = do_func;
	
	change.old_cpos_off     = cpos_off;
	change.old_cursor_state = cursor_state;
	change.old_comments     = comments;
	change.old_highlights   = highlights;
	change.old_types        = types;
	change.old_real_to_virt_segs = real_to_virt_segs;
	change.old_virt_to_real_segs = virt_to_real_segs;
	change.old_dirty        = dirty;
	change.old_dirty_bytes  = dirty_bytes;
	
	do_func();
	
	while(undo_stack.size() >= UNDO_MAX)
	{
		undo_stack.pop_front();
	}
	
	undo_stack.push_back(change);
	redo_stack.clear();
	
	_raise_undo_update();
}

json_t *REHex::Document::_dump_metadata(bool& has_data)
{
	has_data = false;
	json_t *root = json_object();
	if(root == NULL)
	{
		return NULL;
	}
	
	json_t *comments = json_array();
	if(json_object_set_new(root, "comments", comments) == -1)
	{
		json_decref(root);
		return NULL;
	}
	
	for(auto c = this->comments.begin(); c != this->comments.end(); ++c)
	{
		const wxScopedCharBuffer utf8_text = c->second.text->utf8_str();
		
		json_t *comment = json_object();
		if(json_array_append(comments, comment) == -1
			|| json_object_set_new(comment, "offset", json_integer(c->first.offset)) == -1
			|| json_object_set_new(comment, "length", json_integer(c->first.length)) == -1
			|| json_object_set_new(comment, "text",   json_stringn(utf8_text.data(), utf8_text.length())) == -1)
		{
			json_decref(root);
			return NULL;
		}
		has_data = true;
	}
	
	json_t *highlights = json_array();
	if(json_object_set_new(root, "highlights", highlights) == -1)
	{
		json_decref(root);
		return NULL;
	}
	
	for(auto h = this->highlights.begin(); h != this->highlights.end(); ++h)
	{
		json_t *highlight = json_object();
		if(json_array_append(highlights, highlight) == -1
			|| json_object_set_new(highlight, "offset",     json_integer(h->first.offset)) == -1
			|| json_object_set_new(highlight, "length",     json_integer(h->first.length)) == -1
			|| json_object_set_new(highlight, "colour-idx", json_integer(h->second)) == -1)
		{
			json_decref(root);
			return NULL;
		}
		has_data = true;
	}
	
	json_t *data_types = json_array();
	if(json_object_set_new(root, "data_types", data_types) == -1)
	{
		json_decref(root);
		return NULL;
	}
	
	for(auto dt = this->types.begin(); dt != this->types.end(); ++dt)
	{
		if(dt->second == "")
		{
			/* Don't bother serialising "this is data" */
			continue;
		}
		
		json_t *data_type = json_object();
		if(json_array_append(data_types, data_type) == -1
			|| json_object_set_new(data_type, "offset", json_integer(dt->first.offset)) == -1
			|| json_object_set_new(data_type, "length", json_integer(dt->first.length)) == -1
			|| json_object_set_new(data_type, "type",   json_string(dt->second.c_str())) == -1)
		{
			json_decref(root);
			return NULL;
		}
		
		has_data = true;
	}
	
	json_t *virt_mappings = json_array();
	if(json_object_set_new(root, "virt_mappings", virt_mappings) == -1)
	{
		json_decref(root);
		return NULL;
	}
	
	for(auto r2v = real_to_virt_segs.begin(); r2v != real_to_virt_segs.end(); ++r2v)
	{
		json_t *mapping = json_object();
		if(json_array_append(virt_mappings, mapping) == -1
			|| json_object_set_new(mapping, "real_offset", json_integer(r2v->first.offset)) == -1
			|| json_object_set_new(mapping, "virt_offset", json_integer(r2v->second)) == -1
			|| json_object_set_new(mapping, "length",      json_integer(r2v->first.length)) == -1)
		{
			json_decref(root);
			return NULL;
		}
		
		has_data = true;
	}
	
	return root;
}

void REHex::Document::_save_metadata(const std::string &filename)
{
	/* TODO: Atomically replace file. */
	
	bool has_data = false;
	json_t *meta = _dump_metadata(has_data);
	int res = 0;
	if (has_data)
	{
		res = json_dump_file(meta, filename.c_str(), JSON_INDENT(2));
	}
	else if(wxFileExists(filename))
	{
		wxRemoveFile(filename);
	}
	json_decref(meta);
	
	if(res != 0)
	{
		throw std::runtime_error("Unable to write " + filename);
	}
}

REHex::NestedOffsetLengthMap<REHex::Document::Comment> REHex::Document::_load_comments(const json_t *meta, off_t buffer_length)
{
	NestedOffsetLengthMap<Comment> comments;
	
	json_t *j_comments = json_object_get(meta, "comments");
	
	size_t index;
	json_t *value;
	
	json_array_foreach(j_comments, index, value)
	{
		off_t offset  = json_integer_value(json_object_get(value, "offset"));
		off_t length  = json_integer_value(json_object_get(value, "length"));
		wxString text = wxString::FromUTF8(json_string_value(json_object_get(value, "text")));
		
		if(offset >= 0 && offset < buffer_length
			&& length >= 0 && (offset + length) <= buffer_length)
		{
			NestedOffsetLengthMap_set(comments, offset, length, Comment(text));
		}
	}
	
	return comments;
}

REHex::NestedOffsetLengthMap<int> REHex::Document::_load_highlights(const json_t *meta, off_t buffer_length)
{
	NestedOffsetLengthMap<int> highlights;
	
	json_t *j_highlights = json_object_get(meta, "highlights");
	
	size_t index;
	json_t *value;
	
	json_array_foreach(j_highlights, index, value)
	{
		off_t offset = json_integer_value(json_object_get(value, "offset"));
		off_t length = json_integer_value(json_object_get(value, "length"));
		int   colour = json_integer_value(json_object_get(value, "colour-idx"));
		
		if(offset >= 0 && offset < buffer_length
			&& length > 0 && (offset + length) <= buffer_length
			&& colour >= 0 && colour < Palette::NUM_HIGHLIGHT_COLOURS)
		{
			NestedOffsetLengthMap_set(highlights, offset, length, colour);
		}
	}
	
	return highlights;
}

REHex::ByteRangeMap<std::string> REHex::Document::_load_types(const json_t *meta, off_t buffer_length)
{
	ByteRangeMap<std::string> types;
	types.set_range(0, buffer_length, "");
	
	json_t *j_types = json_object_get(meta, "data_types");
	
	size_t index;
	json_t *value;
	
	json_array_foreach(j_types, index, value)
	{
		off_t offset     = json_integer_value(json_object_get(value, "offset"));
		off_t length     = json_integer_value(json_object_get(value, "length"));
		const char *type = json_string_value(json_object_get(value, "type"));
		
		if(offset >= 0 && offset < buffer_length
			&& length > 0 && (offset + length) <= buffer_length
			&& type != NULL)
		{
			types.set_range(offset, length, type);
		}
	}
	
	return types;
}

std::pair< REHex::ByteRangeMap<off_t>, REHex::ByteRangeMap<off_t> > REHex::Document::_load_virt_mappings(const json_t *meta, off_t buffer_length)
{
	ByteRangeMap<off_t> real_to_virt_segs;
	ByteRangeMap<off_t> virt_to_real_segs;
	
	json_t *j_mappings = json_object_get(meta, "virt_mappings");
	
	size_t index;
	json_t *value;
	
	json_array_foreach(j_mappings, index, value)
	{
		off_t real_offset = json_integer_value(json_object_get(value, "real_offset"));
		off_t virt_offset = json_integer_value(json_object_get(value, "virt_offset"));
		off_t length      = json_integer_value(json_object_get(value, "length"));
		
		if(real_offset >= 0 && real_offset < buffer_length
			&& length > 0 && (real_offset + length) <= buffer_length
			&& real_to_virt_segs.get_range_in(real_offset, length) == real_to_virt_segs.end()
			&& virt_to_real_segs.get_range_in(virt_offset, length) == virt_to_real_segs.end())
		{
			real_to_virt_segs.set_range(real_offset, length, virt_offset);
			virt_to_real_segs.set_range(virt_offset, length, real_offset);
		}
	}
	
	return std::make_pair(real_to_virt_segs, virt_to_real_segs);
}

void REHex::Document::_load_metadata(const std::string &filename)
{
	/* TODO: Report errors */
	
	json_error_t json_err;
	json_t *meta = json_load_file(filename.c_str(), 0, &json_err);
	
	comments = _load_comments(meta, buffer_length());
	highlights = _load_highlights(meta, buffer_length());
	types = _load_types(meta, buffer_length());
	std::tie(real_to_virt_segs, virt_to_real_segs) = _load_virt_mappings(meta, buffer_length());
	
	json_decref(meta);
}

void REHex::Document::_raise_comment_modified()
{
	wxCommandEvent event(REHex::EV_COMMENT_MODIFIED);
	event.SetEventObject(this);
	
	wxPostEvent(this, event);
}

void REHex::Document::_raise_undo_update()
{
	wxCommandEvent event(REHex::EV_UNDO_UPDATE);
	event.SetEventObject(this);
	
	wxPostEvent(this, event);
}

void REHex::Document::_raise_dirty()
{
	wxCommandEvent event(REHex::EV_BECAME_DIRTY);
	event.SetEventObject(this);
	
	wxPostEvent(this, event);
}

void REHex::Document::_raise_clean()
{
	wxCommandEvent event(REHex::EV_BECAME_CLEAN);
	event.SetEventObject(this);
	
	wxPostEvent(this, event);
}

void REHex::Document::_raise_highlights_changed()
{
	wxCommandEvent event(REHex::EV_HIGHLIGHTS_CHANGED);
	event.SetEventObject(this);
	
	ProcessEvent(event);
}

void REHex::Document::_raise_types_changed()
{
	wxCommandEvent event(REHex::EV_TYPES_CHANGED);
	event.SetEventObject(this);
	
	ProcessEvent(event);
}

void REHex::Document::_raise_mappings_changed()
{
	wxCommandEvent event(REHex::EV_MAPPINGS_CHANGED);
	event.SetEventObject(this);
	
	ProcessEvent(event);
}

void REHex::Document::set_dirty(bool dirty)
{
	if(this->dirty == dirty)
	{
		return;
	}
	
	this->dirty = dirty;
	
	if(dirty)
	{
		_raise_dirty();
	}
	else{
		_raise_clean();
	}
}

REHex::Document::Comment::Comment(const wxString &text):
	text(new wxString(text)) {}

/* Get a preview of the comment suitable for use as a wxMenuItem label. */
wxString REHex::Document::Comment::menu_preview() const
{
	/* Get the first line of the comment. */
	size_t line_len = text->find_first_of("\r\n");
	wxString first_line = text->substr(0, line_len);
	
	/* Escape any ampersands in the comment. */
	for(size_t i = 0; (i = first_line.find_first_of("&", i)) < first_line.length();)
	{
		/* TODO: Make this actually be an ampersand. Posts suggest &&
		 * should work, but others say not portable.
		*/
		first_line.replace(i, 1, "_");
	}
	
	/* Remove any control characters from the first line. */
	
	wxString ctrl_chars;
	for(char i = 0; i < 32; ++i)
	{
		ctrl_chars.append(1, i);
	}
	
	for(size_t i = 0; (i = first_line.find_first_of(ctrl_chars, i)) < first_line.length();)
	{
		first_line.erase(i, 1);
	}
	
	/* TODO: Truncate on characters rather than bytes. */
	
	static const int MAX_CHARS = 32;
	if(first_line.length() > MAX_CHARS)
	{
		return first_line.substr(0, MAX_CHARS) + "...";
	}
	else{
		return first_line;
	}
}

const wxDataFormat REHex::CommentsDataObject::format("rehex/comments/v1");

REHex::CommentsDataObject::CommentsDataObject():
	wxCustomDataObject(format) {}

REHex::CommentsDataObject::CommentsDataObject(const std::list<NestedOffsetLengthMap<REHex::Document::Comment>::const_iterator> &comments, off_t base):
	wxCustomDataObject(format)
{
	set_comments(comments, base);
}

REHex::NestedOffsetLengthMap<REHex::Document::Comment> REHex::CommentsDataObject::get_comments() const
{
	REHex::NestedOffsetLengthMap<REHex::Document::Comment> comments;
	
	const unsigned char *data = (const unsigned char*)(GetData());
	const unsigned char *end = data + GetSize();
	const Header *header = nullptr;
	
	while(data + sizeof(Header) < end && (header = (const Header*)(data)), (data + sizeof(Header) + header->text_length <= end))
	{
		wxString text(wxString::FromUTF8((const char*)(header + 1), header->text_length));
		
		bool x = NestedOffsetLengthMap_set(comments, header->file_offset, header->file_length, REHex::Document::Comment(text));
		assert(x); /* TODO: Raise some kind of error. Beep? */
		
		data += sizeof(Header) + header->text_length;
	}
	
	return comments;
}

void REHex::CommentsDataObject::set_comments(const std::list<NestedOffsetLengthMap<REHex::Document::Comment>::const_iterator> &comments, off_t base)
{
	size_t size = 0;
	
	for(auto i = comments.begin(); i != comments.end(); ++i)
	{
		size += sizeof(Header) + (*i)->second.text->utf8_str().length();
	}
	
	void *data = Alloc(size); /* Wrapper around new[] - throws on failure */
	
	char *outp = (char*)(data);
	
	for(auto i = comments.begin(); i != comments.end(); ++i)
	{
		Header *header = (Header*)(outp);
		outp += sizeof(Header);
		
		const wxScopedCharBuffer utf8_text = (*i)->second.text->utf8_str();
		
		header->file_offset = (*i)->first.offset - base;
		header->file_length = (*i)->first.length;
		header->text_length = utf8_text.length();
		
		memcpy(outp, utf8_text.data(), utf8_text.length());
		outp += utf8_text.length();
	}
	
	assert(((char*)(data) + size) == outp);
	
	TakeData(size, data);
}
