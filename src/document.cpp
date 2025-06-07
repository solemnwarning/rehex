/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <utility>
#include <wx/clipbrd.h>
#include <wx/dcbuffer.h>

#include "App.hpp"
#include "document.hpp"
#include "CharacterEncoder.hpp"
#include "DataType.hpp"
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

wxDEFINE_EVENT(REHex::EVENT_RECURSION_FIXUP, wxCommandEvent);

REHex::Document::Document():
	write_protect(false),
	current_seq(0),
	buffer_seq(0),
	saved_seq(0),
	highlight_colour_map(wxGetApp().settings->get_highlight_colours()),
	cursor_state(CSTATE_HEX),
	comment_modified_buffer(this, EV_COMMENT_MODIFIED),
	highlights_changed_buffer(this, EV_HIGHLIGHTS_CHANGED),
	types_changed_buffer(this, EV_TYPES_CHANGED),
	mappings_changed_buffer(this, EV_MAPPINGS_CHANGED)
{
	buffer = new Buffer();
	title  = "Untitled";
	
	_forward_buffer_events();
	
	wxGetApp().Bind(PALETTE_CHANGED, &REHex::Document::OnColourPaletteChanged, this);
}

REHex::Document::Document(const std::string &filename):
	filename(filename),
	write_protect(false),
	current_seq(0),
	buffer_seq(0),
	saved_seq(0),
	highlight_colour_map(HighlightColourMap::defaults()),
	cursor_state(CSTATE_HEX),
	comment_modified_buffer(this, EV_COMMENT_MODIFIED),
	highlights_changed_buffer(this, EV_HIGHLIGHTS_CHANGED),
	types_changed_buffer(this, EV_TYPES_CHANGED),
	mappings_changed_buffer(this, EV_MAPPINGS_CHANGED)
{
	buffer = new Buffer(filename);
	
	data_seq.set_range   (0, buffer->length(), 0);
	types.set_range      (0, buffer->length(), TypeInfo(""));
	
	size_t last_slash = filename.find_last_of("/\\");
	title = (last_slash != std::string::npos ? filename.substr(last_slash + 1) : filename);
	
	std::string meta_filename = find_metadata(filename);
	if(!(meta_filename.empty()))
	{
		_load_metadata(meta_filename);
	}
	
	_forward_buffer_events();
	
	wxGetApp().Bind(PALETTE_CHANGED, &REHex::Document::OnColourPaletteChanged, this);
}

#ifdef __APPLE__
REHex::Document::Document(MacFileName &&filename):
	filename(filename.GetFileName().GetFullPath().ToStdString()),
	write_protect(false),
	current_seq(0),
	buffer_seq(0),
	saved_seq(0),
	highlight_colour_map(HighlightColourMap::defaults()),
	cursor_state(CSTATE_HEX),
	comment_modified_buffer(this, EV_COMMENT_MODIFIED),
	highlights_changed_buffer(this, EV_HIGHLIGHTS_CHANGED),
	types_changed_buffer(this, EV_TYPES_CHANGED),
	mappings_changed_buffer(this, EV_MAPPINGS_CHANGED)
{
	buffer = new Buffer(std::move(filename));
	
	data_seq.set_range   (0, buffer->length(), 0);
	types.set_range      (0, buffer->length(), TypeInfo(""));
	
	size_t last_slash = this->filename.find_last_of("/\\");
	title = (last_slash != std::string::npos ? this->filename.substr(last_slash + 1) : this->filename);
	
	std::string meta_filename = find_metadata(this->filename);
	if(!(meta_filename.empty()))
	{
		_load_metadata(meta_filename);
	}
	
	_forward_buffer_events();
	
	wxGetApp().Bind(PALETTE_CHANGED, &REHex::Document::OnColourPaletteChanged, this);
}
#endif /* __APPLE__ */

void REHex::Document::_forward_buffer_events()
{
	buffer->Bind(BACKING_FILE_DELETED, [&](wxCommandEvent &event)
	{
		wxCommandEvent new_event(BACKING_FILE_DELETED);
		new_event.SetEventObject(this);
		
		ProcessEvent(new_event);
	});
	
	buffer->Bind(BACKING_FILE_MODIFIED, [&](wxCommandEvent &event)
	{
		wxCommandEvent new_event(BACKING_FILE_MODIFIED);
		new_event.SetEventObject(this);
		
		ProcessEvent(new_event);
	});
}

REHex::Document::~Document()
{
	wxGetApp().Unbind(PALETTE_CHANGED, &REHex::Document::OnColourPaletteChanged, this);
	delete buffer;
}

void REHex::Document::reload()
{
	/* Ensure no transaction is in progress. */
	assert(undo_stack.empty() || undo_stack.back().complete);
	
	if(filename.empty())
	{
		throw std::logic_error("Attempt to reload document with no backing file");
	}
	
	/* There may be background tasks operating on this document, so we have to signal the
	 * beginning of any operations that change the virtual view of the file to pause any
	 * background processing overlapping it, do the operation and then signal that we are done.
	 *
	 * First, if the file has shrunk, we erase any data past the new EOF, then we swap out the
	 * buffer as an overwrite operation, then finally we raise an insert operation without
	 * actually changing the data if the file has grown.
	*/
	
	Buffer *new_buffer = new Buffer(filename);
	
	wxGetApp().bulk_updates_freeze();
	
	off_t old_size = buffer_length();
	off_t new_size = new_buffer->length();
	
	if(new_size < old_size)
	{
		off_t erase_begin = new_size;
		off_t erase_length = old_size - new_size;
		
		/*
		OffsetLengthEvent data_erasing_event(this, DATA_ERASING, erase_begin, erase_length);
		ProcessEvent(data_erasing_event);
		
		buffer->erase_data(erase_begin, erase_length);
		
		OffsetLengthEvent data_erase_event(this, DATA_ERASE, erase_begin, erase_length);
		ProcessEvent(data_erase_event);
		*/
		
		_UNTRACKED_erase_data(erase_begin, erase_length);
	}
	
	off_t overlap_size = std::min(old_size, new_size);
	
	OffsetLengthEvent data_overwriting_event(this, DATA_OVERWRITING, 0, overlap_size);
	ProcessEvent(data_overwriting_event);
	
	delete buffer;
	buffer = new_buffer;
	
	_forward_buffer_events();
	
	types.clear();
	types.set_range(0, new_size, TypeInfo(""));
	
	OffsetLengthEvent data_overwrite_event(this, DATA_OVERWRITE, 0, overlap_size);
	ProcessEvent(data_overwrite_event);
	
	if(new_size > old_size)
	{
		OffsetLengthEvent data_inserting_event(this, DATA_INSERTING, old_size, new_size - old_size);
		ProcessEvent(data_inserting_event);
		
		OffsetLengthEvent data_insert_event(this, DATA_INSERT, old_size, new_size - old_size);
		ProcessEvent(data_insert_event);
	}
	
	/* Clear all state and reload file metadata. */
	
	current_seq = 0;
	buffer_seq = 0;
	data_seq.clear();
	data_seq.set_range(0, new_size, 0);
	saved_seq = 0;
	
	undo_stack.clear();
	redo_stack.clear();
	
	comments.clear();
	highlights.clear();
	
	real_to_virt_segs.clear();
	virt_to_real_segs.clear();
	
	size_t last_slash = filename.find_last_of("/\\");
	title = (last_slash != std::string::npos ? filename.substr(last_slash + 1) : filename);
	
	std::string meta_filename = find_metadata(filename);
	if(!(meta_filename.empty()))
	{
		_load_metadata(meta_filename);
	}
	
	/* Fire off every metadata change signal. This will trigger an unnecessary amount of
	 * processing, but there's no way to coalesce these together (yet).
	*/
	
	_raise_comment_modified();
	_raise_highlights_changed();
	_raise_types_changed();
	_raise_mappings_changed();
	
	wxGetApp().bulk_updates_thaw();
	
	_raise_undo_update();
	_raise_clean();
}

void REHex::Document::save()
{
	bool externally_changed = file_deleted() || file_modified();
	
	if(is_buffer_dirty() || externally_changed)
	{
		buffer->write_inplace();
	}
	
	save_metadata_for(filename);
	
	if(current_seq != saved_seq || externally_changed)
	{
		saved_seq = current_seq;
		buffer_seq = saved_seq;
		data_seq.set_range(0, buffer->length(), saved_seq);
		
		_raise_clean();
	}
}

void REHex::Document::save(const std::string &filename)
{
	bool externally_changed = file_deleted() || file_modified();
	
	buffer->write_inplace(filename);
	this->filename = filename;
	
	size_t last_slash = filename.find_last_of("/\\");
	title = (last_slash != std::string::npos ? filename.substr(last_slash + 1) : filename);
	
	save_metadata_for(filename);
	
	if(current_seq != saved_seq || externally_changed)
	{
		saved_seq = current_seq;
		buffer_seq = saved_seq;
		data_seq.set_range(0, buffer->length(), saved_seq);
		
		_raise_clean();
	}
	
	DocumentTitleEvent document_title_event(this, title);
	ProcessEvent(document_title_event);
}

std::string REHex::Document::get_title()
{
	return title;
}

void REHex::Document::set_title(const std::string &title)
{
	this->title = title;
	
	DocumentTitleEvent document_title_event(this, title);
	ProcessEvent(document_title_event);
}

std::string REHex::Document::get_filename()
{
	return filename;
}

bool REHex::Document::is_dirty()
{
	return current_seq != saved_seq;
}

bool REHex::Document::is_byte_dirty(BitOffset offset) const
{
	auto i = data_seq.get_range(offset.byte());
	if(i != data_seq.end() && i->second != saved_seq)
	{
		return true;
	}
	
	if(!offset.byte_aligned())
	{
		/* The offset isn't byte-aligned, so we need to check if the
		 * subsequent byte is dirty too.
		*/
		
		i = data_seq.get_range(offset.byte() + 1);
		if(i != data_seq.end() && i->second != saved_seq)
		{
			return true;
		}
	}
	
	return false;
}

bool REHex::Document::is_buffer_dirty() const
{
	return buffer_seq != saved_seq;
}

REHex::BitOffset REHex::Document::get_cursor_position() const
{
	return this->cpos_off;
}

REHex::Document::CursorState REHex::Document::get_cursor_state() const
{
	return cursor_state;
}

void REHex::Document::set_cursor_position(BitOffset off, CursorState cursor_state)
{
	_set_cursor_position(off, cursor_state);
}

void REHex::Document::_set_cursor_position(BitOffset position, enum CursorState cursor_state)
{
	position = std::max(position, BitOffset::ZERO);
	position = std::min(position, BitOffset(buffer_length(), 0));
	
	if(cursor_state == CSTATE_GOTO)
	{
		cursor_state = this->cursor_state;
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

std::vector<unsigned char> REHex::Document::read_data(BitOffset offset, off_t max_length) const
{
	return buffer->read_data(offset, max_length);
}

std::vector<bool> REHex::Document::read_bits(BitOffset offset, size_t max_length) const
{
	return buffer->read_bits(offset, max_length);
}

/* GCC (and Clang) whinge about the below pattern of creating a heap-allocated std::vector from the
 * return value of Buffer::read_data() preventing copy elison and state the std::move should be
 * removed, however, in my testing, removing the std::move leads to the data being copied, which is
 * unnecessarily expensive in terms of CPU time and (momentary) memory usage, while std::move does
 * the right thing.
*/
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpessimizing-move"
#endif

void REHex::Document::overwrite_data(BitOffset offset, const void *data, off_t length, BitOffset new_cursor_pos, CursorState new_cursor_state, const char *change_desc)
{
	if(write_protect)
	{
		wxGetApp().printf_error("Cannot modify file - write protect is enabled\n");
		return;
	}
	
	if(new_cursor_pos < BitOffset(0, 0))   { new_cursor_pos = cpos_off; }
	if(new_cursor_state == CSTATE_CURRENT) { new_cursor_state = cursor_state; }
	
	TransOpFunc first_op([&]()
	{
		std::shared_ptr< std::vector<unsigned char> > old_data(new std::vector<unsigned char>(std::move( read_data(offset, length) )));
		assert(old_data->size() == (size_t)(length));
		
		ByteRangeMap<unsigned int> new_data_seq_slice = data_seq
			.get_slice(offset.byte(), length + !offset.byte_aligned())
			.transform([](const unsigned int &value) { return value + 1; });
		
		_UNTRACKED_overwrite_data(offset, (const unsigned char*)(data), length, new_data_seq_slice);
		buffer_seq = current_seq;
		
		_set_cursor_position(new_cursor_pos, new_cursor_state);
		
		return _op_overwrite_undo(offset, old_data, new_cursor_pos, new_cursor_state);
	});
	
	transact_step(first_op, change_desc);
}

REHex::Document::TransOpFunc REHex::Document::_op_overwrite_undo(BitOffset offset, std::shared_ptr< std::vector<unsigned char> > old_data, BitOffset new_cursor_pos, CursorState new_cursor_state)
{
	return TransOpFunc([this, offset, old_data, new_cursor_pos, new_cursor_state]()
	{
		std::shared_ptr< std::vector<unsigned char> > new_data(new std::vector<unsigned char>(std::move( read_data(offset, old_data->size()) )));
		assert(new_data->size() == old_data->size());
		
		ByteRangeMap<unsigned int> new_data_seq_slice = data_seq
			.get_slice(offset.byte(), old_data->size() + !offset.byte_aligned())
			.transform([](const unsigned int &value) { return value - 1; });
		
		_UNTRACKED_overwrite_data(offset, old_data->data(), old_data->size(), new_data_seq_slice);
		buffer_seq = current_seq;
		
		return _op_overwrite_redo(offset, new_data, new_cursor_pos, new_cursor_state);
	});
}

REHex::Document::TransOpFunc REHex::Document::_op_overwrite_redo(BitOffset offset, std::shared_ptr< std::vector<unsigned char> > new_data, BitOffset new_cursor_pos, CursorState new_cursor_state)
{
	return TransOpFunc([this, offset, new_data, new_cursor_pos, new_cursor_state]()
	{
		std::shared_ptr< std::vector<unsigned char> > old_data(new std::vector<unsigned char>(std::move( read_data(offset, new_data->size()) )));
		assert(old_data->size() == new_data->size());
		
		ByteRangeMap<unsigned int> new_data_seq_slice = data_seq
			.get_slice(offset.byte(), new_data->size() + !offset.byte_aligned())
			.transform([](const unsigned int &value) { return value + 1; });
		
		_UNTRACKED_overwrite_data(offset, new_data->data(), new_data->size(), new_data_seq_slice);
		buffer_seq = current_seq;
		
		_set_cursor_position(new_cursor_pos, new_cursor_state);
		
		return _op_overwrite_undo(offset, old_data, new_cursor_pos, new_cursor_state);
	});
}

void REHex::Document::overwrite_bits(BitOffset offset, const std::vector<bool> &data, BitOffset new_cursor_pos, CursorState new_cursor_state, const char *change_desc)
{
	if(write_protect)
	{
		wxGetApp().printf_error("Cannot modify file - write protect is enabled\n");
		return;
	}
	
	if(new_cursor_pos < BitOffset::ZERO)   { new_cursor_pos = cpos_off; }
	if(new_cursor_state == CSTATE_CURRENT) { new_cursor_state = cursor_state; }
	
	TransOpFunc first_op([&]()
	{
		std::shared_ptr< std::vector<bool> > old_data(new std::vector<bool>(std::move( read_bits(offset, data.size()) )));
		assert(old_data->size() == data.size());
		
		ByteRangeMap<unsigned int> new_data_seq_slice = data_seq
			.get_slice(offset.byte(), ((offset.bit() + data.size() + 7) / 8))
			.transform([](const unsigned int &value) { return value + 1; });
		
		_UNTRACKED_overwrite_bits(offset, data, new_data_seq_slice);
		buffer_seq = current_seq;
		
		_set_cursor_position(new_cursor_pos, new_cursor_state);
		
		return _op_overwrite_bits_undo(offset, old_data, new_cursor_pos, new_cursor_state);
	});
	
	transact_step(first_op, change_desc);
}

REHex::Document::TransOpFunc REHex::Document::_op_overwrite_bits_undo(BitOffset offset, std::shared_ptr< std::vector<bool> > old_data, BitOffset new_cursor_pos, CursorState new_cursor_state)
{
	return TransOpFunc([this, offset, old_data, new_cursor_pos, new_cursor_state]()
	{
		std::shared_ptr< std::vector<bool> > new_data(new std::vector<bool>(std::move( read_bits(offset, old_data->size()) )));
		assert(new_data->size() == old_data->size());
		
		ByteRangeMap<unsigned int> new_data_seq_slice = data_seq
			.get_slice(offset.byte(), ((offset.bit() + old_data->size() + 7) / 8))
			.transform([](const unsigned int &value) { return value - 1; });
		
		_UNTRACKED_overwrite_bits(offset, *old_data, new_data_seq_slice);
		buffer_seq = current_seq;
		
		return _op_overwrite_bits_redo(offset, new_data, new_cursor_pos, new_cursor_state);
	});
}

REHex::Document::TransOpFunc REHex::Document::_op_overwrite_bits_redo(BitOffset offset, std::shared_ptr< std::vector<bool> > new_data, BitOffset new_cursor_pos, CursorState new_cursor_state)
{
	return TransOpFunc([this, offset, new_data, new_cursor_pos, new_cursor_state]()
	{
		std::shared_ptr< std::vector<bool> > old_data(new std::vector<bool>(std::move( read_bits(offset, new_data->size()) )));
		assert(old_data->size() == new_data->size());
		
		ByteRangeMap<unsigned int> new_data_seq_slice = data_seq
			.get_slice(offset.byte(), ((offset.bit() + new_data->size() + 7) / 8))
			.transform([](const unsigned int &value) { return value + 1; });
		
		_UNTRACKED_overwrite_bits(offset, *new_data, new_data_seq_slice);
		buffer_seq = current_seq;
		
		_set_cursor_position(new_cursor_pos, new_cursor_state);
		
		return _op_overwrite_bits_undo(offset, old_data, new_cursor_pos, new_cursor_state);
	});
}

void REHex::Document::insert_data(off_t offset, const void *data, off_t length, BitOffset new_cursor_pos, CursorState new_cursor_state, const char *change_desc)
{
	if(write_protect)
	{
		wxGetApp().printf_error("Cannot modify file - write protect is enabled\n");
		return;
	}
	
	if(new_cursor_pos == BitOffset::INVALID) { new_cursor_pos = cpos_off; }
	if(new_cursor_state == CSTATE_CURRENT)   { new_cursor_state = cursor_state; }
	
	TransOpFunc first_op([&]()
	{
		ByteRangeMap<unsigned int> new_data_seq_slice;
		new_data_seq_slice.set_range(offset, length, current_seq);
		
		_UNTRACKED_insert_data(offset, (const unsigned char*)(data), length, new_data_seq_slice);
		buffer_seq = current_seq;
		
		_set_cursor_position(new_cursor_pos, new_cursor_state);
		
		return _op_insert_undo(offset, length, new_cursor_pos, new_cursor_state);
	});
	
	transact_step(first_op, change_desc);
}

REHex::Document::TransOpFunc REHex::Document::_op_insert_undo(off_t offset, off_t length, BitOffset new_cursor_pos, CursorState new_cursor_state)
{
	return TransOpFunc([this, offset, length, new_cursor_pos, new_cursor_state]()
	{
		std::shared_ptr< std::vector<unsigned char> > data(new std::vector<unsigned char>(std::move( read_data(offset, length) )));
		assert(data->size() == (size_t)(length));
		
		ByteRangeMap<unsigned int> redo_data_seq_slice = data_seq.get_slice(offset, data->size());
		
		_UNTRACKED_erase_data(offset, data->size());
		buffer_seq = current_seq;
		
		return _op_insert_redo(offset, data, new_cursor_pos, new_cursor_state, redo_data_seq_slice);
	});
}

REHex::Document::TransOpFunc REHex::Document::_op_insert_redo(off_t offset, std::shared_ptr< std::vector<unsigned char> > data, BitOffset new_cursor_pos, CursorState new_cursor_state, const ByteRangeMap<unsigned int> &redo_data_seq_slice)
{
	return TransOpFunc([this, offset, data, new_cursor_pos, new_cursor_state, redo_data_seq_slice]()
	{
		_UNTRACKED_insert_data(offset, data->data(), data->size(), redo_data_seq_slice);
		buffer_seq = current_seq;
		
		_set_cursor_position(new_cursor_pos, new_cursor_state);
		
		return _op_insert_undo(offset, data->size(), new_cursor_pos, new_cursor_state);
	});
}

void REHex::Document::erase_data(off_t offset, off_t length, BitOffset new_cursor_pos, CursorState new_cursor_state, const char *change_desc)
{
	if(write_protect)
	{
		wxGetApp().printf_error("Cannot modify file - write protect is enabled\n");
		return;
	}
	
	if(new_cursor_pos == BitOffset::INVALID) { new_cursor_pos = cpos_off; }
	if(new_cursor_state == CSTATE_CURRENT)   { new_cursor_state = cursor_state; }
	
	TransOpFunc first_op([&]()
	{
		std::shared_ptr< std::vector<unsigned char> > old_data(new std::vector<unsigned char>(std::move( read_data(offset, length) )));
		assert(old_data->size() == (size_t)(length));
		
		ByteRangeMap<unsigned int> undo_data_seq_slice = data_seq.get_slice(offset, old_data->size());
		
		_UNTRACKED_erase_data(offset, old_data->size());
		buffer_seq = current_seq;
		
		_set_cursor_position(new_cursor_pos, new_cursor_state);
		
		return _op_erase_undo(offset, old_data, new_cursor_pos, new_cursor_state, undo_data_seq_slice);
	});
	
	transact_step(first_op, change_desc);
}

REHex::Document::TransOpFunc REHex::Document::_op_erase_undo(off_t offset, std::shared_ptr< std::vector<unsigned char> > old_data, BitOffset new_cursor_pos, CursorState new_cursor_state, const ByteRangeMap<unsigned int> &undo_data_seq_slice)
{
	return TransOpFunc([this, offset, old_data, new_cursor_pos, new_cursor_state, undo_data_seq_slice]()
	{
		_UNTRACKED_insert_data(offset, old_data->data(), old_data->size(), undo_data_seq_slice);
		buffer_seq = current_seq;
		
		return _op_erase_redo(offset, old_data->size(), new_cursor_pos, new_cursor_state);
	});
}

REHex::Document::TransOpFunc REHex::Document::_op_erase_redo(off_t offset, off_t length, BitOffset new_cursor_pos, CursorState new_cursor_state)
{
	return TransOpFunc([this, offset, length, new_cursor_pos, new_cursor_state]()
	{
		std::shared_ptr< std::vector<unsigned char> > old_data(new std::vector<unsigned char>(std::move( read_data(offset, length) )));
		assert(old_data->size() == (size_t)(length));
		
		ByteRangeMap<unsigned int> undo_data_seq_slice = data_seq.get_slice(offset, old_data->size());
		
		_UNTRACKED_erase_data(offset, old_data->size());
		buffer_seq = current_seq;
		
		_set_cursor_position(new_cursor_pos, new_cursor_state);
		
		return _op_erase_undo(offset, old_data, new_cursor_pos, new_cursor_state, undo_data_seq_slice);
	});
}

void REHex::Document::replace_data(off_t offset, off_t old_data_length, const void *new_data, off_t new_data_length, BitOffset new_cursor_pos, CursorState new_cursor_state, const char *change_desc)
{
	if(write_protect)
	{
		wxGetApp().printf_error("Cannot modify file - write protect is enabled\n");
		return;
	}
	
	if(new_cursor_pos < 0)                 { new_cursor_pos = cpos_off; }
	if(new_cursor_state == CSTATE_CURRENT) { new_cursor_state = cursor_state; }
	
	if(old_data_length == new_data_length)
	{
		/* Save unnecessary shuffling of the Buffer pages. */
		
		overwrite_data(offset, new_data, new_data_length, new_cursor_pos, new_cursor_state, change_desc);
		return;
	}
	
	TransOpFunc first_op([&]()
	{
		std::shared_ptr< std::vector<unsigned char> > old_data(new std::vector<unsigned char>(std::move( read_data(offset, old_data_length) )));
		assert(old_data->size() == (size_t)(old_data_length));
		
		ByteRangeMap<unsigned int> undo_data_seq_slice = data_seq.get_slice(offset, old_data->size());
		
		ByteRangeMap<unsigned int> new_data_seq_slice;
		new_data_seq_slice.set_range(offset, new_data_length, current_seq);
		
		_UNTRACKED_erase_data(offset, old_data->size());
		_UNTRACKED_insert_data(offset, (const unsigned char*)(new_data), new_data_length, new_data_seq_slice);
		buffer_seq = current_seq;
		
		_set_cursor_position(new_cursor_pos, new_cursor_state);
		
		return _op_replace_undo(offset, old_data, new_data_length, new_cursor_pos, new_cursor_state, undo_data_seq_slice);
	});
	
	transact_step(first_op, change_desc);
}

REHex::Document::TransOpFunc REHex::Document::_op_replace_undo(off_t offset, std::shared_ptr< std::vector<unsigned char> > old_data, off_t new_data_length, BitOffset new_cursor_pos, CursorState new_cursor_state, const ByteRangeMap<unsigned int> &undo_data_seq_slice)
{
	return TransOpFunc([this, offset, old_data, new_data_length, new_cursor_pos, new_cursor_state, undo_data_seq_slice]()
	{
		std::shared_ptr< std::vector<unsigned char> > new_data(new std::vector<unsigned char>(std::move( read_data(offset, new_data_length) )));
		assert(new_data->size() == (size_t)(new_data_length));
		
		_UNTRACKED_erase_data(offset, new_data_length);
		_UNTRACKED_insert_data(offset, old_data->data(), old_data->size(), undo_data_seq_slice);
		buffer_seq = current_seq;
		
		return _op_replace_redo(offset, old_data->size(), new_data, new_cursor_pos, new_cursor_state);
	});
}

REHex::Document::TransOpFunc REHex::Document::_op_replace_redo(off_t offset, off_t old_data_length, std::shared_ptr< std::vector<unsigned char> > new_data, BitOffset new_cursor_pos, CursorState new_cursor_state)
{
	return TransOpFunc([this, offset, old_data_length, new_data, new_cursor_pos, new_cursor_state]()
	{
		std::shared_ptr< std::vector<unsigned char> > old_data(new std::vector<unsigned char>(std::move( read_data(offset, old_data_length) )));
		assert(old_data->size() == (size_t)(old_data_length));
		
		ByteRangeMap<unsigned int> undo_data_seq_slice = data_seq.get_slice(offset, old_data->size());
		
		ByteRangeMap<unsigned int> new_data_seq_slice;
		new_data_seq_slice.set_range(offset, new_data->size(), current_seq);
		
		_UNTRACKED_erase_data(offset, old_data_length);
		_UNTRACKED_insert_data(offset, new_data->data(), new_data->size(), new_data_seq_slice);
		buffer_seq = current_seq;
		
		_set_cursor_position(new_cursor_pos, new_cursor_state);
		
		return _op_replace_undo(offset, old_data, new_data->size(), new_cursor_pos, new_cursor_state, undo_data_seq_slice);
	});
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

int REHex::Document::overwrite_text(BitOffset offset, const std::string &utf8_text, BitOffset new_cursor_pos, CursorState new_cursor_state, const char *change_desc)
{
	BitOffset buffer_length(buffer->length(), 0);
	
	if(offset < BitOffset::ZERO || offset >= buffer_length)
	{
		return WRITE_TEXT_BAD_OFFSET;
	}
	
	std::string encoded_text;
	encoded_text.reserve(utf8_text.size()); /* Assume it'll be about the same size after encoding. */
	
	int ret_flags = WRITE_TEXT_OK;
	
	CharacterEncoderIconv utf8_encoder("UTF-8", 1, true);
	
	size_t utf8_off;
	BitOffset write_pos;
	
	for(utf8_off = 0, write_pos = offset; utf8_off < utf8_text.size();)
	{
		if(write_pos >= buffer_length)
		{
			/* Won't fit without extending document. */
			ret_flags |= WRITE_TEXT_TRUNCATED;
			break;
		}
		
		const CharacterEncoder *encoder = get_text_encoder(write_pos);
		assert(encoder != NULL);
		
		EncodedCharacter ec = encoder->encode(utf8_text.substr(utf8_off, MAX_CHAR_SIZE));
		
		if(ec.valid)
		{
			if((write_pos + BitOffset(ec.encoded_char().size(), 0)) > buffer_length)
			{
				/* Won't fit without extending document. */
				ret_flags |= WRITE_TEXT_TRUNCATED;
				break;
			}
			
			encoded_text.append(ec.encoded_char());
			write_pos += BitOffset(ec.encoded_char().size(), 0);
			
			utf8_off += ec.utf8_char().size();
		}
		else{
			/* Character cannot be represented in destination encoding. Skip it. */
			
			/* Decode the input as a UTF-8 character to find the length. */
			EncodedCharacter ec = utf8_encoder.decode((utf8_text.data() + utf8_off), (utf8_text.size() - utf8_off));
			
			if(ec.valid)
			{
				utf8_off += ec.utf8_char().size();
			}
			else{
				/* Unable to parse input character... skip a byte and hope for the best. */
				++utf8_off;
			}
			
			ret_flags |= WRITE_TEXT_SKIPPED;
		}
	}
	
	assert((offset + BitOffset(encoded_text.size(), 0)) <= buffer_length);
	
	if(new_cursor_pos == WRITE_TEXT_GOTO_NEXT)
	{
		new_cursor_pos = offset + BitOffset(encoded_text.size(), 0);
	}
	
	overwrite_data(offset, encoded_text.data(), encoded_text.size(), new_cursor_pos, new_cursor_state, change_desc);
	
	return ret_flags;
}

int REHex::Document::insert_text(off_t offset, const std::string &utf8_text, off_t new_cursor_pos, CursorState new_cursor_state, const char *change_desc)
{
	off_t buffer_length = buffer->length();
	
	if(offset < 0 || offset > buffer_length)
	{
		return WRITE_TEXT_BAD_OFFSET;
	}
	
	std::string encoded_text;
	encoded_text.reserve(utf8_text.size()); /* Assume it'll be about the same size after encoding. */
	
	int ret_flags = WRITE_TEXT_OK;
	
	CharacterEncoderIconv utf8_encoder("UTF-8", 1, true);
	
	TypeInfo data_type;
	const CharacterEncoder *encoder;
	
	if(buffer_length > 0)
	{
		off_t ref_offset = std::min(offset, (buffer_length - 1)); /* Offset to copy encoding from. */
		
		auto type = types.get_range(ref_offset);
		assert(type != types.end());
		
		data_type = type->second;
		encoder = get_text_encoder(ref_offset);
	}
	else{
		encoder = &ascii_encoder;
	}
	
	for(off_t utf8_off = 0; utf8_off < (off_t)(utf8_text.size());)
	{
		EncodedCharacter ec = encoder->encode(utf8_text.substr(utf8_off, MAX_CHAR_SIZE));
		
		if(ec.valid)
		{
			encoded_text.append(ec.encoded_char());
			
			utf8_off += ec.utf8_char().size();
		}
		else{
			/* Character cannot be represented in destination encoding. Skip it. */
			
			/* Decode the input as a UTF-8 character to find the length. */
			EncodedCharacter ec = utf8_encoder.decode((utf8_text.data() + utf8_off), (utf8_text.size() - utf8_off));
			
			if(ec.valid)
			{
				utf8_off += ec.utf8_char().size();
			}
			else{
				/* Unable to parse input character... skip a byte and hope for the best. */
				++utf8_off;
			}
			
			ret_flags |= WRITE_TEXT_SKIPPED;
		}
	}
	
	if(new_cursor_pos == WRITE_TEXT_GOTO_NEXT)
	{
		new_cursor_pos = offset + (off_t)(encoded_text.size());
	}
	
	ScopedTransaction t(this, change_desc);
	
	if(!encoded_text.empty())
	{
		insert_data(offset, encoded_text.data(), encoded_text.size(), new_cursor_pos, new_cursor_state);
		set_data_type(offset, encoded_text.size(), data_type.name, data_type.options);
	}
	
	t.commit();
	
	return ret_flags;
}

int REHex::Document::replace_text(off_t offset, off_t old_data_length, const std::string &utf8_text, off_t new_cursor_pos, CursorState new_cursor_state, const char *change_desc)
{
	off_t buffer_length = buffer->length();
	
	if(offset < 0 || offset >= buffer_length)
	{
		return WRITE_TEXT_BAD_OFFSET;
	}
	
	std::string encoded_text;
	encoded_text.reserve(utf8_text.size()); /* Assume it'll be about the same size after encoding. */
	
	int ret_flags = WRITE_TEXT_OK;
	
	CharacterEncoderIconv utf8_encoder("UTF-8", 1, true);
	
	const CharacterEncoder *encoder = get_text_encoder(offset);
	assert(encoder != NULL);
	
	TypeInfo data_type = types.get_range(offset)->second;
	
	for(off_t utf8_off = 0; utf8_off < (off_t)(utf8_text.size());)
	{
		EncodedCharacter ec = encoder->encode(utf8_text.substr(utf8_off, MAX_CHAR_SIZE));
		
		if(ec.valid)
		{
			encoded_text.append(ec.encoded_char());
			
			utf8_off += ec.utf8_char().size();
		}
		else{
			/* Character cannot be represented in destination encoding. Skip it. */
			
			/* Decode the input as a UTF-8 character to find the length. */
			EncodedCharacter ec = utf8_encoder.decode((utf8_text.data() + utf8_off), (utf8_text.size() - utf8_off));
			
			if(ec.valid)
			{
				utf8_off += ec.utf8_char().size();
			}
			else{
				/* Unable to parse input character... skip a byte and hope for the best. */
				++utf8_off;
			}
			
			ret_flags |= WRITE_TEXT_SKIPPED;
		}
	}
	
	if(new_cursor_pos == WRITE_TEXT_GOTO_NEXT)
	{
		new_cursor_pos = offset + (off_t)(encoded_text.size());
	}
	
	ScopedTransaction t(this, change_desc);
	
	if(!encoded_text.empty())
	{
		replace_data(offset, old_data_length, encoded_text.data(), encoded_text.size(), new_cursor_pos, new_cursor_state);
		set_data_type(offset, encoded_text.size(), data_type.name, data_type.options);
	}
	
	t.commit();
	
	return ret_flags;
}

off_t REHex::Document::buffer_length() const
{
	return buffer->length();
}

bool REHex::Document::file_deleted() const
{
	return buffer->file_deleted();
}

bool REHex::Document::file_modified() const
{
	return buffer->file_modified();
}

void REHex::Document::set_write_protect(bool write_protect)
{
	this->write_protect = write_protect;
}

bool REHex::Document::get_write_protect() const
{
	return write_protect;
}

const REHex::BitRangeTree<REHex::Document::Comment> &REHex::Document::get_comments() const
{
	return comments;
}

bool REHex::Document::set_comment(BitOffset offset, BitOffset length, const Comment &comment)
{
	assert(offset >= BitOffset::ZERO);
	assert(length >= BitOffset::ZERO);
	
	if(!comments.can_set(offset, length))
	{
		return false;
	}
	
	_tracked_change("set comment",
		[this, offset, length, comment]()
		{
			comments.set(offset, length, comment);
			_raise_comment_modified();
		},
		[this]()
		{
			/* Comments are restored implicitly. */
			_raise_comment_modified();
		});
	
	return true;
}

bool REHex::Document::erase_comment(BitOffset offset, BitOffset length)
{
	if(comments.find(BitRangeTreeKey(offset, length)) == comments.end())
	{
		return false;
	}
	
	_tracked_change("delete comment",
		[this, offset, length]()
		{
			comments.erase(BitRangeTreeKey(offset, length));
			_raise_comment_modified();
		},
		[this]()
		{
			/* Comments are restored implicitly. */
			_raise_comment_modified();
		});
	
	return true;
}

bool REHex::Document::erase_comment_recursive(BitOffset offset, BitOffset length)
{
	if(comments.find(BitRangeTreeKey(offset, length)) == comments.end())
	{
		return false;
	}
	
	_tracked_change("delete comment and children",
		[this, offset, length]()
		{
			comments.erase_recursive(BitRangeTreeKey(offset, length));
			_raise_comment_modified();
		},
		[this]()
		{
			/* Comments are restored implicitly. */
			_raise_comment_modified();
		});
	
	return true;
}

const REHex::HighlightColourMap &REHex::Document::get_highlight_colours() const
{
	return highlight_colour_map;
}

void REHex::Document::set_highlight_colours(const HighlightColourMap &highlight_colours)
{
	_tracked_change("change highlight colours",
		[this, highlight_colours]()
		{
			highlight_colour_map = highlight_colours;
			
			/* Delete any highlights using a deleted colour. */
			
			for(auto it = highlights.begin(); it != highlights.end();)
			{
				if(highlight_colour_map.find(it->second) != highlight_colour_map.end())
				{
					++it;
				}
				else{
					BitOffset it_offset = it->first.offset;
					BitOffset it_length = it->first.length;
					
					highlights.clear_range(it_offset, it_length);
					
					it = highlights.get_range_in(it_offset, BitOffset::MAX);
				}
			}
			
			_raise_highlights_changed();
		},
		
		[this]()
		{
			/* Highlight changes are undone implicitly. */
			_raise_highlights_changed();
		});
}

int REHex::Document::allocate_highlight_colour(const wxString &label, const wxColour &primary_colour, const wxColour &secondary_colour)
{
	for(auto it = highlight_colour_map.begin(); it != highlight_colour_map.end(); ++it)
	{
		if(it->second.label == label
			&& (primary_colour == wxNullColour || it->second.primary_colour == primary_colour)
			&& (secondary_colour == wxNullColour || it->second.secondary_colour == secondary_colour))
		{
			return it->first;
		}
	}
	
	int next_highlight_idx = highlight_colour_map.next_free_idx();
	if(next_highlight_idx == -1)
	{
		return -1;
	}
	
	_tracked_change("change highlight colours",
		[=, this]()
		{
			auto new_colour_it = highlight_colour_map.add();
			assert(new_colour_it != highlight_colour_map.end());
			assert(new_colour_it->first == next_highlight_idx);
			
			new_colour_it->second.set_label(label);
			if(primary_colour != wxNullColour) { new_colour_it->second.set_primary_colour(primary_colour); }
			if(secondary_colour != wxNullColour) { new_colour_it->second.set_secondary_colour(secondary_colour); }
			
			_raise_highlights_changed();
		},
		
		[this]()
		{
			/* Highlight changes are undone implicitly. */
			_raise_highlights_changed();
		});
	
	return next_highlight_idx;
}

const REHex::BitRangeMap<int> &REHex::Document::get_highlights() const
{
	return highlights;
}

bool REHex::Document::set_highlight(BitOffset off, BitOffset length, int highlight_colour_idx)
{
	if(off < BitOffset::ZERO || length < BitOffset(0, 1) || (off + length) > BitOffset(buffer_length(), 0)
		|| highlight_colour_map.find(highlight_colour_idx) == highlight_colour_map.end())
	{
		return false;
	}
	
	_tracked_change("set highlight",
		[this, off, length, highlight_colour_idx]()
		{
			highlights.set_range(off, length, highlight_colour_idx);
			_raise_highlights_changed();
		},
		
		[this]()
		{
			/* Highlight changes are undone implicitly. */
			_raise_highlights_changed();
		});
	
	return true;
}

bool REHex::Document::erase_highlight(BitOffset off, BitOffset length)
{
	auto highlight = highlights.get_range(off);
	if(highlight == highlights.end() || highlight->first.offset != off || highlight->first.length != length)
	{
		return false;
	}
	
	_tracked_change("remove highlight",
		[this, off, length]()
		{
			highlights.clear_range(off, length);
			_raise_highlights_changed();
		},
		
		[this]()
		{
			/* Highlight changes are undone implicitly. */
			_raise_highlights_changed();
		});
	
	return true;
}

const REHex::BitRangeMap<REHex::Document::TypeInfo> &REHex::Document::get_data_types() const
{
	return types;
}

bool REHex::Document::set_data_type(BitOffset offset, BitOffset length, const std::string &type, const json_t *options)
{
	if(offset < BitOffset::ZERO || length <= BitOffset::ZERO || (offset + length).byte() > buffer_length())
	{
		return false;
	}
	
	TypeInfo type_info(type, options);
	
	_tracked_change("set data type",
		[this, offset, length, type_info]()
		{
			types.set_range(offset, length, type_info);
			_raise_types_changed();
		},
		
		[]()
		{
			/* Data type changes are undone implicitly. */
		});
	
	return true;
}

const REHex::CharacterEncoder *REHex::Document::get_text_encoder(BitOffset offset) const
{
	if(offset < 0 || offset >= buffer_length())
	{
		return NULL;
	}
	
	auto type_at_off = types.get_range(offset);
	assert(type_at_off != types.end());
	
	if(type_at_off->second.name != "")
	{
		auto type = DataTypeRegistry::get_type(type_at_off->second.name, type_at_off->second.options);
		assert(type != NULL);
		
		if(type->encoder != NULL)
		{
			return type->encoder;
		}
	}
	
	static REHex::CharacterEncoderASCII ascii_encoder;
	return &ascii_encoder;
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
			
			_raise_mappings_changed();
		},
		
		[]()
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
			
			_raise_mappings_changed();
		},
		
		[]()
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
			
			_raise_mappings_changed();
		},
		
		[]()
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

void REHex::Document::handle_paste(wxWindow *modal_dialog_parent, const BitRangeTree<Document::Comment> &clipboard_comments)
{
	BitOffset cursor_pos = get_cursor_position();
	BitOffset buffer_length = BitOffset(this->buffer_length(), 0);
	
	for(auto cc = clipboard_comments.begin(); cc != clipboard_comments.end(); ++cc)
	{
		if((cursor_pos + cc->first.offset + cc->first.length) >= buffer_length)
		{
			wxMessageBox("Cannot paste comment(s) - would extend beyond end of file", "Error", (wxOK | wxICON_ERROR), modal_dialog_parent);
			return;
		}
		
		if(comments.find(BitRangeTreeKey(cursor_pos + cc->first.offset, cc->first.length)) != comments.end()
			|| !comments.can_set(cursor_pos + cc->first.offset, cc->first.length))
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
				comments.set(cursor_pos + cc->first.offset, cc->first.length, cc->second);
			}
			
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
		wxGetApp().bulk_updates_freeze();
		
		auto &trans = undo_stack.back();
		
		--current_seq;
		
		std::list<TransOpFunc> redo_funcs;
		
		for(auto undo_func = trans.ops.begin(); undo_func != trans.ops.end(); ++undo_func)
		{
			TransOpFunc redo_func = (*undo_func)();
			redo_funcs.push_front(redo_func);
		}
		
		trans.ops.swap(redo_funcs);
		
		bool cursor_updated = (cpos_off != trans.old_cpos_off || cursor_state != trans.old_cursor_state);
		
		cpos_off     = trans.old_cpos_off;
		cursor_state = trans.old_cursor_state;
		comments     = trans.old_comments;
		highlight_colour_map = trans.old_highlight_colours;
		highlights   = trans.old_highlights;
		
		if(types != trans.old_types)
		{
			types = trans.old_types;
			_raise_types_changed();
		}
		
		if(real_to_virt_segs != trans.old_real_to_virt_segs || virt_to_real_segs != trans.old_virt_to_real_segs)
		{
			real_to_virt_segs = trans.old_real_to_virt_segs;
			virt_to_real_segs = trans.old_virt_to_real_segs;
			_raise_mappings_changed();
		}
		
		if(current_seq == saved_seq)
		{
			_raise_clean();
		}
		else if(current_seq == saved_seq - 1)
		{
			_raise_dirty();
		}
		
		if(cursor_updated)
		{
			CursorUpdateEvent cursor_update_event(this, cpos_off, cursor_state);
			ProcessEvent(cursor_update_event);
		}
		
		redo_stack.push_back(trans);
		undo_stack.pop_back();
		
		_raise_undo_update();
		
		wxGetApp().bulk_updates_thaw();
	}
}

const char *REHex::Document::undo_desc()
{
	if(!undo_stack.empty())
	{
		return undo_stack.back().desc.c_str();
	}
	else{
		return NULL;
	}
}

void REHex::Document::redo()
{
	if(!redo_stack.empty())
	{
		wxGetApp().bulk_updates_freeze();
		
		auto &trans = redo_stack.back();
		
		++current_seq;
		
		std::list<TransOpFunc> undo_funcs;
		
		for(auto redo_func = trans.ops.begin(); redo_func != trans.ops.end(); ++redo_func)
		{
			TransOpFunc undo_func = (*redo_func)();
			undo_funcs.push_front(undo_func);
		}
		
		if(current_seq == saved_seq)
		{
			_raise_clean();
		}
		else if(current_seq == saved_seq + 1)
		{
			_raise_dirty();
		}
		
		trans.ops.swap(undo_funcs);
		
		undo_stack.push_back(trans);
		redo_stack.pop_back();
		
		_raise_undo_update();
		
		wxGetApp().bulk_updates_thaw();
	}
}

const char *REHex::Document::redo_desc()
{
	if(!redo_stack.empty())
	{
		return redo_stack.back().desc.c_str();
	}
	else{
		return NULL;
	}
}

void REHex::Document::reset_to_clean()
{
	current_seq = 0;
	buffer_seq = 0;
	saved_seq = 0;
	data_seq.set_range(0, buffer->length(), 0);
	
	undo_stack.clear();
	redo_stack.clear();
	_raise_undo_update();
}

void REHex::Document::transact_begin(const std::string &desc)
{
	if(undo_stack.empty() || undo_stack.back().complete)
	{
		wxGetApp().bulk_updates_freeze();
		
		++current_seq;
		
		if(current_seq == saved_seq)
		{
			/* The file has been saved, then changes undone, and NOW we're starting a
			 * fresh transaction - rewriting history from prior to the save.
			 *
			 * Flip the most significant bit of current_seq so it differs from the
			 * current saved_seq - all that really matters is that any new sequence
			 * numbers written to data_seq DON'T match saved_seq.
			*/
			
			static const unsigned int SEQ_MSB = (1 << ((sizeof(unsigned int) * CHAR_BIT) - 1));
			current_seq ^= SEQ_MSB;
		}
		
		undo_stack.emplace_back(desc, this);
		redo_stack.clear();
		
		_raise_undo_update();
	}
	else{
		throw std::runtime_error("Attempted to start a transaction when one is already open");
	}
}

void REHex::Document::transact_step(const TransOpFunc &op, const std::string &desc)
{
	if(undo_stack.empty() || undo_stack.back().complete)
	{
		/* No transaction open, this op will be executed within its own one. */
		
		ScopedTransaction t(this, desc);
		
		TransOpFunc undo_op = op();
		undo_stack.back().ops.push_front(undo_op);
		
		t.commit();
	}
	else{
		TransOpFunc undo_op = op();
		undo_stack.back().ops.push_front(undo_op);
	}
}

void REHex::Document::transact_commit()
{
	if(undo_stack.empty() || undo_stack.back().complete)
	{
		throw std::runtime_error("Attempted to commit without an open transaction");
	}
	
	undo_stack.back().complete = true;
	
	if(current_seq == saved_seq + 1)
	{
		_raise_dirty();
	}
	
	while(undo_stack.size() > UNDO_MAX)
	{
		undo_stack.pop_front();
	}
	
	wxGetApp().bulk_updates_thaw();
}

void REHex::Document::transact_rollback()
{
	if(undo_stack.empty() || undo_stack.back().complete)
	{
		throw std::runtime_error("Attempted to rollback without an open transaction");
	}
	
	undo();
	
	redo_stack.clear();
	_raise_undo_update();
	
	wxGetApp().bulk_updates_thaw();
}

void REHex::Document::_UNTRACKED_overwrite_data(BitOffset offset, const unsigned char *data, off_t length, const ByteRangeMap<unsigned int> &data_seq_slice)
{
	/* The overwrite events use byte offsets and lengths, there isn't really much reason to
	 * refactor them for bit alignment, so we just grow the reported length by one when the
	 * write length isn't byte aligned to ensure it covers all modified bytes.
	*/
	off_t byte_offset = offset.byte();
	off_t byte_length = length + !offset.byte_aligned();
	
	assert(data_seq_slice.empty() || data_seq_slice.front().first.offset <= byte_offset);
	assert(data_seq_slice.empty() || (data_seq_slice.back().first.offset + data_seq_slice.back().first.length) >= (byte_offset + byte_length));
	
	OffsetLengthEvent data_overwriting_event(this, DATA_OVERWRITING, byte_offset, byte_length);
	ProcessEvent(data_overwriting_event);
	
	bool ok = buffer->overwrite_data(offset, data, length);
	assert(ok);
	
	if(ok)
	{
		data_seq.set_slice(data_seq_slice);
		
		OffsetLengthEvent data_overwrite_event(this, DATA_OVERWRITE, byte_offset, byte_length);
		ProcessEvent(data_overwrite_event);
	}
	else{
		OffsetLengthEvent data_overwrite_aborted_event(this, DATA_OVERWRITE_ABORTED, byte_offset, byte_length);
		ProcessEvent(data_overwrite_aborted_event);
	}
}

void REHex::Document::_UNTRACKED_overwrite_bits(BitOffset offset, const std::vector<bool> &data, const ByteRangeMap<unsigned int> &data_seq_slice)
{
	/* The overwrite events use byte offsets and lengths, there isn't really much reason to
	 * refactor them for bit alignment, so we just grow the reported length by one when the
	 * write length isn't byte aligned to ensure it covers all modified bytes.
	*/
	off_t byte_offset = offset.byte();
	off_t byte_length = (offset.bit() + data.size() + 7) / 8;
	
	assert(data_seq_slice.empty() || data_seq_slice.front().first.offset <= byte_offset);
	assert(data_seq_slice.empty() || (data_seq_slice.back().first.offset + data_seq_slice.back().first.length) >= (byte_offset + byte_length));
	
	OffsetLengthEvent data_overwriting_event(this, DATA_OVERWRITING, byte_offset, byte_length);
	ProcessEvent(data_overwriting_event);
	
	bool ok = buffer->overwrite_bits(offset, data);
	assert(ok);
	
	if(ok)
	{
		data_seq.set_slice(data_seq_slice);
		
		OffsetLengthEvent data_overwrite_event(this, DATA_OVERWRITE, byte_offset, byte_length);
		ProcessEvent(data_overwrite_event);
	}
	else{
		OffsetLengthEvent data_overwrite_aborted_event(this, DATA_OVERWRITE_ABORTED, byte_offset, byte_length);
		ProcessEvent(data_overwrite_aborted_event);
	}
}

/* Insert some data into the Buffer and update our own data structures. */
void REHex::Document::_UNTRACKED_insert_data(off_t offset, const unsigned char *data, off_t length, const ByteRangeMap<unsigned int> &data_seq_slice)
{
	assert(data_seq_slice.empty() || data_seq_slice.front().first.offset <= offset);
	assert(data_seq_slice.empty() || (data_seq_slice.back().first.offset + data_seq_slice.back().first.length) >= (offset + length));
	
	OffsetLengthEvent data_inserting_event(this, DATA_INSERTING, offset, length);
	ProcessEvent(data_inserting_event);
	
	bool ok = buffer->insert_data(offset, data, length);
	assert(ok);
	
	if(ok)
	{
		data_seq.data_inserted(offset, length);
		data_seq.set_slice(data_seq_slice);
		
		types.data_inserted(offset, length);
		types.set_range(offset, length, TypeInfo(""));
		
		OffsetLengthEvent data_insert_event(this, DATA_INSERT, offset, length);
		ProcessEvent(data_insert_event);
		
		if(comments.data_inserted(offset, length) > 0)
		{
			_raise_comment_modified();
		}
		
		if(highlights.data_inserted(offset, length))
		{
			_raise_highlights_changed();
		}
		
		_update_mappings_data_inserted(offset, length);
		
		OffsetLengthEvent data_insert_done_event(this, DATA_INSERT_DONE, offset, length);
		ProcessEvent(data_insert_done_event);
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
		data_seq.data_erased(offset, length);
		
		types.data_erased(offset, length);
		
		OffsetLengthEvent data_erase_event(this, DATA_ERASE, offset, length);
		ProcessEvent(data_erase_event);
		
		if(comments.data_erased(offset, length) > 0)
		{
			_raise_comment_modified();
		}
		
		if(highlights.data_erased(offset, length))
		{
			_raise_highlights_changed();
		}
		
		_virt_to_real_segs_data_erased(offset, length);
		bool r2v_updated = real_to_virt_segs.data_erased(offset, length);
		
		if(r2v_updated)
		{
			_raise_mappings_changed();
		}
		
		OffsetLengthEvent data_erase_done_event(this, DATA_ERASE_DONE, offset, length);
		ProcessEvent(data_erase_done_event);
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

void REHex::Document::_tracked_change(const char *desc, const std::function< void() > &do_func, const std::function< void() > &undo_func)
{
	transact_step(_op_tracked_change(do_func, undo_func), desc);
}

REHex::Document::TransOpFunc REHex::Document::_op_tracked_change(const std::function< void() > &func, const std::function< void() > &next_func)
{
	return TransOpFunc([this, func, next_func]()
	{
		func();
		return _op_tracked_change(next_func, func);
	});
}

json_t *REHex::Document::serialise_metadata(bool even_if_empty) const
{
	bool has_data = even_if_empty;
	
	json_t *root = json_object();
	if(root == NULL)
	{
		return NULL;
	}
	
	if(json_object_set_new(root, "write_protect", json_boolean(write_protect)) == -1)
	{
		json_decref(root);
		return NULL;
	}
	
	if(write_protect)
	{
		has_data = true;
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
		if(json_array_append_new(comments, comment) == -1
			|| json_object_set_new(comment, "offset", c->first.offset.to_json()) == -1
			|| json_object_set_new(comment, "length", c->first.length.to_json()) == -1
			|| json_object_set_new(comment, "text",   json_stringn(utf8_text.data(), utf8_text.length())) == -1)
		{
			json_decref(root);
			return NULL;
		}
		has_data = true;
	}
	
	json_t *highlight_colours = highlight_colour_map.to_json();
	if(json_object_set_new(root, "highlight-colours", highlight_colours) == -1)
	{
		json_decref(root);
		return NULL;
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
		if(json_array_append_new(highlights, highlight) == -1
			|| json_object_set_new(highlight, "offset",     h->first.offset.to_json()) == -1
			|| json_object_set_new(highlight, "length",     h->first.length.to_json()) == -1
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
		if(dt->second.name == "")
		{
			/* Don't bother serialising "this is data" */
			continue;
		}
		
		json_t *data_type = json_object();
		if(json_array_append_new(data_types, data_type) == -1
			|| json_object_set_new(data_type, "offset", dt->first.offset.to_json()) == -1
			|| json_object_set_new(data_type, "length", dt->first.length.to_json()) == -1
			|| json_object_set_new(data_type, "type",   json_string(dt->second.name.c_str())) == -1
			|| (dt->second.options != NULL && json_object_set(data_type, "options", dt->second.options) == -1))
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
		if(json_array_append_new(virt_mappings, mapping) == -1
			|| json_object_set_new(mapping, "real_offset", json_integer(r2v->first.offset)) == -1
			|| json_object_set_new(mapping, "virt_offset", json_integer(r2v->second)) == -1
			|| json_object_set_new(mapping, "length",      json_integer(r2v->first.length)) == -1)
		{
			json_decref(root);
			return NULL;
		}
		
		has_data = true;
	}
	
	if(!has_data)
	{
		json_decref(root);
		root = NULL;
	}
	
	return root;
}

void REHex::Document::save_metadata(const std::string &filename) const
{
	/* TODO: Atomically replace file. */
	
	json_t *meta = serialise_metadata(true);
	if(meta == NULL)
	{
		throw std::bad_alloc();
	}
	
	int res = json_dump_file(meta, filename.c_str(), JSON_INDENT(2));
	json_decref(meta);
	
	if(res != 0)
	{
		throw std::runtime_error("Unable to write " + filename);
	}
}

void REHex::Document::save_metadata_for(const std::string &filename)
{
	/* TODO: Atomically replace file. */
	
	json_t *meta = serialise_metadata(false);
	int res = 0;
	if (meta != NULL)
	{
		res = json_dump_file(meta, (filename + ".rehex-meta").c_str(), JSON_INDENT(2));
		
#ifdef __APPLE__
		std::string sandbox = App::get_home_directory();
		
		wxFileName fn(filename);
		
		fn.MakeAbsolute();
		
		fn.SetPath(sandbox + fn.GetPath());
		fn.SetFullName(fn.GetFullName() + ".rehex-meta");
		
		if(res == 0)
		{
			/* We managed to save the rehex-meta alongside the actual file, delete any
			 * file within the application sandbox.
			*/
			wxRemoveFile(fn.GetFullPath());
		}
		else if(wxDirExists(sandbox))
		{
			/* Couldn't save the rehex-meta file, probably because we're sandboxed.
			 * Save the rehex-meta within the application sandbox directory.
			*/
			
			recursive_mkdir(fn.GetPath().ToStdString());
			res = json_dump_file(meta, fn.GetFullPath().ToStdString().c_str(), JSON_INDENT(2));
		}
#endif
	}
	else{
		std::string meta_filename = find_metadata(filename);
		if(!(meta_filename.empty()))
		{
			wxRemoveFile(meta_filename);
		}
	}
	json_decref(meta);
	
	if(res != 0)
	{
		throw std::runtime_error("Unable to write " + filename);
	}
}

REHex::BitRangeTree<REHex::Document::Comment> REHex::Document::_load_comments(const json_t *meta, off_t buffer_length)
{
	BitRangeTree<Comment> comments;
	
	json_t *j_comments = json_object_get(meta, "comments");
	
	size_t index;
	json_t *value;
	
	json_array_foreach(j_comments, index, value)
	{
		if(!json_is_string(json_object_get(value, "text")))
		{
			continue;
		}
		
		BitOffset offset = BitOffset::from_json(json_object_get(value, "offset"));
		BitOffset length = BitOffset::from_json(json_object_get(value, "length"));
		wxString text = wxString::FromUTF8(json_string_value(json_object_get(value, "text")));
		
		if(offset >= BitOffset::ZERO && offset < BitOffset(buffer_length, 0)
			&& length >= BitOffset::ZERO && (offset + length) <= BitOffset(buffer_length, 0))
		{
			comments.set(offset, length, Comment(text));
		}
	}
	
	return comments;
}

REHex::BitRangeMap<int> REHex::Document::_load_highlights(const json_t *meta, off_t buffer_length, const HighlightColourMap &highlight_colour_map)
{
	BitRangeMap<int> highlights;
	
	json_t *j_highlights = json_object_get(meta, "highlights");
	
	size_t index;
	json_t *value;
	
	json_array_foreach(j_highlights, index, value)
	{
		BitOffset offset = BitOffset::from_json(json_object_get(value, "offset"));
		BitOffset length = BitOffset::from_json(json_object_get(value, "length"));
		int       colour = json_integer_value(json_object_get(value, "colour-idx"));
		
		if(offset >= 0 && offset < BitOffset(buffer_length, 0)
			&& length > 0 && (offset + length) <= BitOffset(buffer_length, 0)
			&& highlight_colour_map.find(colour) != highlight_colour_map.end())
		{
			highlights.set_range(offset, length, colour);
		}
	}
	
	return highlights;
}

REHex::BitRangeMap<REHex::Document::TypeInfo> REHex::Document::_load_types(const json_t *meta, off_t buffer_length)
{
	BitRangeMap<TypeInfo> types;
	types.set_range(BitOffset(0, 0), BitOffset(buffer_length, 0), TypeInfo(""));
	
	json_t *j_types = json_object_get(meta, "data_types");
	
	size_t index;
	json_t *value;
	
	json_array_foreach(j_types, index, value)
	{
		BitOffset offset = BitOffset::from_json(json_object_get(value, "offset"));
		BitOffset length = BitOffset::from_json(json_object_get(value, "length"));
		const char *type_name = json_string_value(json_object_get(value, "type"));
		json_t *options  = json_object_get(value, "options");
		
		if(offset >= BitOffset::ZERO && offset < BitOffset(buffer_length, 0)
			&& length > BitOffset::ZERO && (offset + length) <= BitOffset(buffer_length, 0)
			&& type_name != NULL)
		{
			std::shared_ptr<const DataType> type;
			try {
				type = DataTypeRegistry::get_type(type_name, options);
				if(type == NULL)
				{
					wxGetApp().printf_error("Ignoring unknown data type '%s' in metadata\n", type_name);
				}
			}
			catch(const std::invalid_argument &e)
			{
				wxGetApp().printf_error("Ignoring data type with invalid options (%s) in metadata\n", e.what());
			}
			
			if(type)
			{
				types.set_range(offset, length, TypeInfo(type_name, options));
			}
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

void REHex::Document::load_metadata(const std::string &filename)
{
	json_error_t json_err;
	json_t *meta = json_load_file(filename.c_str(), 0, &json_err);
	if(meta == NULL)
	{
		throw std::runtime_error(json_err.text);
	}
	
	wxGetApp().bulk_updates_freeze();
	
	ScopedTransaction t(this, "Import metadata");
	load_metadata(meta);
	t.commit();
	
	/* Fire off every metadata change signal. This will trigger an unnecessary amount of
	 * processing, but there's no way to coalesce these together (yet).
	*/
	
	_raise_comment_modified();
	_raise_highlights_changed();
	_raise_types_changed();
	_raise_mappings_changed();
	
	wxGetApp().bulk_updates_thaw();
	
	json_decref(meta);
}

void REHex::Document::_load_metadata(const std::string &filename)
{
	/* TODO: Report errors */
	
	json_error_t json_err;
	json_t *meta = json_load_file(filename.c_str(), 0, &json_err);
	
	load_metadata(meta);
	
	json_decref(meta);
}

std::string REHex::Document::find_metadata(const std::string &filename)
{
#ifdef __APPLE__
	{
		wxFileName fn(filename);
		
		fn.MakeAbsolute();
		
		fn.SetPath(App::get_home_directory() + fn.GetPath());
		fn.SetFullName(fn.GetFullName() + ".rehex-meta");
		
		if(fn.FileExists())
		{
			return fn.GetFullPath().ToStdString();
		}
	}
#endif
	
	{
		wxFileName fn(filename);
		
		fn.SetFullName(fn.GetFullName() + ".rehex-meta");
		
		if(fn.FileExists())
		{
			return fn.GetFullPath().ToStdString();
		}
	}
	
	return std::string();
}

void REHex::Document::load_metadata(const json_t *metadata)
{
	comments = _load_comments(metadata, buffer_length());
	
	json_t *highlight_colours = json_object_get(metadata, "highlight-colours");
	if(highlight_colours != NULL)
	{
		try {
			highlight_colour_map = HighlightColourMap::from_json(highlight_colours);
		}
		catch(const std::exception &e)
		{
			wxGetApp().printf_error("Error loading highlight colours from file: %s\n", e.what());
		}
	}
	
	highlights = _load_highlights(metadata, buffer_length(), highlight_colour_map);
	types = _load_types(metadata, buffer_length());
	std::tie(real_to_virt_segs, virt_to_real_segs) = _load_virt_mappings(metadata, buffer_length());
	
	json_t *write_protect = json_object_get(metadata, "write_protect");
	set_write_protect(json_is_true(write_protect));
}

void REHex::Document::_raise_comment_modified()
{
	comment_modified_buffer.raise();
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
	highlights_changed_buffer.raise();
}

void REHex::Document::_raise_types_changed()
{
	types_changed_buffer.raise();
}

void REHex::Document::_raise_mappings_changed()
{
	mappings_changed_buffer.raise();
}

void REHex::Document::OnColourPaletteChanged(wxCommandEvent &event)
{
	highlight_colour_map.set_default_lightness(active_palette->get_default_highlight_lightness());
	event.Skip();
}

bool REHex::Document::ProcessEvent(wxEvent &event)
{
	/* When a handler is removed from a wxEvtHandler object, the slot is cleared but the array
	 * doesn't get compacted until the next time an event is dispatched.
	 *
	 * If the next event dispatched on that wxEvtHandler happens to recurse, it triggers an
	 * assertion failure in wxEvtHandler::SearchDynamicEventTable() and may cause handlers on
	 * that event to be skipped.
	 *
	 * To work around this, we always raise a stub event which should have no handlers bound to
	 * it before each real event, which causes the handler table compaction to run sooner.
	 *
	 * This won't fix all cases - if the handler callback removes a handler from the
	 * wxEvtHandler before further recursion happens then we are still screwed, but hopefully
	 * that condition won't ever happen...
	 *
	 * See https://github.com/wxWidgets/wxWidgets/issues/24803 for more details.
	*/
	
	wxCommandEvent stub_event(EVENT_RECURSION_FIXUP);
	wxEvtHandler::ProcessEvent(stub_event);
	
	return wxEvtHandler::ProcessEvent(event);
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

REHex::Document::TypeInfo::TypeInfo():
	name(""),
	options(NULL) {}

REHex::Document::TypeInfo::TypeInfo(const std::string &name, const json_t *options):
	name(name),
	options(NULL)
{
	if(options != NULL)
	{
		this->options = json_deep_copy(options);
		if(this->options == NULL)
		{
			throw std::bad_alloc();
		}
	}
}

REHex::Document::TypeInfo::TypeInfo(const TypeInfo &typeinfo):
	name(typeinfo.name),
	options(typeinfo.options)
{
	json_incref(options);
}

REHex::Document::TypeInfo &REHex::Document::TypeInfo::operator=(const TypeInfo &rhs)
{
	name = rhs.name;
	options = rhs.options;
	
	if(options != NULL)
	{
		json_incref(options);
	}
	
	return *this;
}

REHex::Document::TypeInfo::~TypeInfo()
{
	json_decref(options);
}

bool REHex::Document::TypeInfo::operator==(const TypeInfo &rhs) const
{
	return name == rhs.name
		&& ((options == NULL && rhs.options == NULL) || json_equal(options, rhs.options));
}

bool REHex::Document::TypeInfo::operator!=(const TypeInfo &rhs) const
{
	return !(*this == rhs);
}

bool REHex::Document::TypeInfo::operator<(const TypeInfo &rhs) const
{
	if(name < rhs.name)
	{
		return true;
	}
	else if(name > rhs.name)
	{
		return false;
	}
	else{
		if(options == NULL && rhs.options == NULL)
		{
			/* this == rhs */
			return false;
		}
		else if(options == NULL)
		{
			/* this < rhs */
			return true;
		}
		else if(rhs.options == NULL)
		{
			/* this > rhs */
			return false;
		}
		else{
			/* TODO: Implement a proper JSON compare function. */
			
			char *lhs_options = json_dumps(options,     JSON_COMPACT | JSON_SORT_KEYS);
			char *rhs_options = json_dumps(rhs.options, JSON_COMPACT | JSON_SORT_KEYS);
			
			if(lhs_options == NULL || rhs_options == NULL)
			{
				free(lhs_options);
				free(rhs_options);
				
				throw std::bad_alloc();
			}
			
			int result = strcmp(lhs_options, rhs_options);
			
			free(lhs_options);
			free(rhs_options);
			
			return result < 0;
		}
	}
}

REHex::Document::TransOpFunc::TransOpFunc(const std::function<TransOpFunc()> &func):
	func(func) {}

REHex::Document::TransOpFunc::TransOpFunc(const TransOpFunc &src):
	func(src.func) {}

REHex::Document::TransOpFunc::TransOpFunc(TransOpFunc &&src):
	func(std::move(src.func)) {}

REHex::Document::TransOpFunc REHex::Document::TransOpFunc::operator()() const
{
	return func();
}

const wxDataFormat REHex::CommentsDataObject::format("rehex/comments/v2");

REHex::CommentsDataObject::CommentsDataObject():
	wxCustomDataObject(format) {}

REHex::CommentsDataObject::CommentsDataObject(const std::list<BitRangeTree<Document::Comment>::const_iterator> &comments, BitOffset base):
	wxCustomDataObject(format)
{
	set_comments(comments, base);
}

REHex::BitRangeTree<REHex::Document::Comment> REHex::CommentsDataObject::get_comments() const
{
	BitRangeTree<Document::Comment> comments;
	
	const unsigned char *data = (const unsigned char*)(GetData());
	const unsigned char *end = data + GetSize();
	
	while(data + sizeof(Header) < end)
	{
		Header header;
		memcpy(&header, data, sizeof(Header));
		
		if((data + sizeof(Header) + header.text_length) <= end)
		{
			wxString text(wxString::FromUTF8((const char*)(data + sizeof(Header)), header.text_length));
			
			#ifndef NDEBUG
			bool x =
			#endif
				comments.set(BitOffset::from_int64(header.file_offset), BitOffset::from_int64(header.file_length), REHex::Document::Comment(text));
			assert(x); /* TODO: Raise some kind of error. Beep? */
			
			data += sizeof(Header) + header.text_length;
		}
		else{
			break;
		}
	}
	
	return comments;
}

void REHex::CommentsDataObject::set_comments(const std::list<BitRangeTree<Document::Comment>::const_iterator> &comments, BitOffset base)
{
	size_t size = 0;
	
	for(auto i = comments.begin(); i != comments.end(); ++i)
	{
		size += sizeof(Header) + (*i)->value.text->utf8_str().length();
	}
	
	void *data = Alloc(size); /* Wrapper around new[] - throws on failure */
	
	char *outp = (char*)(data);
	
	for(auto i = comments.begin(); i != comments.end(); ++i)
	{
		const wxScopedCharBuffer utf8_text = (*i)->value.text->utf8_str();
		
		Header header;
		memset(&header, 0, sizeof(header));
		
		header.file_offset = ((*i)->key.offset - base).to_int64();
		header.file_length = (*i)->key.length.to_int64();
		header.text_length = utf8_text.length();
		
		memcpy(outp, &header, sizeof(Header));
		outp += sizeof(Header);
		
		memcpy(outp, utf8_text.data(), utf8_text.length());
		outp += utf8_text.length();
	}
	
	assert(((char*)(data) + size) == outp);
	
	TakeData(size, data);
}

REHex::Document::CommandEventBuffer::CommandEventBuffer(wxEvtHandler *handler, wxEventType type):
	handler(handler),
	type(type),
	frozen(false),
	pending(false)
{
	wxGetApp().Bind(BULK_UPDATES_FROZEN, &REHex::Document::CommandEventBuffer::OnBulkUpdatesFrozen, this);
	wxGetApp().Bind(BULK_UPDATES_THAWED, &REHex::Document::CommandEventBuffer::OnBulkUpdatesThawed, this);
}

REHex::Document::CommandEventBuffer::~CommandEventBuffer()
{
	wxGetApp().Unbind(BULK_UPDATES_THAWED, &REHex::Document::CommandEventBuffer::OnBulkUpdatesThawed, this);
	wxGetApp().Unbind(BULK_UPDATES_FROZEN, &REHex::Document::CommandEventBuffer::OnBulkUpdatesFrozen, this);
}

void REHex::Document::CommandEventBuffer::raise()
{
	if(frozen)
	{
		pending = true;
		return;
	}
	
	wxCommandEvent event(type);
	event.SetEventObject(handler);
	
	handler->ProcessEvent(event);
}

void REHex::Document::CommandEventBuffer::OnBulkUpdatesFrozen(wxCommandEvent &event)
{
	frozen = true;
	event.Skip();
}

void REHex::Document::CommandEventBuffer::OnBulkUpdatesThawed(wxCommandEvent &event)
{
	frozen = false;
	
	if(pending)
	{
		pending = false;
		raise();
	}
	
	event.Skip();
}
