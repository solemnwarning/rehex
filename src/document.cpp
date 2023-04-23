/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2023 Daniel Collins <solemnwarning@solemnwarning.net>
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

REHex::Document::Document():
	write_protect(false),
	current_seq(0),
	buffer_seq(0),
	saved_seq(0),
	cursor_state(CSTATE_HEX),
	comment_modified_buffer(this, EV_COMMENT_MODIFIED),
	highlights_changed_buffer(this, EV_HIGHLIGHTS_CHANGED),
	types_changed_buffer(this, EV_TYPES_CHANGED),
	mappings_changed_buffer(this, EV_MAPPINGS_CHANGED)
{
	buffer = new Buffer();
	title  = "Untitled";
	
	_forward_buffer_events();
}

REHex::Document::Document(const std::string &filename):
	filename(filename),
	write_protect(false),
	current_seq(0),
	buffer_seq(0),
	saved_seq(0),
	cursor_state(CSTATE_HEX),
	comment_modified_buffer(this, EV_COMMENT_MODIFIED),
	highlights_changed_buffer(this, EV_HIGHLIGHTS_CHANGED),
	types_changed_buffer(this, EV_TYPES_CHANGED),
	mappings_changed_buffer(this, EV_MAPPINGS_CHANGED)
{
	buffer = new Buffer(filename);
	
	data_seq.set_range   (0, buffer->length(), 0);
	types.set_range      (0, buffer->length(), "");
	
	size_t last_slash = filename.find_last_of("/\\");
	title = (last_slash != std::string::npos ? filename.substr(last_slash + 1) : filename);
	
	std::string meta_filename = filename + ".rehex-meta";
	if(wxFileExists(meta_filename))
	{
		_load_metadata(meta_filename);
	}
	
	_forward_buffer_events();
}

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
	types.set_range(0, new_size, "");
	
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
	
	std::string meta_filename = filename + ".rehex-meta";
	if(wxFileExists(meta_filename))
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
	
	_save_metadata(filename + ".rehex-meta");
	
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
	
	_save_metadata(filename + ".rehex-meta");
	
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

bool REHex::Document::is_byte_dirty(off_t offset) const
{
	auto i = data_seq.get_range(offset);
	return i != data_seq.end() && i->second != saved_seq;
}

bool REHex::Document::is_buffer_dirty() const
{
	return buffer_seq != saved_seq;
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
	if(write_protect)
	{
		wxGetApp().printf_error("Cannot modify file - write protect is enabled\n");
		return;
	}
	
	if(new_cursor_pos < 0)                 { new_cursor_pos = cpos_off; }
	if(new_cursor_state == CSTATE_CURRENT) { new_cursor_state = cursor_state; }
	
	TransOpFunc first_op([&]()
	{
		std::shared_ptr< std::vector<unsigned char> > old_data(new std::vector<unsigned char>(std::move( read_data(offset, length) )));
		assert(old_data->size() == (size_t)(length));
		
		ByteRangeMap<unsigned int> new_data_seq_slice = data_seq
			.get_slice(offset, length)
			.transform([](const unsigned int &value) { return value + 1; });
		
		_UNTRACKED_overwrite_data(offset, (const unsigned char*)(data), length, new_data_seq_slice);
		buffer_seq = current_seq;
		
		_set_cursor_position(new_cursor_pos, new_cursor_state);
		
		return _op_overwrite_undo(offset, old_data, new_cursor_pos, new_cursor_state);
	});
	
	transact_step(first_op, change_desc);
}

REHex::Document::TransOpFunc REHex::Document::_op_overwrite_undo(off_t offset, std::shared_ptr< std::vector<unsigned char> > old_data, off_t new_cursor_pos, CursorState new_cursor_state)
{
	return TransOpFunc([this, offset, old_data, new_cursor_pos, new_cursor_state]()
	{
		std::shared_ptr< std::vector<unsigned char> > new_data(new std::vector<unsigned char>(std::move( read_data(offset, old_data->size()) )));
		assert(new_data->size() == old_data->size());
		
		ByteRangeMap<unsigned int> new_data_seq_slice = data_seq
			.get_slice(offset, old_data->size())
			.transform([](const unsigned int &value) { return value - 1; });
		
		_UNTRACKED_overwrite_data(offset, old_data->data(), old_data->size(), new_data_seq_slice);
		buffer_seq = current_seq;
		
		return _op_overwrite_redo(offset, new_data, new_cursor_pos, new_cursor_state);
	});
}

REHex::Document::TransOpFunc REHex::Document::_op_overwrite_redo(off_t offset, std::shared_ptr< std::vector<unsigned char> > new_data, off_t new_cursor_pos, CursorState new_cursor_state)
{
	return TransOpFunc([this, offset, new_data, new_cursor_pos, new_cursor_state]()
	{
		std::shared_ptr< std::vector<unsigned char> > old_data(new std::vector<unsigned char>(std::move( read_data(offset, new_data->size()) )));
		assert(old_data->size() == new_data->size());
		
		ByteRangeMap<unsigned int> new_data_seq_slice = data_seq
			.get_slice(offset, new_data->size())
			.transform([](const unsigned int &value) { return value + 1; });
		
		_UNTRACKED_overwrite_data(offset, new_data->data(), new_data->size(), new_data_seq_slice);
		buffer_seq = current_seq;
		
		_set_cursor_position(new_cursor_pos, new_cursor_state);
		
		return _op_overwrite_undo(offset, old_data, new_cursor_pos, new_cursor_state);
	});
}

void REHex::Document::insert_data(off_t offset, const void *data, off_t length, off_t new_cursor_pos, CursorState new_cursor_state, const char *change_desc)
{
	if(write_protect)
	{
		wxGetApp().printf_error("Cannot modify file - write protect is enabled\n");
		return;
	}
	
	if(new_cursor_pos < 0)                 { new_cursor_pos = cpos_off; }
	if(new_cursor_state == CSTATE_CURRENT) { new_cursor_state = cursor_state; }
	
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

REHex::Document::TransOpFunc REHex::Document::_op_insert_undo(off_t offset, off_t length, off_t new_cursor_pos, CursorState new_cursor_state)
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

REHex::Document::TransOpFunc REHex::Document::_op_insert_redo(off_t offset, std::shared_ptr< std::vector<unsigned char> > data, off_t new_cursor_pos, CursorState new_cursor_state, const ByteRangeMap<unsigned int> &redo_data_seq_slice)
{
	return TransOpFunc([this, offset, data, new_cursor_pos, new_cursor_state, redo_data_seq_slice]()
	{
		_UNTRACKED_insert_data(offset, data->data(), data->size(), redo_data_seq_slice);
		buffer_seq = current_seq;
		
		_set_cursor_position(new_cursor_pos, new_cursor_state);
		
		return _op_insert_undo(offset, data->size(), new_cursor_pos, new_cursor_state);
	});
}

void REHex::Document::erase_data(off_t offset, off_t length, off_t new_cursor_pos, CursorState new_cursor_state, const char *change_desc)
{
	if(write_protect)
	{
		wxGetApp().printf_error("Cannot modify file - write protect is enabled\n");
		return;
	}
	
	if(new_cursor_pos < 0)                 { new_cursor_pos = cpos_off; }
	if(new_cursor_state == CSTATE_CURRENT) { new_cursor_state = cursor_state; }
	
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

REHex::Document::TransOpFunc REHex::Document::_op_erase_undo(off_t offset, std::shared_ptr< std::vector<unsigned char> > old_data, off_t new_cursor_pos, CursorState new_cursor_state, const ByteRangeMap<unsigned int> &undo_data_seq_slice)
{
	return TransOpFunc([this, offset, old_data, new_cursor_pos, new_cursor_state, undo_data_seq_slice]()
	{
		_UNTRACKED_insert_data(offset, old_data->data(), old_data->size(), undo_data_seq_slice);
		buffer_seq = current_seq;
		
		return _op_erase_redo(offset, old_data->size(), new_cursor_pos, new_cursor_state);
	});
}

REHex::Document::TransOpFunc REHex::Document::_op_erase_redo(off_t offset, off_t length, off_t new_cursor_pos, CursorState new_cursor_state)
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

void REHex::Document::replace_data(off_t offset, off_t old_data_length, const void *new_data, off_t new_data_length, off_t new_cursor_pos, CursorState new_cursor_state, const char *change_desc)
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

REHex::Document::TransOpFunc REHex::Document::_op_replace_undo(off_t offset, std::shared_ptr< std::vector<unsigned char> > old_data, off_t new_data_length, off_t new_cursor_pos, CursorState new_cursor_state, const ByteRangeMap<unsigned int> &undo_data_seq_slice)
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

REHex::Document::TransOpFunc REHex::Document::_op_replace_redo(off_t offset, off_t old_data_length, std::shared_ptr< std::vector<unsigned char> > new_data, off_t new_cursor_pos, CursorState new_cursor_state)
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

int REHex::Document::overwrite_text(off_t offset, const std::string &utf8_text, off_t new_cursor_pos, CursorState new_cursor_state, const char *change_desc)
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
	
	for(off_t utf8_off = 0, write_pos = offset; utf8_off < (off_t)(utf8_text.size());)
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
			if((write_pos + (off_t)(ec.encoded_char().size())) > buffer_length)
			{
				/* Won't fit without extending document. */
				ret_flags |= WRITE_TEXT_TRUNCATED;
				break;
			}
			
			encoded_text.append(ec.encoded_char());
			write_pos += ec.encoded_char().size();
			
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
	
	assert((offset + (off_t)(encoded_text.size())) <= buffer_length);
	
	if(new_cursor_pos == WRITE_TEXT_GOTO_NEXT)
	{
		new_cursor_pos = offset + (off_t)(encoded_text.size());
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
	
	std::string data_type;
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
		data_type = "";
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
		set_data_type(offset, encoded_text.size(), data_type);
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
	
	std::string data_type = types.get_range(offset)->second;
	
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
		set_data_type(offset, encoded_text.size(), data_type);
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

const REHex::ByteRangeTree<REHex::Document::Comment> &REHex::Document::get_comments() const
{
	return comments;
}

bool REHex::Document::set_comment(off_t offset, off_t length, const Comment &comment)
{
	assert(offset >= 0);
	assert(length >= 0);
	
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

bool REHex::Document::erase_comment(off_t offset, off_t length)
{
	if(comments.find(ByteRangeTreeKey(offset, length)) == comments.end())
	{
		return false;
	}
	
	_tracked_change("delete comment",
		[this, offset, length]()
		{
			comments.erase(ByteRangeTreeKey(offset, length));
			_raise_comment_modified();
		},
		[this]()
		{
			/* Comments are restored implicitly. */
			_raise_comment_modified();
		});
	
	return true;
}

bool REHex::Document::erase_comment_recursive(off_t offset, off_t length)
{
	if(comments.find(ByteRangeTreeKey(offset, length)) == comments.end())
	{
		return false;
	}
	
	_tracked_change("delete comment and children",
		[this, offset, length]()
		{
			comments.erase_recursive(ByteRangeTreeKey(offset, length));
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
	
	if(!highlights.can_set(off, length))
	{
		return false;
	}
	
	_tracked_change("set highlight",
		[this, off, length, highlight_colour_idx]()
		{
			highlights.set(off, length, highlight_colour_idx);
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
			_raise_types_changed();
		},
		
		[]()
		{
			/* Data type changes are undone implicitly. */
		});
	
	return true;
}

const REHex::CharacterEncoder *REHex::Document::get_text_encoder(off_t offset) const
{
	if(offset < 0 || offset >= buffer_length())
	{
		return NULL;
	}
	
	auto type_at_off = types.get_range(offset);
	assert(type_at_off != types.end());
	
	if(type_at_off->second != "")
	{
		const DataTypeRegistration *dt_reg = DataTypeRegistry::by_name(type_at_off->second);
		assert(dt_reg != NULL);
		
		return dt_reg->encoder;
	}
	else{
		static REHex::CharacterEncoderASCII ascii_encoder;
		return &ascii_encoder;
	}
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

void REHex::Document::handle_paste(wxWindow *modal_dialog_parent, const ByteRangeTree<Document::Comment> &clipboard_comments)
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
		
		if(comments.find(ByteRangeTreeKey(cursor_pos + cc->first.offset, cc->first.length)) != comments.end()
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

void REHex::Document::_UNTRACKED_overwrite_data(off_t offset, const unsigned char *data, off_t length, const ByteRangeMap<unsigned int> &data_seq_slice)
{
	assert(data_seq_slice.empty() || data_seq_slice.front().first.offset <= offset);
	assert(data_seq_slice.empty() || (data_seq_slice.back().first.offset + data_seq_slice.back().first.length) >= (offset + length));
	
	OffsetLengthEvent data_overwriting_event(this, DATA_OVERWRITING, offset, length);
	ProcessEvent(data_overwriting_event);
	
	bool ok = buffer->overwrite_data(offset, data, length);
	assert(ok);
	
	if(ok)
	{
		data_seq.set_slice(data_seq_slice);
		
		OffsetLengthEvent data_overwrite_event(this, DATA_OVERWRITE, offset, length);
		ProcessEvent(data_overwrite_event);
	}
	else{
		OffsetLengthEvent data_overwrite_aborted_event(this, DATA_OVERWRITE_ABORTED, offset, length);
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
		types.set_range(offset, length, "");
		
		OffsetLengthEvent data_insert_event(this, DATA_INSERT, offset, length);
		ProcessEvent(data_insert_event);
		
		if(comments.data_inserted(offset, length) > 0)
		{
			_raise_comment_modified();
		}
		
		if(highlights.data_inserted(offset, length) > 0)
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
		data_seq.data_erased(offset, length);
		
		types.data_erased(offset, length);
		
		OffsetLengthEvent data_erase_event(this, DATA_ERASE, offset, length);
		ProcessEvent(data_erase_event);
		
		if(comments.data_erased(offset, length) > 0)
		{
			_raise_comment_modified();
		}
		
		if(highlights.data_erased(offset, length) > 0)
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

json_t *REHex::Document::_dump_metadata(bool& has_data)
{
	has_data = false;
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

REHex::ByteRangeTree<REHex::Document::Comment> REHex::Document::_load_comments(const json_t *meta, off_t buffer_length)
{
	ByteRangeTree<Comment> comments;
	
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
			comments.set(offset, length, Comment(text));
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
			highlights.set(offset, length, colour);
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
	
	json_t *write_protect = json_object_get(meta, "write_protect");
	set_write_protect(json_is_true(write_protect));
	
	json_decref(meta);
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

const wxDataFormat REHex::CommentsDataObject::format("rehex/comments/v1");

REHex::CommentsDataObject::CommentsDataObject():
	wxCustomDataObject(format) {}

REHex::CommentsDataObject::CommentsDataObject(const std::list<ByteRangeTree<Document::Comment>::const_iterator> &comments, off_t base):
	wxCustomDataObject(format)
{
	set_comments(comments, base);
}

REHex::ByteRangeTree<REHex::Document::Comment> REHex::CommentsDataObject::get_comments() const
{
	ByteRangeTree<Document::Comment> comments;
	
	const unsigned char *data = (const unsigned char*)(GetData());
	const unsigned char *end = data + GetSize();
	const Header *header = nullptr;
	
	while(data + sizeof(Header) < end && (header = (const Header*)(data)), (data + sizeof(Header) + header->text_length <= end))
	{
		wxString text(wxString::FromUTF8((const char*)(header + 1), header->text_length));
		
		bool x = comments.set(header->file_offset, header->file_length, REHex::Document::Comment(text));
		assert(x); /* TODO: Raise some kind of error. Beep? */
		
		data += sizeof(Header) + header->text_length;
	}
	
	return comments;
}

void REHex::CommentsDataObject::set_comments(const std::list<ByteRangeTree<Document::Comment>::const_iterator> &comments, off_t base)
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
		Header *header = (Header*)(outp);
		outp += sizeof(Header);
		
		const wxScopedCharBuffer utf8_text = (*i)->value.text->utf8_str();
		
		header->file_offset = (*i)->key.offset - base;
		header->file_length = (*i)->key.length;
		header->text_length = utf8_text.length();
		
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
