/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <assert.h>
#include <ctype.h>
#include <iterator>
#include <numeric>
#include <unictype.h>
#include <unistr.h>
#include <wx/artprov.h>
#include <wx/clipbrd.h>
#include <wx/filename.h>
#include <wx/mstream.h>
#include <wx/numformatter.h>

#include "App.hpp"
#include "CharacterEncoder.hpp"
#include "FileWriter.hpp"
#include "profile.hpp"
#include "StringPanel.hpp"
#include "util.hpp"

#include "../res/spinner24.h"

static const size_t WINDOW_SIZE = 2 * 1024 * 1024; /* 2MiB */
static const size_t MAX_STRINGS = 1000000;

static const size_t MAX_STRINGS_BATCH = 64;
static const int MAX_CYCLES_BATCH = 16;

static REHex::ToolPanel *StringPanel_factory(wxWindow *parent, REHex::SharedDocumentPointer &document, REHex::DocumentCtrl *document_ctrl)
{
	return new REHex::StringPanel(parent, document, document_ctrl);
}

static REHex::ToolPanelRegistration tpr("StringPanel", "Strings", REHex::ToolPanel::TPS_TALL, &StringPanel_factory);

enum {
	ID_ENCODING_CHOICE = 1,
	ID_RESET_BUTTON,
	ID_CONTINUE_BUTTON,
	ID_MIN_STRING_LENGTH,
	ID_CJK_TOGGLE,
};

BEGIN_EVENT_TABLE(REHex::StringPanel, wxPanel)
	EVT_TIMER(wxID_ANY, REHex::StringPanel::OnTimerTick)
	EVT_LIST_ITEM_ACTIVATED(wxID_ANY, REHex::StringPanel::OnItemActivate)
	EVT_LIST_ITEM_RIGHT_CLICK(wxID_ANY, REHex::StringPanel::OnItemRightClick)
	EVT_CHOICE(ID_ENCODING_CHOICE, REHex::StringPanel::OnEncodingChanged)
	
	EVT_BUTTON(ID_RESET_BUTTON,     REHex::StringPanel::OnReset)
	EVT_BUTTON(ID_CONTINUE_BUTTON,  REHex::StringPanel::OnContinue)
	
	EVT_SPINCTRL(ID_MIN_STRING_LENGTH, REHex::StringPanel::OnMinStringLength)
	EVT_CHECKBOX(ID_CJK_TOGGLE, REHex::StringPanel::OnCJKToggle)
END_EVENT_TABLE()

REHex::StringPanel::StringPanel(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl):
	ToolPanel(parent),
	document(document),
	document_ctrl(document_ctrl),
	min_string_length(8),
	ignore_cjk(false),
	update_needed(false),
	processor([this](off_t window_base, off_t window_length) { work_func(window_base, window_length); }, WINDOW_SIZE),
	timer(this, wxID_ANY),
	m_search_pending(false),
	m_search_running(false),
	search_base(0)
{
	const int MARGIN = 4;
	
	list_ctrl = new StringPanelListCtrl(this);
	
	list_ctrl->AppendColumn("Offset");
	list_ctrl->AppendColumn("Text");
	
	status_text = new wxStaticText(this, wxID_ANY, "");
	
	encoding_choice = new wxChoice(this, ID_ENCODING_CHOICE);
	
	std::vector<const CharacterEncoding*> all_encodings = CharacterEncoding::all_encodings();
	for(auto i = all_encodings.begin(); i != all_encodings.end(); ++i)
	{
		const CharacterEncoding *ce = *i;
		encoding_choice->Append(ce->label, (void*)(ce));
	}
	
	encoding_choice->SetSelection(0);
	selected_encoding = all_encodings.front();
	
	min_string_length_ctrl = new wxSpinCtrl(
		this, ID_MIN_STRING_LENGTH, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxSP_ARROW_KEYS,
		1, 1024, min_string_length);
	
	wxBoxSizer *min_string_length_sizer = new wxBoxSizer(wxHORIZONTAL);
	
	min_string_length_sizer->Add(new wxStaticText(this, wxID_ANY, "Minimum string length: "), 0, wxALIGN_CENTER_VERTICAL);
	min_string_length_sizer->Add(min_string_length_ctrl, 0, wxALIGN_CENTER_VERTICAL);
	min_string_length_sizer->Add(new wxStaticText(this, wxID_ANY, " code points"), 0, wxALIGN_CENTER_VERTICAL);
	
	ignore_cjk_check = new wxCheckBox(this, ID_CJK_TOGGLE, "Ignore CJK code points");
	ignore_cjk_check->SetValue(ignore_cjk);
	
	wxMemoryInputStream spinner_stream(spinner24_gif, sizeof(spinner24_gif));
	
	wxAnimation spinner_anim;
	spinner_anim.Load(spinner_stream, wxANIMATION_TYPE_GIF);
	
	spinner = new wxAnimationCtrl(this, wxID_ANY, spinner_anim, wxDefaultPosition, wxSize(24, 24));
	spinner->Hide();
	
	reset_button = new wxBitmapButton(this, ID_RESET_BUTTON, wxArtProvider::GetBitmap(wxART_GOTO_FIRST, wxART_BUTTON));
	reset_button->SetToolTip("Search from start of file");
	reset_button->Disable();
	
	continue_button = new wxBitmapButton(this, ID_CONTINUE_BUTTON, wxArtProvider::GetBitmap(wxART_GO_FORWARD, wxART_BUTTON));
	continue_button->SetToolTip("Continue search");
	continue_button->Disable();
	
	wxBoxSizer *status_sizer = new wxBoxSizer(wxHORIZONTAL);
	
	status_sizer->Add(status_text, 1);
	status_sizer->Add(spinner, 0, (wxRESERVE_SPACE_EVEN_IF_HIDDEN | wxALIGN_CENTER_VERTICAL));
	status_sizer->Add(reset_button, 0, wxALIGN_CENTER_VERTICAL);
	status_sizer->Add(continue_button, 0, wxALIGN_CENTER_VERTICAL);
	
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);
	sizer->Add(encoding_choice, 0, (wxLEFT | wxRIGHT | wxTOP), MARGIN);
	sizer->Add(min_string_length_sizer, 0, (wxLEFT | wxRIGHT | wxTOP), MARGIN);
	sizer->Add(ignore_cjk_check, 0, (wxLEFT | wxRIGHT | wxTOP), MARGIN);
	sizer->Add(status_sizer, 0, (wxEXPAND | wxLEFT | wxRIGHT | wxTOP), MARGIN);
	sizer->Add(list_ctrl, 1, (wxEXPAND | wxALL), MARGIN);
	SetSizerAndFit(sizer);
	
	this->document.auto_cleanup_bind(DATA_ERASE,     &REHex::StringPanel::OnDataErase,     this);
	this->document.auto_cleanup_bind(DATA_INSERT,    &REHex::StringPanel::OnDataInsert,    this);
	this->document.auto_cleanup_bind(DATA_OVERWRITE, &REHex::StringPanel::OnDataOverwrite, this);
	
	this->document.auto_cleanup_bind(DATA_ERASING,              &REHex::StringPanel::OnDataModifying,        this);
	this->document.auto_cleanup_bind(DATA_ERASE_ABORTED,        &REHex::StringPanel::OnDataModifyAborted,    this);
	this->document.auto_cleanup_bind(DATA_INSERTING,            &REHex::StringPanel::OnDataModifying,        this);
	this->document.auto_cleanup_bind(DATA_INSERT_ABORTED,       &REHex::StringPanel::OnDataModifyAborted,    this);
	
	processor.pause_threads();
	restart_search();
}

REHex::StringPanel::~StringPanel()
{
	suspend_search();
}

std::string REHex::StringPanel::name() const
{
	return "StringPanel";
}

std::string REHex::StringPanel::label() const
{
	return "Strings";
}

REHex::ToolPanel::Shape REHex::StringPanel::shape() const
{
	return ToolPanel::TPS_TALL;
}

void REHex::StringPanel::save_state(wxConfig *config) const
{
	/* TODO */
}

void REHex::StringPanel::load_state(wxConfig *config)
{
	/* TODO */
}

wxSize REHex::StringPanel::DoGetBestClientSize() const
{
	/* TODO */
	return wxSize(100, -1);
}

void REHex::StringPanel::update()
{
	if (!is_visible)
	{
		/* There is no sense in updating this if we are not visible */
		return;
	}
	
	if(m_search_pending && !m_search_running)
	{
		processor.resume_threads();
		timer.Start(100, wxTIMER_CONTINUOUS);
		
		m_search_running = true;
	}
	
	bool queue_empty = processor.queue_empty();
	
	if((update_needed || queue_empty) && document_ctrl)
	{
		size_t strings_count;
		
		{
			std::lock_guard<std::mutex> sl(strings_lock);
			
			strings_count = strings.size();
			update_needed = false;
		}
		
		ByteRangeSet queue = processor.get_queue();
		
		if(m_search_pending && (strings_count >= MAX_STRINGS || queue_empty))
		{
			stop_search();
			flush_all_batches();
			
			strings_count = strings.size();
			update_needed = false;
			
			queue_empty = processor.queue_empty();
		}
		
		list_ctrl->SetItemCount(strings_count);
		
		std::string status_text = "";
		
		if(m_search_pending)
		{
			status_text += "Searching from " + format_offset(search_base, document_ctrl->get_offset_display_base(), document->buffer_length());
			continue_button->Disable();
		}
		else{
			status_text += "Searched from " + format_offset(search_base, document_ctrl->get_offset_display_base(), document->buffer_length());
			continue_button->Enable(!queue_empty);
		}
		
		status_text += "\n";
		
		if(strings_count > 0)
		{
			status_text += "Found "
				+ wxNumberFormatter::ToString((long)(strings_count))
				+ " strings";
		}
		else if(!m_search_pending)
		{
			status_text += "No strings found";
		}
		
		this->status_text->SetLabelText(status_text);
	}
}

void REHex::StringPanel::mark_dirty_pad(off_t offset, off_t length)
{
	const off_t ideal_pad = min_string_length * MAX_CHAR_SIZE;
	
	off_t pre_pad = std::min(ideal_pad, offset);
	offset -= pre_pad;
	length += pre_pad;
	
	off_t post_pad = std::min(ideal_pad, (document->buffer_length() - offset));
	length += post_pad;
	
	processor.queue_range(offset, length);
}

off_t REHex::StringPanel::sum_dirty_bytes()
{
	/* Merge the all the ranges in dirty, pending and working. */
	
	ByteRangeSet merged = processor.get_queue();
	
	/* Sum the length of the merged ranges. */
	
	off_t dirty_total = std::accumulate(merged.begin(), merged.end(),
		(off_t)(0), [](off_t sum, const ByteRangeSet::Range &range) { return sum + range.length; });
	
	return dirty_total;
}

off_t REHex::StringPanel::sum_clean_bytes()
{
	return document->buffer_length() - sum_dirty_bytes();
}

REHex::ByteRangeSet REHex::StringPanel::get_strings()
{
	std::lock_guard<std::mutex> sl(strings_lock);
	return strings;
}

off_t REHex::StringPanel::get_clean_bytes()
{
	return sum_clean_bytes();
}

void REHex::StringPanel::set_encoding(const std::string &encoding_key)
{
	processor.pause_threads();
	
	int num_encodings = encoding_choice->GetCount();
	
	int encoding_idx = -1;
	const CharacterEncoding *encoding = NULL;
	
	for(int i = 0; i < num_encodings; ++i)
	{
		const CharacterEncoding *ce = (const CharacterEncoding*)(encoding_choice->GetClientData(i));
		
		if(ce->key == encoding_key)
		{
			encoding_idx = i;
			encoding = ce;
			
			break;
		}
	}
	
	if(encoding_idx < 0)
	{
		return;
	}
	
	encoding_choice->SetSelection(encoding_idx);
	this->selected_encoding = encoding;
	
	restart_search();
}

void REHex::StringPanel::set_min_string_length(int min_string_length)
{
	processor.pause_threads();
	
	min_string_length_ctrl->SetValue(min_string_length);
	this->min_string_length = min_string_length;
	
	restart_search();
}

void REHex::StringPanel::select_all()
{
	int num_items = list_ctrl->GetItemCount();
	
	for(int i = 0; i < num_items; ++i)
	{
		list_ctrl->SetItemState(i, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
	}
}

void REHex::StringPanel::select_by_file_offset(off_t offset)
{
	int idx;
	
	{
		std::lock_guard<std::mutex> sl(strings_lock);
		
		auto it = strings.find_first_in(offset, 1);
		assert(it != strings.end() && it->offset == offset);
		
		idx = std::distance(strings.begin(), it);
		assert(idx < list_ctrl->GetItemCount());
	}
	
	list_ctrl->SetItemState(idx, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
}

wxString REHex::StringPanel::copy_get_string(wxString (*get_item_func)(StringPanelListCtrl*, int))
{
	wxString s = "";
	
	for(long list_idx = -1; (list_idx = list_ctrl->GetNextItem(list_idx, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED)) >= 0;)
	{
		if(!s.empty())
		{
			s += "\n";
		}
		
		s += get_item_func(list_ctrl, list_idx);
	}
	
	return s;
}

void REHex::StringPanel::do_copy(wxString (*get_item_func)(StringPanelListCtrl*, int))
{
	ClipboardGuard cg;
	if(cg)
	{
		wxString s = copy_get_string(get_item_func);
		wxTheClipboard->SetData(new wxTextDataObject(s));
	}
}

void REHex::StringPanel::work_func(off_t window_base, off_t window_length)
{
	PROFILE_BLOCK("REHex::StringPanel::work_func");
	
	/* Grow both ends of our window by MIN_STRING_LENGTH bytes to ensure we can match
	 * strings starting before/after it. Any data that is part of the string beyond our
	 * expanded window will be merged later.
	*/
	
	off_t window_pre = std::min<off_t>(window_base, (min_string_length * MAX_CHAR_SIZE));
	
	off_t  window_base_adj   = window_base   - window_pre;
	size_t window_length_adj = window_length + window_pre + (min_string_length * MAX_CHAR_SIZE);
	
	/* Read the data from our window and search for strings in it. */
	
	std::vector<unsigned char> data;
	try {
		data = document->read_data(window_base_adj, window_length_adj);
	}
	catch(const std::exception&)
	{
		/* Failed to read the file. Stick this back in the dirty queue and fetch
		 * another block to process.
		 *
		 * TODO: Somehow de-prioritise this block or delay it becoming available
		 * again. Permanent I/O errors will result in worker threads trying to read
		 * the same bad blocks over and over as things stand now.
		*/
		
		//working.clear_range(window_base, window_length);
		//mark_dirty(window_base, window_length);
		
		return;
	}
	
	Batch batch = next_batch();
	
	for(size_t i = 0; i < data.size();)
	{
		off_t string_base = window_base_adj + i;
		off_t string_end  = string_base;
		
		/* TODO: Align with encoding word size. */
		
		bool is_really_string;
		size_t num_codepoints = 1;
		
		auto is_i_string = [&](bool force_advance)
		{
			EncodedCharacter ec = selected_encoding->encoder->decode(data.data() + i, data.size() - i);
			
			if(ec.valid)
			{
				ucs4_t c;
				u8_mbtouc_unsafe(&c, (const uint8_t*)(ec.utf8_char().data()), ec.utf8_char().size());
				
				bool is_valid = c >= 0x20
					&& c != 0x7F
					&& c != 0xFFFD
					&& !uc_is_property_unassigned_code_value(c)
					&& !uc_is_property_not_a_character(c)
					&& (!ignore_cjk || !(uc_is_property_ideographic(c) || uc_is_property_unified_ideograph(c) || uc_is_property_radical(c)));
				
				if(force_advance || is_valid == is_really_string)
				{
					string_end += ec.encoded_char().size();
					i          += ec.encoded_char().size();
				}
				
				return is_valid;
			}
			else{
				if(force_advance || !is_really_string)
				{
					++string_end;
					++i;
				}
				
				return false;
			}
		};
		
		is_really_string = is_i_string(true);
		
		while(i < data.size() && is_i_string(false) == is_really_string)
		{
			++num_codepoints;
		}
		
		off_t clamped_string_base = std::max(string_base, window_base);
		off_t clamped_string_end  = std::min(string_end,  (off_t)(window_base + window_length));
		
		if(clamped_string_base < clamped_string_end)
		{
			if(is_really_string && num_codepoints >= (size_t)(min_string_length))
			{
				batch.ranges_to_set.set_range(clamped_string_base, (clamped_string_end - clamped_string_base));
			}
			else if(clamped_string_base <= clamped_string_end)
			{
				batch.ranges_to_clear.set_range(clamped_string_base, (clamped_string_end - clamped_string_base));
			}
		}
	}
	
	release_batch(std::move(batch));
}

REHex::StringPanel::Batch REHex::StringPanel::next_batch()
{
	std::unique_lock<std::mutex> lock(m_batch_mutex);
	
	if(m_batch_queue.empty())
	{
		Batch new_batch;
		new_batch.ttl = MAX_CYCLES_BATCH;
		
		return new_batch;
	}
	else{
		Batch batch = std::move(m_batch_queue.front());
		m_batch_queue.pop();
		
		return batch;
	}
}

void REHex::StringPanel::release_batch(Batch &&batch)
{
	bool ttl_expired = --(batch.ttl) <= 0;
	
	flush_batch(&batch, ttl_expired);
	
	if(ttl_expired)
	{
		batch.ttl = MAX_CYCLES_BATCH;
	}
	
	std::unique_lock<std::mutex> lock(m_batch_mutex);
	m_batch_queue.push(std::move(batch));
}

void REHex::StringPanel::flush_batch(Batch *batch, bool force)
{
	if((force && !(batch->ranges_to_clear.empty())) || batch->ranges_to_clear.size() >= MAX_STRINGS_BATCH)
	{
		std::lock_guard<std::mutex> sl(strings_lock);
		
		strings.clear_ranges(batch->ranges_to_clear.begin(), batch->ranges_to_clear.end());
		batch->ranges_to_clear.clear_all();
		
		update_needed = true;
	}
	
	if((force && !(batch->ranges_to_set.empty())) || batch->ranges_to_set.size() >= MAX_STRINGS_BATCH)
	{
		std::lock_guard<std::mutex> sl(strings_lock);
		
		size_t size_hint = strings.size() + batch->ranges_to_set.size();
		off_t set_end = batch->ranges_to_set.last().offset + batch->ranges_to_set.last().length;
		
		assert(set_end > 0);
		
		size_hint = std::max<size_t>(
			((double)(size_hint) / ((double)(set_end) / (double)(document->buffer_length()))),
			MAX_STRINGS);
		
		strings.set_ranges(batch->ranges_to_set.begin(), batch->ranges_to_set.end(), size_hint);
		batch->ranges_to_set.clear_all();
		
		update_needed = true;
	}
}

void REHex::StringPanel::flush_all_batches()
{
	std::unique_lock<std::mutex> lock(m_batch_mutex);
	
	for(size_t i = 0; i < m_batch_queue.size(); ++i)
	{
		Batch batch = std::move(m_batch_queue.front());
		m_batch_queue.pop();
		
		flush_batch(&batch, true);
		
		m_batch_queue.push(std::move(batch));
	}
}

void REHex::StringPanel::start_search()
{
	if(m_search_pending)
	{
		return;
	}
	
	m_search_pending = true;
	
	spinner->Show();
	spinner->Play();
	
	update_needed = true;
	update();
}

void REHex::StringPanel::suspend_search()
{
	if(m_search_running)
	{
		processor.pause_threads();
		timer.Stop();
		
		m_search_running = false;
	}
}

void REHex::StringPanel::stop_search()
{
	suspend_search();
	
	if(m_search_pending)
	{
		spinner->Stop();
		spinner->Hide();
		
		m_search_pending = false;
	}
}

void REHex::StringPanel::restart_search()
{
	stop_search();
	
	reset_button->Disable();
	
	search_base = 0;
	processor.queue_range(0, document->buffer_length());
	
	{
		std::lock_guard<std::mutex> sl(strings_lock);
		strings.clear_all();
	}
	
	start_search();
}

void REHex::StringPanel::do_export(wxString (*get_item_func)(StringPanelListCtrl*, int))
{
	std::string dir;
	std::string doc_filename = document->get_filename();
	
	if(doc_filename != "")
	{
		wxFileName wxfn(doc_filename);
		wxfn.MakeAbsolute();
		
		dir  = wxfn.GetPath();
	}
	else{
		dir  = wxGetApp().get_last_directory();
	}
	
	wxFileDialog saveFileDialog(this, "Export Strings", dir, "", "", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
	if(saveFileDialog.ShowModal() == wxID_CANCEL)
		return;
	
	std::string filename = saveFileDialog.GetPath().ToStdString();
	
	{
		wxFileName wxfn(filename);
		wxString dirname = wxfn.GetPath();
		
		wxGetApp().set_last_directory(dirname.ToStdString());
	}
	
	try {
		FileWriter file(filename.c_str());
		
		for(long list_idx = -1; (list_idx = list_ctrl->GetNextItem(list_idx, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED)) >= 0;)
		{
			wxString s = get_item_func(list_ctrl, list_idx) + "\n";
			const wxScopedCharBuffer s_utf8 = s.utf8_str();
			
			file.write(s_utf8.data(), s_utf8.length());
		}
		
		file.commit();
	}
	catch(const std::exception &e)
	{
		wxMessageBox(e.what(), "Error", wxICON_ERROR, this);
	}
}

bool REHex::StringPanel::search_pending() const
{
	return m_search_pending;
}

wxString REHex::StringPanel::get_item_string(StringPanelListCtrl *list_ctrl, int item_idx)
{
	return list_ctrl->OnGetItemText(item_idx, 1);
}

wxString REHex::StringPanel::get_item_offset_and_string(StringPanelListCtrl *list_ctrl, int item_idx)
{
	return list_ctrl->OnGetItemText(item_idx, 0) + "\t" + list_ctrl->OnGetItemText(item_idx, 1);
}

void REHex::StringPanel::OnDataModifying(OffsetLengthEvent &event)
{
	if(m_search_running)
	{
		processor.pause_threads();
	}
	
	flush_all_batches();
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::StringPanel::OnDataModifyAborted(OffsetLengthEvent &event)
{
	if(m_search_running)
	{
		processor.resume_threads();
	}
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::StringPanel::OnDataErase(OffsetLengthEvent &event)
{
	assert(processor.paused());
	
	strings.data_erased(event.offset, event.length);
	processor.data_erased(event.offset, event.length);
	
	mark_dirty_pad(event.offset, 0);
	
	if(m_search_running)
	{
		processor.resume_threads();
	}
	else{
		start_search();
	}
	
	update_needed = true;
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::StringPanel::OnDataInsert(OffsetLengthEvent &event)
{
	assert(processor.paused());
	
	strings.data_inserted(event.offset, event.length);
	processor.data_inserted(event.offset, event.length);
	
	mark_dirty_pad(event.offset, event.length);
	
	if(m_search_running)
	{
		processor.resume_threads();
	}
	else{
		start_search();
	}
	
	update_needed = true;
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::StringPanel::OnDataOverwrite(OffsetLengthEvent &event)
{
	{
		std::unique_lock<std::mutex> sl(strings_lock);
		strings.clear_range(event.offset, event.length);
	}
	
	mark_dirty_pad(event.offset, event.length);
	
	start_search();
	
	update_needed = true;
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::StringPanel::OnItemActivate(wxListEvent &event)
{
	int num_selected = list_ctrl->GetSelectedItemCount();
	if(num_selected > 1)
	{
		wxBell();
		return;
	}
	
	long item_idx = event.GetIndex();
	assert(item_idx >= 0);
	
	std::lock_guard<std::mutex> sl(strings_lock);
	
	if((size_t)(item_idx) >= strings.size())
	{
		/* UI thread probably hasn't caught up to worker threads yet. */
		return;
	}
	
	const ByteRangeSet::Range &string_range = strings[item_idx];
	
	document->set_cursor_position(string_range.offset);
	document_ctrl->set_selection_raw(string_range.offset, (string_range.offset + string_range.length - 1));
}

void REHex::StringPanel::OnItemRightClick(wxListEvent &event)
{
	int num_selected = list_ctrl->GetSelectedItemCount();
	
	wxMenu menu;
	
	wxMenuItem *copy_strings = menu.Append(wxID_ANY, "&Copy Strings");
	menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
	{
		do_copy(&get_item_string);
	}, copy_strings->GetId(), copy_strings->GetId());
	
	wxMenuItem *copy_strings_and_offsets = menu.Append(wxID_ANY, "Copy Strings and &Offsets");
	menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
	{
		do_copy(&get_item_offset_and_string);
	}, copy_strings_and_offsets->GetId(), copy_strings_and_offsets->GetId());
	
	wxMenuItem *export_strings = menu.Append(wxID_ANY, "&Export Strings");
	menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
	{
		do_export(&get_item_string);
	}, export_strings->GetId(), export_strings->GetId());
	
	wxMenuItem *export_strings_and_offsets = menu.Append(wxID_ANY, "E&xport Strings and Offsets");
	menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
	{
		do_export(&get_item_offset_and_string);
	}, export_strings_and_offsets->GetId(), export_strings_and_offsets->GetId());
	
	copy_strings->Enable(num_selected > 0);
	copy_strings_and_offsets->Enable(num_selected > 0);
	export_strings->Enable(num_selected > 0);
	export_strings_and_offsets->Enable(num_selected > 0);
	
	menu.AppendSeparator();
	
	wxMenuItem *select_all = menu.Append(wxID_ANY, "Select &All");
	menu.Bind(wxEVT_MENU, [&](wxCommandEvent &event)
	{
		this->select_all();
	}, select_all->GetId(), select_all->GetId());
	
	PopupMenu(&menu);
}

void REHex::StringPanel::OnTimerTick(wxTimerEvent &event)
{
	if(!is_visible)
	{
		/* We should only get called once after the panel is hidden. */
		assert(m_search_running);
		
		suspend_search();
		return;
	}
	
	update();
}

void REHex::StringPanel::OnEncodingChanged(wxCommandEvent &event)
{
	processor.pause_threads();
	
	int encoding_idx = event.GetSelection();
	selected_encoding = (const CharacterEncoding*)(encoding_choice->GetClientData(encoding_idx));
	
	restart_search();
}

void REHex::StringPanel::OnMinStringLength(wxSpinEvent &event)
{
	processor.pause_threads();
	
	min_string_length = event.GetPosition();
	
	restart_search();
}

void REHex::StringPanel::OnCJKToggle(wxCommandEvent &event)
{
	processor.pause_threads();
	
	ignore_cjk = event.IsChecked();
	
	restart_search();
}

void REHex::StringPanel::OnReset(wxCommandEvent &event)
{
	restart_search();
}

void REHex::StringPanel::OnContinue(wxCommandEvent &event)
{
	assert(!m_search_pending);
	
	auto queue = processor.get_queue();
	auto next_pending = queue.find_first_in(search_base, std::numeric_limits<off_t>::max());
	
	if(next_pending != queue.end())
	{
		search_base = next_pending->offset;
		
		if(!strings.empty())
		{
			strings.clear_all();
		}
		
		start_search();
		
		reset_button->Enable();
	}
	else{
		continue_button->Disable();
	}
}

REHex::StringPanel::StringPanelListCtrl::StringPanelListCtrl(StringPanel *parent):
	wxListCtrl(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize, (wxLC_REPORT | wxLC_VIRTUAL)) {}

wxString REHex::StringPanel::StringPanelListCtrl::OnGetItemText(long item, long column) const
{
	StringPanel *parent = dynamic_cast<StringPanel*>(GetParent());
	assert(parent != NULL);
	
	std::lock_guard<std::mutex> sl(parent->strings_lock);
	
	if((size_t)(item) >= parent->strings.size())
	{
		/* wxWidgets has asked for an item beyond the end of the set.
		 *
		 * This probably means an element has been removed by a worker thread but the UI
		 * thread hasn't caught up and called SetItemCount() yet.
		*/
		
		return "???";
	}
	
	const ByteRangeSet::Range &si = parent->strings.get_ranges()[item];
	
	switch(column)
	{
		case 0:
		{
			/* Offset column */
			return format_offset(si.offset, parent->document_ctrl->get_offset_display_base(), parent->document->buffer_length());
		}
		
		case 1:
		{
			/* Text column */
			
			try {
				std::vector<unsigned char> string_data = parent->document->read_data(si.offset, si.length);
				std::string string;
				
				for(size_t i = 0; i < string_data.size();)
				{
					EncodedCharacter ec = parent->selected_encoding->encoder->decode(string_data.data() + i, string_data.size() - i);
					
					string += ec.utf8_char();
					i += ec.encoded_char().size();
				}
				
				return wxString::FromUTF8(string.data(), string.size());
			}
			catch(const std::exception&)
			{
				/* Probably a file I/O error. */
				return "???";
			}
		}
		
		default:
			/* Unknown column */
			abort();
	}
}
