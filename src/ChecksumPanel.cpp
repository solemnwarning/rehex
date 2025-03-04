/* Reverse Engineer's Hex Editor
 * Copyright (C) 2023-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <wx/artprov.h>
#include <wx/clipbrd.h>
#include <wx/sizer.h>
#include <wx/stattext.h>

#include "App.hpp"
#include "ChecksumPanel.hpp"
#include "util.hpp"

#define CHECKSUM_PANEL_PADDING 4

#define CHECKSUM_CHUNK_SIZE (4 * 1024 * 1024) /* 4MiB */

static REHex::ToolPanel *checksumpanel_factory(wxWindow *parent, REHex::SharedDocumentPointer &document, REHex::DocumentCtrl *document_ctrl)
{
	return new REHex::ChecksumPanel(parent, document, document_ctrl);
}

static REHex::ToolPanelRegistration main_console_tpr("ChecksumPanel", "Checksum", REHex::ToolPanel::TPS_WIDE, &checksumpanel_factory);

enum {
	ID_RANGE_CHOICE = 1,
	ID_ALGO_CHOICE,
	ID_COPY_BUTTON,
};

BEGIN_EVENT_TABLE(REHex::ChecksumPanel, wxPanel)
	EVT_COMMAND(ID_RANGE_CHOICE, EV_SELECTION_CHANGED, REHex::ChecksumPanel::OnRangeChanged)
	EVT_CHOICE(ID_ALGO_CHOICE, REHex::ChecksumPanel::OnAlgoChanged)
	EVT_BUTTON(ID_COPY_BUTTON, REHex::ChecksumPanel::OnCopyChecksum)
END_EVENT_TABLE()

REHex::ChecksumPanel::ChecksumPanel(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl):
	ToolPanel(parent),
	document(document),
	document_ctrl(document_ctrl)
{
	range_choice = new RangeChoiceLinear(this, ID_RANGE_CHOICE, document, document_ctrl);
	range_choice->set_allow_bit_aligned_offset(true);
	
	algo_choice = new wxChoice(this, ID_ALGO_CHOICE);
	
	cs_algos = ChecksumAlgorithm::all_algos();
	for(auto i = cs_algos.begin(); i != cs_algos.end(); ++i)
	{
		algo_choice->Append((*i)->label);
	}
	
	wxBoxSizer *range_sizer = new wxBoxSizer(wxHORIZONTAL);
	range_sizer->Add(new wxStaticText(this, wxID_ANY, "Range:"), 0, wxALIGN_CENTER_VERTICAL);
	range_sizer->Add(range_choice, 0, wxALIGN_CENTER_VERTICAL | wxLEFT, CHECKSUM_PANEL_PADDING);
	range_sizer->Add(new wxStaticText(this, wxID_ANY, "Algorithm:"), 0, wxALIGN_CENTER_VERTICAL | wxLEFT, CHECKSUM_PANEL_PADDING);
	range_sizer->Add(algo_choice, 1, wxALIGN_CENTER_VERTICAL | wxLEFT, CHECKSUM_PANEL_PADDING);
	
	output = new wxTextCtrl(this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_READONLY);
	
	copy_btn = new wxButton(this, ID_COPY_BUTTON, "Copy checksum", wxDefaultPosition, wxDefaultSize, wxBU_NOTEXT | wxBU_EXACTFIT);
	copy_btn->SetBitmap(wxArtProvider::GetBitmap(wxART_COPY, wxART_BUTTON));
	copy_btn->SetToolTip("Copy checksum");
	
	wxBoxSizer *output_sizer = new wxBoxSizer(wxHORIZONTAL);
	output_sizer->Add(new wxStaticText(this, wxID_ANY, "Checksum:"), 0, wxALIGN_CENTER_VERTICAL);
	output_sizer->Add(output, 1, wxALIGN_CENTER_VERTICAL | wxLEFT, CHECKSUM_PANEL_PADDING);
	output_sizer->Add(copy_btn, 0, wxALIGN_CENTER_VERTICAL | wxLEFT, CHECKSUM_PANEL_PADDING);
	
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);
	sizer->Add(range_sizer, 0, wxEXPAND | wxALL, CHECKSUM_PANEL_PADDING);
	sizer->Add(output_sizer, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, CHECKSUM_PANEL_PADDING);
	SetSizerAndFit(sizer);
	
	this->document.auto_cleanup_bind(DATA_ERASE,     &REHex::ChecksumPanel::OnDataErase,     this);
	this->document.auto_cleanup_bind(DATA_INSERT,    &REHex::ChecksumPanel::OnDataInsert,    this);
	this->document.auto_cleanup_bind(DATA_OVERWRITE, &REHex::ChecksumPanel::OnDataOverwrite, this);
	
	algo_choice->SetSelection(0);
	range_choice->set_follow_selection();
	
	restart();
}

REHex::ChecksumPanel::~ChecksumPanel()
{
	if(work_task)
	{
		work_task->finish();
		work_task->join();
	}
}

std::string REHex::ChecksumPanel::name() const
{
	return "ChecksumPanel";
}

std::string REHex::ChecksumPanel::label() const
{
	return "Checksum";
}

REHex::ToolPanel::Shape REHex::ChecksumPanel::shape() const
{
	return ToolPanel::TPS_WIDE;
}

void REHex::ChecksumPanel::save_state(wxConfig *config) const {}
void REHex::ChecksumPanel::load_state(wxConfig *config) {}

wxSize REHex::ChecksumPanel::DoGetBestClientSize() const
{
	return GetMinClientSize();
}

void REHex::ChecksumPanel::update()
{
	if(!work_task)
	{
		restart();
	}
}

void REHex::ChecksumPanel::restart()
{
	if(work_task)
	{
		work_task->finish();
		work_task->join();
		work_task.reset(NULL);
	}
	
	if (!is_visible)
	{
		/* There is no sense in updating this if we are not visible */
		return;
	}
	
	copy_btn->Disable();
	
	BitOffset range_length_tmp;
	std::tie(range_offset, range_length_tmp) = range_choice->get_range();
	
	assert(range_length_tmp.byte_aligned());
	range_length = range_length_tmp.byte();
	
	if(range_length <= 0)
	{
		output->SetValue("No data selected");
		return;
	}
	
	output->SetValue("Computing checksum...");
	
	work_offset = range_offset;
	
	int algo_idx = algo_choice->GetSelection();
	cs_gen.reset(cs_algos[algo_idx]->factory());
	
	work_task.reset(new ThreadPool::TaskHandle(wxGetApp().thread_pool->queue_task([this]() { return process(); }, 1)));
}

bool REHex::ChecksumPanel::process()
{
	BitOffset remain = (range_offset + BitOffset(range_length, 0)) - work_offset;
	assert(remain.byte_aligned());
	assert(remain > 0);
	
	std::vector<unsigned char> data;
	try {
		data = document->read_data(work_offset, std::min<off_t>(CHECKSUM_CHUNK_SIZE, remain.byte()));
	}
	catch(const std::exception &e)
	{
		wxGetApp().printf_error("Data read error in ChecksumPanel: %s\n", e.what());
		
		CallAfter([this, e]()
		{
			output->SetValue(std::string("Read error: ") + e.what());
		});
		
		return true;
	}
	
	if(data.size() == 0)
	{
		CallAfter([this]()
		{
			output->SetValue("Unexpected end of file");
		});
		
		return true;
	}
	
	cs_gen->add_data(data.data(), data.size());
	work_offset += BitOffset(data.size(), 0);
	
	remain = (range_offset + range_length) - work_offset;
	assert(remain.byte_aligned());
	assert(remain >= 0);
	
	if(remain == BitOffset::ZERO)
	{
		cs_gen->finish();
		std::string checksum = cs_gen->checksum_hex();
		
		CallAfter([this, checksum]()
		{
			output->SetValue(checksum);
			copy_btn->Enable();
		});
		
		return true;
	}
	
	return false;
}

void REHex::ChecksumPanel::OnRangeChanged(wxCommandEvent &event)
{
	restart();
}

void REHex::ChecksumPanel::OnAlgoChanged(wxCommandEvent &event)
{
	restart();
}

void REHex::ChecksumPanel::OnCopyChecksum(wxCommandEvent &event)
{
	ClipboardGuard cg;
	if(cg)
	{
		wxTheClipboard->SetData(new wxTextDataObject(output->GetValue()));
	}
}

void REHex::ChecksumPanel::OnDataErase(OffsetLengthEvent &event)
{
	/* Reset if the data was erased before the end of our range. */
	if(range_length > 0 && BitOffset(event.offset, 0) < (range_offset + BitOffset(range_length, 0)))
	{
		restart();
	}
	
	event.Skip();
}

void REHex::ChecksumPanel::OnDataInsert(OffsetLengthEvent &event)
{
	/* Reset if the data was inserted before the end of our range. */
	if(range_length > 0 && BitOffset(event.offset, 0) < (range_offset + BitOffset(range_length, 0)))
	{
		restart();
	}
	
	event.Skip();
}

void REHex::ChecksumPanel::OnDataOverwrite(OffsetLengthEvent &event)
{
	/* Reset if any of the overwritten bytes were within our chosen range. */
	if(range_length > 0
		&& !(range_offset >= BitOffset((event.offset + event.length), 0) || (range_offset + BitOffset(range_length, 0)) <= BitOffset(event.offset, 0)))
	{
		restart();
	}
	
	event.Skip();
}
