/* Reverse Engineer's Hex Editor
 * Copyright (C) 2023-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#define __STDC_FORMAT_MACROS

#include "platform.hpp"

#include <inttypes.h>
#include <stdexcept>
#include <wx/artprov.h>
#include <wx/sizer.h>
#include <wx/statline.h>

#include "App.hpp"
#include "BitEditor.hpp"
#include "Events.hpp"
#include "NumericEntryDialog.hpp"

static REHex::ToolPanel *BitEditor_factory(wxWindow *parent, REHex::SharedDocumentPointer &document, REHex::DocumentCtrl *document_ctrl)
{
	return new REHex::BitEditor(parent, document, document_ctrl);
}

static REHex::ToolPanelRegistration tpr("BitEditor", "Bit editor", REHex::ToolPanel::TPS_TALL, &BitEditor_factory);

#define BITEDITOR_PADDING 4

#define BITEDITOR_GRID_VGAP 1
#define BITEDITOR_GRID_HGAP 4

enum {
	ID_ENDIAN = 1,
	ID_NUM_BYTES,
	ID_NUM_VALUE,
	ID_NUM_BASE,
	
	ID_NOT_BTN,
	ID_AND_BTN,
	ID_OR_BTN,
	ID_XOR_BTN,
	ID_LSH_BTN,
	ID_RSH_BTN,
	
	ID_BITS_BASE, /* Keep this at the end of the list */
};

BEGIN_EVENT_TABLE(REHex::BitEditor, wxPanel)
	EVT_CHOICE(ID_ENDIAN, REHex::BitEditor::OnEndian)
	EVT_SPINCTRL(ID_NUM_BYTES, REHex::BitEditor::OnNumBytes)
	
	EVT_TEXT(ID_NUM_VALUE, REHex::BitEditor::OnValueChange)
	EVT_CHOICE(ID_NUM_BASE, REHex::BitEditor::OnBaseChange)
	EVT_CHECKBOX(wxID_ANY, REHex::BitEditor::OnBitToggle)
	
	EVT_BUTTON(ID_NOT_BTN, REHex::BitEditor::OnNot)
	EVT_BUTTON(ID_AND_BTN, REHex::BitEditor::OnAnd)
	EVT_BUTTON(ID_OR_BTN,  REHex::BitEditor::OnOr)
	EVT_BUTTON(ID_XOR_BTN, REHex::BitEditor::OnXor)
	EVT_BUTTON(ID_LSH_BTN, REHex::BitEditor::OnLeftShift)
	EVT_BUTTON(ID_RSH_BTN, REHex::BitEditor::OnRightShift)
END_EVENT_TABLE()

REHex::BitEditor::BitEditor(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl):
	ToolPanel(parent),
	document(document),
	document_ctrl(document_ctrl)
{
	endian = new wxChoice(this, ID_ENDIAN);
	
	endian->Append("Big endian");
	endian->Append("Little endian");
	endian->SetSelection(1);
	
	size_bytes = new wxSpinCtrl(this, ID_NUM_BYTES, wxEmptyString,
		wxDefaultPosition, wxDefaultSize, wxSP_ARROW_KEYS, 1, 8, 1);
	
	wxBoxSizer *size_sizer = new wxBoxSizer(wxHORIZONTAL);
	size_sizer->Add(new wxStaticText(this, wxID_ANY, "Word size:"), 0, wxALIGN_CENTER_VERTICAL);
	size_sizer->Add(size_bytes, 0, wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT, BITEDITOR_PADDING);
	size_sizer->Add(new wxStaticText(this, wxID_ANY, "bytes"), 0, wxALIGN_CENTER_VERTICAL);
	
	num_value = new NumericTextCtrl(this, ID_NUM_VALUE, wxEmptyString);
	
	num_base = new wxChoice(this, ID_NUM_BASE);
	num_base->Append("Hex");
	num_base->Append("Dec");
	num_base->Append("Oct");
	num_base->Append("Bin");
	num_base->SetSelection(0);
	
	wxSize input_size = num_value->GetSizeFromTextSize(num_value->GetTextExtent("0x000000000000"));
	wxBitmap bad_input_bitmap = wxArtProvider::GetBitmap(wxART_WARNING, wxART_OTHER, wxSize(input_size.GetHeight(), input_size.GetHeight()));
	
	num_value_bad = new wxStaticBitmap(this, wxID_ANY, bad_input_bitmap);
	
	wxBoxSizer *num_value_sizer = new wxBoxSizer(wxHORIZONTAL);
	num_value_sizer->Add(new wxStaticText(this, wxID_ANY, "Value:"), 0, wxALIGN_CENTER_VERTICAL);
	num_value_sizer->Add(num_value, 1, wxALIGN_CENTER_VERTICAL | wxLEFT, BITEDITOR_PADDING);
	num_value_sizer->Add(num_base, 0, wxALIGN_CENTER_VERTICAL | wxLEFT, BITEDITOR_PADDING);
	num_value_sizer->Add(num_value_bad, 0, wxALIGN_CENTER_VERTICAL | wxLEFT | wxRESERVE_SPACE_EVEN_IF_HIDDEN, BITEDITOR_PADDING);
	
	wxFlexGridSizer *bits_grid = new wxFlexGridSizer(9, BITEDITOR_GRID_VGAP, BITEDITOR_GRID_HGAP);
	
	bits_grid->AddSpacer(1);
	bits_grid->Add(new wxStaticText(this, wxID_ANY, "80"));
	bits_grid->Add(new wxStaticText(this, wxID_ANY, "40"));
	bits_grid->Add(new wxStaticText(this, wxID_ANY, "20"));
	bits_grid->Add(new wxStaticText(this, wxID_ANY, "10"));
	bits_grid->Add(new wxStaticText(this, wxID_ANY, "08"));
	bits_grid->Add(new wxStaticText(this, wxID_ANY, "04"));
	bits_grid->Add(new wxStaticText(this, wxID_ANY, "02"));
	bits_grid->Add(new wxStaticText(this, wxID_ANY, "01"));
	
	for(int i = 0; i < MAX_BYTES; ++i)
	{
		std::string label_s = "0x";
		
		for(int j = 7; j > i; --j)
		{
			label_s += "FF";
		}
		
		label_s += "__";
		
		for(int j = 0; j < i; ++j)
		{
			label_s += "FF";
		}
		
		byte_labels[i] = new wxStaticText(this, wxID_ANY, label_s);
		bits_grid->Add(byte_labels[i]);
		
		for(int j = 0; j < NUM_BITS; ++j)
		{
			bits[i][j] = new wxCheckBox(this, (ID_BITS_BASE + (i * NUM_BITS) + j), wxEmptyString);
			
			uint64_t bit = (128ULL << (8 * i)) >> j;
			
			char bit_s[64];
			snprintf(bit_s, sizeof(bit_s), "0x%" PRIX64 " (%" PRIu64 ")", bit, bit);
			bits[i][j]->SetToolTip(bit_s);
			
			bits_grid->Add(bits[i][j]);
		}
	}
	
	wxGridSizer *btn_sizer = new wxGridSizer(3, BITEDITOR_PADDING, BITEDITOR_PADDING);
	
	not_btn = new wxButton(this, ID_NOT_BTN, "NOT");
	not_btn->SetToolTip("Apply binary NOT to the current word");
	btn_sizer->Add(not_btn);
	
	and_btn = new wxButton(this, ID_AND_BTN, "AND");
	and_btn->SetToolTip("Apply binary AND to the current word with an operand");
	btn_sizer->Add(and_btn);
	
	or_btn = new wxButton(this, ID_OR_BTN,  "OR");
	or_btn->SetToolTip("Apply binary OR to the current word with an operand");
	btn_sizer->Add(or_btn);
	
	xor_btn = new wxButton(this, ID_XOR_BTN, "XOR");
	xor_btn->SetToolTip("Apply binary XOR to the current word with an operand");
	btn_sizer->Add(xor_btn);
	
	lsh_btn = new wxButton(this, ID_LSH_BTN, "<<");
	lsh_btn->SetToolTip("Apply binary left shift to the current word");
	btn_sizer->Add(lsh_btn);
	
	rsh_btn = new wxButton(this, ID_RSH_BTN, ">>");
	rsh_btn->SetToolTip("Apply binary right shift to the current word");
	btn_sizer->Add(rsh_btn);
	
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);
	
	sizer->Add(size_sizer, 0, wxEXPAND | wxALL, BITEDITOR_PADDING);
	sizer->Add(endian, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, BITEDITOR_PADDING);
	
	sizer->Add(new wxStaticLine(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLI_HORIZONTAL),
		0, wxEXPAND | wxBOTTOM, BITEDITOR_PADDING);
	
	sizer->Add(num_value_sizer, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, BITEDITOR_PADDING);
	sizer->Add(bits_grid, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, BITEDITOR_PADDING);
	sizer->Add(btn_sizer, 0, wxLEFT | wxRIGHT | wxBOTTOM, BITEDITOR_PADDING);
	
	SetSizerAndFit(sizer);
	
	this->document.auto_cleanup_bind(CURSOR_UPDATE, &REHex::BitEditor::OnCursorUpdate,    this);
	
	this->document.auto_cleanup_bind(DATA_ERASE,     &REHex::BitEditor::OnDataModified, this);
	this->document.auto_cleanup_bind(DATA_INSERT,    &REHex::BitEditor::OnDataModified, this);
	this->document.auto_cleanup_bind(DATA_OVERWRITE, &REHex::BitEditor::OnDataModified, this);
	
	update();
}

std::string REHex::BitEditor::name() const
{
	return "BitEditor";
}

void REHex::BitEditor::save_state(wxConfig *config) const
{
	bool big_endian = (endian->GetSelection() == 0);
	config->Write("big-endian", big_endian);
}

void REHex::BitEditor::load_state(wxConfig *config)
{
	bool big_endian = config->Read("big-endian", (endian->GetSelection() == 0));
	if(big_endian)
	{
		endian->SetSelection(0);
	}
	else{
		endian->SetSelection(1);
	}
	
	update();
}

void REHex::BitEditor::update()
{
	if (!is_visible)
	{
		/* There is no sense in updating this if we are not visible */
		return;
	}
	
	int num_bytes = size_bytes->GetValue();
	int num_base = this->num_base->GetSelection();
	
	endian->Enable(num_bytes > 1);
	
	max_value = 0;
	for(int i = 0; i < num_bytes; ++i)
	{
		max_value <<= 8;
		max_value |= 0xFF;
	}
	
	num_value_bad->Hide();
	
	value_offset = document->get_cursor_position();
	
	if((value_offset + BitOffset(num_bytes, 0)) > BitOffset(document->buffer_length(), 0))
	{
		/* There aren't num_bytes of data left from cursor to end of file. */
		
		disable_edit_controls();
		return;
	}
	
	uint64_t value;
	try {
		value = read_value();
	}
	catch(const std::exception &e)
	{
		/* An I/O error... */
		wxGetApp().printf_error("Exception in REHex::BitEditor::update: %s\n", e.what());
		
		disable_edit_controls();
		return;
	}
	
	/* Update the numeric value field.
	 *
	 * If the field already has the correct numeric value, don't reset it
	 * because it makes the cursor jump around annoyingly while typing a 
	 * value in.
	*/
	
	uint64_t old_val = value + 1;
	try {
		int num_value_base = get_num_base();
		old_val = num_value->GetValue<uint64_t>(0, std::numeric_limits<uint64_t>::max(), 0, num_value_base);
	}
	catch(const REHex::NumericTextCtrl::InputError&) {}
	
	if(value != old_val)
	{
		char val_s[72];
		
		switch(num_base)
		{
			default:
			case 0: /* Hex */
				snprintf(val_s, sizeof(val_s), "%" PRIX64, value);
				break;
			
			case 1: /* Dec */
				snprintf(val_s, sizeof(val_s), "%" PRIu64, value);
				break;
			
			case 2: /* Oct */
				snprintf(val_s, sizeof(val_s), "%" PRIo64, value);
				break;
			
			case 3: /* Bin */
				for(int i = 0; i < num_bytes; ++i)
				{
					for(int j = 0; j < NUM_BITS; ++j)
					{
						val_s[(((num_bytes - 1) - i) * NUM_BITS) + ((NUM_BITS - 1) - j)]
							= (value & (1ULL << ((i * NUM_BITS) + j))) ? '1' : '0';
					}
				}
				
				val_s[num_bytes * NUM_BITS] = '\0';
				
				break;
		}
		
		num_value->ChangeValue(val_s);
		num_value->Enable();
	}
	
	/* Update the bit twiddling checkboxes. */
	
	for(int i = 0; i < MAX_BYTES; ++i)
	{
		uint64_t this_bit = 128ULL << (i * NUM_BITS);
		
		byte_labels[i]->Enable(i < num_bytes);
		
		for(int j = 0; j < NUM_BITS; ++j)
		{
			if(i >= num_bytes)
			{
				bits[i][j]->SetValue(false);
				bits[i][j]->Disable();
			}
			else{
				bits[i][j]->Enable();
				bits[i][j]->SetValue((value & this_bit) != 0);
			}
			
			this_bit >>= 1;
		}
	}
	
	not_btn->Enable();
	and_btn->Enable();
	or_btn ->Enable();
	xor_btn->Enable();
	lsh_btn->Enable();
	rsh_btn->Enable();
}

int REHex::BitEditor::get_num_base()
{
	int num_base_idx = num_base->GetSelection();
	
	switch(num_base_idx)
	{
		case 0:  return 16;
		case 1:  return 10;
		case 2:  return 8;
		case 3:  return 2;
		default: return 0;
	}
}

uint64_t REHex::BitEditor::read_value()
{
	int num_bytes = size_bytes->GetValue();
	bool big_endian = (endian->GetSelection() == 0);
	
	std::vector<unsigned char> data = document->read_data(value_offset, num_bytes);
	uint64_t value = 0;
	
	if((ssize_t)(data.size()) < num_bytes)
	{
		throw std::runtime_error("Read error: unexpected end of file");
	}
	
	if(big_endian)
	{
		for(int i = 0; i < num_bytes; ++i)
		{
			value <<= 8;
			value |= data[i];
		}
	}
	else{
		for(int i = num_bytes - 1; i >= 0; --i)
		{
			value <<= 8;
			value |= data[i];
		}
	}
	
	return value;
}

void REHex::BitEditor::write_value(uint64_t value)
{
	int num_bytes = size_bytes->GetValue();
	bool big_endian = (endian->GetSelection() == 0);
	
	std::vector<unsigned char> new_data(num_bytes);
	
	if(big_endian)
	{
		for(int i = num_bytes - 1; i >= 0; --i)
		{
			new_data[i] = value & 0xFF;
			value >>= 8;
		}
	}
	else{
		for(int i = 0; i < num_bytes; ++i)
		{
			new_data[i] = value & 0xFF;
			value >>= 8;
		}
	}
	
	document->overwrite_data(value_offset, new_data.data(), num_bytes);
}

bool REHex::BitEditor::modify_value(const std::function<uint64_t(uint64_t)> &func)
{
	try {
		uint64_t value = read_value();
		
		value = func(value);
		write_value(value);
	}
	catch(const std::exception &e)
	{
		wxGetApp().printf_error("Exception in REHex::BitEditor::modify_value: %s\n", e.what());
		return false;
	}
	
	return true;
}

void REHex::BitEditor::disable_edit_controls()
{
	num_value->ChangeValue(wxEmptyString);
	num_value->Disable();
	
	for(int i = 0; i < MAX_BYTES; ++i)
	{
		byte_labels[i]->Disable();
		
		for(int j = 0; j < NUM_BITS; ++j)
		{
			bits[i][j]->SetValue(false);
			bits[i][j]->Disable();
		}
	}
	
	not_btn->Disable();
	and_btn->Disable();
	or_btn ->Disable();
	xor_btn->Disable();
	lsh_btn->Disable();
	rsh_btn->Disable();
}

void REHex::BitEditor::OnCursorUpdate(CursorUpdateEvent &event)
{
	update();
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::BitEditor::OnDataModified(OffsetLengthEvent &event)
{
	update();
	
	/* Continue propogation. */
	event.Skip();
}

void REHex::BitEditor::OnEndian(wxCommandEvent &event)
{
	update();
}

void REHex::BitEditor::OnNumBytes(wxSpinEvent &event)
{
	update();
}

void REHex::BitEditor::OnValueChange(wxCommandEvent &event)
{
	int num_value_base = get_num_base();
	
	uint64_t new_value;
	try {
		new_value = num_value->GetValue<uint64_t>(0, max_value, 0, num_value_base);
	}
	catch(const REHex::NumericTextCtrl::InputError &e)
	{
		num_value_bad->SetToolTip(e.what());
		num_value_bad->Show();
		return;
	}
	
	write_value(new_value);
}

void REHex::BitEditor::OnBaseChange(wxCommandEvent &event)
{
	num_value->ChangeValue(wxEmptyString);
	update();
}

void REHex::BitEditor::OnBitToggle(wxCommandEvent &event)
{
	int byte_num = (event.GetId() - ID_BITS_BASE) / NUM_BITS;
	int bit_num  = (event.GetId() - ID_BITS_BASE) % NUM_BITS;
	bool bit_set = event.GetInt();
	
	uint64_t this_bit = (128ULL << (byte_num * NUM_BITS)) >> bit_num;
	
	bool ok = modify_value([&](uint64_t value)
	{
		if(bit_set)
		{
			return value | this_bit;
		}
		else{
			return value & ~this_bit;
		}
	});
	
	if(!ok)
	{
		/* Flip the bit back in the UI on error. */
		bits[byte_num][bit_num]->SetValue(!bit_set);
	}
}

void REHex::BitEditor::OnNot(wxCommandEvent &event)
{
	modify_value([](uint64_t value)
	{
		return ~value;
	});
}

void REHex::BitEditor::OnAnd(wxCommandEvent &event)
{
	NumericEntryDialog<uint64_t> dialog(this,
		"Bitwise AND",
		"Enter operand for AND operation",
		0, 0, max_value, 0, NumericEntryDialog<uint64_t>::BaseHint::AUTO);
	
	int rc = dialog.ShowModal();
	if(rc == wxID_OK)
	{
		modify_value([&](uint64_t value)
		{
			return value & dialog.GetValue();
		});
	}
}

void REHex::BitEditor::OnOr(wxCommandEvent &event)
{
	NumericEntryDialog<uint64_t> dialog(this,
		"Bitwise OR",
		"Enter operand for OR operation",
		0, 0, max_value, 0, NumericEntryDialog<uint64_t>::BaseHint::AUTO);
	
	int rc = dialog.ShowModal();
	if(rc == wxID_OK)
	{
		modify_value([&](uint64_t value)
		{
			return value | dialog.GetValue();
		});
	}
}

void REHex::BitEditor::OnXor(wxCommandEvent &event)
{
	NumericEntryDialog<uint64_t> dialog(this,
		"Bitwise XOR",
		"Enter operand for XOR operation",
		0, 0, max_value, 0, NumericEntryDialog<uint64_t>::BaseHint::AUTO);
	
	int rc = dialog.ShowModal();
	if(rc == wxID_OK)
	{
		modify_value([&](uint64_t value)
		{
			return value ^ dialog.GetValue();
		});
	}
}

void REHex::BitEditor::OnLeftShift(wxCommandEvent &event)
{
	modify_value([&](uint64_t value)
	{
		return value << 1;
	});
}

void REHex::BitEditor::OnRightShift(wxCommandEvent &event)
{
	modify_value([&](uint64_t value)
	{
		return value >> 1;
	});
}
