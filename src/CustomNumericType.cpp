/* Reverse Engineer's Hex Editor
 * Copyright (C) 2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <stdexcept>
#include <wx/button.h>
#include <wx/sizer.h>
#include <wx/statline.h>
#include <wx/stattext.h>

#include "CustomNumericType.hpp"
#include "DataType.hpp"
#include "NumericTextCtrl.hpp"

static json_t *CustomNumericType_DataTypeConfigurator(wxWindow *parent)
{
	REHex::CustomNumericTypeDialog dialog(parent);
	
	int result = dialog.ShowModal();
	if(result == wxID_OK)
	{
		return dialog.get_options();
	}
	else{
		return NULL;
	}
}

static REHex::DataType CustomNumericType_DataTypeFactory(const json_t *options)
{
	return REHex::CustomNumericType(options).get_DataType();
}

static REHex::ConfigurableDataTypeRegistration CustomNumericType_Reg(
	"custom-number", "Custom", { "Number" },
	&CustomNumericType_DataTypeConfigurator,
	&CustomNumericType_DataTypeFactory);

REHex::CustomNumericType::CustomNumericType(BaseType base_type, Endianness endianness, size_t bits):
	base_type(base_type),
	endianness(endianness),
	bits(bits)
{
	if(bits < 1 || bits > 64)
	{
		throw std::invalid_argument("Unsupported number of bits: " + std::to_string(bits));
	}
	
	if((bits % 8) != 0 && endianness != Endianness::BIG)
	{
		throw std::invalid_argument("Little-endian non-whole-byte types are not supported");
	}
}

REHex::CustomNumericType::CustomNumericType(const json_t *options)
{
	if(!json_is_object(options))
	{
		throw std::invalid_argument("Expected a JSON object");
	}
	
	json_t *base_type_js = json_object_get(options, "base-type");
	if(!json_is_string(base_type_js))
	{
		throw std::invalid_argument("Expected a string \"base-type\" option");
	}
	
	const char *base_type_string = json_string_value(base_type_js);
	BaseType base_type_value;
	
	if(strcmp(base_type_string, "UNSIGNED_INT") == 0)
	{
		base_type_value = BaseType::UNSIGNED_INT;
	}
	else{
		throw std::invalid_argument(std::string("Invalid \"base-type\" option (") + base_type_string + ")");
	}
	
	json_t *endianness_js = json_object_get(options, "endianness");
	if(!json_is_string(endianness_js))
	{
		throw std::invalid_argument("Expected an string \"endianness\" option");
	}
	
	const char *endianness_string = json_string_value(endianness_js);
	Endianness endianness_value;
	
	if(strcmp(endianness_string, "LITTLE") == 0)
	{
		endianness_value = Endianness::LITTLE;
	}
	else if(strcmp(endianness_string, "BIG") == 0)
	{
		endianness_value = Endianness::BIG;
	}
	else{
		throw std::invalid_argument(std::string("Invalid \"endianness\" option (") + endianness_string + ")");
	}
	
	json_t *bits_js = json_object_get(options, "bits");
	if(!json_is_integer(bits_js))
	{
		throw std::invalid_argument("Expected an integer \"bits\" option");
	}
	
	size_t bits_value = json_integer_value(bits_js);
	
	*this = CustomNumericType(base_type_value, endianness_value, bits_value);
}

REHex::CustomNumericType::BaseType REHex::CustomNumericType::get_base_type() const
{
	return base_type;
}

REHex::CustomNumericType::Endianness REHex::CustomNumericType::get_endianness() const
{
	return endianness;
}

size_t REHex::CustomNumericType::get_bits() const
{
	return bits;
}

REHex::DataType REHex::CustomNumericType::get_DataType() const
{
	return DataType()
		.WithWordSize(BitOffset::from_int64(bits))
		.WithFixedSizeRegion([](REHex::SharedDocumentPointer &doc, REHex::BitOffset offset, REHex::BitOffset length, REHex::BitOffset virt_offset)
		{
			return new DocumentCtrl::DataRegion(doc, offset, length, virt_offset);
		}, REHex::BitOffset((bits / 8), (bits % 8)));
}

std::string REHex::CustomNumericType::format_value(const std::vector<bool> &data) const
{
	assert(data.size() == bits);
	
	switch(base_type)
	{
		case BaseType::UNSIGNED_INT:
		{
			uint64_t value = 0;
			
			for(auto b = data.begin(); b != data.end(); ++b)
			{
				value <<= 1;
				value |= *b;
			}
			
			if(endianness == Endianness::LITTLE)
			{
				assert((bits % 8) == 0);
				
				uint64_t swapped = 0;
				
				int shift = bits - 8;
				uint64_t vmask = 0xFFULL << shift;
				
				for(size_t i = 0; i < (bits / 8); ++i)
				{
					if(shift >= 0)
					{
						swapped |= (value & vmask) >> shift;
					}
					else{
						swapped |= (value & vmask) << -shift;
					}
					
					vmask >>= 8;
					shift -= 16;
				}
				
				value = swapped;
			}
			
			return std::to_string(value);
		}
	}
	
	abort(); /* Unreachable */
}

std::vector<bool> REHex::CustomNumericType::parse_value(const std::string &value) const
{
	std::vector<bool> data;
	data.reserve(bits);
	
	switch(base_type)
	{
		case BaseType::UNSIGNED_INT:
		{
			assert(bits <= 64);
			
			uint64_t value_max = bits < 64
				? (1ULL << bits) - 1
				: std::numeric_limits<uint64_t>::max();
			
			uint64_t value_u;
			try {
				value_u = NumericTextCtrl::ParseValue<uint64_t>(value, 0, value_max);
			}
			catch(const NumericTextCtrl::InputError &e)
			{
				throw std::invalid_argument(e.what());
			}
			
			for(size_t i = 0; i < bits; ++i)
			{
				data.insert(data.begin(), (value_u & (1ULL << i)) != 0);
			}
			
			if(endianness == Endianness::LITTLE)
			{
				assert((bits % 8) == 0);
				
				std::vector<bool> swapped;
				swapped.reserve(bits);
				
				for(int i = bits - 8; i >= 0; i -= 8)
				{
					swapped.insert(swapped.end(),
						(data.begin() + i), (data.begin() + i + 8));
				}
				
				data = swapped;
			}
		}
	}
	
	return data;
}

BEGIN_EVENT_TABLE(REHex::CustomNumericTypeDialog, wxDialog)
	EVT_SPINCTRL(wxID_ANY, REHex::CustomNumericTypeDialog::OnSizeChange)
END_EVENT_TABLE()

REHex::CustomNumericTypeDialog::CustomNumericTypeDialog(wxWindow *parent):
	wxDialog(parent, wxID_ANY, "Configure custom numeric type")
{
	static int MARGIN = 8;
	
	wxBoxSizer *top_sizer = new wxBoxSizer(wxVERTICAL);
	
	wxFlexGridSizer *grid_sizer = new wxFlexGridSizer(2, (MARGIN / 2), MARGIN);
	top_sizer->Add(grid_sizer, 0, wxALL, MARGIN);
	
	grid_sizer->Add(new wxStaticText(this, wxID_ANY, "Base type:"), 0, wxALIGN_CENTER_VERTICAL);
	
	base_type_choice = new wxChoice(this, wxID_ANY);
	grid_sizer->Add(base_type_choice, 0, wxALIGN_CENTER_VERTICAL);
	
	base_type_choice->Append("Unsigned integer");
	base_type_choice->SetSelection(0);
	
	grid_sizer->Add(new wxStaticText(this, wxID_ANY, "Endianness:"), 0, wxALIGN_CENTER_VERTICAL);
	
	endianness_choice = new wxChoice(this, wxID_ANY);
	grid_sizer->Add(endianness_choice, 0, wxALIGN_CENTER_VERTICAL);
	
	endianness_choice->Append("Little endian");
	endianness_choice->Append("Big endian");
	endianness_choice->SetSelection(0);
	
	grid_sizer->Add(new wxStaticText(this, wxID_ANY, "Size:"), 0, wxALIGN_CENTER_VERTICAL);
	
	wxBoxSizer *size_value_sizer = new wxBoxSizer(wxHORIZONTAL);
	grid_sizer->Add(size_value_sizer, 0, wxALIGN_CENTER_VERTICAL);
	
	size_spinctrl = new wxSpinCtrl(this, wxID_ANY);
	size_value_sizer->Add(size_spinctrl, 0, wxALIGN_CENTER_VERTICAL);
	
	size_spinctrl->SetRange(1, 64);
	size_spinctrl->SetValue(32);
	
	size_value_sizer->Add(new wxStaticText(this, wxID_ANY, "bits"), 0, (wxALIGN_CENTER_VERTICAL | wxLEFT), 4);
	
	top_sizer->Add(new wxStaticLine(this), 0, (wxEXPAND | wxBOTTOM | wxRIGHT | wxLEFT), MARGIN);
	
	wxSizer *button_sizer = new wxBoxSizer(wxHORIZONTAL);
	top_sizer->Add(button_sizer, 0, (wxBOTTOM | wxALIGN_RIGHT), MARGIN);
	
	wxButton *ok_button = new wxButton(this, wxID_OK);
	button_sizer->Add(ok_button, 0, wxRIGHT, MARGIN);
	
	wxButton *cancel_button = new wxButton(this, wxID_CANCEL);
	button_sizer->Add(cancel_button, 0, wxRIGHT, MARGIN);
	
	SetSizerAndFit(top_sizer);
}

json_t *REHex::CustomNumericTypeDialog::get_options() const
{
	json_t *json = json_object();
	
	static const char *BASE_TYPE_STRINGS[] = {
		"UNSIGNED_INT",
	};
	
	static const char *ENDIANNESS_STRINGS[] = {
		"LITTLE",
		"BIG",
	};
	
	int endianness_idx = (size_spinctrl->GetValue() % 8) == 0
		? endianness_choice->GetSelection()
		: 1;
	
	if(json == NULL
		|| json_object_set_new(json, "base-type", json_string(BASE_TYPE_STRINGS[ base_type_choice->GetSelection() ])) == -1
		|| json_object_set_new(json, "endianness", json_string(ENDIANNESS_STRINGS[ endianness_idx ])) == -1
		|| json_object_set_new(json, "bits", json_integer(size_spinctrl->GetValue())) == -1)
	{
		json_decref(json);
		return NULL;
	}
	
	return json;
}

void REHex::CustomNumericTypeDialog::OnSizeChange(wxSpinEvent &event)
{
	endianness_choice->Enable((event.GetPosition() % 8) == 0);
}
