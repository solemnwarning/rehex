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

#include "App.hpp"
#include "ByteColourMap.hpp"

const wxString &REHex::ByteColourMap::get_label() const
{
	return label;
}

void REHex::ByteColourMap::set_label(const wxString &label)
{
	this->label = label;
}

void REHex::ByteColourMap::set_colour(unsigned char byte, Colour colour)
{
	Value &elem = bytes[byte];
	
	elem.colour1 = colour;
	elem.colour2 = colour;
	elem.colour_delta_steps = 0;
	elem.colour_delta_pos = 0;
}

void REHex::ByteColourMap::set_colour_range(unsigned char first_byte, unsigned char last_byte, Colour colour)
{
	assert(first_byte <= last_byte);
	
	for(int i = first_byte; i <= (int)(last_byte); ++i)
	{
		set_colour(i, colour);
	}
}

void REHex::ByteColourMap::set_colour_gradient(unsigned char first_byte, unsigned char last_byte, Colour first_byte_colour, Colour last_byte_colour)
{
	assert(first_byte <= last_byte);
	
	if(first_byte == last_byte)
	{
		set_colour(first_byte, first_byte_colour);
		return;
	}
	else if(first_byte_colour == last_byte_colour)
	{
		set_colour_range(first_byte, last_byte, first_byte_colour);
		return;
	}
	
	int diff = last_byte - first_byte;
	
	for(int i = first_byte; i <= (int)(last_byte); ++i)
	{
		Value &elem = bytes[i];
		
		elem.colour1 = first_byte_colour;
		elem.colour2 = last_byte_colour;
		elem.colour_delta_steps = diff;
		elem.colour_delta_pos = i - first_byte;
	}
}

wxColour REHex::ByteColourMap::get_colour(unsigned char byte) const
{
	auto &elem = bytes[byte];
	
	return elem.get_colour();
}

const REHex::ByteColourMap::Value &REHex::ByteColourMap::operator[](unsigned char byte) const
{
	return bytes[byte];
}

bool REHex::ByteColourMap::Value::is_single() const
{
	return colour_delta_steps == 0;
}

bool REHex::ByteColourMap::Value::is_start() const
{
	return colour_delta_pos == 0 && colour_delta_steps > 0;
}

bool REHex::ByteColourMap::Value::is_end() const
{
	return colour_delta_pos == colour_delta_steps && colour_delta_steps > 0;
}

wxColour REHex::ByteColourMap::Value::get_colour() const
{
	wxColour c1, c2;
	
	if(colour1.is_palette_colour())
	{
		c1 = (*active_palette)[colour1.get_palette_colour()];
	}
	else if(colour1.is_custom_colour())
	{
		c1 = colour1.get_custom_colour();
	}
	else{
		abort(); /* Unreachable. */
	}
	
	if(colour_delta_steps == 0)
	{
		return c1;
	}
	
	if(colour2.is_palette_colour())
	{
		c2 = (*active_palette)[colour2.get_palette_colour()];
	}
	else if(colour2.is_custom_colour())
	{
		c2 = colour2.get_custom_colour();
	}
	else{
		abort(); /* Unreachable. */
	}
	
	float alpha = (float)(colour_delta_pos) / (float)(colour_delta_steps);
	
	unsigned char r = wxColour::AlphaBlend(c2.Red(), c1.Red(), alpha);
	unsigned char g = wxColour::AlphaBlend(c2.Green(), c1.Green(), alpha);
	unsigned char b = wxColour::AlphaBlend(c2.Blue(), c1.Blue(), alpha);
	
	return wxColour(r, g, b);
}

static const std::vector< std::pair<REHex::Palette::ColourIndex, std::string> > SERIALISED_COLOURS = {
	{ REHex::Palette::PAL_NORMAL_TEXT_FG,     "PAL_NORMAL_TEXT_FG"     },
	{ REHex::Palette::PAL_CONTRAST_TEXT_1_FG, "PAL_CONTRAST_TEXT_1_FG" },
	{ REHex::Palette::PAL_CONTRAST_TEXT_2_FG, "PAL_CONTRAST_TEXT_2_FG" },
	{ REHex::Palette::PAL_CONTRAST_TEXT_3_FG, "PAL_CONTRAST_TEXT_3_FG" },
	{ REHex::Palette::PAL_CONTRAST_TEXT_4_FG, "PAL_CONTRAST_TEXT_4_FG" },
	{ REHex::Palette::PAL_CONTRAST_TEXT_5_FG, "PAL_CONTRAST_TEXT_5_FG" },
};

std::string REHex::ByteColourMap::serialise_colour_index(Colour index)
{
	if(index.is_palette_colour())
	{
		Palette::ColourIndex colour = index.get_palette_colour();
		
		for(auto i = SERIALISED_COLOURS.begin(); i != SERIALISED_COLOURS.end(); ++i)
		{
			if(i->first == colour)
			{
				return i->second;
			}
		}
		
		throw std::invalid_argument("Unexpected colour in REHex::ByteColourMap::serialise_colour_index()");
	}
	else{
		assert(index.is_custom_colour());
		return "#" + colour_to_string(index.get_custom_colour());
	}
}

REHex::ByteColourMap::Colour REHex::ByteColourMap::deserialise_colour_index(const std::string &string)
{
	if(string.length() > 0 && string[0] == '#')
	{
		return Colour(colour_from_string(string.substr(1)));
	}
	
	for(auto i = SERIALISED_COLOURS.begin(); i != SERIALISED_COLOURS.end(); ++i)
	{
		if(i->second == string)
		{
			return Colour(i->first);
		}
	}
	
	throw std::invalid_argument("Invalid string passed to REHex::ByteColourMap::deserialise_colour_index() (" + string + ")");
}

REHex::ByteColourMap REHex::ByteColourMap::load(const wxConfigBase *config)
{
	ByteColourMap map;
	
	map.label = config->Read("label", map.label);
	
	for(int i = 0; i < 256; ++i)
	{
		char path[8];
		snprintf(path, sizeof(path), "%d/", i);
		
		if(!config->HasGroup(path))
		{
			continue;
		}
		
		wxConfigPathChanger scoped_path(config, path);
		
		map.bytes[i].colour1 = deserialise_colour_index(config->Read("colour1", wxEmptyString).ToStdString());
		map.bytes[i].colour2 = deserialise_colour_index(config->Read("colour2", wxEmptyString).ToStdString());
		
		map.bytes[i].colour_delta_steps = config->Read("colour_delta_steps", (long)(-1));
		map.bytes[i].colour_delta_pos   = config->Read("colour_delta_pos",   (long)(-1));
		
		if(map.bytes[i].colour_delta_steps < 0
			|| map.bytes[i].colour_delta_pos < 0
			|| map.bytes[i].colour_delta_pos > map.bytes[i].colour_delta_steps)
		{
			throw std::invalid_argument("invalid colour_delta_steps/colour_delta_pos values");
		}
	}
	
	return map;
}

void REHex::ByteColourMap::save(wxConfigBase *config)
{
	config->Write("label", label);
	
	for(int i = 0; i < 256; ++i)
	{
		if(bytes[i] == Value())
		{
			/* Skip serialising default colours. */
			continue;
		}
		
		char path[8];
		snprintf(path, sizeof(path), "%d/", i);
		wxConfigPathChanger scoped_path(config, path);
		
		std::string colour1 = serialise_colour_index(bytes[i].colour1);
		std::string colour2 = serialise_colour_index(bytes[i].colour2);
		
		config->Write("colour1", wxString(colour1));
		config->Write("colour2", wxString(colour2));
		
		config->Write("colour_delta_steps", (long)(bytes[i].colour_delta_steps));
		config->Write("colour_delta_pos", (long)(bytes[i].colour_delta_pos));
	}
}
