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

#include "HighlightColourMap.hpp"
#include "HSVColour.hpp"
#include "util.hpp"

REHex::HighlightColourMap::HighlightColourMap():
	default_colour_lightness(100) {}

REHex::HighlightColourMap REHex::HighlightColourMap::defaults(int default_colour_lightness)
{
	HighlightColourMap map;
	map.default_colour_lightness = default_colour_lightness;
	
	for(size_t i = 0; i < DEFAULT_NUM; ++i)
	{
		auto it = map.add();
		assert(it->first == i);
	}
	
	return map;
}

REHex::HighlightColourMap REHex::HighlightColourMap::from_config(const wxConfigBase *config, int default_colour_lightness)
{
	HighlightColourMap map;
	map.default_colour_lightness = default_colour_lightness;
	
	wxString group_path;
	long group_idx;
	bool group_valid = config->GetFirstGroup(group_path, group_idx);
	
	while(group_valid)
	{
		size_t v_index = atoi(group_path.mb_str());
		
		if(group_path.find_first_not_of("1234567890") != wxString::npos || v_index >= MAX_NUM)
		{
			throw std::invalid_argument("Invalid highlight index");
		}
		
		{
			wxConfigPathChanger scoped_path(config, group_path + "/");
			
			HighlightColour hc = make_default_highlight(v_index, default_colour_lightness);
			
			if(config->HasEntry("primary_colour"))
			{
				hc.set_primary_colour(colour_from_string(config->Read("primary_colour", wxEmptyString).ToStdString()));
			}
			
			if(config->HasEntry("secondary_colour"))
			{
				hc.set_secondary_colour(colour_from_string(config->Read("secondary_colour", wxEmptyString).ToStdString()));
			}
			
			if(config->HasEntry("label"))
			{
				hc.set_label(config->Read("label", wxEmptyString));
			}
			
			map.colours.insert(std::make_pair(v_index, hc));
		}
		
		group_valid = config->GetNextGroup(group_path, group_idx);
	}
	
	return map;
}

void REHex::HighlightColourMap::to_config(wxConfigBase *config) const
{
	for(auto c = colours.begin(); c != colours.end(); ++c)
	{
		char index_s[16];
		snprintf(index_s, sizeof(index_s), "%zu/", c->first);
		
		wxConfigPathChanger scoped_path(config, index_s);
		
		bool all_default = true;
		
		if(!(c->second.primary_colour_is_default))
		{
			config->Write("primary_colour", wxString(colour_to_string(c->second.primary_colour)));
			all_default = false;
		}
		
		if(!(c->second.secondary_colour_is_default))
		{
			config->Write("secondary_colour", wxString(colour_to_string(c->second.secondary_colour)));
			all_default = false;
		}
		
		if(!(c->second.label_is_default))
		{
			config->Write("label", c->second.label);
			all_default = false;
		}
		
		if(all_default)
		{
			config->Write("all_default", true);
		}
	}
}

REHex::HighlightColourMap REHex::HighlightColourMap::from_json(const json_t *json, int default_colour_lightness)
{
	HighlightColourMap map;
	map.default_colour_lightness = default_colour_lightness;
	
	if(!json_is_array(json))
	{
		throw std::invalid_argument("Expected a JSON array (highlight array)");
	}
	
	size_t index;
	json_t *value;
	
	json_array_foreach(json, index, value)
	{
		if(!json_is_object(value))
		{
			throw std::invalid_argument("Expected a JSON object (highlight object)");
		}
		
		json_t *js_index = json_object_get(value, "index");
		json_t *js_primary_colour = json_object_get(value, "primary_colour");
		json_t *js_secondary_colour = json_object_get(value, "secondary_colour");
		json_t *js_label = json_object_get(value, "label");
		
		if(!json_is_integer(js_index))
		{
			throw std::invalid_argument("Expected a JSON integer (highlight index)");
		}
		
		int v_index = json_integer_value(js_index);
		if(v_index < 0 || (size_t)(v_index) >= MAX_NUM)
		{
			throw std::invalid_argument("Highlight index out of range");
		}
		
		HighlightColour hc = make_default_highlight(v_index, default_colour_lightness);
		
		wxColour colour_from_json(const json_t *json);
		json_t *colour_to_json(const wxColour &colour);
		
		if(js_primary_colour != NULL)
		{
			hc.primary_colour = colour_from_json(js_primary_colour);
			hc.primary_colour_is_default = false;
		}
		
		if(js_secondary_colour != NULL)
		{
			hc.secondary_colour = colour_from_json(js_secondary_colour);
			hc.secondary_colour_is_default = false;
		}
		
		if(js_label != NULL)
		{
			if(!json_is_string(js_label))
			{
				throw std::invalid_argument("Expected a JSON string (highlight label)");
			}
			
			hc.label = wxString::FromUTF8(json_string_value(js_label));
			hc.label_is_default = false;
		}
		
		if(map.colours.find(v_index) != map.colours.end())
		{
			throw std::invalid_argument("Duplicate index in highlights array");
		}
		
		map.colours.insert(std::make_pair(v_index, hc));
	}
	
	return map;
}

json_t *REHex::HighlightColourMap::to_json() const
{
	json_t *json = json_array();
	if(json == NULL)
	{
		return NULL;
	}
	
	for(auto c = colours.begin(); c != colours.end(); ++c)
	{
		const wxScopedCharBuffer label_utf8 = c->second.label.utf8_str();
		
		json_t *elem = json_object();
		if(
			json_array_append_new(json, elem) == -1
			|| json_object_set_new(elem, "index", json_integer(c->first)) == -1
			|| (!(c->second.primary_colour_is_default) && json_object_set_new(elem, "primary_colour", colour_to_json(c->second.primary_colour)) == -1)
			|| (!(c->second.secondary_colour_is_default) && json_object_set_new(elem, "secondary_colour", colour_to_json(c->second.secondary_colour)) == -1)
			|| (!(c->second.label_is_default) && json_object_set_new(elem, "label", json_stringn(label_utf8.data(), label_utf8.length())) == -1))
		{
			json_decref(json);
			return NULL;
		}
	}
	
	return json;
}

REHex::HighlightColourMap::iterator REHex::HighlightColourMap::add()
{
	for(size_t i = 0; i < MAX_NUM; ++i)
	{
		if(colours.find(i) == colours.end())
		{
			return colours.insert(std::make_pair(i, make_default_highlight(i, default_colour_lightness))).first;
		}
	}
	
	return end();
}

void REHex::HighlightColourMap::erase(size_t highlight_idx)
{
	colours.erase(highlight_idx);
}

void REHex::HighlightColourMap::erase(const const_iterator &it)
{
	colours.erase(it);
}

size_t REHex::HighlightColourMap::size() const
{
	return colours.size();
}

bool REHex::HighlightColourMap::empty() const
{
	return colours.empty();
}

REHex::HighlightColourMap::iterator REHex::HighlightColourMap::find(size_t highlight_idx)
{
	return colours.find(highlight_idx);
}

REHex::HighlightColourMap::const_iterator REHex::HighlightColourMap::find(size_t highlight_idx) const
{
	return colours.find(highlight_idx);
}

REHex::HighlightColourMap::iterator REHex::HighlightColourMap::begin()
{
	return colours.begin();
}

REHex::HighlightColourMap::iterator REHex::HighlightColourMap::end()
{
	return colours.end();
}

REHex::HighlightColourMap::const_iterator REHex::HighlightColourMap::begin() const
{
	return colours.begin();
}

REHex::HighlightColourMap::const_iterator REHex::HighlightColourMap::end() const
{
	return colours.end();
}

REHex::HighlightColourMap::HighlightColour &REHex::HighlightColourMap::operator[](size_t highlight_idx)
{
	auto it = colours.find(highlight_idx);
	if(it == colours.end())
	{
		it = colours.insert(std::make_pair(highlight_idx, make_default_highlight(highlight_idx, default_colour_lightness))).first;
	}
	
	return it->second;
}

void REHex::HighlightColourMap::set_default_lightness(int lightness)
{
	default_colour_lightness = lightness;
	
	for(auto it = colours.begin(); it != colours.end(); ++it)
	{
		HighlightColour default_hc = make_default_highlight(it->first, default_colour_lightness);
		
		if(it->second.primary_colour_is_default)
		{
			it->second.primary_colour = default_hc.primary_colour;
		}
	}
}

REHex::HighlightColourMap::HighlightColour REHex::HighlightColourMap::make_default_highlight(size_t highlight_idx, int lightness)
{
	HighlightColour hc;
	
	switch(highlight_idx)
	{
		case 0: /* White on Red */
			hc.primary_colour = wxColour(0xFF, 0x00, 0x00);
			hc.secondary_colour = wxColour(0xFF, 0xFF, 0xFF);
			hc.label = "Red";
			
			break;
		
		case 1: /* White on Orange */
			hc.primary_colour = wxColour(0xFE, 0x63, 0x00);
			hc.secondary_colour = wxColour(0xFF, 0xFF, 0xFF);
			hc.label = "Orange";
			
			break;
			
		case 2: /* Black on Yellow */
			hc.primary_colour = wxColour(0xFC, 0xFF, 0x00);
			hc.secondary_colour = wxColour(0x00, 0x00, 0x00);
			hc.label = "Yellow";
			break;
			
		case 3: /* Black on Green */
			hc.primary_colour = wxColour(0x02, 0xFE, 0x07);
			hc.secondary_colour = wxColour(0x00, 0x00, 0x00);
			hc.label = "Green";
			
			break;
			
		case 4: /* White on Violet */
			hc.primary_colour = wxColour(0xFD, 0x00, 0xFF);
			hc.secondary_colour = wxColour(0xFF, 0xFF, 0xFF);
			hc.label = "Violet";
			
			break;
			
		case 5: /* White on Grey */
			hc.primary_colour = wxColour(0x6A, 0x63, 0x6F);
			hc.secondary_colour = wxColour(0xFF, 0xFF, 0xFF);
			hc.label = "Grey";
			
			break;
			
		default:
		{
			std::vector<float> existing_primary_hues;
			existing_primary_hues.reserve(highlight_idx);
			
			for(size_t i = 0; i < highlight_idx && i < 6; ++i)
			{
				HighlightColour i_hc = make_default_highlight(i, 100);
				HSVColour primary_colour_hsv = HSVColour(i_hc.primary_colour);
				
				existing_primary_hues.push_back(primary_colour_hsv.h);
			}
			
			for(size_t i = 6; i <= highlight_idx; ++i)
			{
				float next_primary_hue, next_primary_hue_diff;
				std::tie(next_primary_hue, next_primary_hue_diff) = HSVColour::pick_contrasting_hue(existing_primary_hues);
				
				existing_primary_hues.push_back(next_primary_hue);
			}
			
			HSVColour primary_colour_hsv(existing_primary_hues.back(), 1.0f, 1.0f);
			
			hc.primary_colour = primary_colour_hsv.to_rgb();
			hc.secondary_colour = wxColour(0x00, 0x00, 0x00);
			hc.label = "Highlight " + std::to_string(highlight_idx + 1);
			
			break;
		}
	}
	
	hc.primary_colour = hc.primary_colour.ChangeLightness(lightness);
	
	hc.primary_colour_is_default = true;
	hc.secondary_colour_is_default = true;
	hc.label_is_default = true;
	
	return hc;
}

void REHex::HighlightColourMap::HighlightColour::set_primary_colour(const wxColour &colour)
{
	primary_colour = colour;
	primary_colour_is_default = false;
}

void REHex::HighlightColourMap::HighlightColour::set_secondary_colour(const wxColour &colour)
{
	secondary_colour = colour;
	secondary_colour_is_default = false;
}

void REHex::HighlightColourMap::HighlightColour::set_label(const wxString &label)
{
	this->label = label;
	label_is_default = false;
}
