/* Reverse Engineer's Hex Editor
 * Copyright (C) 2019 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <utility>

#include "ToolPanel.hpp"

REHex::ToolPanel::ToolPanel(wxWindow *parent):
	wxPanel(parent),
	is_visible(false)
{
}

REHex::ToolPanel::~ToolPanel() {}

void REHex::ToolPanel::set_visible(bool visible)
{
	is_visible = visible;
	if (is_visible)
	{
		update();
	}
}

std::map<std::string, const REHex::ToolPanelRegistration*> *REHex::ToolPanelRegistry::registrations = NULL;
const std::map<std::string, const REHex::ToolPanelRegistration*> REHex::ToolPanelRegistry::no_registrations;

std::map<std::string, const REHex::ToolPanelRegistration*>::const_iterator REHex::ToolPanelRegistry::begin()
{
	return registrations != NULL
		? registrations->begin()
		: no_registrations.begin();
}

std::map<std::string, const REHex::ToolPanelRegistration*>::const_iterator REHex::ToolPanelRegistry::end()
{
	return registrations != NULL
		? registrations->end()
		: no_registrations.end();
}

const REHex::ToolPanelRegistration *REHex::ToolPanelRegistry::by_name(const std::string &name)
{
	if(registrations == NULL)
	{
		return NULL;
	}
	
	auto i = registrations->find(name);
	if(i != registrations->end())
	{
		return i->second;
	}
	else{
		return NULL;
	}
}

REHex::ToolPanelRegistration::ToolPanelRegistration(const std::string &name, const std::string &label, REHex::ToolPanel::Shape shape, REHex::ToolPanelRegistration::FactoryFunction factory):
	name(name), label(label), shape(shape), factory(factory)
{
	if(ToolPanelRegistry::registrations == NULL)
	{
		ToolPanelRegistry::registrations = new std::map<std::string, const REHex::ToolPanelRegistration*>();
	}
	
	ToolPanelRegistry::registrations->insert(std::make_pair(name, this));
}

REHex::ToolPanelRegistration::~ToolPanelRegistration()
{
	ToolPanelRegistry::registrations->erase(name);
	
	if(ToolPanelRegistry::registrations->empty())
	{
		delete ToolPanelRegistry::registrations;
		ToolPanelRegistry::registrations = NULL;
	}
}
