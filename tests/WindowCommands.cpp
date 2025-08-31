/* Reverse Engineer's Hex Editor
 * Copyright (C) 2024-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "../src/platform.hpp"
#include <gtest/gtest.h>

#include <memory>
#include <wx/fileconf.h>
#include <wx/frame.h>
#include <wx/menu.h>
#include <wx/menuitem.h>
#include <wx/sstream.h>

#include "testutil.hpp"

#include "../src/WindowCommands.hpp"

using namespace REHex;

TEST(WindowCommandTableTest, BasicTests)
{
	enum {
		ID_COMMAND1 = 1,
		ID_COMMAND2,
		ID_COMMAND3,
		ID_COMMAND4,
	};
	
	AutoFrame frame(NULL, wxID_ANY, "REHex Tests");
	
	wxMenuBar *menubar = new wxMenuBar;
	frame->SetMenuBar(menubar);
	
	wxMenu *menu = new wxMenu;
	menubar->Append(menu, "Menu");
	
	wxMenuItem *command1 = menu->Append(ID_COMMAND1, "Menu Command 1\tCtrl+A");
	wxMenuItem *command2 = menu->Append(ID_COMMAND2, "Menu Command 2");
	wxMenuItem *command3 = menu->Append(ID_COMMAND3, "Menu Command 3");
	wxMenuItem *command4 = menu->Append(ID_COMMAND4, "Menu Command 4\tCtrl+P");
	
	WindowCommandTable wct(std::vector<WindowCommand>({
		WindowCommand("command1", "Command 1", ID_COMMAND1),
		WindowCommand("command2", "Command 2", ID_COMMAND2),
		WindowCommand("command3", "Command 3", ID_COMMAND3, wxACCEL_CTRL, 'C'),
	}), frame);
	
	{
		std::unique_ptr<wxAcceleratorEntry> command1_accel(command1->GetAccel());
		EXPECT_EQ(command1_accel, nullptr) << "REHex::WindowCommandTable clears unset menu accelerator";
	}
	
	{
		std::unique_ptr<wxAcceleratorEntry> command2_accel(command2->GetAccel());
		EXPECT_EQ(command2_accel, nullptr) << "REHex::WindowCommandTable leaves unset menu accelerator";
	}
	
	{
		std::unique_ptr<wxAcceleratorEntry> command3_accel(command3->GetAccel());
		ASSERT_NE(command3_accel, nullptr)                  << "REHex::WindowCommandTable sets accelerator on menu item";
		EXPECT_EQ(command3_accel->GetFlags(), wxACCEL_CTRL) << "REHex::WindowCommandTable sets accelerator on menu item";
		EXPECT_EQ(command3_accel->GetKeyCode(), 'C')        << "REHex::WindowCommandTable sets accelerator on menu item";
	}
	
	{
		std::unique_ptr<wxAcceleratorEntry> command4_accel(command4->GetAccel());
		ASSERT_NE(command4_accel, nullptr)                  << "REHex::WindowCommandTable leaves accelerator on menu item without associated command";
		EXPECT_EQ(command4_accel->GetFlags(), wxACCEL_CTRL) << "REHex::WindowCommandTable leaves accelerator on menu item without associated command";
		EXPECT_EQ(command4_accel->GetKeyCode(), 'P')        << "REHex::WindowCommandTable leaves accelerator on menu item without associated command";
	}
	
	EXPECT_EQ(wct.get_command_by_name("command1").label, "Command 1");
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND2).label, "Command 2");
	
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND2).accel_modifiers, 0);
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND2).accel_keycode,   WXK_NONE);
	
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND3).accel_modifiers, wxACCEL_CTRL);
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND3).accel_keycode,   'C');
	
	wct.set_command_accelerator("command1", wxACCEL_CTRL | wxACCEL_ALT, 'C');
	
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND1).accel_modifiers, wxACCEL_CTRL | wxACCEL_ALT) << "REHex::WindowCommandTable::set_command_accelerator(std::string, ...) sets command accelerator";
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND1).accel_keycode, 'C')                          << "REHex::WindowCommandTable::set_command_accelerator(std::string, ...) sets command accelerator";
	
	wct.set_command_accelerator(ID_COMMAND2, wxACCEL_CTRL, 'C');
	
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND2).accel_modifiers, wxACCEL_CTRL) << "REHex::WindowCommandTable::set_command_accelerator(int, ...) sets command accelerator";
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND2).accel_keycode, 'C')            << "REHex::WindowCommandTable::set_command_accelerator(int, ...) sets command accelerator";
	
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND1).accel_modifiers, wxACCEL_CTRL | wxACCEL_ALT) << "REHex::WindowCommandTable::set_command_accelerator(int, ...) leaves accelerator on other command";
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND1).accel_keycode, 'C')                          << "REHex::WindowCommandTable::set_command_accelerator(int, ...) leaves accelerator on other command";
	
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND3).accel_modifiers, 0)      << "REHex::WindowCommandTable::set_command_accelerator(int, ...) removes conflicting accelerator from other command";
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND3).accel_keycode, WXK_NONE) << "REHex::WindowCommandTable::set_command_accelerator(int, ...) removes conflicting accelerator from other command";
	
	{
		std::unique_ptr<wxAcceleratorEntry> command1_accel(command1->GetAccel());
		ASSERT_NE(command1_accel, nullptr)                                << "REHex::WindowCommandTable::set_command_accelerator(std::string, ...) sets accelerator on menu item";
		EXPECT_EQ(command1_accel->GetFlags(), wxACCEL_CTRL | wxACCEL_ALT) << "REHex::WindowCommandTable::set_command_accelerator(std::string, ...) sets accelerator on menu item";
		EXPECT_EQ(command1_accel->GetKeyCode(), 'C')                      << "REHex::WindowCommandTable::set_command_accelerator(std::string, ...) sets accelerator on menu item";
	}
	
	{
		std::unique_ptr<wxAcceleratorEntry> command2_accel(command2->GetAccel());
		ASSERT_NE(command2_accel, nullptr)                  << "REHex::WindowCommandTable::set_command_accelerator(int, ...) sets accelerator on menu item";
		EXPECT_EQ(command2_accel->GetFlags(), wxACCEL_CTRL) << "REHex::WindowCommandTable::set_command_accelerator(int, ...) sets accelerator on menu item";
		EXPECT_EQ(command2_accel->GetKeyCode(), 'C')        << "REHex::WindowCommandTable::set_command_accelerator(int, ...) sets accelerator on menu item";
	}
	
	{
		std::unique_ptr<wxAcceleratorEntry> command3_accel(command3->GetAccel());
		EXPECT_EQ(command3_accel, nullptr) << "REHex::WindowCommandTable::set_command_accelerator(int, ...) removes conflicting accelerator from other menu item";
	}
	
	wct.clear_command_accelerator("command1");
	
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND1).accel_modifiers, 0)      << "REHex::WindowCommandTable::clear_command_accelerator(std::string) removes command accelerator";
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND1).accel_keycode, WXK_NONE) << "REHex::WindowCommandTable::clear_command_accelerator(std::string) removes command accelerator";
	
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND2).accel_modifiers, wxACCEL_CTRL) << "REHex::WindowCommandTable::clear_command_accelerator(std::string) leaves accelerator on other command";
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND2).accel_keycode, 'C')            << "REHex::WindowCommandTable::clear_command_accelerator(std::string) leaves accelerator on other command";
	
	wct.clear_command_accelerator(ID_COMMAND2);
	
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND2).accel_modifiers, 0)      << "REHex::WindowCommandTable::clear_command_accelerator(std::string) removes command accelerator";
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND2).accel_keycode, WXK_NONE) << "REHex::WindowCommandTable::clear_command_accelerator(std::string) removes command accelerator";
	
	{
		std::unique_ptr<wxAcceleratorEntry> command1_accel(command1->GetAccel());
		EXPECT_EQ(command1_accel, nullptr) << "REHex::WindowCommandTable::clear_command_accelerator(std::string) removes accelerator from menu item";
	}
	
	{
		std::unique_ptr<wxAcceleratorEntry> command2_accel(command2->GetAccel());
		EXPECT_EQ(command2_accel, nullptr) << "REHex::WindowCommandTable::clear_command_accelerator(int) removes accelerator from menu item";
	}
}

TEST(WindowCommandTableTest, SetMenuItemAcceleratorByName)
{
	enum {
		ID_COMMAND1 = 1,
		ID_COMMAND2,
		ID_COMMAND3,
	};
	
	WindowCommandTable wct(std::vector<WindowCommand>({
		WindowCommand("command1", "Command 1", ID_COMMAND1),
		WindowCommand("command2", "Command 2", ID_COMMAND2, wxACCEL_CTRL, 'X'),
		WindowCommand("command3", "Command 3", ID_COMMAND3, wxACCEL_CTRL, 'C'),
	}));
	
	std::unique_ptr<wxMenuItem> itm(new wxMenuItem());
	std::unique_ptr<wxAcceleratorEntry> accel;
	
	wct.set_menu_item_accelerator(itm.get(), "command3");
	accel.reset(itm->GetAccel());
	
	EXPECT_NE(accel, nullptr) << "REHex::WindowCommandTable::set_menu_item_accelerator(wxMenuItem*, std::string) adds accelerator to menu item";
	if(accel)
	{
		EXPECT_EQ(accel->GetFlags(), wxACCEL_CTRL) << "REHex::WindowCommandTable::set_menu_item_accelerator(wxMenuItem*, std::string) adds accelerator to menu item";
		EXPECT_EQ(accel->GetKeyCode(), 'C')        << "REHex::WindowCommandTable::set_menu_item_accelerator(wxMenuItem*, std::string) adds accelerator to menu item";
	}
	
	wct.set_menu_item_accelerator(itm.get(), "command2");
	accel.reset(itm->GetAccel());
	
	EXPECT_NE(accel, nullptr) << "REHex::WindowCommandTable::set_menu_item_accelerator(wxMenuItem*, std::string) replaces accelerator on menu item";
	if(accel)
	{
		EXPECT_EQ(accel->GetFlags(), wxACCEL_CTRL) << "REHex::WindowCommandTable::set_menu_item_accelerator(wxMenuItem*, std::string) replaces accelerator on menu item";
		EXPECT_EQ(accel->GetKeyCode(), 'X')        << "REHex::WindowCommandTable::set_menu_item_accelerator(wxMenuItem*, std::string) replaces accelerator on menu item";
	}
	
	wct.set_menu_item_accelerator(itm.get(), "command1");
	accel.reset(itm->GetAccel());
	
	EXPECT_EQ(accel, nullptr) << "REHex::WindowCommandTable::set_menu_item_accelerator(wxMenuItem*, std::string) removes accelerator from menu item";
}

TEST(WindowCommandTableTest, SetMenuItemAcceleratorByID)
{
	enum {
		ID_COMMAND1 = 1,
		ID_COMMAND2,
		ID_COMMAND3,
	};
	
	WindowCommandTable wct(std::vector<WindowCommand>({
		WindowCommand("command1", "Command 1", ID_COMMAND1),
		WindowCommand("command2", "Command 2", ID_COMMAND2, wxACCEL_CTRL, 'X'),
		WindowCommand("command3", "Command 3", ID_COMMAND3, wxACCEL_CTRL, 'C'),
	}));
	
	std::unique_ptr<wxMenuItem> itm(new wxMenuItem());
	std::unique_ptr<wxAcceleratorEntry> accel;
	
	wct.set_menu_item_accelerator(itm.get(), ID_COMMAND3);
	accel.reset(itm->GetAccel());
	
	EXPECT_NE(accel, nullptr) << "REHex::WindowCommandTable::set_menu_item_accelerator(wxMenuItem*, int) adds accelerator to menu item";
	if(accel)
	{
		EXPECT_EQ(accel->GetFlags(), wxACCEL_CTRL) << "REHex::WindowCommandTable::set_menu_item_accelerator(wxMenuItem*, int) adds accelerator to menu item";
		EXPECT_EQ(accel->GetKeyCode(), 'C')        << "REHex::WindowCommandTable::set_menu_item_accelerator(wxMenuItem*, int) adds accelerator to menu item";
	}
	
	wct.set_menu_item_accelerator(itm.get(), ID_COMMAND2);
	accel.reset(itm->GetAccel());
	
	EXPECT_NE(accel, nullptr) << "REHex::WindowCommandTable::set_menu_item_accelerator(wxMenuItem*, int) replaces accelerator on menu item";
	if(accel)
	{
		EXPECT_EQ(accel->GetFlags(), wxACCEL_CTRL) << "REHex::WindowCommandTable::set_menu_item_accelerator(wxMenuItem*, int) replaces accelerator on menu item";
		EXPECT_EQ(accel->GetKeyCode(), 'X')        << "REHex::WindowCommandTable::set_menu_item_accelerator(wxMenuItem*, int) replaces accelerator on menu item";
	}
	
	wct.set_menu_item_accelerator(itm.get(), ID_COMMAND1);
	accel.reset(itm->GetAccel());
	
	EXPECT_EQ(accel, nullptr) << "REHex::WindowCommandTable::set_menu_item_accelerator(wxMenuItem*, int) removes accelerator from menu item";
}

TEST(WindowCommandTableTest, ReplaceAccelerators)
{
	enum {
		ID_COMMAND1 = 1,
		ID_COMMAND2,
		ID_COMMAND3,
		ID_COMMAND4,
	};
	
	AutoFrame frame(NULL, wxID_ANY, "REHex Tests");
	
	wxMenuBar *menubar = new wxMenuBar;
	frame->SetMenuBar(menubar);
	
	wxMenu *menu = new wxMenu;
	menubar->Append(menu, "Menu");
	
	wxMenuItem *command1 = menu->Append(ID_COMMAND1, "Menu Command 1\tCtrl+A");
	wxMenuItem *command2 = menu->Append(ID_COMMAND2, "Menu Command 2\tCtrl+B");
	wxMenuItem *command3 = menu->Append(ID_COMMAND3, "Menu Command 3");
	wxMenuItem *command4 = menu->Append(ID_COMMAND4, "Menu Command 4\tCtrl+P");
	
	WindowCommandTable wct(std::vector<WindowCommand>({
		WindowCommand("command1", "Command 1", ID_COMMAND1, wxACCEL_CTRL, 'A'),
		WindowCommand("command2", "Command 2", ID_COMMAND2, wxACCEL_CTRL, 'B'),
		WindowCommand("command3", "Command 3", ID_COMMAND3),
	}), frame);
	
	WindowCommandTable wct2(std::vector<WindowCommand>({
		WindowCommand("command1", "Command 1", ID_COMMAND1),
		WindowCommand("command2", "Command 2", ID_COMMAND2),
		WindowCommand("command3", "Command 3", ID_COMMAND3),
	}));
	
	wct2.set_command_accelerator(ID_COMMAND2, wxACCEL_CTRL, 'Z');
	wct2.set_command_accelerator(ID_COMMAND3, wxACCEL_CTRL, 'X');
	
	wct.replace_accelerators(wct2);
	
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND1).accel_modifiers, 0)        << "REHex::WindowCommandTable::replace_accelerators() removes unset menu accelerator";
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND1).accel_keycode,   WXK_NONE) << "REHex::WindowCommandTable::replace_accelerators() removes unset menu accelerator";
	
	{
		std::unique_ptr<wxAcceleratorEntry> command1_accel(command1->GetAccel());
		EXPECT_EQ(command1_accel, nullptr) << "REHex::WindowCommandTable::replace_accelerators() removes unset menu accelerator";
	}
	
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND2).accel_modifiers, wxACCEL_CTRL) << "REHex::WindowCommandTable::replace_accelerators() sets accelerator on command";
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND2).accel_keycode,   'Z')          << "REHex::WindowCommandTable::replace_accelerators() sets accelerator on command";
	
	{
		std::unique_ptr<wxAcceleratorEntry> command2_accel(command2->GetAccel());
		ASSERT_NE(command2_accel, nullptr)                  << "REHex::WindowCommandTable::replace_accelerators() sets accelerator on menu item";
		EXPECT_EQ(command2_accel->GetFlags(), wxACCEL_CTRL) << "REHex::WindowCommandTable::replace_accelerators() sets accelerator on menu item";
		EXPECT_EQ(command2_accel->GetKeyCode(), 'Z')        << "REHex::WindowCommandTable::replace_accelerators() sets accelerator on menu item";
	}
	
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND3).accel_modifiers, wxACCEL_CTRL) << "REHex::WindowCommandTable::replace_accelerators() sets accelerator on command";
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND3).accel_keycode,   'X')          << "REHex::WindowCommandTable::replace_accelerators() sets accelerator on command";
	
	{
		std::unique_ptr<wxAcceleratorEntry> command3_accel(command3->GetAccel());
		ASSERT_NE(command3_accel, nullptr)                  << "REHex::WindowCommandTable::replace_accelerators() sets accelerator on menu item";
		EXPECT_EQ(command3_accel->GetFlags(), wxACCEL_CTRL) << "REHex::WindowCommandTable::replace_accelerators() sets accelerator on menu item";
		EXPECT_EQ(command3_accel->GetKeyCode(), 'X')        << "REHex::WindowCommandTable::replace_accelerators() sets accelerator on menu item";
	}
	
	{
		std::unique_ptr<wxAcceleratorEntry> command4_accel(command4->GetAccel());
		ASSERT_NE(command4_accel, nullptr)                  << "REHex::WindowCommandTable::replace_accelerators() leaves accelerator on menu item without associated command";
		EXPECT_EQ(command4_accel->GetFlags(), wxACCEL_CTRL) << "REHex::WindowCommandTable::replace_accelerators() leaves accelerator on menu item without associated command";
		EXPECT_EQ(command4_accel->GetKeyCode(), 'P')        << "REHex::WindowCommandTable::replace_accelerators() leaves accelerator on menu item without associated command";
	}
}

TEST(WindowCommandTableTest, SaveAccelerators)
{
	enum {
		ID_COMMAND1 = 1,
		ID_COMMAND2,
		ID_COMMAND3,
	};
	
	WindowCommandTable wct(std::vector<WindowCommand>({
		WindowCommand("command1", "Command 1", ID_COMMAND1),
		WindowCommand("command2", "Command 2", ID_COMMAND2, wxACCEL_CTRL, 'X'),
		WindowCommand("command3", "Command 3", ID_COMMAND3, wxACCEL_CTRL, 'C'),
	}));
	
	wxStringInputStream empty_ss(wxEmptyString);
	wxFileConfig config(empty_ss, wxConvUTF8);
	config.SetPath("flame");
	
	wct.save_accelerators(&config);
	
	wxStringOutputStream config_ss;
	config.Save(config_ss, wxConvUTF8);
	
	EXPECT_EQ(config_ss.GetString().ToStdString(),
		"[flame]" CONFIG_EOL
		"command1=" CONFIG_EOL
		"command2=Ctrl+X" CONFIG_EOL
		"command3=Ctrl+C" CONFIG_EOL);
}

TEST(WindowCommandTableTest, LoadAccelerators)
{
	enum {
		ID_COMMAND1 = 1,
		ID_COMMAND2,
		ID_COMMAND3,
		ID_COMMAND4,
		ID_COMMAND5,
	};
	
	WindowCommandTable wct(std::vector<WindowCommand>({
		WindowCommand("command1", "Command 1", ID_COMMAND1),
		WindowCommand("command2", "Command 2", ID_COMMAND2, wxACCEL_CTRL, 'X'),
		WindowCommand("command3", "Command 3", ID_COMMAND3, wxACCEL_CTRL, 'C'),
		WindowCommand("command4", "Command 4", ID_COMMAND4, wxACCEL_CTRL, 'V'),
		WindowCommand("command5", "Command 5", ID_COMMAND5, wxACCEL_CTRL, 'B'),
	}));
	
	wxStringInputStream config_ss(
		"[exercise]" CONFIG_EOL
		"command1=Ctrl+Q" CONFIG_EOL
		"command4=Ctrl+C" CONFIG_EOL
		"command5=" CONFIG_EOL);
	
	wxFileConfig config(config_ss, wxConvUTF8);
	config.SetPath("exercise");
	
	wct.load_accelerators(&config);
	
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND1).accel_modifiers, wxACCEL_CTRL) << "REHex::WindowCommandTable::load() loads an accelerator from the configuration";
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND1).accel_keycode,   'Q')          << "REHex::WindowCommandTable::load() loads an accelerator from the configuration";
	
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND2).accel_modifiers, wxACCEL_CTRL) << "REHex::WindowCommandTable::load() keeps a default accelerator not specified in the configuration";
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND2).accel_keycode,   'X')          << "REHex::WindowCommandTable::load() keeps a default accelerator not specified in the configuration";
	
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND4).accel_modifiers, wxACCEL_CTRL) << "REHex::WindowCommandTable::load() loads an accelerator from the configuration";
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND4).accel_keycode,   'C')          << "REHex::WindowCommandTable::load() loads an accelerator from the configuration";
	
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND3).accel_modifiers, 0)        << "REHex::WindowCommandTable::load() clears a default accelerator used by another command";
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND3).accel_keycode,   WXK_NONE) << "REHex::WindowCommandTable::load() clears a default accelerator used by another command";
	
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND5).accel_modifiers, 0)        << "REHex::WindowCommandTable::load() clears the accelerator of a blank command in the configuration";
	EXPECT_EQ(wct.get_command_by_id(ID_COMMAND5).accel_keycode,   WXK_NONE) << "REHex::WindowCommandTable::load() clears the accelerator of a blank command in the configuration";
}
