/* Reverse Engineer's Hex Editor
 * Copyright (C) 2022-2023 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <stdexcept>
#include <stdlib.h>
#include <string.h>

#include "App.hpp"
#include "DiffWindow.hpp"
#include "IPC.hpp"
#include "mainwindow.hpp"

#include "../res/version.h"

static REHex::MainWindow *new_window()
{
	wxSize windowSize(740, 540);
	
	#ifndef __APPLE__
	wxGetApp().config->Read("/default-view/window-width", &windowSize.x, windowSize.x);
	wxGetApp().config->Read("/default-view/window-height", &windowSize.y, windowSize.y);
	#endif
	
	return new REHex::MainWindow(windowSize);
}

bool REHex::IPCConnection::OnExec(const wxString &topic, const wxString &data)
{
	std::vector<std::string> command;
	try {
		command = decode_command(data.ToStdString());
	}
	catch(const std::exception &e)
	{
		return false;
	}
	
	if(command.size() == 2 && command[0] == "open")
	{
		MainWindow *window = MainWindow::get_instances().front();
		window->Show();
		
		Tab *tab = window->open_file(command[1]);
		return tab != NULL;
	}
	else if(command.size() >= 3 && command[0] == "compare")
	{
		MainWindow *window = new_window();
		DiffWindow *diff = new DiffWindow(NULL);
		
		for(size_t i = 1; i < command.size(); ++i)
		{
			Tab *tab = window->open_file(command[i]);
			if(tab != NULL)
			{
				diff->add_range(DiffWindow::Range(tab->doc, tab->doc_ctrl, 0, tab->doc->buffer_length()));
			}
			else{
				diff->Destroy();
				window->Destroy();
				return false;
			}
		}
		
		diff->set_invisible_owner_window(window);
		diff->Show();
		
		return true;
	}
	else{
		return false;
	}
}

wxConnectionBase *REHex::IPCServer::OnAcceptConnection(const wxString &topic)
{
	if(topic == get_ipc_topic())
	{
		return new IPCConnection();
	}
	else{
		return NULL;
	}
}

std::string REHex::get_ipc_host()
{
	return "localhost";
}

std::string REHex::get_ipc_service()
{
	#if defined(_WIN32)
	/* DDE service name on Windows */
	return std::string("rehex_") + REHEX_SHORT_VERSION;
	
	#elif defined(__APPLE__)
	/* Socket under ~/Library/Application Support/rehex/ on macOS. */
	
	char *HOME = getenv("HOME");
	if(HOME != NULL && strcmp(HOME, "") != 0)
	{
		return std::string(HOME) + "/Library/Application Support/rehex/rehex_" + REHEX_SHORT_VERSION + ".sock";
	}
	
	throw std::runtime_error("HOME environment variable not set");
	
	#else
	/* Socket under $XDG_RUNTIME_DIR or $HOME on UNIX/Linux. */
	
	char *XDG_RUNTIME_DIR = getenv("XDG_RUNTIME_DIR");
	if(XDG_RUNTIME_DIR != NULL && strcmp(XDG_RUNTIME_DIR, "") != 0)
	{
		return std::string(XDG_RUNTIME_DIR) + "/rehex_" + REHEX_SHORT_VERSION + ".sock";
	}
	
	char *HOME = getenv("HOME");
	if(HOME != NULL && strcmp(HOME, "") != 0)
	{
		return std::string(HOME) + "/.rehex_" + REHEX_SHORT_VERSION + ".sock";
	}
	
	throw std::runtime_error("XDG_RUNTIME_DIR/HOME environment variable not set");
	#endif
}

std::string REHex::get_ipc_topic()
{
	return "rehex";
}

std::string REHex::encode_command(const std::vector<std::string> &command)
{
	json_t *j = json_array();
	
	for(auto i = command.begin(); i != command.end(); ++i)
	{
		json_array_append(j, json_string(i->c_str()));
	}
	
	char *json_c = json_dumps(j, JSON_ENSURE_ASCII);
	json_decref(j);
	
	std::string json_s = json_c;
	free(json_c);
	
	return json_s;
}

std::vector<std::string> REHex::decode_command(const std::string &data)
{
	json_error_t json_err;
	json_t *j = json_loads(data.c_str(), 0, &json_err);
	
	if(j == NULL)
	{
		throw std::runtime_error(std::string("Error decoding command: ") + json_err.text);
	}
	
	std::vector<std::string> decoded_command;
	decoded_command.reserve(json_array_size(j));
	
	size_t index;
	json_t *value;
	
	json_array_foreach(j, index, value)
	{
		decoded_command.push_back(json_string_value(value));
	}
	
	json_decref(j);
	
	return decoded_command;
}
