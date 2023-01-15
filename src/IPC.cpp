/* Reverse Engineer's Hex Editor
 * Copyright (C) 2022 Daniel Collins <solemnwarning@solemnwarning.net>
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

bool REHex::IPCConnection::OnExecute(const wxString &topic, const void *data, size_t size, wxIPCFormat format)
{
	if(format != wxIPC_PRIVATE)
	{
		return false;
	}
	
	std::vector<std::string> command;
	try {
		command = decode_command(data, size);
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
	return "";
}

std::vector<unsigned char> REHex::encode_command(const std::vector<std::string> &command)
{
	size_t size = sizeof(size_t);
	
	for(auto i = command.begin(); i != command.end(); ++i)
	{
		size += sizeof(size_t);
		size += i->length();
	}
	
	std::vector<unsigned char> encoded_command(size);
	unsigned char *p = encoded_command.data();
	
	size_t num_strings = command.size();
	memcpy(p, &num_strings, sizeof(num_strings));
	p += sizeof(num_strings);
	
	for(auto i = command.begin(); i != command.end(); ++i)
	{
		size_t string_len = i->length();
		memcpy(p, &string_len, sizeof(string_len));
		p += sizeof(string_len);
		
		memcpy(p, i->data(), string_len);
		p += string_len;
	}
	
	assert(p == (encoded_command.data() + encoded_command.size()));
	
	return encoded_command;
}

std::vector<std::string> REHex::decode_command(const void *data, size_t len)
{
	const unsigned char *p = (const unsigned char*)(data);
	const unsigned char *end = p + len;
	
	auto throw_decode_error = [&]()
	{
		throw std::runtime_error(std::string("Error decoding command at offset ") + std::to_string(p - (const unsigned char*)(data)));
	};
	
	if((p + sizeof(size_t)) > end)
	{
		throw_decode_error();
	}
	
	size_t num_strings;
	memcpy(&num_strings, p, sizeof(num_strings));
	p += sizeof(num_strings);
	
	std::vector<std::string> decoded_command;
	decoded_command.reserve(num_strings);
	
	for(size_t i = 0; i < num_strings; ++i)
	{
		if((p + sizeof(size_t)) > end)
		{
			throw_decode_error();
		}
		
		size_t string_len;
		memcpy(&string_len, p, sizeof(string_len));
		p += sizeof(string_len);
		
		if((p + string_len) > end)
		{
			throw_decode_error();
		}
		
		decoded_command.emplace_back((const char*)(p), string_len);
		p += string_len;
	}
	
	if(p != end)
	{
		throw_decode_error();
	}
	
	return decoded_command;
}
