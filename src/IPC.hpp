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

#ifndef REHEX_IPC_HPP
#define REHEX_IPC_HPP

#include <string>
#include <vector>
#include <wx/ipc.h>

namespace REHex
{
	class IPCConnection: public wxConnection
	{
		public:
			virtual bool OnExecute(const wxString &topic, const void *data, size_t size, wxIPCFormat format) override;
	};
	
	class IPCServer: public wxServer
	{
		public:
			virtual wxConnectionBase *OnAcceptConnection(const wxString &topic) override;
	};
	
	class IPCClient: public wxClient
	{
		
	};
	
	std::string get_ipc_host();
	std::string get_ipc_service();
	std::string get_ipc_topic();
	
	std::vector<unsigned char> encode_command(const std::vector<std::string> &command);
	std::vector<std::string> decode_command(const void *data, size_t len);
}

#endif /* !REHEX_IPC_HPP */
