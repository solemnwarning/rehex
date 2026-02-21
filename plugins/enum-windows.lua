-- Window enumerator plugin for REHex
-- Copyright (C) 2026 Daniel Collins <solemnwarning@solemnwarning.net>
--
-- This program is free software; you can redistribute it and/or modify it
-- under the terms of the GNU General Public License version 2 as published by
-- the Free Software Foundation.
--
-- This program is distributed in the hope that it will be useful, but WITHOUT
-- ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
-- FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
-- more details.
--
-- You should have received a copy of the GNU General Public License along with
-- this program; if not, write to the Free Software Foundation, Inc., 51
-- Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

-- This plugin sets up a listening TCP server which, upon connection, sends any client an XML
-- document describing all application windows and then closes the connection.
--
-- NOTE: This plugin is for TESTING PURPOSES ONLY, it makes no attempts to be secure and will
-- potentially leak sensitive data as well as probably providing an easy way to remotely hang the
-- application.

local function serialise_windows()
	local result = "<MainWindows>\n"
	
	local do_window = function(do_window, w, depth)
		result = result
			.. string.rep("  ", depth)
			.. "<" .. (depth == 0 and "MainWindow" or "wxWindow")
			
		if depth > 0
		then
			result = result
				.. " class=\"" .. w:GetClassInfo():GetClassName() .. "\""
				.. " id=\"" .. w:GetId() .. "\""
				.. " name=\"" .. w:GetName() .. "\""
				.. " label=\"" .. w:GetLabel() .. "\""
		end
		
		local local_rect = w:GetRect()
		result = result
			.. " local_x1=\"" .. local_rect:GetLeft() .. "\""
			.. " local_y1=\"" .. local_rect:GetTop() .. "\""
			.. " local_x2=\"" .. local_rect:GetRight() .. "\""
			.. " local_y2=\"" .. local_rect:GetBottom() .. "\""
		
		local screen_rect = w:GetScreenRect()
		result = result
			.. " screen_x1=\"" .. screen_rect:GetLeft() .. "\""
			.. " screen_y1=\"" .. screen_rect:GetTop() .. "\""
			.. " screen_x2=\"" .. screen_rect:GetRight() .. "\""
			.. " screen_y2=\"" .. screen_rect:GetBottom() .. "\""
		
		local children = w:GetChildren()
		
		if children:GetCount() == 0
		then
			result = result .. " />\n"
		else
			result = result .. ">\n"
			
			local cnode = children:GetFirst()
			while cnode ~= nil
			do
				local child = cnode:GetData():DynamicCast("wxWindow")
				do_window(do_window, child, depth + 1)
				
				cnode = cnode:GetNext()
			end
			
			result = result
				.. string.rep("  ", depth)
				.. "</" .. (depth == 0 and "MainWindow" or "wxWindow") .. ">\n"
		end
	end
	
	local windows = rehex.MainWindow.all_windows()
	
	for _, window in ipairs(windows)
	do
		do_window(do_window, window, 0)
	end
	
	result = result .. "</MainWindows>\n"
	
	return result
end

-- NOTE: server and handler are global so that they don't get destroyed after initialisation.
server = nil
handler = nil

rehex.OnAppDone(function()
	handler = wx.wxEvtHandler()

	handler:Connect(wx.wxEVT_SOCKET, function(event)
		local windows = serialise_windows()
		
		while true
		do
			local client = server:Accept(false)
			if client ~= nil
			then
				local sent = 0
				while sent < windows:len()
				do
					client:Write(windows:sub((1 + sent), windows:len()))
					
					if client:Error()
					then
						break
					end
					
					sent = sent + client:LastCount()
				end
				
				-- client:ShutdownOutput()
				client:Destroy()
			else
				break
			end
		end
	end)

	local bind_addr = wx.wxIPV4address()
	bind_addr:AnyAddress()
	bind_addr:Service(0)

	server = wx.wxSocketServer(bind_addr)

	server:GetLocal(bind_addr)
	io.stdout:write("Window enumerator bound to port " .. bind_addr:Service() .. "\n")
	io.stdout:flush()

	server:SetEventHandler(handler)
	server:SetNotify(wx.wxSOCKET_CONNECTION_FLAG)
	server:Notify(true)
end)
