-- Application Updater plugin for REHex
-- Copyright (C) 2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

local Updater = require 'updater'
local config = require 'config'

local function validate_signature(message, signature)
	return rehex._verify_signature(message, signature, config.pubkey)
end

local function check_now()
	handler = wx.wxEvtHandler()
	request = wx.wxWebSession.GetDefault():CreateRequest(handler, config.feed);

	if not request:IsOk()
	then
		error("???")
	end

	print("Our version is " .. rehex.SHORT_VERSION)

	handler:Connect(wx.wxEVT_WEBREQUEST_STATE, function(event)
		local state = event:GetState()

		if state == wx.wxWebRequest.State_Completed
		then
			local response = event:GetResponse()
			local response_body = response:GetStream():Read(response:GetContentLength())

			local ok, result = pcall(function() return Updater.parse_feed(response_body, validate_signature) end)
			if ok
			then
				for _, release in ipairs(result)
				do
					print("Found version " .. release.version .. " in feed " .. (Updater.versioncmp(release.version, rehex.SHORT_VERSION) > 0 and "New!" or ""))
				end
			else
				print("Feed error: " .. result)
			end
		elseif state == wx.wxWebRequest.State_Failed or state == wx.wxWebRequest.State_Unauthorized
		then
			print("Request error: " .. event:GetErrorDescription())
		end
	end)

	request:Start()
end

local function download_file(url, destination, checksum, on_success, on_error)
	local handler = wx.wxEvtHandler()
	local request = wx.wxWebSession.GetDefault():CreateRequest(handler, url)

	local file = nil

	local handle_error = function(err)
		if file ~= nil
		then
			file:close()
			file = nil
		end

		os.remove(destination)

		request = nil
		handler = nil

		on_error(err)
	end

	if not request:IsOk()
	then
		handle_error("Error initiating web request")
		return
	end

	local err

	local sha256_accum = rehex.Checksum("SHA-256")
	file, err = io.open(destination, "wb")
	if not file
	then
		handle_error("Error opening " .. destination .. "(" + err + ")")
		return
	end

	request:SetStorage(wx.wxWebRequest.Storage_None)

	handler:Connect(wx.wxEVT_WEBREQUEST_DATA, function(event)
		local data = event:GetData()

		print("Received " .. data:len() .. " bytes")

		local _, err = file:write(data)
		if err ~= nil
		then
			handle_error("Error writing to " .. destination .. "(" .. err .. ")")
			return
		end

		sha256_accum:update(data)
	end)

	handler:Connect(wx.wxEVT_WEBREQUEST_STATE, function(event)
		local state = event:GetState()

		if state == wx.wxWebRequest.State_Completed
		then
			sha256_accum:finish()
			local sha256_result = sha256_accum:checksum_hex()

			local _, err = file:close()
			if err ~= nil
			then
				handle_error("Error writing to " .. destination .. "(" .. err .. ")")
				return
			end

			if sha256_result:lower() ~= checksum:lower()
			then
				handle_error("Downloaded file has checksum " .. sha256_result .. ", expected " .. checksum)
				return
			end

			request = nil
			handler = nil

			on_success()
			return
		elseif state == wx.wxWebRequest.State_Failed or state == wx.wxWebRequest.State_Unauthorized
		then
			handle_error("Request error: " .. event:GetErrorDescription())
			return
		end
	end)

	request:Start()
end

local function appimage_update(url, checksum)
	local appimage_path = os.getenv("APPIMAGE")
	if appimage_path == nil
	then
		error("TODO")
	end

	-- Get offset of final path component in appimage path
	local appimage_name_idx = appimage_path.find("[^/]+$")

	-- Download the update appimage to the same directory so we can just rename it
	local download_path = appimage_name:sub(1, (appimage_name_idx - 1)) + ".rehex-update-download";

	download_file(url, download_path, checksum,
		-- Callback if download succeeds
		function()

		end,

		-- Callback if download fails
		function(err)

		end)
end

local help_menu_setup_hook = rehex.REHex_MainWindow_SetupHookRegistration.new(
	rehex.MainWindow_SetupPhase_HELP_MENU_BOTTOM,
	function(mainwindow)
		local help = mainwindow:get_help_menu()
		
		local about_item = help:FindItem(wx.wxID_ABOUT)

		local insertion_pos = help:GetMenuItemCount()

		for i = 0, (insertion_pos - 1)
		do
			local item = help:FindItemByPosition(i)
			if item:GetId() == wx.wxID_ABOUT
			then
				insertion_pos = i
				break
			end
		end

		local item = wx.wxMenuItem(help, wx.wxID_ANY, "Check for updates", "Check for a new version of the application")
		item:SetBitmap(wx.wxArtProvider.GetBitmap(wx.wxART_GO_UP, wx.wxART_MENU))

		--local item = help:Insert(insertion_pos, wx.wxID_ANY, "Check for updates")
		item = help:Insert(insertion_pos, item)
		local id = item:GetId();
		
		mainwindow:Connect(id, wx.wxEVT_MENU, function(event)
			check_now()
		end);
	end);
