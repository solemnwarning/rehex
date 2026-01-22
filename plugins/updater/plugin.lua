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

local update_done = false
local update_running = false

local function validate_signature(message, signature)
	return rehex._verify_signature(message, signature, config.pubkey)
end

--- Display update version information and ask the user if they want to install it.
--
-- @tparam string version        Application version in update.
-- @tparam string release_notes  Release notes, with LF line separators.
-- @tparam bool force_prompt     Display prompt even if user has ignored this version.
--
local function update_prompt(version, release_notes, force_prompt)
	local ID_IGNORE_UPDATE = 1
	local ID_REMIND_UPDATE = 2
	local ID_DOWNLOAD_UPDATE = 3

	local MARGIN = 8

	local frame = wx.wxDialog(
		wx.NULL,
		wx.wxID_ANY,
		"Update Available - Reverse Engineers' Hex Editor",
		wx.wxDefaultPosition,
		wx.wxSize(800, 320),
		(wx.wxDEFAULT_DIALOG_STYLE | wx.wxRESIZE_BORDER))

	local frame_sizer = wx.wxBoxSizer(wx.wxVERTICAL)

	local text = wx.wxStaticText(frame, wx.wxID_ANY, "REHex " .. version .. " is available to download")
	frame_sizer:Add(text, 0, (wx.wxEXPAND | wx.wxLEFT | wx.wxRIGHT | wx.wxTOP), MARGIN)

	local changes_sw = wx.wxScrolledWindow(frame, wx.wxID_ANY, wx.wxDefaultPosition, wx.wxDefaultSize, (wx.wxVSCROLL | wx.wxBORDER_SIMPLE))
	frame_sizer:Add(changes_sw, 1, (wx.wxEXPAND | wx.wxLEFT | wx.wxRIGHT | wx.wxTOP), MARGIN)

	local sw_sizer = wx.wxBoxSizer(wx.wxHORIZONTAL)
	changes_sw:SetSizer(sw_sizer)
	changes_sw:SetBackgroundColour(wx.wxSystemSettings.GetColour(wx.wxSYS_COLOUR_WINDOW))
	changes_sw:SetScrollRate(0, 10)

	local changes = wx.wxStaticText(changes_sw, wx.wxID_ANY, release_notes)
	sw_sizer:Add(changes, 0, wx.wxALL, MARGIN)

	local button_sizer = wx.wxBoxSizer(wx.wxHORIZONTAL)

	local ignore_button = wx.wxButton(frame, ID_IGNORE_UPDATE, "Ignore this update")
	ignore_button:SetBitmap(wx.wxArtProvider.GetBitmap(wx.wxART_CROSS_MARK, wx.wxART_BUTTON))
	button_sizer:Add(ignore_button, 0)

	local later_button = wx.wxButton(frame, ID_REMIND_UPDATE, "Remind me later")
	later_button:SetBitmap(wx.wxArtProvider.GetBitmap(wx.wxART_ADD_BOOKMARK, wx.wxART_BUTTON))
	button_sizer:Add(later_button, 0, wx.wxLEFT, MARGIN)

	local download_button = wx.wxButton(frame, ID_DOWNLOAD_UPDATE, "Download now")
	download_button:SetBitmap(wx.wxArtProvider.GetBitmap(wx.wxART_GO_DOWN, wx.wxART_BUTTON))
	button_sizer:Add(download_button, 0, wx.wxLEFT, MARGIN)

	frame:SetAffirmativeId(ID_DOWNLOAD_UPDATE)
	frame:SetEscapeId(ID_REMIND_UPDATE)

	frame:Connect(wx.wxEVT_BUTTON, function(event)
		frame:EndModal(event:GetId())
	end)

	frame_sizer:Add(button_sizer, 0, (wx.wxALIGN_CENTER_HORIZONTAL | wx.wxALL), MARGIN)

	frame:SetSizer(frame_sizer)
	frame:Center(wx.wxBOTH)

	local result = frame:ShowModal()
	
	frame:Destroy()

	-- TODO: Save version when ID_IGNORE_UPDATE is pressed to ignore it on future automatic checks.
	
	return result == ID_DOWNLOAD_UPDATE
end

local function fmt_size(bytes)
	return string.format("%.02f MiB", (bytes / (1024 * 1024)))
end

--- Download a file to disk while accumulating SHA256 checksum.
--
-- @param url          Source HTTP(S) URL.
-- @param destination  Destination file name.
-- @param on_success   Callback to call on success.
-- @param on_error     Callback for an error downloading or writing the file.
-- @param on_progress  Callback for progress updates during download.
--
-- The on_success callback receives the SHA256 checksum of the downloaded file in hex form.
--
-- The on_error callback receives a string describing the error.
--
-- The on_progress callback receives the currently received number of bytes and the total expected
-- number of bytes (which may be nil if the server didn't send a Content-Length header).
--
local function download_file(url, destination, on_success, on_error, on_progress)
	local handler = wx.wxEvtHandler()
	local request = wx.wxWebSession.GetDefault():CreateRequest(handler, url)

	local deferred_error = nil
	local cancelled = false
	
	local file = nil
	
	local cleanup = function()
		if file ~= nil
		then
			file:close()
			file = nil
		end

		if cancelled
		then
			os.remove(destination)
		end

		request = nil
		handler = nil
	end

	local handle_error = function(err)
		cleanup()
		os.remove(destination)

		if not cancelled
		then
			on_error(err)
		end
	end

	if not request:IsOk()
	then
		handle_error("Error downloading update")
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
		
		if cancelled
		then
			return
		end

		local _, err = file:write(data)
		if err ~= nil
		then
			deferred_error = "Error writing to " .. destination .. "(" .. err .. ")"
			request:Cancel()
		end

		sha256_accum:update(data)

		local total_size = request:GetBytesExpectedToReceive()
		local received_size = request:GetBytesReceived()

		if total_size > 0
		then
			on_progress(received_size, total_size)
		else
			on_progress(received_size, nil)
		end
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

			request = nil
			handler = nil

			if not cancelled
			then
				on_success(sha256_result)
			end
			
			return
		elseif state == wx.wxWebRequest.State_Failed or state == wx.wxWebRequest.State_Unauthorized
		then
			handle_error("Request error: " .. event:GetErrorDescription())
			return
		elseif state == wx.wxWebRequest.State_Cancelled
		then
			if deferred_error ~= nil
			then
				handle_error(deferred_error)
			else
				cleanup()
			end
			
			return
		end
	end)

	request:Start()
	
	return function()
		cancelled = true
		request:Cancel()
		
		update_running = false
	end
end

local function appimage_update(url, checksum, version)
	local appimage_path = os.getenv("APPIMAGE")

	-- Get offset of final path component in appimage path
	local appimage_name_idx = appimage_path:find("[^/]+$")

	local appimage_dir = appimage_path:sub(1, (appimage_name_idx - 1))

	local progress_dialog = wx.wxProgressDialog("Downloading update", "Downloading REHex " .. version, 100, wx.NULL, wx.wxPD_CAN_ABORT | wx.wxPD_ELAPSED_TIME | wx.wxPD_REMAINING_TIME)
	local dialog_timer = wx.wxTimer()
	
	local request_cancel = nil
	
	dialog_timer:Connect(wx.wxEVT_TIMER, function(event)
		if progress_dialog:WasCancelled()
		then
			dialog_timer:Stop()
			dialog_timer = nil
			
			request_cancel()
			
			progress_dialog:Destroy()
			progress_dialog = nil
		end
	end)
	
	dialog_timer:Start(100, wx.wxTIMER_CONTINUOUS)

	-- Download the update appimage to the same directory so we can just rename it
	local download_name = ".rehex-update-download"
	local download_path = appimage_dir .. download_name;
	
	request_cancel = download_file(url, download_path,
		-- Download succeeded
		function(download_checksum)
			dialog_timer:Stop()
			dialog_timer = nil
			
			if download_checksum:lower() ~= checksum:lower()
			then
				progress_dialog:Destroy()
				progress_dialog = nil

				os.remove(download_path)
				
				wx.wxMessageBox("Downloaded file is corrupt", "Update error", wx.wxOK)
				
				update_running = false
				return
			end
			
			progress_dialog:Update((progress_dialog:GetRange() - 1), "Installing REHex " .. version)
			
			-- Copy permissions from current AppImage to new one.
			local chmod_ok, chmod_etype, chmod_ecode = os.execute("chmod \"$(stat -c '%a' \"$APPIMAGE\")\" \"$(dirname \"$APPIMAGE\")/" .. download_name .. "\"")
			if not chmod_ok
			then
				progress_dialog:Destroy()
				progress_dialog = nil
				
				wx.wxMessageBox("Error setting permissions on " .. download_path, "Update error", wx.wxOK)
				
				update_running = false
				return
			end

			if false
			then
				local ok, err = os.remove(appimage_path)
				if not ok
				then
					progress_dialog:Destroy()
					progress_dialog = nil
					
					wx.wxMessageBox("Error replacing " .. appimage_path, "Update error", wx.wxOK)
					
					update_running = false
					return
				end

				ok, err = os.rename(download_path, appimage_path)
				if not ok
				then
					progress_dialog:Destroy()
					progress_dialog = nil
					
					wx.wxMessageBox("Error replacing " .. appimage_path, "Update error", wx.wxOK)
					
					update_running = false
					return
				end
			end
			
			progress_dialog:Destroy()
			progress_dialog = nil

			wx.wxMessageBox("REHex has been updated, restart the application to use the new version", "Update installed", wx.wxOK)
			
			update_done = true
			update_running = false
		end,
		
		-- Download failed
		function(error_desc)
			dialog_timer:Stop()
			dialog_timer = nil
			
			progress_dialog:Destroy()
			progress_dialog = nil
			
			wx.wxMessageBox(error_desc, "Update error", wx.wxOK)
			update_running = false
		end,
		
		-- Downlad progress
		function(received_size, total_size)
			if total_size ~= nil
			then
				-- We scale the progress value from zero to one less than complete because calling
				-- wxProgressDialog::Update() with its maximum value will put the dialog into modal
				-- state with an internal event loop and a close button to dismiss it, not only is
				-- this not the behaviour we want, but the modal event loop will dispatch further
				-- wxWebRequest events before we finish handling wxEVT_WEBREQUEST_DATA, which will
				-- really screw things up.

				progress_dialog:Update(((received_size / total_size) * (progress_dialog:GetRange() - 1)), ("Downloading REHex " .. version .. " (" .. fmt_size(received_size) .. " / " .. fmt_size(total_size) .. ")"))
			else
				progress_dialog:Pulse(("Downloading REHex " .. version .. " (" .. fmt_size(received_size) .. " / ???)"))
			end
		end)
	
	progress_dialog:Show()
end

--- Get the latest version from the update feed.
--
-- Downloads the update feed and extracts the latest version. This function is asynchronous and
-- returns everything via callbacks.
--
-- @param interactive  Whether a progress dialog should be displayed (blocks the UI!)
-- @param on_success   Callback to call on success.
-- @param on_error     Callback for an error downloading or parsing the feed.
-- @param on_cancel    Callback for the user pressing cancel.
--
-- The on_success function receives a table with the following fields:
--
-- {
--   version:   "1.0",
--   url:       "http://<url to download update package>",
--   sha256sum: "<SHA256 checksum in hex format>",
-- }
--
-- The on_error callback receives a string desribing the error.
--
-- The on_cancel callback receives no arguments.
--
local function get_available_update(interactive, on_success, on_error, on_cancel)
	local handler = wx.wxEvtHandler()
	local request = wx.wxWebSession.GetDefault():CreateRequest(handler, config.feed);

	if not request:IsOk()
	then
		on_error("Error downloading update feed")
		return
	end
	
	local progress_dialog = nil
	local dialog_timer = nil
	
	local cleanup = function()
		if interactive
		then
			dialog_timer:Stop()
			dialog_timer = nil
			
			progress_dialog:Destroy()
			progress_dialog = nil
		end
		
		request = nil
		handler = nil
	end
	
	if interactive
	then
		progress_dialog = wx.wxProgressDialog("Checking for updates", "Downloading update feed...", 100, wx.NULL, (wx.wxPD_CAN_ABORT | wx.wxPD_ELAPSED_TIME | wx.wxPD_APP_MODAL))
		progress_dialog:Show()
		
		-- We are being run interatively, set up a timer to periodically check if the user has
		-- pressed the cancel button on the progress dialog.
		
		dialog_timer = wx.wxTimer()
		
		dialog_timer:Connect(wx.wxEVT_TIMER, function(event)
			if progress_dialog:WasCancelled()
			then
				request:Cancel()
			end
		end)
		
		dialog_timer:Start(100, wx.wxTIMER_CONTINUOUS)
	end

	handler:Connect(wx.wxEVT_WEBREQUEST_STATE, function(event)
		local state = event:GetState()

		if state == wx.wxWebRequest.State_Completed
		then
			local response = event:GetResponse()
			local response_body = response:GetStream():Read(response:GetContentLength())

			local ok, result = pcall(function() return Updater.parse_feed(response_body, validate_signature) end)
			if ok
			then
				local latest_in_feed = result[1]

				for i = 2, #result
				do
					if Updater.versioncmp(result[i].version, latest_in_feed.version) > 0
					then
						latest_in_feed = result[i]
					end
				end

				cleanup()
				on_success(latest_in_feed)
			else
				rehex.print_error("Update feed error: " .. result .. "\n")

				cleanup()
				on_error("Invalid update feed")
			end
		elseif state == wx.wxWebRequest.State_Failed or state == wx.wxWebRequest.State_Unauthorized
		then
			cleanup()
			on_error("Error downloading update feed: " .. event.GetErrorDescription())
		elseif state == wx.wxWebRequest.State_Cancelled
		then
			cleanup()
			on_cancel()
		end
	end)

	request:Start()
end

--- Check for an available update and prompt the user if they want to install it
--
-- @tparam bool interactive true if requested by the user, false if periodic/background check.
--
local function check_now(interactive)
	if update_running
	then
		-- Update process already running
		return
	end
	
	update_running = true
	
	-- Ignore any further updates after one has been downloaded if the application hasn't been
	-- restarted yet so we don't keep telling the user to download what they've already got.
	if update_done
	then
		if interactive
		then
			wx.wxMessageBox("No updates available", "Update", wx.wxOK)
		end

		update_running = false
		return
	end
	
	get_available_update(interactive,
		function(update)
			-- Update feed was downloaded successfully
			
			if Updater.versioncmp(update.version, rehex.SHORT_VERSION) > 0
			then
				local update_now = update_prompt(update.version, update.notes, (progress_dialog ~= nil))
				if update_now
				then
					if config.method == "AppImage"
					then
						appimage_update(update.url, update.sha256sum, update.version)
						return -- Early exit to avoid clearing update_running
					else
						rehex.print_error("Unrecognised update method '" .. config.method .. "'\n")
					end
				end
			elseif interactive
			then
				wx.wxMessageBox("No updates available", "Update", wx.wxOK)
			end
			
			update_running = false
		end,
		
		function(error_desc)
			-- An error was encountered downloading the update feed
			
			wx.wxMessageBox(error_desc, "Update error", wx.wxOK)
			update_running = false
		end,
		
		function()
			-- The user cancelled the update
			update_running = false
		end)
end

if config.method == "AppImage" and os.getenv("APPIMAGE") == nil
then
	rehex.print_error("Disabling updater - APPIMAGE environment variable not set\n")
	return -- Bail out before setting up updater callbacks
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

		item = help:Insert(insertion_pos, item)
		local id = item:GetId();
		
		mainwindow:Connect(id, wx.wxEVT_MENU, function(event)
			check_now(true)
		end)
	end)

local timer = nil

rehex.OnAppDone(function()
	-- Set up timer to periodically check for updates in the background.
	
	if config.interval_minutes ~= nil
		then
		timer = wx.wxTimer()
		
		timer:Connect(wx.wxEVT_TIMER, function(event)
			check_now(false)
		end)
		
		timer:Start((config.interval_minutes * 60 * 1000), wx.wxTIMER_CONTINUOUS)
	end
	
	-- Start a background update check now.
	check_now(false)
end)
