-- Binary Template plugin for REHex
-- Copyright (C) 2021-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

require 'stable_sort';

local preprocessor = require 'preprocessor';
local parser = require 'parser';
local executor = require 'executor';

local function _find_templates(path)
	local templates = {}
	
	local dir = wx.wxDir.new(path)
	if not dir:IsOpened()
	then
		print("Unable to open " .. path)
		return templates
	end
	
	local ok, name = dir:GetFirst("*.bt", wx.wxDIR_FILES)
	while ok
	do
		table.insert(templates, { name, path .. "/" .. name })
		ok, name = dir:GetNext()
	end
	
-- 	ok, name = dir:GetFirst("*", wx.wxDIR_DIRS)
-- 	
-- 	while ok
-- 	do
-- 		local t = _find_templates(path .. "/" .. name)
-- 		
-- 		for _, v in ipairs(t)
-- 		do
-- 			table.insert(templates, v)
-- 		end
-- 		
-- 		ok, name = dir:GetNext()
-- 	end
	
	-- Sort templates by name
	table.sort(templates, function(a, b) return a[1]:upper() < b[1]:upper() end)
	
	return templates
end

local ID_BROWSE = 1
local ID_RANGE_FILE = 2
local ID_RANGE_SEL = 3
local ID_RANGE_CURSOR = 4

rehex.AddToToolsMenu("Execute binary template / script...", function(window)
	local tab = window:active_tab()
	local doc = window:active_document()
	
	-- Find any templates under the templates/ directory.
	local templates = _find_templates(rehex.PLUGIN_DIR .. "/" .. "templates")
	local base_templates_count = #templates
	
	-- Find templates recently selected using the "Browse..." button.
	local config = wx.wxConfigBase.Get()
	config:SetPath("/plugins/binary-template/recent-templates/")
	
	local recent_templates = wx.wxFileHistory.new(5)
	recent_templates:Load(config)
	
	local recent_templates_count = recent_templates:GetCount()
	for i = 0, (recent_templates_count - 1)
	do
		local path = recent_templates:GetHistoryFile(i)
		local name = wx.wxFileName.new(path):GetFullName()
		
		table.insert(templates, { name, path })
	end
	
	local my_window = wx.wxDialog(window, wx.wxID_ANY, "Execute binary template")
	
	local template_sizer = wx.wxStaticBoxSizer(wx.wxHORIZONTAL, my_window, "Template")
	local template_box = template_sizer:GetStaticBox()
	
	local template_choice = wx.wxChoice(template_box, wx.wxID_ANY)
	template_sizer:Add(template_choice, 1, wx.wxALL, 5)
	
	for _, v in ipairs(templates)
	do
		template_choice:Append(v[1])
	end
	
	template_choice:SetSelection(0)
	
	local browse_btn = wx.wxButton(template_box, ID_BROWSE, "Browse...")
	template_sizer:Add(browse_btn, 0, wx.wxLEFT | wx.wxRIGHT | wx.wxTOP, 5)
	
	my_window:Connect(ID_BROWSE, wx.wxEVT_BUTTON, function(event)
		local browse_dialog = wx.wxFileDialog(my_window, "Select template file", "", "", "Binary Template files (*.bt)|*.bt", wx.wxFD_OPEN | wx.wxFD_FILE_MUST_EXIST)
		local result = browse_dialog:ShowModal()
		
		if result == wx.wxID_OK
		then
			local name = browse_dialog:GetFilename()
			local path = browse_dialog:GetPath()
			
			template_choice:Append(name)
			template_choice:SetSelection(#templates)
			
			table.insert(templates, { name, path })
		end
	end)
	
	local range_sizer = wx.wxStaticBoxSizer(wx.wxVERTICAL, my_window, "Range")
	local range_box = range_sizer:GetStaticBox()
	
	local range_file = wx.wxRadioButton(range_box, ID_RANGE_FILE, "Apply template to whole file")
	range_sizer:Add(range_file)
	
	local range_sel  = wx.wxRadioButton(range_box, ID_RANGE_SEL,  "Apply template to selection only")
	range_sizer:Add(range_sel)
	
	local range_cursor = wx.wxRadioButton(range_box, ID_RANGE_CURSOR, "Apply template from cursor")
	range_sizer:Add(range_cursor)
	
	local selection_off, selection_length = tab:get_selection_linear()
	if selection_off ~= nil and selection_length:byte_aligned()
	then
		range_sel:SetValue(true)
		selection_length = selection_length:byte()
	else
		range_sel:Disable()
		range_file:SetValue(true)
	end
	
	local ok_btn = wx.wxButton(my_window, wx.wxID_OK, "OK")
	local cancel_btn = wx.wxButton(my_window, wx.wxID_CANCEL, "Cancel")
	
	local btn_sizer = wx.wxBoxSizer(wx.wxHORIZONTAL)
	btn_sizer:Add(ok_btn)
	btn_sizer:Add(cancel_btn, 0, wx.wxLEFT, 5)
	
	local main_sizer = wx.wxBoxSizer(wx.wxVERTICAL)
	main_sizer:Add(template_sizer, 0, wx.wxEXPAND | wx.wxTOP | wx.wxLEFT | wx.wxRIGHT, 5)
	main_sizer:Add(range_sizer, 0, wx.wxEXPAND | wx.wxTOP | wx.wxLEFT | wx.wxRIGHT, 5)
	main_sizer:Add(btn_sizer, 0, wx.wxALIGN_RIGHT | wx.wxALL, 5)
	
	my_window:SetSizerAndFit(main_sizer)
	
	local btn_id = my_window:ShowModal()
	
	if btn_id == wx.wxID_OK
	then
		local template_idx = template_choice:GetSelection() + 1
		local template_path = templates[template_idx][2]
		
		-- If the template was browsed to manually (now or in the past), add it to the
		-- front of the recent templates list.
		if template_idx > base_templates_count
		then
			recent_templates:AddFileToHistory(template_path)
			recent_templates:Save(config)
		end
		
		local progress_dialog = wx.wxProgressDialog("Processing template", "Processing template...", 100, window, wx.wxPD_CAN_ABORT | wx.wxPD_ELAPSED_TIME)
		progress_dialog:Show()
		
		if range_file:GetValue()
		then
			selection_off = rehex.BitOffset(0, 0)
			selection_length = doc:buffer_length()
		elseif range_cursor:GetValue()
		then
			selection_off = doc:get_cursor_position()
			selection_length = (rehex.BitOffset(doc:buffer_length(), 0) - selection_off):byte()
		end
		
		local yield_counter = 0
		local data_types = {}
		local comments = {}
		
		local interface = {
			set_data_type = function(offset, length, data_type)
				table.insert(data_types, { (selection_off:byte() + offset), selection_off:bit(), length, 0, data_type })
			end,
			
			set_comment = function(offset, length, text)
				table.insert(comments, { (selection_off:byte() + offset), selection_off:bit(), length, 0, text })
			end,
			
			allocate_highlight_colour = function(label, primary_colour, secondary_colour)
				return doc:allocate_highlight_colour(label, primary_colour, secondary_colour)
			end,
			
			set_highlight = function(offset, length, colour)
				doc:set_highlight(selection_off + rehex.BitOffset(offset, 0), rehex.BitOffset(length, 0), colour)
			end,
			
			read_data = function(offset, length)
				return doc:read_data(selection_off + rehex.BitOffset(offset, 0), length)
			end,
			
			file_length = function()
				return selection_length
			end,
			
			print = function(s) rehex.print_info(s) end,
			
			yield = function(desc)
				-- The yield method gets called at least once for every statement
				-- as it gets executed, don't pump the event loop every time or we
				-- wind up spending all our time doing that.
				--
				-- There isn't any (portable) time counter I can check in Lua, so
				-- the interval is an arbitrarily chosen number that seems to give
				-- (more than) good responsiveness on my PC and speeds up execution
				-- of an idle loop by ~10x ish.
				
				if yield_counter < 8000
				then
					yield_counter = yield_counter + 1
					return
				end
				
				yield_counter = 0
				
				if desc ~= nil
				then
					progress_dialog:Pulse(desc)
				else
					progress_dialog:Pulse()
				end
				
				wx.wxGetApp():ProcessPendingEvents()
				
				if progress_dialog:WasCancelled()
				then
					error("Template execution aborted", 0)
				end
			end,
			
			get_valid_charsets = function()
				local all_encodings = rehex.CharacterEncoding.all_encodings()
				local valid_charsets = {}
				
				for i = 1, #all_encodings
				do
					table.insert(valid_charsets, all_encodings[i].key)
				end
				
				return valid_charsets
			end,
		}
		
		doc:transact_begin("Binary template")
		
		local start_time = os.time()
		
		local ok, err = pcall(function()
			executor.execute(interface, parser.parse_text(preprocessor.preprocess_file(template_path)))
			
			progress_dialog:Pulse("Setting data types...")
			
			local sort_counter = 0
			table.stable_sort(data_types, function(a, b)
				-- Reduce yield frequency down within sort comparator.
				if sort_counter < 20
				then
					sort_counter = sort_counter + 1
				else
					sort_counter = 0
					interface.yield()
				end
				
				return a[1] < b[1]
			end)
			
			local TYPES_PER_BATCH = 50000
			for i = 1, #data_types, TYPES_PER_BATCH
			do
				progress_dialog:Pulse("Setting data types... (" .. i .. "/" .. #data_types ..")")
				wx.wxGetApp():ProcessPendingEvents()
				
				if progress_dialog:WasCancelled()
				then
					error("Template execution aborted", 0)
				end
				
				local dt_slice = { table.unpack(data_types, i, (i + TYPES_PER_BATCH)) }
				doc:set_data_type_bulk(dt_slice)
			end
			
			progress_dialog:Pulse("Setting comments...")
			wx.wxGetApp():ProcessPendingEvents()
			
			doc:set_comment_bulk(comments)
		end)
		
		local end_time = os.time()
		
		rehex.print_info("Template execution took " .. (end_time - start_time) .. " seconds\n")
		
		progress_dialog:Destroy()
		
		if ok
		then
			doc:transact_commit()
		else
			doc:transact_rollback()
			wx.wxMessageBox(err, "Error")
		end
	end
end);
