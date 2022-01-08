-- Binary Template plugin for REHex
-- Copyright (C) 2021 Daniel Collins <solemnwarning@solemnwarning.net>
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
	
	return templates
end

rehex.AddToToolsMenu("Binary Template test", function(window)
	local doc = window:active_document()
	
	local templates = _find_templates(rehex.PLUGIN_DIR .. "/" .. "templates")
	
	local my_window = wx.wxDialog(window, wx.wxID_ANY, "hello")
	
	local template_choice = wx.wxChoice(my_window, wx.wxID_ANY)
	
	for _, v in ipairs(templates)
	do
		template_choice:Append(v[1] .. " [" .. v[2] .. "]")
	end
	
	template_choice:SetSelection(0)
	
	local ok_btn = wx.wxButton(my_window, wx.wxID_OK, "OK")
	local cancel_btn = wx.wxButton(my_window, wx.wxID_CANCEL, "Cancel")
	
	local btn_sizer = wx.wxBoxSizer(wx.wxHORIZONTAL)
	btn_sizer:Add(ok_btn)
	btn_sizer:Add(cancel_btn, 0, wx.wxLEFT, 5)
	
	local main_sizer = wx.wxBoxSizer(wx.wxVERTICAL)
	main_sizer:Add(template_choice)
	main_sizer:Add(btn_sizer, 0, wx.wxALIGN_RIGHT | wx.wxALL, 5)
	
	my_window:SetSizerAndFit(main_sizer)
	
	local btn_id = my_window:ShowModal()
	
	if btn_id == wx.wxID_OK
	then
		local template_idx = template_choice:GetSelection() + 1
		local template_path = templates[template_idx][2]
		
		local interface = {
			set_data_type = function(offset, length, data_type)
				doc:set_data_type(offset, length, data_type)
			end,
			
			set_comment = function(offset, length, text)
				doc:set_comment(offset, length, rehex.Comment.new(text))
			end,
			
			read_data = function(offset, length)
				return doc:read_data(offset, length)
			end,
			
			file_length = function()
				return doc:buffer_length()
			end,
			
			print = function(s) print(s) end,
			
			yield = function() end,
		}
		
		executor.execute(interface, parser.parse_text(preprocessor.preprocess_file(template_path)))
	end
end);
