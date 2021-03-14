-- PE EXE/DLL parsing plugin for REHex
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

require('microsoft_pe')
DocumentStream = require('document_stream')

function process_document(doc)
	local kai_object = MicrosoftPe(KaitaiStream(DocumentStream(doc)));
	
	local code_type = nil
	
	if     kai_object.pe.coff_hdr.machine.label == "i386"  then code_type = "code:i386"
	elseif kai_object.pe.coff_hdr.machine.label == "amd64" then code_type = "code:x86_64"
	end
	
	for section_idx, section in pairs(kai_object.pe.sections) do
		local section_off = section.pointer_to_raw_data
		local section_len = section.size_of_raw_data
		
		if section_len > 0 then
			local comment_text = "Section " .. section.name
			
			if (section.characteristics & 0x00000020) ~= 0 then
				comment_text = comment_text .. "\n" .. kai_object.pe.coff_hdr.machine.label .. " machine code"
				
				if code_type ~= nil then
					-- Set a machine code data type on this section to enable inline disassembly
					doc:set_data_type(section_off, section_len, code_type)
				end
			end
			
			comment_text = comment_text .. "\nVirtual address: " .. string.format("0x%x", section.virtual_address)
			comment_text = comment_text .. "\nVirtual size: " .. string.format("0x%x", section.virtual_size)
			
			if (section.characteristics & 0xE0000000) ~= 0 then
				local access = {}
				
				if (section.characteristics & 0x20000000) ~= 0 then table.insert(access, "execute") end
				if (section.characteristics & 0x40000000) ~= 0 then table.insert(access, "read") end
				if (section.characteristics & 0x80000000) ~= 0 then table.insert(access, "write") end
				
				comment_text = comment_text .. "\nMemory access: " .. table.concat(access, ", ")
			end
			
			doc:set_comment(section_off, section_len, rehex.Comment.new(comment_text))
			
			doc:set_virt_mapping(section_off, section.virtual_address, section_len)
		end
	end
end

rehex.OnTabCreated(function(mainwindow, tab)
	local comments = tab.doc:get_comments()
	if #comments > 0 then
		-- Don't offer to analyse if there are any comments.
		return
	end
	
	local filename = tab.doc:get_filename()
	
	if string.match(filename:lower(), "%.exe$") or string.match(filename:lower(), "%.dll$") then
		-- Get the last component of the filename (i.e. skip any directories)
		local basename_off = filename:find("[^\\/]+$")
		local basename = filename:sub(basename_off)
		
		local message = basename .. " might be a PE EXE/DLL, attempt to analyse?"
		
		local res = wx.wxMessageBox(message, "Analyse PE file", wx.wxYES_NO, mainwindow)
		if res == wx.wxYES then
			process_document(tab.doc)
		end
	end
end)

rehex.AddToToolsMenu("Analyse PE EXE/DLL", function(mainwindow)
	local doc = mainwindow:active_document()
	process_document(doc)
end);
