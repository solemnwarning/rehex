-- pcap parsing plugin for REHex
-- Copyright (C) 2021 Pavel Martens <regularitcat@gmail.com>
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

function process_packet_record(doc, offset, num)
	doc:set_comment(offset, 4, rehex.Comment.new("Timestamp (Seconds)"))
	doc:set_comment(offset + 4, 4, rehex.Comment.new("Timestamp (Microseconds or nanoseconds)"))
	doc:set_comment(offset + 8, 4, rehex.Comment.new("Captured Packet Length"))
	doc:set_data_type(offset + 8, 4, "u32le")
	doc:set_comment(offset + 12, 4, rehex.Comment.new("Original Packet Length"))
	doc:set_data_type(offset + 12, 4, "u32le")
	local PacketLength = string.unpack('<I4', doc:read_data(offset+12, 4))
	doc:set_comment(offset + 16, PacketLength, rehex.Comment.new("Packet Data"))
	doc:set_comment(offset, PacketLength+16, rehex.Comment.new("Packet #" .. num))
	if (PacketLength >= 14) then
		doc:set_comment(offset+16, 6, rehex.Comment.new("Ethernet Destination"))
		doc:set_comment(offset+22, 6, rehex.Comment.new("Ethernet Source"))
		doc:set_comment(offset+28, 2, rehex.Comment.new("Type"))
		local PacketType = string.unpack('<I2', doc:read_data(offset+28,2))
		if (PacketType == 8) then
			doc:set_comment(offset+30,1,rehex.Comment.new("Version + Header Length"))
			doc:set_comment(offset+31,1,rehex.Comment.new("Differentiated Services Field"))
			doc:set_comment(offset+32,2,rehex.Comment.new("IP Total Length"))
			doc:set_data_type(offset+32, 2, "u16be")
			doc:set_comment(offset+34,2,rehex.Comment.new("IP Identification"))
			doc:set_comment(offset+36,2,rehex.Comment.new("IP Flags"))
			doc:set_comment(offset+38,1,rehex.Comment.new("IP TTL"))
			local Proto = string.unpack('<I1', doc:read_data(offset+39,1))
			if (Proto == 6) then
				doc:set_comment(offset+39,1,rehex.Comment.new("TCP Protocol"))
			elseif (Proto == 17) then
				doc:set_comment(offset+39,1,rehex.Comment.new("UDP Protocol"))
			end
			doc:set_comment(offset+40,2,rehex.Comment.new("IP Checksum"))
			doc:set_comment(offset+42,4,rehex.Comment.new("IP SRC"))
			doc:set_comment(offset+46,4,rehex.Comment.new("IP DST"))
			if (Proto == 6) then
				doc:set_comment(offset+50,2,rehex.Comment.new("TCP SRC Port"))
				doc:set_data_type(offset+50, 2, "u16be")
				doc:set_comment(offset+52,2,rehex.Comment.new("TCP DST Port"))
				doc:set_data_type(offset+52, 2, "u16be")
				doc:set_comment(offset+54,4,rehex.Comment.new("TCP Sequence Number"))
				doc:set_data_type(offset+54, 4, "u32be")
				doc:set_comment(offset+58,4,rehex.Comment.new("TCP Acknowledgment Number"))
				doc:set_data_type(offset+58, 4, "u32be")
				local TCPHeaderLength = string.unpack('<I1', doc:read_data(offset+62,1)) // 15 * 4
				doc:set_comment(offset+62,2,rehex.Comment.new("TCP Header Length = " .. tostring(TCPHeaderLength) .. " and TCP Flags field"))
				doc:set_comment(offset+64,2,rehex.Comment.new("TCP Window"))
				doc:set_data_type(offset+64, 2, "u16be")
				doc:set_comment(offset+66,2,rehex.Comment.new("TCP Checksum"))
				doc:set_comment(offset+68,2,rehex.Comment.new("TCP Urgent Pointer"))
				if (TCPHeaderLength > 20) then
					doc:set_comment(offset+70,TCPHeaderLength-20,rehex.Comment.new("TCP Options"))
				end
			elseif (Proto == 17) then
				doc:set_comment(offset+50,2,rehex.Comment.new("UDP SRC Port"))
				doc:set_data_type(offset+50, 2, "u16be")
				doc:set_comment(offset+52,2,rehex.Comment.new("UDP DST Port"))
				doc:set_data_type(offset+52, 2, "u16be")
				doc:set_comment(offset+54,2,rehex.Comment.new("UDP Length"))
				doc:set_data_type(offset+54, 2, "u16be")
				doc:set_comment(offset+56,2,rehex.Comment.new("UDP Checksum"))
			end
		end
	end
	return PacketLength+16
end

function process_document(doc)
	doc:set_comment(0, 24, rehex.Comment.new("File Header"))
	doc:set_comment(0, 4, rehex.Comment.new("Magic Number"))
	doc:set_comment(4, 2, rehex.Comment.new("Major Version"))
	doc:set_comment(6, 2, rehex.Comment.new("Minor Version"))
	doc:set_comment(8, 4, rehex.Comment.new("Reserved1"))
	doc:set_comment(12, 4, rehex.Comment.new("Reserved2"))
	doc:set_comment(16, 4, rehex.Comment.new("SnapLen"))
	doc:set_comment(20, 4, rehex.Comment.new("LinkType"))
	local DataLen = doc:buffer_length() - 24
	local CurrentIndex = 24
	local Packet = 1
	doc:set_comment(24, DataLen, rehex.Comment.new("Packet Records"))
	while( DataLen > 0 )
	do
		local Offset = process_packet_record(doc, CurrentIndex, Packet)
		DataLen = DataLen - Offset
		CurrentIndex = CurrentIndex + Offset
		Packet = Packet + 1
	end
end

rehex.OnTabCreated(function(mainwindow, tab)
	local comments = tab.doc:get_comments()
	if #comments > 0 then
		-- Don't offer to analyse if there are any comments.
		return
	end
	
	local filename = tab.doc:get_filename()
	
	if string.match(filename:lower(), "%.pcap$") then
		-- Get the last component of the filename (i.e. skip any directories)
		local basename_off = filename:find("[^\\/]+$")
		local basename = filename:sub(basename_off)
		
		local message = basename .. " might be a pcap, attempt to analyse?"
		
		local res = wx.wxMessageBox(message, "Analyse pcap file", wx.wxYES_NO, mainwindow)
		if res == wx.wxYES then
			local doc = tab.doc
			doc:transact_begin("Processing pcap")
			local ok, err = pcall(function()
				process_document(doc)
				end)
			if ok
			then
				doc:transact_commit()
			else
				doc:transact_rollback()
				wx.wxMessageBox(err, "Error")
			end
		end
	end
end)

rehex.AddToToolsMenu("Analyse pcap", function(mainwindow)
	local doc = mainwindow:active_document()
	doc:transact_begin("Processing pcap")
	local ok, err = pcall(function()
		process_document(doc)
	end)
	if ok
	then
		doc:transact_commit()
	else
		doc:transact_rollback()
		wx.wxMessageBox(err, "Error")
	end
end);
