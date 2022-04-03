-- Binary Template plugin for REHex
-- Copyright (C) 2022 Daniel Collins <solemnwarning@solemnwarning.net>
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

--- Value (as in lvalue) class for single POD values backed by the document.

local FileValue = {}
FileValue.__index = FileValue

--- Construct a new FileValue object
--
-- @param context Reference to executor internal context table
-- @param offset  Offset to the value within the document
-- @param length  Length of the value within the document
-- @param fmt     Format token for string.unpack() to read the raw value
--
function FileValue:new(context, offset, length, fmt)
	local self = {
		context = context,
		
		offset = offset,
		length = length,
		fmt = fmt,
	}
	
	setmetatable(self, FileValue)
	return self
end

function FileValue:get()
	local data = self.context.interface.read_data(self.offset, self.length)
	if data:len() < self.length
	then
		return nil
	end
	
	return string.unpack(self.fmt, data)
end

function FileValue:set(value)
	self.context.template_error(self.context, "Attempt to write to file variable")
end

function FileValue:copy()
	return FileValue:new(self.context, self.offset, self.length, self.fmt)
end

function FileValue:data_range()
	return self.offset, self.offset + self.length
end

return FileValue
