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

local PlainValue = {}
PlainValue.__index = PlainValue

function PlainValue:new(value)
	local self = {
		value = value,
	}
	
	setmetatable(self, PlainValue)
	
	return self
end

function PlainValue:get()
	return self.value
end

function PlainValue:set(value)
	self.value = value
end

function PlainValue:copy()
	return PlainValue:new(self.value)
end

function PlainValue:data_range()
	return -- Not backed by file data
end

return PlainValue
