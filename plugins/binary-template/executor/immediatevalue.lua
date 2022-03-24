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

local ImmediateValue = {}
ImmediateValue.__index = ImmediateValue

function ImmediateValue:new(value)
	local self = {
		value = value,
	}
	
	setmetatable(self, ImmediateValue)
	
	return self
end

function ImmediateValue:get()
	return self.value
end

function ImmediateValue:set(value)
	-- ImmediateValue variables should always be const, so it shouldn't be
	-- possible to reach this from a template.
	
	error("Internal error: attempt to change immediate value", -1)
end

function ImmediateValue:copy()
	return ImmediateValue:new(self.value)
end

function ImmediateValue:data_range()
	return -- Not backed by file data
end

return ImmediateValue
