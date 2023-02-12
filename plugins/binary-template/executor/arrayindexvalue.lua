-- Binary Template plugin for REHex
-- Copyright (C) 2023 Daniel Collins <solemnwarning@solemnwarning.net>
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

--- Value (as in lvalue) class for the global ArrayIndex variable.

local ArrayIndexValue = {}
ArrayIndexValue.__index = ArrayIndexValue

-- Copied from executor.lua - ugh
local FRAME_TYPE_STRUCT   = "struct"
local FRAME_TYPE_FUNCTION = "function"

--- Construct a new ArrayIndexValue object
--
-- @param context Reference to executor internal context table
--
function ArrayIndexValue:new(context)
	local self = {
		context = context,
	}
	
	setmetatable(self, ArrayIndexValue)
	return self
end

function ArrayIndexValue:get()
	for frame_idx = #self.context.stack, 1, -1
	do
		local frame = self.context.stack[frame_idx]
		
		if frame.frame_type == FRAME_TYPE_FUNCTION or frame.frame_type == FRAME_TYPE_STRUCT
		then
			if frame.array_element_idx ~= nil
			then
				return frame.array_element_idx
			end
			
			-- Don't look for variables beyond containing scope
			break
		end
	end
	
	self.context.template_error(self.context, "Attempt to read ArrayIndex variable outside of an array element")
end

function ArrayIndexValue:set(value)
	self.context.template_error(self.context, "Attempt to write to ArrayIndex variable")
end

function ArrayIndexValue:copy()
	return ArrayIndexValue:new(self.context)
end

function ArrayIndexValue:data_range()
	return -- Not backed by file data
end

return ArrayIndexValue
