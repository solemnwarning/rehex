-- Binary Template plugin for REHex
-- Copyright (C) 2022-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

--- Value (as in lvalue) class for "struct" variables.
--
-- Structs are built on top of Lua tables - each member in the StructValue
-- table is a table containing the struct members' type info and value object.

local StructValue = {}
StructValue.__index = StructValue

--- Construct an empty StructValue table.
--
function StructValue:new()
	local self = {}
	
	setmetatable(self, StructValue)
	return self
end

function StructValue.__pairs(tbl)
	-- Iterator function takes the table and an index and returns the next index and associated value
	-- or nil to end iteration
	
	local function stateless_iter(tbl, k)
		local v
		k, v = next(tbl, k)
		
		-- Skip over any internal variables shoehorned into the struct
		while k and k:find("^__INTERNAL") ~= nil
		do
			k, v = next(tbl, k)
		end
		
		if v ~= nil
		then
			return k, v
		end
	end
	
	-- Return an iterator function, the table, starting point
	return stateless_iter, tbl, nil
end

function StructValue:data_range()
	local data_start = nil
	local data_end = nil
	
	for k,v in pairs(self)
	do
		local member_type = v[1]
		local member_val  = v[2]
		
		local member_start, member_end = member_val:data_range()
		
		if member_start ~= nil and (data_start == nil or member_start < data_start)
		then
			data_start = member_start
		end
		
		if member_end ~= nil and (data_end == nil or member_end > data_end)
		then
			data_end = member_end
		end
	end
	
	return data_start, data_end
end

return StructValue
