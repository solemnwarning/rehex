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

--- Value (as in lvalue) class for arrays.
--
-- Arrays are built on top of Lua tables. Each numeric index in the table is
-- the Value object of each element in the template array.

local ArrayValue = {}
ArrayValue.__index = ArrayValue

--- Construct a new empty ArrayValue table.
--
function ArrayValue:new()
	local self = {}
	
	setmetatable(self, ArrayValue)
	return self
end

function ArrayValue:data_range()
	local data_start = self.offset
	local data_end = self.offset
	
	local x = function(v)
		local v_data_start, v_data_end = v:data_range()
		if v_data_start ~= nil
		then
			if data_start == nil or v_data_start < data_start
			then
				data_start = v_data_start
			end
			
			if data_end == nil or v_data_end > data_end
			then
				data_end = v_data_end
			end
		end
	end
	
	if #self > 0
	then
		x(self[1])
		x(self[#self])
	end
	
	return data_start, data_end
end

return ArrayValue
