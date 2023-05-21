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

local ArrayValue = require 'executor.arrayvalue'
local FileValue  = require 'executor.filevalue'

--- Value (as in lvalue) class for arrays of document-backed POD values.
--
-- This is a special-case of ArrayValue used for arrays of fixed-length POD
-- values in the document which creates child Value objects on demand to avoid
-- having to construct many hundreds/thousands for buffers/etc.
--
-- Once constructed this can be accessed using the Lua [] and # operators like
-- an ordinary ArrayValue.

local FileArrayValue = {}
FileArrayValue.__index = ArrayValue

--- Construct a new FileArrayValue object.
--
-- @param context      Reference to executor internal context table
-- @param offset       Offset to the values within the document
-- @param n_elements   Number of elements in the array
-- @param elem_length  Length of each element, in bytes
-- @param fmt          Format token for string.unpack() to read the raw value
--
function FileArrayValue:new(context, offset, n_elements, elem_length, fmt)
	local self = {
		offset = offset,
		n_elements = n_elements,
		elem_length = elem_length,
		fmt = fmt,
	}
	
	setmetatable(self, {
		__index = function(self, k)
			if type(k) == "number"
			then
				if k >= 1 and k <= self.n_elements
				then
					return FileValue:new(context, (self.offset + ((k - 1) * self.elem_length)), self.elem_length, self.fmt)
				end
			else
				return FileArrayValue[k]
			end
		end,
		
		__len = function(self)
			return self.n_elements
		end,
	})
	
	return self
end

--- Resize the FileArrayValue object
--
-- @param n_elements  New array length
--
function FileArrayValue:resize(n_elements)
	self.n_elements = n_elements
end

function FileArrayValue:data_range()
	return self.offset, self.offset + self.n_elements * self.elem_length
end

return FileArrayValue
