--
-- A class that provides file-like operations on a REHex::Document so a KaitaiStream can access it.
-- Based on https://github.com/kaitai-io/kaitai_struct_lua_runtime/blob/master/string_stream.lua
--

local class = require("class")

local DocumentStream = class.class()

function DocumentStream:_init(s)
	self._doc = s
	self._pos = 0
end

function DocumentStream:close()
    -- Nothing to do here
end

function DocumentStream:seek(whence, offset)
	local len = self._doc:buffer_length()
	whence = whence or "cur"

	if whence == "set" then
		self._pos = offset or 0
	elseif whence == "cur" then
		self._pos = self._pos + (offset or 0)
	elseif whence == "end" then
		self._pos = len + (offset or 0)
	else
		error("bad argument #1 to 'seek' (invalid option '" .. tostring(whence) .. "')", 2)
	end

	if self._pos < 0 then
		self._pos = 0
	elseif self._pos > len then
		self._pos = len
	end

	return self._pos
end

function DocumentStream:read(num)
	local len = self._doc:buffer_length()

	if num == "*all" then
		if self._pos >= len then
			return nil
		end

		local ret = self._doc:read_data(self._pos)
		self._pos = len

		return ret
	elseif num <= 0 then
		return ""
	end

	local ret = self._doc:read_data(self._pos, num)

	if ret:len() == 0 then
		return nil
	end

	self._pos = self._pos + ret:len()
	if self._pos > len then
		self._pos = len
	end

	return ret
end

function DocumentStream:pos()
	return self._pos
end

return DocumentStream
