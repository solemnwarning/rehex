--
-- A "string stream" class that provides file-like operations on a string.
-- Inspired by https://gist.github.com/MikuAuahDark/e6428ac49248dd436f67c6c64fcec604
--

local class = require("class")

local StringStream = class.class()

function StringStream:_init(s)
    self._buf = s
    self._pos = 0
end

function StringStream:close()
    -- Nothing to do here
end

function StringStream:seek(whence, offset)
    local len = self._buf:len()
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

function StringStream:read(num)
    local len = self._buf:len()

    if num == "*all" then
        if self._pos == len then
            return nil
        end

        local ret = self._buf:sub(self._pos + 1)
        self._pos = len

        return ret
    elseif num <= 0 then
        return ""
    end

    local ret = self._buf:sub(self._pos + 1, self._pos + num)

    if ret:len() == 0 then
        return nil
    end

    self._pos = self._pos + num
    if self._pos > len then
        self._pos = len
    end

    return ret
end

function StringStream:pos()
    return self._pos
end

return StringStream
