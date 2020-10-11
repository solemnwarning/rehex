--
-- String decoder functions
--

local stringdecode = {}
local bit32 = bit32 or require('bitops52')

-- From http://lua-users.org/wiki/LuaUnicode
local function utf8_to_32(utf8str)
    assert(type(utf8str) == "string")
    local res, seq, val = {}, 0, nil

    for i = 1, #utf8str do
        local c = string.byte(utf8str, i)
        if seq == 0 then
            table.insert(res, val)
            seq = c < 0x80 and 1 or c < 0xE0 and 2 or c < 0xF0 and 3 or
                  c < 0xF8 and 4 or --c < 0xFC and 5 or c < 0xFE and 6 or
                error("Invalid UTF-8 character sequence")
            val = bit32.band(c, 2^(8-seq) - 1)
        else
            val = bit32.bor(bit32.lshift(val, 6), bit32.band(c, 0x3F))
        end

        seq = seq - 1
    end

    table.insert(res, val)

    return res
end

function stringdecode.decode(str, encoding)
    local enc = encoding and encoding:lower() or "ascii"

    if enc == "ascii" then
        return str
    elseif enc == "utf-8" then
        local code_points = utf8_to_32(str)

        return utf8.char(table.unpack(code_points))
    else
        error("Encoding " .. encoding .. " not supported")
    end
end

return stringdecode
