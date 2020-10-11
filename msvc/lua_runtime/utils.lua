--
-- Utility functions for KaitaiStruct
--

local utils = {}

local function array_compare(arr, fn, subscript_fn)
    if #arr == 0 then
        return nil
    end

    local ret = subscript_fn(arr, 1)

    for i = 2, #arr do
        local el = subscript_fn(arr, i)
        if fn(el, ret) then
            ret = el
        end
    end

    return ret
end

local function array_subscript(arr, i)
    return arr[i]
end

local function bytes_subscript(str, i)
    return string.byte(str, i)
end

function utils.array_min(arr)
    return array_compare(arr, function(x, y) return x < y end, array_subscript)
end

function utils.array_max(arr)
    return array_compare(arr, function(x, y) return x > y end, array_subscript)
end

function utils.byte_array_min(str)
    return array_compare(str, function(x, y) return x < y end, bytes_subscript)
end

function utils.byte_array_max(str)
    return array_compare(str, function(x, y) return x > y end, bytes_subscript)
end

-- http://lua-users.org/wiki/TernaryOperator (section Boxing/unboxing, using functions)

local False = {}
local Nil = {}

function utils.box_wrap(o)
  return o == nil and Nil or o == false and False or o
end

function utils.box_unwrap(o)
  if o == Nil then return nil
  elseif o == False then return false
  else return o end
end

return utils
