--
-- Each enum "value" is a table containing both a string label and an integer
-- value. When two enums are compared these labels and values are individually
-- compared.
--

local enum = {}

function enum.Enum(t)
    local e = { _enums = {} }

    for k, v in pairs(t) do
        e._enums[k] = {
            label = k,
            value = v,
        }
    end

    return setmetatable(e, {
        __index = function(table, key)
            return rawget(table._enums, key)
        end,

        __call = function(table, value)
            for k, v in pairs(table._enums) do
                if v.value == value then
                    return v
                end
            end

            return nil
        end,

        __eq = function(lhs, rhs)
            for k, v in pairs(lhs._enums) do
                if v ~= rhs._enums[k] then
                    return false
                end
            end

            return true
        end
    })
end

return enum
