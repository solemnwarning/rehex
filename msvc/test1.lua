
print('test1 plugin loaded!')

function dump(whitespace, obj)
    for n in pairs(obj) do
        --print(name)
        if type(n) ~= 'string' or n:sub(1, 1) ~= '_' then
            local t = type(obj[n])
            if t == 'table' then
                print(whitespace .. n .. ':')
                dump(whitespace .. '  ', obj[n])
            else
                print(whitespace .. n .. '(' .. t .. '):' .. tostring(obj[n]))
            end
        end
    end
end

function init(doc)
    print('title:', doc:get_title())
    print('filename:', doc:get_filename())
    print('dirty:', doc:is_dirty())
    print('buffer_length:', doc:buffer_length())
    if doc:get_filename():sub(-4) == '.zip' then
        package.path = package.path .. ";./lua_runtime/?.lua"
        require('zip')
        local data = doc:read_data('*all')
        local kai_object = Zip:from_string(data)
        dump('', kai_object)
    end
    -- return array for string list,
    -- return table for grid view?
end

