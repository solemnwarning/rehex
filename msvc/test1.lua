
print('test1 plugin loaded!')

function init(doc)
    print('title:', doc:get_title())
    print('filename:', doc:get_filename())
    print('dirty:', doc:is_dirty())
    print('buffer_length:', doc:buffer_length())
    -- return array for string list,
    -- return table for grid view?
end

