if newproxy ~= nil then
	-- Lua 5.1 (https://stackoverflow.com/questions/27426704/lua-5-1-workaround-for-gc-metamethod-for-tables)
	
	a = newproxy(true)
	getmetatable(a).__gc = function() print("stub plugin unloaded") end
else
	-- Lua 5.2+
	
	a = { __gc = function() print("stub plugin unloaded") end }
	setmetatable(a,a)
end

print("stub plugin loaded")
