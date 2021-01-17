a = { __gc = function() print("stub plugin unloaded") end }
setmetatable(a,a)

print("stub plugin loaded")
