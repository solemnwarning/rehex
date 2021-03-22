rehex.OnTabCreated(function(window, tab)
	local doc = tab.doc
	
	local data = doc:read_data(128, 1024)
	local len = string.len(data)
	
	for i = 1, len
	do
		local byte = string.byte(data, i)
		print(string.format("%02x", byte))
	end
end);
