-- wx.wxMessageBox("Hello world");

inspect = require("inspect");

rehex.OnAppReady(function()
	print("OnAppReady hook called");
end);

rehex.OnAppDone(function()
	print("OnAppDone hook called");
end);

rehex.AddToToolsMenu("test", function(mainwindow)
	wx.wxMessageBox("hello");
end);

rehex.AddToToolsMenu("read some data", function(mainwindow)
	local doc = mainwindow:active_document();
	
	local data = doc:read_data(0, 10);
	wx.wxMessageBox(inspect(data));
end);

--function init()
--	print("init() called");
--	print(inspect(rehex));
--end
