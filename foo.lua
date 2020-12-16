-- wx.wxMessageBox("Hello world");

inspect = require("inspect");

rehex.OnAppReady(function()
	print("OnAppReady hook called");
end);

rehex.OnAppDone(function()
	print("OnAppDone hook called");
end);

--function init()
--	print("init() called");
--	print(inspect(rehex));
--end
