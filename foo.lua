-- wx.wxMessageBox("Hello world");

inspect = require("inspect");

local onReady = rehex.REHex_App_SetupHookRegistration.new(
	rehex.App_SetupPhase_READY,
	function()
		print("App READY setup hook called");
	end);

local onDone = rehex.REHex_App_SetupHookRegistration.new(
	rehex.App_SetupPhase_DONE,
	function()
		print("App DONE setup hook called");
	end);

function init()
	print("init() called");
	print(inspect(rehex));
end
