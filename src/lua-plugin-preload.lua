local registrations = {};

rehex.OnAppReady = function(callback)
	local registration = rehex.REHex_App_SetupHookRegistration.new(rehex.App_SetupPhase_READY, callback);
	table.insert(registrations, registration);
end

rehex.OnAppDone = function(callback)
	local registration = rehex.REHex_App_SetupHookRegistration.new(rehex.App_SetupPhase_DONE, callback);
	table.insert(registrations, registration);
end
