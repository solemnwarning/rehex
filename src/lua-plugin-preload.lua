local registrations = {};

rehex.OnAppReady = function(callback)
	local registration = rehex.REHex_App_SetupHookRegistration.new(rehex.App_SetupPhase_READY, callback);
	table.insert(registrations, registration);
end

rehex.OnAppDone = function(callback)
	local registration = rehex.REHex_App_SetupHookRegistration.new(rehex.App_SetupPhase_DONE, callback);
	table.insert(registrations, registration);
end

rehex.AddToToolsMenu = function(label, callback)
	local registration = rehex.REHex_MainWindow_SetupHookRegistration.new(
		rehex.MainWindow_SetupPhase_TOOLS_MENU_BOTTOM,
		function(mainwindow)
			local tools = mainwindow:get_tools_menu();
			
			local item = tools:Append(wx.wxID_ANY, label);
			local id = item:GetId();
			
			mainwindow:Connect(id, wx.wxEVT_MENU, function(event)
				callback(mainwindow)
			end);
		end);
	
	table.insert(registrations, registration);
end
