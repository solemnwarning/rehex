-- REHex example plugins
--
-- Adds a "Window test" command to the "Tools" menu which creates and displays a
-- simple window (wxFrame) as a non-modal child of the main window.

rehex.AddToToolsMenu("Window test", function(mainwindow)
	local ID_BTN = 1;
	
	local frame = wx.wxFrame.new(mainwindow, wx.wxID_ANY, "Example plugin");
	local panel = wx.wxPanel.new(frame, wx.wxID_ANY);
	
	wx.wxButton.new(panel, ID_BTN, "Click me");
	
	frame:Connect(ID_BTN, wx.wxEVT_BUTTON, function(event)
		local res = wx.wxMessageBox("Close the window?", "Dialog", wx.wxYES_NO, frame)
		if res == wx.wxYES then
			frame:Close()
		end
	end);
	
	frame:Show();
end);
